// Gobierna: CA-124 (H09), decisión D2 de Carlos (2026-09-29: migraciones en SQL plano con
// runner propio, sin dependencia nueva), ADR-002, TEST-CNS-749 (propuesto en el diseño: sin
// ID; el runner no tenía test asignado).
//
// Runner de migraciones SQL planas `db/migrations/NNNN_nombre.sql`. Cada archivo declara su
// alcance en la primera línea: `-- scope: cluster` (roles; lo ejecuta un superusuario, solo
// para crear roles, idempotente y sin registro) o `-- scope: database` (lo ejecuta
// consent_migrator como consent_owner, una tx por archivo, registrado en
// ops.schema_migration(version, sha256); si el checksum de un archivo ya aplicado cambia, el
// runner falla).
//
// La credencial del migrador solo existe en el paso de migración, nunca en el proceso web.
// Las contraseñas de los roles nunca están en el repo: setRolePasswords las recibe del entorno.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Queryable } from "./pool.ts";

export type MigrationScope = "cluster" | "database";

export interface Migration {
  version: string; // "0001"
  name: string; // "schemas_catalog"
  scope: MigrationScope;
  sql: string;
  sha256: string;
}

const FILE_RE = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const SCOPE_RE = /^-- scope: (cluster|database)\s*$/;
const ADVISORY_LOCK_KEY = 7_240_124; // CA-124; serializa runners concurrentes sobre la misma base

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

export function parseMigration(fileName: string, sql: string): Migration {
  const match = FILE_RE.exec(fileName);
  if (match === null) {
    throw new MigrationError(`Nombre de migración inválido: "${fileName}" (esperado NNNN_nombre.sql en minúsculas).`);
  }
  const firstLine = sql.split("\n", 1)[0] ?? "";
  const scope = SCOPE_RE.exec(firstLine);
  if (scope === null) {
    throw new MigrationError(`"${fileName}" debe comenzar con "-- scope: cluster" o "-- scope: database".`);
  }
  return {
    version: match[1] as string,
    name: match[2] as string,
    scope: scope[1] as MigrationScope,
    sql,
    sha256: createHash("sha256").update(sql).digest("hex"),
  };
}

/** Lee y valida todas las migraciones de un directorio, ordenadas por versión. */
export function loadMigrations(dir: string): Migration[] {
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  const migrations = files.map((f) => parseMigration(f, readFileSync(join(dir, f), "utf-8")));
  const seen = new Set<string>();
  for (const m of migrations) {
    if (seen.has(m.version)) throw new MigrationError(`Versión de migración duplicada: ${m.version}.`);
    seen.add(m.version);
  }
  return migrations;
}

/** Hash estable del conjunto completo de migraciones (nombre de la plantilla de tests). */
export function migrationSetDigest(migrations: readonly Migration[]): string {
  const h = createHash("sha256");
  for (const m of migrations) h.update(`${m.version}:${m.name}:${m.scope}:${m.sha256}\n`);
  return h.digest("hex");
}

/**
 * Alcance cluster (superusuario): aplica los archivos `-- scope: cluster` en orden. Son
 * idempotentes y no se registran. Requiere una conexión con privilegio de crear roles; es
 * el único uso de superusuario y solo crea roles (P1-3).
 */
export async function applyClusterScope(superuser: Queryable, migrations: readonly Migration[]): Promise<string[]> {
  const applied: string[] = [];
  await superuser.query("SELECT pg_advisory_lock($1)", [ADVISORY_LOCK_KEY]);
  try {
    for (const m of migrations.filter((x) => x.scope === "cluster")) {
      await superuser.query(m.sql);
      applied.push(m.version);
    }
  } finally {
    await superuser.query("SELECT pg_advisory_unlock($1)", [ADVISORY_LOCK_KEY]);
  }
  return applied;
}

export type RoleName = "consent_migrator" | "app_rw" | "worker" | "platform_rw";
const ROLE_NAMES: readonly RoleName[] = ["consent_migrator", "app_rw", "worker", "platform_rw"];

/**
 * Fija contraseñas de roles LOGIN (las recibe del entorno; jamás del repo). Un rol sin
 * contraseña en el mapa queda sin poder autenticarse por contraseña.
 * `superuser` debe exponer escapeLiteral (pg.Client).
 */
export async function setRolePasswords(
  superuser: Queryable & { escapeLiteral(value: string): string },
  passwords: Partial<Record<RoleName, string>>,
): Promise<void> {
  for (const role of ROLE_NAMES) {
    const password = passwords[role];
    if (password === undefined) continue;
    if (password.length < 8) throw new MigrationError(`Contraseña demasiado corta para ${role}.`);
    // role viene de una lista cerrada; la contraseña se escapa como literal.
    await superuser.query(`ALTER ROLE ${role} PASSWORD ${superuser.escapeLiteral(password)}`);
  }
}

export interface DatabaseScopeOptions {
  /** Valor de ops.db_catalog.environment al aprovisionar (LOCAL por defecto). */
  environment?: "LOCAL" | "DEV" | "STAGING";
}

/**
 * Alcance database: `migrator` es la conexión de consent_migrator. Aplica en orden las
 * migraciones `-- scope: database` pendientes, una tx por archivo (todo o nada), y falla si
 * el checksum de una ya aplicada cambió. Devuelve las versiones aplicadas en esta corrida.
 */
export async function applyDatabaseScope(
  migrator: Queryable,
  migrations: readonly Migration[],
  options: DatabaseScopeOptions = {},
): Promise<string[]> {
  const environment = options.environment ?? "LOCAL";
  const applied: string[] = [];
  await migrator.query("SELECT pg_advisory_lock($1)", [ADVISORY_LOCK_KEY]);
  try {
    await migrator.query("BEGIN");
    try {
      await migrator.query("SET LOCAL ROLE consent_owner");
      await migrator.query("CREATE SCHEMA IF NOT EXISTS ops AUTHORIZATION consent_owner");
      await migrator.query(
        "CREATE TABLE IF NOT EXISTS ops.schema_migration (version text PRIMARY KEY, name text NOT NULL, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())",
      );
      await migrator.query("COMMIT");
    } catch (error) {
      await migrator.query("ROLLBACK");
      throw error;
    }

    const recorded = await migrator.query<{ version: string; sha256: string }>("SELECT version, sha256 FROM ops.schema_migration");
    const checksums = new Map(recorded.rows.map((r) => [r.version, r.sha256]));

    for (const m of migrations.filter((x) => x.scope === "database")) {
      const previous = checksums.get(m.version);
      if (previous !== undefined) {
        if (previous !== m.sha256) {
          throw new MigrationError(`El checksum de la migración ${m.version}_${m.name} cambió respecto de la ya aplicada; las migraciones aplicadas son inmutables.`);
        }
        continue;
      }
      await migrator.query("BEGIN");
      try {
        await migrator.query("SET LOCAL ROLE consent_owner");
        await migrator.query("SELECT set_config('consent.environment', $1, true)", [environment]);
        await migrator.query(m.sql);
        await migrator.query("INSERT INTO ops.schema_migration (version, name, sha256) VALUES ($1, $2, $3)", [m.version, m.name, m.sha256]);
        await migrator.query("COMMIT");
      } catch (error) {
        await migrator.query("ROLLBACK");
        throw error;
      }
      applied.push(m.version);
    }
  } finally {
    await migrator.query("SELECT pg_advisory_unlock($1)", [ADVISORY_LOCK_KEY]);
  }
  return applied;
}
