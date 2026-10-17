// Gobierna: CA-124 (H09), decisión D2 de Carlos (2026-09-29: migraciones en SQL plano con
// runner propio, sin dependencia nueva), ADR-002, TEST-CNS-749 (propuesto en el diseño: sin
// ID; el runner no tenía test asignado).
//
// Runner de migraciones SQL planas `db/migrations/NNNN_nombre.sql`. Cada archivo declara su
// alcance en la primera línea: `-- scope: cluster` (roles; lo ejecuta un superusuario, solo
// para crear roles, idempotente y sin registro), `-- scope: database` (lo ejecuta
// consent_migrator como consent_owner, una tx por archivo, registrado en
// ops.schema_migration(version, sha256); si el checksum de un archivo ya aplicado cambia, el
// runner falla) o `-- scope: cluster-post` (ADR-010 rev. 6 PR-7d: fase POSTERIOR del superusuario, idempotente y sin
// registro; corre despues de las migraciones de base y retira lo que estas necesitaban: revoke de integrity_owner,
// dueño de la base, modo REAL_DATA). Orden de un deploy: cluster -> database -> cluster-post (`applyDeploy`).
//
// La credencial del migrador solo existe en el paso de migración, nunca en el proceso web.
// Las contraseñas de los roles nunca están en el repo: setRolePasswords las recibe del entorno.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Queryable } from "./pool.ts";
import { checkDatabaseLevel } from "./database-level.ts";
import { checkRoleMemberships, resolveDbRoleMode } from "./role-membership.ts";
import type { DbRoleMode } from "./role-membership.ts";

/**
 * Serializa toda mutacion del catalogo global de roles (pg_authid / pg_auth_members: CREATE/ALTER ROLE, GRANT/REVOKE de
 * membresias, contrasenas) entre procesos que usan la misma base de conexion. Sin ella dos escritores concurrentes sobre la misma fila
 * fallan con "tuple concurrently updated" (XX000): Postgres no serializa las actualizaciones del catalogo de roles. Es el mismo lock que
 * toma el alcance cluster. Los advisory locks son POR BASE DE DATOS: todos los escritores de roles deben conectarse a la misma base
 * (la de conexion del superusuario del deploy). Reentrante en la misma sesion.
 */
export async function withClusterRoleLock<T>(superuser: Queryable, fn: () => Promise<T>): Promise<T> {
  await superuser.query("SELECT pg_advisory_lock($1)", [ADVISORY_LOCK_KEY]);
  try {
    return await fn();
  } finally {
    await superuser.query("SELECT pg_advisory_unlock($1)", [ADVISORY_LOCK_KEY]);
  }
}

export type MigrationScope = "cluster" | "database" | "cluster-post";

export interface Migration {
  version: string; // "0001"
  name: string; // "schemas_catalog"
  scope: MigrationScope;
  sql: string;
  sha256: string;
}

const FILE_RE = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const SCOPE_RE = /^-- scope: (cluster-post|cluster|database)\s*$/;
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
    throw new MigrationError(`"${fileName}" debe comenzar con "-- scope: cluster", "-- scope: database" o "-- scope: cluster-post".`);
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

export interface ClusterScopeOptions {
  /** Modo de roles (ADR-010 §4.1.1). Por defecto lo declara el deploy en CNS_DB_ROLE_MODE; sin valor = IT0B_SYNTHETIC. */
  mode?: DbRoleMode;
  /** Entorno del deploy (LOCAL/DEV/STAGING). Si falta CNS_DB_ROLE_MODE, solo LOCAL y DEV caen a IT0B_SYNTHETIC; sin entorno declarado es error. */
  environment?: string;
  /**
   * ADR-010 rev. 6 PR-7d: NO ejecutar la fase `cluster-post` ni la aserción final (las hace `applyClusterPostScope` despues de las migraciones de base). Solo para un deploy con migraciones de base pendientes: una base nueva necesita que
   * consent_owner conserve SET sobre integrity_owner (re-otorgado por 0026) mientras se aplican 0027, 0030, 0037... Sin esta bandera la fase cluster y la posterior van en UNA transaccion (el catalogo no muestra el estado intermedio).
   */
  deferPost?: boolean;
}

/** GUC de sesion que leen las migraciones de cluster y cluster-post (0034/0080/0086: sin SET de consent_owner en REAL_DATA). Se limpia al terminar. */
async function withDeclaredMode<T>(superuser: Queryable, mode: DbRoleMode, fn: () => Promise<T>): Promise<T> {
  await superuser.query("SELECT set_config('cns.db_role_mode', $1, false)", [mode]);
  try {
    return await fn();
  } finally {
    await superuser.query("SELECT set_config('cns.db_role_mode', '', false)");
  }
}

/** Aserción posterior al deploy (INV-DBR-03, INV-DBR-09): membresias exactas del modo y estado a nivel de base (dueño, CONNECT, ddl_breakglass). Cualquier diferencia aborta (fail-closed). */
async function assertDeployState(superuser: Queryable, mode: DbRoleMode, stage: string): Promise<void> {
  const problems = [...(await checkRoleMemberships(superuser, mode)), ...(await checkDatabaseLevel(superuser, mode, { breakglassMustBeClosed: true }))];
  if (problems.length > 0) throw new MigrationError(`Aserción de membresía de roles y de nivel de base ${stage} falló (INV-DBR-03, INV-DBR-09): ${problems.join("; ")}.`);
}

/**
 * ADR-010 rev. 6 PR-7d: ANTES de los archivos cluster se revocan las membresias de ddl_breakglass (si el rol ya existe). Varios archivos cluster ya mergeados (0034, 0046, 0064, 0080) asertan que consent_owner es el UNICO miembro
 * de su owner; las membresias de ddl_breakglass de un deploy anterior las harian fallar. La fase `cluster-post` (0086) las restablece en la misma transaccion (o justo despues de las migraciones de base), asi que el estado visible
 * al terminar siempre las incluye. SQL del runner, no de una migracion: no se registra ni se versiona.
 */
const PREFLIGHT_SQL = `DO $preflight$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE x.rolname = 'ddl_breakglass' LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM ddl_breakglass', m.role_name);
  END LOOP;
END
$preflight$`;

async function inTransaction<T>(superuser: Queryable, fn: () => Promise<T>): Promise<T> {
  await superuser.query("BEGIN");
  try {
    const result = await fn();
    await superuser.query("COMMIT");
    return result;
  } catch (error) {
    await superuser.query("ROLLBACK");
    throw error;
  }
}

/**
 * Alcance cluster (superusuario): aplica los archivos `-- scope: cluster` en orden. Son
 * idempotentes y no se registran. Requiere una conexión con privilegio de crear roles; es
 * el único uso de superusuario y solo crea roles (P1-3).
 *
 * ADR-010 PR-2 (INV-DBR-03, Q-19): al terminar, aserción posterior al cluster. La membresía de
 * los roles gobernados debe coincidir EXACTAMENTE con la lista del modo; cualquier fila extra o
 * faltante aborta el deploy (fail-closed).
 *
 * ADR-010 rev. 6 PR-7d (F-PR7-05, T-11): toda la fase va en UNA transaccion (un fallo a mitad no deja un SET re-otorgado por 0026 ni roles a medio crear), y
 * sin `deferPost` incluye los archivos `cluster-post` y la aserción final dentro de la misma transaccion. Los dos modos (IT0B_SYNTHETIC y REAL_DATA) estan activos como modos verificables; REAL_DATA NO autoriza
 * datos reales (F-PR7-12; REAL_DATA_BLOCKERS lo bloquea al resolver el modo desde el entorno, y el catalogo exige SYNTHETIC).
 */
export async function applyClusterScope(
  superuser: Queryable,
  migrations: readonly Migration[],
  options: ClusterScopeOptions = {},
): Promise<string[]> {
  const mode = options.mode ?? resolveDbRoleMode(process.env, options.environment);
  const applied: string[] = [];
  await withClusterRoleLock(superuser, async () => {
    await withDeclaredMode(superuser, mode, async () => {
      await inTransaction(superuser, async () => {
        await superuser.query(PREFLIGHT_SQL);
        for (const m of migrations.filter((x) => x.scope === "cluster")) {
          await superuser.query(m.sql);
          applied.push(m.version);
        }
        if (options.deferPost === true) return;
        for (const m of migrations.filter((x) => x.scope === "cluster-post")) {
          await superuser.query(m.sql);
          applied.push(m.version);
        }
        await assertDeployState(superuser, mode, "posterior al cluster");
      });
    });
  });
  return applied;
}

/**
 * Fase `cluster-post` (ADR-010 rev. 6 PR-7d): despues de las migraciones de base. Una transaccion con los archivos `-- scope: cluster-post` y la aserción de membresía y de nivel de base (que tambien repite
 * la aserción tras la fase database, F-A10-11; un deploy con una ceremonia de break-glass abierta falla cerrado). `superuser` debe estar conectado a la base de la aplicacion (ALTER DATABASE actua sobre la base de la conexion).
 */
export async function applyClusterPostScope(
  superuser: Queryable,
  migrations: readonly Migration[],
  options: Pick<ClusterScopeOptions, "mode" | "environment"> = {},
): Promise<string[]> {
  const mode = options.mode ?? resolveDbRoleMode(process.env, options.environment);
  const applied: string[] = [];
  await withClusterRoleLock(superuser, async () => {
    await withDeclaredMode(superuser, mode, async () => {
      await inTransaction(superuser, async () => {
        for (const m of migrations.filter((x) => x.scope === "cluster-post")) {
          await superuser.query(m.sql);
          applied.push(m.version);
        }
        await assertDeployState(superuser, mode, "posterior a la fase database");
      });
    });
  });
  return applied;
}

export interface DeployOptions extends ClusterScopeOptions {
  /** Valor de ops.db_catalog.environment al aprovisionar (LOCAL por defecto). */
  databaseEnvironment?: "LOCAL" | "DEV" | "STAGING";
}

/**
 * Deploy completo (cluster -> database -> cluster-post). La fase posterior corre SIEMPRE (finally), tambien si una migracion de base falla: no deja a consent_owner con el SET de integrity_owner re-otorgado por la
 * fase cluster (F-PR7-05). Si fallan ambas se reporta el primer error. `superuser` conectado a la base de la aplicacion; `migrator` es consent_migrator.
 */
export async function applyDeploy(
  superuser: Queryable,
  migrator: Queryable,
  migrations: readonly Migration[],
  options: DeployOptions = {},
): Promise<{ cluster: string[]; database: string[]; post: string[] }> {
  const mode = options.mode ?? resolveDbRoleMode(process.env, options.environment);
  const cluster = await applyClusterScope(superuser, migrations, { mode, deferPost: true });
  let database: string[] = [];
  let primary: unknown;
  try {
    database = await applyDatabaseScope(migrator, migrations, options.databaseEnvironment === undefined ? {} : { environment: options.databaseEnvironment });
  } catch (error) {
    primary = error;
  }
  try {
    const post = await applyClusterPostScope(superuser, migrations, { mode });
    if (primary !== undefined) throw primary;
    return { cluster, database, post };
  } catch (error) {
    throw primary ?? error;
  }
}

export type RoleName = "consent_migrator" | "app_rw" | "worker" | "platform_rw" | "integrity_verifier" | "integrity_reconciler" | "integrity_chain_verifier";
const ROLE_NAMES: readonly RoleName[] = ["consent_migrator", "app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier"];

/**
 * Fija contraseñas de roles LOGIN (las recibe del entorno; jamás del repo). Un rol sin
 * contraseña en el mapa queda sin poder autenticarse por contraseña.
 * `superuser` debe exponer escapeLiteral (pg.Client).
 */
export async function setRolePasswords(
  superuser: Queryable & { escapeLiteral(value: string): string },
  passwords: Partial<Record<RoleName, string>>,
): Promise<void> {
  // ALTER ROLE ... PASSWORD actualiza pg_authid: va dentro del lock de cluster (ver withClusterRoleLock).
  await withClusterRoleLock(superuser, async () => {
    for (const role of ROLE_NAMES) {
      const password = passwords[role];
      if (password === undefined) continue;
      if (password.length < 8) throw new MigrationError(`Contraseña demasiado corta para ${role}.`);
      // role viene de una lista cerrada; la contraseña se escapa como literal.
      await superuser.query(`ALTER ROLE ${role} PASSWORD ${superuser.escapeLiteral(password)}`);
    }
  });
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
      // ADR-010 rev. 6 PR-7d: tras 0086 consent_owner no tiene CREATE en la base en REAL_DATA; el esquema solo se crea si falta (una base ya migrada tiene ops, de ops_schema_owner desde 0082).
      const ops = await migrator.query<{ present: boolean }>("SELECT pg_catalog.to_regnamespace('ops') IS NOT NULL AS present");
      if (ops.rows[0]?.present !== true) await migrator.query("CREATE SCHEMA ops AUTHORIZATION consent_owner");
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
