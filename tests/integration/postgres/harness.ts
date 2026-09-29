// Gobierna: CA-124 (H09), specs/test-framework.spec.yaml (integrationHarness), ADR-002,
// DEC-BR-014 §4 (solo datos sintéticos), diseño de CA-124 §6 (harness).
//
// Harness de tests con PostgreSQL real. Bajo un pg_advisory_lock: el superusuario del
// service container crea los roles (db/migrations/0000_roles.sql, scope cluster) y fija sus
// contraseñas (efímeras, del entorno; cero secretos en el repo); consent_migrator migra una
// plantilla (`consent_tpl_<digest de las migraciones>`); cada archivo de test crea su
// propia base con CREATE DATABASE ... TEMPLATE y se conecta como app_rw (nunca como
// superusuario, salvo la conexión de administración explícita del test).
//
// Entorno:
//   TEST_DATABASE_URL          superusuario del service container (CI) o del docker local.
//   TEST_APP_DB_PASSWORD       contraseña efímera de app_rw / worker / platform_rw.
//   TEST_MIGRATOR_DB_PASSWORD  contraseña efímera de consent_migrator.
//
// Skip/fail-closed idéntico a postgres-smoke.test.ts (SEC-CNS-011 P1-01): sin las variables
// y FUERA de CI el test se omite; en CI (CI/GITHUB_ACTIONS = "true") falla.

import test, { after } from "node:test";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import type { Client } from "pg";
import {
  applyClusterScope,
  applyDatabaseScope,
  loadMigrations,
  migrationSetDigest,
  setRolePasswords,
} from "../../../src/infra/adapters/postgres/migrate.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = join(HERE, "..", "..", "..", "db", "migrations");
const HARNESS_LOCK_KEY = 7_240_125;
const IN_CI = process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true";

export type PgRole = "consent_migrator" | "app_rw" | "worker" | "platform_rw";

export interface PgTestContext {
  dbName: string;
  /** Cliente conectado como el rol dado a la base de este archivo (se cierra al terminar). */
  connectAs(role: PgRole): Promise<Client>;
  /** Conexión de superusuario a la base de este archivo (solo para preparar/inspeccionar). */
  connectAsSuperuser(): Promise<Client>;
  /** URL de conexión del rol (para createPool). */
  urlFor(role: PgRole): string;
}

interface Config {
  url: string;
  appPassword: string;
  migratorPassword: string;
}

function readConfig(): Config | { missing: string[] } {
  const url = process.env.TEST_DATABASE_URL;
  const appPassword = process.env.TEST_APP_DB_PASSWORD;
  const migratorPassword = process.env.TEST_MIGRATOR_DB_PASSWORD;
  const missing = [
    url ? "" : "TEST_DATABASE_URL",
    appPassword ? "" : "TEST_APP_DB_PASSWORD",
    migratorPassword ? "" : "TEST_MIGRATOR_DB_PASSWORD",
  ].filter((v) => v !== "");
  if (missing.length > 0 || !url || !appPassword || !migratorPassword) return { missing };
  return { url, appPassword, migratorPassword };
}

function urlWith(base: string, user: string, password: string, database: string): string {
  const u = new URL(base);
  u.username = encodeURIComponent(user);
  u.password = encodeURIComponent(password);
  u.pathname = `/${database}`;
  return u.toString();
}

function quoteIdent(name: string): string {
  if (!/^[a-z0-9_]+$/.test(name)) throw new Error(`Identificador inválido: ${name}`);
  return `"${name}"`;
}

async function provisionTemplate(config: Config, admin: Client): Promise<string> {
  const migrations = loadMigrations(MIGRATIONS_DIR);
  const template = `consent_tpl_${migrationSetDigest(migrations).slice(0, 16)}`;

  await applyClusterScope(admin, migrations);
  await setRolePasswords(admin, {
    consent_migrator: config.migratorPassword,
    app_rw: config.appPassword,
    worker: config.appPassword,
    platform_rw: config.appPassword,
  });

  const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [template]);
  if (exists.rows.length > 0) return template;

  const building = `${template}_b`;
  await admin.query(`DROP DATABASE IF EXISTS ${quoteIdent(building)} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${quoteIdent(building)} OWNER consent_owner`);
  const migrator = new pg.Client({ connectionString: urlWith(config.url, "consent_migrator", config.migratorPassword, building) });
  await migrator.connect();
  try {
    await applyDatabaseScope(migrator, migrations, { environment: "LOCAL" });
  } finally {
    await migrator.end();
  }
  await admin.query(`ALTER DATABASE ${quoteIdent(building)} RENAME TO ${quoteIdent(template)}`);
  return template;
}

async function provision(config: Config): Promise<{ ctx: PgTestContext; teardown: () => Promise<void> }> {
  const admin = new pg.Client({ connectionString: config.url });
  await admin.connect();
  const dbName = `t_${randomBytes(6).toString("hex")}`;
  const clients: Client[] = [];
  try {
    await admin.query("SELECT pg_advisory_lock($1)", [HARNESS_LOCK_KEY]);
    try {
      const template = await provisionTemplate(config, admin);
      await admin.query(`CREATE DATABASE ${quoteIdent(dbName)} TEMPLATE ${quoteIdent(template)} OWNER consent_owner`);
    } finally {
      await admin.query("SELECT pg_advisory_unlock($1)", [HARNESS_LOCK_KEY]);
    }
  } catch (error) {
    await admin.end();
    throw error;
  }

  const passwordFor = (role: PgRole): string => (role === "consent_migrator" ? config.migratorPassword : config.appPassword);
  const ctx: PgTestContext = {
    dbName,
    urlFor: (role) => urlWith(config.url, role, passwordFor(role), dbName),
    async connectAs(role) {
      const client = new pg.Client({ connectionString: urlWith(config.url, role, passwordFor(role), dbName) });
      await client.connect();
      clients.push(client);
      return client;
    },
    async connectAsSuperuser() {
      const u = new URL(config.url);
      u.pathname = `/${dbName}`;
      const client = new pg.Client({ connectionString: u.toString() });
      await client.connect();
      clients.push(client);
      return client;
    },
  };
  const teardown = async (): Promise<void> => {
    for (const c of clients) await c.end().catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS ${quoteIdent(dbName)} WITH (FORCE)`).catch(() => {});
    await admin.end();
  };
  return { ctx, teardown };
}

let shared: Promise<{ ctx: PgTestContext; teardown: () => Promise<void> }> | undefined;

/**
 * test() con Postgres real. Una base por archivo de test (creada perezosamente desde la
 * plantilla migrada y eliminada al terminar el archivo). Skip fuera de CI sin entorno;
 * falla en CI sin entorno (fail-closed).
 */
export function pgTest(name: string, fn: (ctx: PgTestContext) => Promise<void>): void {
  const config = readConfig();
  if ("missing" in config) {
    if (IN_CI) {
      test(name, () => {
        throw new Error(
          `Faltan variables del harness de Postgres en CI: ${config.missing.join(", ")}. El job "integration" ` +
            `(.github/workflows/tests.yml) debe exponerlas; no se permite un skip vacuo en CI (fail-closed, SEC-CNS-011 P1-01).`,
        );
      });
    } else {
      test(name, { skip: `sin Postgres disponible (falta ${config.missing.join(", ")}); ver tests/README.md` }, () => {});
    }
    return;
  }
  if (shared === undefined) {
    shared = provision(config);
    after(async () => {
      const s = await shared?.catch(() => undefined);
      await s?.teardown();
    });
  }
  test(name, async () => {
    const s = await (shared as NonNullable<typeof shared>);
    await fn(s.ctx);
  });
}
