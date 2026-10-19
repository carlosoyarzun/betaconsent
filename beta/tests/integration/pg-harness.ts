// Gobierna: plan v2 H1-02. Harness de integración: crea una base desechable por archivo de test con bootstrap-roles.sql REAL (vía psql)
// y la elimina al terminar. Requiere TEST_DATABASE_URL (superusuario de un clúster TEMPORAL: en CI el service container; en local
// beta/scripts/pg-temp.sh). Nunca apuntar al Postgres de uso diario. Sin la variable los tests fallan (no se saltan en silencio en CI).

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "pg";

const HERE = dirname(fileURLToPath(import.meta.url));
export const BETA_ROOT = join(HERE, "..", "..");
export const MIGRATIONS_DIR = join(BETA_ROOT, "db", "migrations");
const BOOTSTRAP = join(BETA_ROOT, "db", "bootstrap-roles.sql");

export function superUrl(): string {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) throw new Error("TEST_DATABASE_URL (superusuario de un clúster temporal) es obligatoria para los tests de integración.");
  return url;
}

function withCredentials(base: string, user: string, password: string, database: string): string {
  const u = new URL(base);
  u.username = user;
  u.password = password;
  u.pathname = `/${database}`;
  return u.toString();
}

export interface TestDb {
  readonly dbName: string;
  readonly migratorUrl: string;
  readonly appUrl: string;
  readonly superDbUrl: string;
  drop(): Promise<void>;
}

export async function createTestDb(): Promise<TestDb> {
  const sup = superUrl();
  const dbName = `consent_beta_${randomBytes(6).toString("hex")}`;
  const migratorPw = randomBytes(12).toString("hex");
  const appPw = randomBytes(12).toString("hex");
  const run = spawnSync(
    process.env.PSQL ?? "psql",
    [sup, "-v", `dbname=${dbName}`, "-v", `migrator_password=${migratorPw}`, "-v", `app_password=${appPw}`, "-v", "ON_ERROR_STOP=1", "-q", "-f", BOOTSTRAP],
    { encoding: "utf8" },
  );
  if (run.status !== 0) throw new Error(`bootstrap-roles.sql falló (${run.status}): ${run.stderr || run.error?.message}`);
  const superDbUrl = withCredentials(sup, new URL(sup).username, decodeURIComponent(new URL(sup).password), dbName);
  return {
    dbName,
    migratorUrl: withCredentials(sup, "consent_migrator", migratorPw, dbName),
    appUrl: withCredentials(sup, "consent_app", appPw, dbName),
    superDbUrl,
    async drop() {
      const c = new Client({ connectionString: sup });
      await c.connect();
      try {
        await c.query(`DROP DATABASE IF EXISTS ${c.escapeIdentifier(dbName)} WITH (FORCE)`);
      } finally {
        await c.end();
      }
    },
  };
}

export async function connect(url: string): Promise<Client> {
  const c = new Client({ connectionString: url });
  await c.connect();
  return c;
}

/** Cliente migrador con la sesión en SET ROLE consent_owner (para sembrar y probar al dueño). */
export async function connectAsOwner(db: TestDb): Promise<Client> {
  const c = await connect(db.migratorUrl);
  await c.query("SET ROLE consent_owner");
  return c;
}

/** Ejecuta `sql` dentro de una tx que SIEMPRE se revierte y devuelve el mensaje de error (o null si no falló). */
export async function failure(c: Client, sql: string, values: readonly unknown[] = []): Promise<string | null> {
  await c.query("BEGIN");
  try {
    await c.query(sql, values);
    await c.query("ROLLBACK");
    return null;
  } catch (e) {
    await c.query("ROLLBACK");
    return (e as Error).message;
  }
}
