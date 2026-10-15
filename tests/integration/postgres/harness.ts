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
  withClusterRoleLock,
} from "../../../src/infra/adapters/postgres/migrate.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = join(HERE, "..", "..", "..", "db", "migrations");
const HARNESS_LOCK_KEY = 7_240_125;
const IN_CI = process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true";

export type PgRole = "consent_migrator" | "app_rw" | "worker" | "platform_rw" | "integrity_verifier" | "integrity_reconciler";

export interface PgTestContext {
  dbName: string;
  /** Cliente conectado como el rol dado a la base de este archivo (se cierra al terminar). */
  connectAs(role: PgRole): Promise<Client>;
  /** Conexión de superusuario a la base de este archivo (solo para preparar/inspeccionar). */
  connectAsSuperuser(): Promise<Client>;
  /** Conexion de superusuario COMPARTIDA (una por archivo) para los helpers de fixtures: connectAsSuperuser abre una conexion nueva por llamada y el service container de CI tiene max_connections=100. */
  fixtureAdmin(): Promise<Client>;
  /**
   * Ejecuta `fn` con el lock de cluster de mutaciones del catalogo de roles (el mismo de migrate.ts). OBLIGATORIO para todo test que haga
   * CREATE/ALTER/GRANT/REVOKE sobre roles: el catalogo es global al cluster y los archivos de test corren en paralelo; sin el lock otro
   * archivo que provisiona (applyClusterScope/setRolePasswords) falla con "tuple concurrently updated". El lock se toma en una conexion
   * a la base de conexion (los advisory locks son por base de datos), no en la base del archivo.
   */
  withRoleCatalogLock<T>(fn: () => Promise<T>): Promise<T>;
  /** URL de conexión del rol (para createPool). */
  urlFor(role: PgRole): string;
  /**
   * URL del superusuario del service container sobre la base de este archivo. ADR-010 rev. 5 PR-b: app_rw ya NO inserta en integrity.audit_event (los eventos los generan los triggers de
   * ledger_gen); los tests de MECANICA del ledger (cadena, idempotencia, lista blanca, locks) que necesitan un append arbitrario lo hacen con esta conexion, nunca con app_rw.
   * Solo tests: ningun codigo de producto usa esta URL.
   */
  superuserUrl: string;
}

/**
 * ADR-010 rev. 5 PR-b: triggers de guarda y emision del ledger derivado (esquema ledger_gen) de las tablas de estado. Son ENABLE ALWAYS: tambien rigen para el superusuario.
 * Los FIXTURES de tests que necesitan filas en un estado arbitrario (p. ej. una invitacion COMPLETED sin decision) y NO prueban el ledger las siembran con `seedRaw`, que los
 * deshabilita SOLO durante el fixture y los vuelve a dejar ENABLE ALWAYS. Es un helper de tests: el codigo de producto nunca deshabilita triggers.
 */
export const LEDGER_GEN_TRIGGERS: ReadonlyArray<readonly [string, string]> = [
  ["app.enrollment", "enrollment_ledger_guard"],
  ["app.enrollment", "enrollment_ledger_emit"],
  ["app.otp_verification", "otp_verification_ledger_guard"],
  ["app.otp_verification", "otp_verification_ledger_emit"],
  ["app.invitation", "invitation_ledger_guard"],
  ["app.invitation", "invitation_ledger_emit"],
  ["app.consent_decision", "consent_decision_ledger_guard"],
  ["app.consent_decision", "consent_decision_ledger_emit"],
];

/**
 * ADR-010 rev. 5 PR-b: tras 0049 app_rw ya no puede insertar en integrity.audit_event. Los tests de MECANICA del ledger (cadena SHA-256, idempotencia, lista blanca de tipos, locks, contrato de
 * LedgerPort) necesitan un append arbitrario dentro de una unidad de trabajo de tenant con RLS. Este helper recrea, SOLO en la base descartable de ESE archivo de test (nunca en una migracion),
 * el INSERT por columnas y una policy por tenant para app_rw, para poder ejercitar esa mecanica. Los archivos que prueban "app_rw no inserta" NO lo llaman. Helper de tests, nunca de producto.
 */
export async function enableLedgerMechanicsAppend(ctx: PgTestContext): Promise<void> {
  const admin = await ctx.fixtureAdmin();
  await admin.query(
    `GRANT INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
                   chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment) ON integrity.audit_event TO app_rw`,
  );
  await admin.query("DROP POLICY IF EXISTS test_mechanics_app_rw_insert ON integrity.audit_event");
  await admin.query("CREATE POLICY test_mechanics_app_rw_insert ON integrity.audit_event FOR INSERT TO app_rw WITH CHECK (tenant_id = app.current_tenant_id())");
}

let currentCtx: PgTestContext | undefined;

/** Como `seedRaw` sobre la base del test en curso (para helpers de siembra que no reciben `ctx`). Solo tests. */
export async function seedFixture<T>(work: () => Promise<T>): Promise<T> {
  if (currentCtx === undefined) throw new Error("seedFixture solo se usa dentro de un pgTest");
  return seedRaw(await currentCtx.fixtureAdmin(), work);
}

/** Como `seedFixture` pero entrega la conexion de superusuario al fixture (p. ej. para dejar una decision en REVOKED sin pasar por R4: la base solo lo admite por apply_revocation). Solo tests. */
export async function seedFixtureAdmin<T>(work: (admin: Client) => Promise<T>): Promise<T> {
  if (currentCtx === undefined) throw new Error("seedFixtureAdmin solo se usa dentro de un pgTest");
  const admin = await currentCtx.fixtureAdmin();
  return seedRaw(admin, () => work(admin));
}

/** `pgTest` cuyo cuerpo corre con los triggers de ledger_gen deshabilitados: para tests de ESQUEMA (CHECK, UNIQUE, RLS) que ejercitan SQL crudo y no el ledger. Solo tests. */
export function pgTestRaw(name: string, fn: (ctx: PgTestContext) => Promise<void>): void {
  pgTest(name, async (ctx) => {
    await seedRaw(await ctx.fixtureAdmin(), () => fn(ctx));
  });
}

/** Revierte `enableLedgerMechanicsAppend` (DROP POLICY + REVOKE INSERT de app_rw): para tests que lo activan y comparten base con tests que afirman "app_rw no inserta". Solo tests. */
export async function disableLedgerMechanicsAppend(ctx: PgTestContext): Promise<void> {
  const admin = await ctx.fixtureAdmin();
  await admin.query("DROP POLICY IF EXISTS test_mechanics_app_rw_insert ON integrity.audit_event");
  await admin.query(
    `REVOKE INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
                    chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment) ON integrity.audit_event FROM app_rw`,
  );
}

let seedRawDepth = 0;

export async function seedRaw<T>(admin: Client, work: () => Promise<T>): Promise<T> {
  // Reentrante: un fixture anidado (p. ej. outside-tx dentro de un pgTestRaw) no vuelve a habilitar los triggers a mitad del test exterior.
  if (seedRawDepth === 0) for (const [table, trg] of LEDGER_GEN_TRIGGERS) await admin.query(`ALTER TABLE ${table} DISABLE TRIGGER ${trg}`);
  seedRawDepth += 1;
  try {
    return await work();
  } finally {
    seedRawDepth -= 1;
    if (seedRawDepth === 0) for (const [table, trg] of LEDGER_GEN_TRIGGERS) await admin.query(`ALTER TABLE ${table} ENABLE ALWAYS TRIGGER ${trg}`);
  }
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

  await applyClusterScope(admin, migrations, { environment: "LOCAL" }); // la plantilla es LOCAL sintetica; sin CNS_DB_ROLE_MODE el modo cae a IT0B_SYNTHETIC
  await setRolePasswords(admin, {
    consent_migrator: config.migratorPassword,
    app_rw: config.appPassword,
    worker: config.appPassword,
    platform_rw: config.appPassword,
    integrity_verifier: config.appPassword, // ADR-010 PR-2 (0034)
    integrity_reconciler: config.appPassword, // ADR-010 rev. 5 PR-6e (0056)
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
  let fixtureClient: Promise<Client> | undefined;
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
    superuserUrl: ((): string => {
      const u = new URL(config.url);
      u.pathname = `/${dbName}`;
      return u.toString();
    })(),
    async connectAs(role) {
      const client = new pg.Client({ connectionString: urlWith(config.url, role, passwordFor(role), dbName) });
      await client.connect();
      clients.push(client);
      return client;
    },
    async withRoleCatalogLock(fn) {
      const locker = new pg.Client({ connectionString: config.url });
      await locker.connect();
      try {
        return await withClusterRoleLock(locker, fn);
      } finally {
        await locker.end();
      }
    },
    fixtureAdmin() {
      fixtureClient ??= (async () => {
        const u = new URL(config.url);
        u.pathname = `/${dbName}`;
        const client = new pg.Client({ connectionString: u.toString() });
        await client.connect();
        clients.push(client);
        return client;
      })();
      return fixtureClient;
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
    currentCtx = s.ctx;
    await fn(s.ctx);
  });
}
