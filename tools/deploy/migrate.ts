// Gobierna: orden de Carlos 2026-10-18 (PR-F, paquete de instalacion manual, modo sintetico); CA-124 (H09, runner de migraciones),
// ADR-010 rev. 6 PR-7d (orden de un deploy: cluster -> database -> cluster-post), DEC-BR-014 §4 (solo datos sinteticos).
//
// CLI del runner de src/infra/adapters/postgres/migrate.ts. NO redefine ninguna regla: solo conecta, fija el perfil LOCAL/SYNTHETIC y llama al runner.
//
//   node tools/deploy/migrate.ts --phase cluster|database|cluster-post|local-grants|fixtures|all [--dry-run]
//
// Conexion (variables PG* estandar de libpq):
//   PGHOST, PGPORT, PGUSER, PGPASSWORD   SUPERUSUARIO del cluster (fases cluster y cluster-post, y para crear la base). Con el socket de Unix y el
//                                        usuario de SO "postgres" no hace falta PGPASSWORD (peer).
//   PGDATABASE                           base de mantenimiento a la que conectar para crear roles/base (default "postgres").
//   CNS_DB_NAME                          base de la aplicacion (default "consent").
//   CNS_MIGRATOR_HOST, CNS_MIGRATOR_PORT consent_migrator conecta SIEMPRE por TCP con contrasena (default 127.0.0.1 y PGPORT|5432): su rol exige scram.
//   CNS_PW_<ROL>                         contrasenas de los 7 roles LOGIN (CONSENT_MIGRATOR, APP_RW, WORKER, PLATFORM_RW, INTEGRITY_VERIFIER,
//                                        INTEGRITY_RECONCILER, INTEGRITY_CHAIN_VERIFIER). Las fija la fase cluster (setRolePasswords); la fase database
//                                        usa la de consent_migrator. Nunca se imprimen.
//
// Perfil: CNS_ENVIRONMENT=LOCAL (ops.db_catalog queda LOCAL/SYNTHETIC; consent.environment=LOCAL) y CNS_DB_ROLE_MODE=IT0B_SYNTHETIC. REAL_DATA y cualquier
// otro entorno se rechazan aqui y, ademas, en el runner (REAL_DATA_BLOCKERS). Sin datos reales.
//
// Por que consent_migrator y superusuario por separado: el runner exige un superusuario para cluster/cluster-post (CREATE ROLE, GRANT/REVOKE de
// membresias, dueño de la base) y consent_migrator (no superusuario, SET ROLE consent_owner) para database; el propio runner lo verifica. No se puede
// usar un solo rol.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

type DbClient = InstanceType<typeof pg.Client>;
import {
  applyClusterPostScope,
  applyClusterScope,
  applyDatabaseScope,
  applyDeploy,
  loadMigrations,
  setRolePasswords,
} from "../../src/infra/adapters/postgres/migrate.ts";
import type { Migration, RoleName } from "../../src/infra/adapters/postgres/migrate.ts";
import { applyLocalFixtures, loadLocalFixtures } from "../../src/infra/adapters/postgres/local-fixtures.ts";

export type Phase = "cluster" | "database" | "cluster-post" | "local-grants" | "fixtures" | "all";
const PHASES: readonly Phase[] = ["cluster", "database", "cluster-post", "local-grants", "fixtures", "all"];

const ROLE_ENV: Readonly<Record<RoleName, string>> = {
  consent_migrator: "CNS_PW_CONSENT_MIGRATOR",
  app_rw: "CNS_PW_APP_RW",
  worker: "CNS_PW_WORKER",
  platform_rw: "CNS_PW_PLATFORM_RW",
  integrity_verifier: "CNS_PW_INTEGRITY_VERIFIER",
  integrity_reconciler: "CNS_PW_INTEGRITY_RECONCILER",
  integrity_chain_verifier: "CNS_PW_INTEGRITY_CHAIN_VERIFIER",
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIGRATIONS_DIR = join(ROOT, "db", "migrations");
const FIXTURES_DIR = join(ROOT, "db", "fixtures", "local");
const DB_NAME_RE = /^[a-z][a-z0-9_]{0,62}$/;

export interface CliArgs {
  readonly phase: Phase;
  readonly dryRun: boolean;
}

export function parseArgs(argv: readonly string[]): CliArgs {
  let phase: string | undefined;
  let dryRun = false;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--dry-run") dryRun = true;
    else if (a === "--phase") phase = argv[(i += 1)];
    else if (a?.startsWith("--phase=")) phase = a.slice("--phase=".length);
    else throw new Error(`argumento desconocido: ${a ?? "(vacio)"}. Uso: migrate.ts --phase ${PHASES.join("|")} [--dry-run]`);
  }
  if (phase === undefined || !(PHASES as readonly string[]).includes(phase)) {
    throw new Error(`--phase es obligatorio y debe ser uno de: ${PHASES.join(", ")}.`);
  }
  return { phase: phase as Phase, dryRun };
}

/** Fija el perfil LOCAL/SYNTHETIC. Rechaza cualquier otro entorno o modo de roles (no se "corrige" en silencio). */
export function pinSyntheticProfile(env: NodeJS.ProcessEnv): void {
  if (env.CNS_ENVIRONMENT !== undefined && env.CNS_ENVIRONMENT !== "" && env.CNS_ENVIRONMENT !== "LOCAL") {
    throw new Error("El paquete solo soporta CNS_ENVIRONMENT=LOCAL (modo sintetico). Abortando.");
  }
  if (env.CNS_DB_ROLE_MODE !== undefined && env.CNS_DB_ROLE_MODE !== "" && env.CNS_DB_ROLE_MODE !== "IT0B_SYNTHETIC") {
    throw new Error("El paquete solo soporta CNS_DB_ROLE_MODE=IT0B_SYNTHETIC (REAL_DATA no esta autorizado). Abortando.");
  }
  env.CNS_ENVIRONMENT = "LOCAL";
  env.CNS_DB_ROLE_MODE = "IT0B_SYNTHETIC";
}

function readPasswords(env: NodeJS.ProcessEnv, roles: readonly RoleName[]): Partial<Record<RoleName, string>> {
  const out: Partial<Record<RoleName, string>> = {};
  const missing: string[] = [];
  for (const role of roles) {
    const v = env[ROLE_ENV[role]];
    if (v === undefined || v === "") missing.push(ROLE_ENV[role]);
    else out[role] = v;
  }
  if (missing.length > 0) throw new Error(`Faltan contrasenas de roles en el entorno: ${missing.join(", ")}.`);
  return out;
}

function appDatabaseName(env: NodeJS.ProcessEnv): string {
  const name = env.CNS_DB_NAME ?? "consent";
  if (!DB_NAME_RE.test(name)) throw new Error("CNS_DB_NAME invalido (minusculas, digitos y guion bajo; empieza por letra).");
  return name;
}

async function connectSuperuser(env: NodeJS.ProcessEnv, database: string): Promise<DbClient> {
  // pg lee PGHOST/PGPORT/PGUSER/PGPASSWORD del entorno; solo cambia la base destino (PGDATABASE).
  env.PGDATABASE = database;
  const client = new pg.Client();
  await client.connect();
  const who = await client.query<{ rolsuper: boolean }>("SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user");
  if (who.rows[0]?.rolsuper !== true) {
    await client.end();
    throw new Error("La conexion PG* no es de un superusuario: las fases cluster y cluster-post lo exigen (migrate.ts del runner).");
  }
  return client;
}

async function databaseExists(admin: DbClient, name: string): Promise<boolean> {
  return (await admin.query("SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1", [name])).rows.length > 0;
}

function connectMigrator(env: NodeJS.ProcessEnv, database: string, password: string): DbClient {
  const host = env.CNS_MIGRATOR_HOST ?? "127.0.0.1";
  const port = env.CNS_MIGRATOR_PORT ?? env.PGPORT ?? "5432";
  return new pg.Client({ connectionString: `postgresql://consent_migrator:${encodeURIComponent(password)}@${host}:${port}/${database}` });
}

async function phaseCluster(env: NodeJS.ProcessEnv, migrations: readonly Migration[]): Promise<void> {
  const appDb = appDatabaseName(env);
  const passwords = readPasswords(env, Object.keys(ROLE_ENV) as RoleName[]);
  const maintenance = await connectSuperuser(env, env.PGDATABASE ?? "postgres");
  try {
    const encoding = await maintenance.query<{ enc: string }>("SELECT pg_catalog.current_setting('server_encoding') AS enc");
    if (encoding.rows[0]?.enc !== "UTF8") throw new Error(`La base de mantenimiento no es UTF8 (${encoding.rows[0]?.enc ?? "?"}); el paquete exige un cluster UTF8.`);
    const exists = await databaseExists(maintenance, appDb);
    // Con la base ya creada la fase cluster corre en ella (el runner calcula las migraciones pendientes con ops.schema_migration y no difiere la fase posterior si no hay pendientes).
    const target = exists ? await connectSuperuser(env, appDb) : maintenance;
    try {
      const applied = await applyClusterScope(target, migrations, { environment: "LOCAL" });
      console.log(`cluster: ${applied.length} archivos aplicados (idempotentes).`);
    } finally {
      if (target !== maintenance) await target.end();
    }
    await setRolePasswords(maintenance, passwords);
    console.log("cluster: contrasenas de los 7 roles LOGIN fijadas.");
    if (!exists) {
      await maintenance.query(`CREATE DATABASE "${appDb}" OWNER consent_owner`);
      console.log(`cluster: base "${appDb}" creada (dueño consent_owner).`);
    }
  } finally {
    await maintenance.end();
  }
}

async function phaseDatabase(env: NodeJS.ProcessEnv, migrations: readonly Migration[]): Promise<string[]> {
  const migrator = connectMigrator(env, appDatabaseName(env), readPasswords(env, ["consent_migrator"]).consent_migrator as string);
  await migrator.connect();
  try {
    const applied = await applyDatabaseScope(migrator, migrations, { environment: "LOCAL" });
    console.log(`database: ${applied.length} migraciones nuevas aplicadas${applied.length > 0 ? ` (${applied[0]}..${applied[applied.length - 1]})` : ""}.`);
    return applied;
  } finally {
    await migrator.end();
  }
}

async function phaseClusterPost(env: NodeJS.ProcessEnv, migrations: readonly Migration[]): Promise<void> {
  const superuser = await connectSuperuser(env, appDatabaseName(env));
  try {
    const applied = await applyClusterPostScope(superuser, migrations, { environment: "LOCAL" });
    console.log(`cluster-post: ${applied.length} archivos aplicados; aserciones de membresia y de nivel de base OK.`);
  } finally {
    await superuser.end();
  }
}

/**
 * Siembras LOCAL del proceso web (FINDING F-PR-F-01, ver README-DEPLOY.md): dev.ts siembra el caso RH3 con case_state.seed_local_* como app_rw, pero 0070 las revoco de app_rw y el
 * inventario de arranque (consent-owner-inventory.allowlist.ts) espera la ACL CON app_rw; el harness de tests las devuelve con la misma sentencia
 * (tests/integration/postgres/harness.ts, grantLocalSeedToAppRw). Sin esto el web no arranca sobre una base construida solo con migraciones. Solo superusuario, solo si el catalogo
 * es LOCAL/SYNTHETIC (las funciones ademas fallan fuera de LOCAL). No es una migracion y no se registra.
 */
export const LOCAL_SEED_GRANTS: readonly string[] = [
  "GRANT EXECUTE ON FUNCTION case_state.seed_local_revocation(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text) TO app_rw",
  "GRANT EXECUTE ON FUNCTION case_state.seed_local_rights_case(uuid, text, text, text, text, text, text) TO app_rw",
];

/** Guarda de local-grants (F-PR-F-01): solo con catalogo LOCAL/SYNTHETIC (exactamente una fila). Fail-closed con mensaje claro. */
export function assertLocalSyntheticCatalog(localSyntheticRows: string | undefined, totalRows: string | undefined): void {
  if (localSyntheticRows !== "1" || totalRows !== "1") {
    throw new Error("local-grants SE NIEGA: ops.db_catalog no es exactamente una fila LOCAL/SYNTHETIC. Esta fase solo vale en modo sintetico; no se conceden las siembras LOCAL (fail-closed).");
  }
}

async function phaseLocalGrants(env: NodeJS.ProcessEnv): Promise<void> {
  const superuser = await connectSuperuser(env, appDatabaseName(env));
  try {
    const cat = await superuser.query<{ n: string }>("SELECT pg_catalog.count(*)::pg_catalog.text AS n FROM ops.db_catalog WHERE environment = 'LOCAL' AND data_class = 'SYNTHETIC'");
    const total = await superuser.query<{ n: string }>("SELECT pg_catalog.count(*)::pg_catalog.text AS n FROM ops.db_catalog");
    assertLocalSyntheticCatalog(cat.rows[0]?.n, total.rows[0]?.n);
    for (const sql of LOCAL_SEED_GRANTS) await superuser.query(sql);
    console.log("local-grants: EXECUTE de case_state.seed_local_revocation / seed_local_rights_case concedido a app_rw (solo LOCAL/SYNTHETIC; ver F-PR-F-01).");
  } finally {
    await superuser.end();
  }
}

async function phaseAll(env: NodeJS.ProcessEnv, migrations: readonly Migration[]): Promise<void> {
  await phaseCluster(env, migrations);
  const superuser = await connectSuperuser(env, appDatabaseName(env));
  const migrator = connectMigrator(env, appDatabaseName(env), readPasswords(env, ["consent_migrator"]).consent_migrator as string);
  await migrator.connect();
  try {
    // applyDeploy repite cluster (idempotente) -> database -> cluster-post, y ejecuta siempre la fase posterior (solo-REVOKE de seguridad si algo falla).
    const r = await applyDeploy(superuser, migrator, migrations, { environment: "LOCAL", databaseEnvironment: "LOCAL" });
    console.log(`all: cluster ${r.cluster.length}, database ${r.database.length} nuevas, cluster-post ${r.post.length}; aserciones OK.`);
  } finally {
    await migrator.end();
    await superuser.end();
  }
  await phaseLocalGrants(env);
}

async function phaseFixtures(env: NodeJS.ProcessEnv): Promise<void> {
  const migrator = connectMigrator(env, appDatabaseName(env), readPasswords(env, ["consent_migrator"]).consent_migrator as string);
  await migrator.connect();
  try {
    const applied = await applyLocalFixtures(migrator, loadLocalFixtures(FIXTURES_DIR), { environment: "LOCAL" });
    console.log(`fixtures: ${applied.join(", ") || "(ninguna)"} (datos SINTETICOS; exige ops.db_catalog LOCAL/SYNTHETIC).`);
  } finally {
    await migrator.end();
  }
}

export function planText(args: CliArgs, migrations: readonly Migration[], env: NodeJS.ProcessEnv): string {
  const count = (s: Migration["scope"]): number => migrations.filter((m) => m.scope === s).length;
  const lines = [
    `migrate.ts --dry-run (no conecta a ninguna base, no escribe nada)`,
    `  fase solicitada : ${args.phase}`,
    `  base de la app  : ${appDatabaseName(env)}  (mantenimiento: ${env.PGDATABASE ?? "postgres"})`,
    `  perfil          : CNS_ENVIRONMENT=LOCAL, CNS_DB_ROLE_MODE=IT0B_SYNTHETIC, ops.db_catalog LOCAL/SYNTHETIC`,
    `  migraciones     : ${migrations.length} (cluster ${count("cluster")}, database ${count("database")}, cluster-post ${count("cluster-post")}); ultima ${migrations[migrations.length - 1]?.version ?? "-"}`,
    `  orden de "all"  : cluster (+ contrasenas de roles + CREATE DATABASE si falta) -> database -> cluster-post (aserciones)`,
    `  contrasenas     : ${(Object.values(ROLE_ENV) as string[]).map((n) => `${n}=${(env[n] ?? "") === "" ? "FALTA" : "presente"}`).join(", ")}`,
  ];
  return lines.join("\n");
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  pinSyntheticProfile(process.env);
  const migrations = loadMigrations(MIGRATIONS_DIR);
  if (args.dryRun) {
    console.log(planText(args, migrations, process.env));
    return;
  }
  switch (args.phase) {
    case "cluster":
      return phaseCluster(process.env, migrations);
    case "database":
      await phaseDatabase(process.env, migrations);
      return;
    case "cluster-post":
      return phaseClusterPost(process.env, migrations);
    case "local-grants":
      return phaseLocalGrants(process.env);
    case "fixtures":
      return phaseFixtures(process.env);
    case "all":
      return phaseAll(process.env, migrations);
  }
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error: unknown) => {
    // Sin message de pg completo: puede traer detalle de filas. Se imprime nombre y, para errores propios del runner/CLI, el mensaje.
    const e = error as { name?: string; message?: string; code?: string };
    const own = e.name === "MigrationError" || e.name === "LockTimeoutError" || e.name === "RoleModeError" || e.name === "LocalFixtureError" || e.name === "Error";
    console.error(`migrate: fallo (${e.name ?? "Error"}${e.code ? ` ${e.code}` : ""}). ${own ? (e.message ?? "") : ""}`);
    process.exit(1);
  });
}
