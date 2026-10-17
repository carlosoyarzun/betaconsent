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
import { BREAKGLASS_OWNER_ROLES, checkRoleMemberships, resolveDbRoleMode } from "./role-membership.ts";
import type { DbRoleMode } from "./role-membership.ts";

/** Tope de espera de un advisory lock del runner (ADR-010 rev. 6 PR-7d, F-PR7D-09): un lock tomado por otro proceso no bloquea el deploy para siempre. */
export const DEFAULT_LOCK_TIMEOUT_MS = 120_000;
const LOCK_POLL_MS = 100;

/** pg_try_advisory_lock con reintentos hasta `timeoutMs` (en vez de pg_advisory_lock sin tope). Reentrante en la misma sesion. Lanza MigrationError al agotar la espera. */
async function acquireAdvisoryLock(db: Queryable, key: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await db.query<{ locked: boolean }>("SELECT pg_try_advisory_lock($1) AS locked", [key]);
    if (r.rows[0]?.locked === true) return;
    if (Date.now() >= deadline) throw new MigrationError(`No se obtuvo el lock del runner de migraciones en ${timeoutMs} ms (otro deploy o una ceremonia lo retiene); no se aplica nada (F-PR7D-09).`);
    await new Promise((resolve) => setTimeout(resolve, LOCK_POLL_MS));
  }
}

/**
 * Serializa toda mutacion del catalogo global de roles (pg_authid / pg_auth_members: CREATE/ALTER ROLE, GRANT/REVOKE de
 * membresias, contrasenas) entre procesos que usan la misma base de conexion. Sin ella dos escritores concurrentes sobre la misma fila
 * fallan con "tuple concurrently updated" (XX000): Postgres no serializa las actualizaciones del catalogo de roles. Es el mismo lock que
 * toma el alcance cluster. Los advisory locks son POR BASE DE DATOS: todos los escritores de roles deben conectarse a la misma base
 * (la de conexion del superusuario del deploy). Reentrante en la misma sesion. Espera como maximo `timeoutMs` (pg_try_advisory_lock con reintentos).
 */
export async function withClusterRoleLock<T>(superuser: Queryable, fn: () => Promise<T>, timeoutMs: number = DEFAULT_LOCK_TIMEOUT_MS): Promise<T> {
  await acquireAdvisoryLock(superuser, ADVISORY_LOCK_KEY, timeoutMs);
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
   * ADR-010 rev. 6 PR-7d (F-PR7D-09): la fase `cluster-post` y su aserción se difieren SOLO si hay migraciones de base pendientes (el runner lo calcula con ops.schema_migration antes de empezar): una base nueva necesita que
   * consent_owner conserve SET sobre integrity_owner (re-otorgado por 0026) mientras se aplican 0027, 0030, 0037... En REAL_DATA no se difiere nunca si ops.schema_migration existe (una base viva no puede dejar abierto el SET).
   * `true` fuerza el diferimiento (tests); `false`/ausente = decision automatica. Sin diferimiento la fase cluster y la posterior van en UNA transaccion (el catalogo no muestra el estado intermedio).
   */
  deferPost?: boolean;
  /** Tope de espera del lock de roles (ms). Por defecto DEFAULT_LOCK_TIMEOUT_MS. */
  lockTimeoutMs?: number;
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

/** Aserción posterior al deploy (INV-DBR-03, INV-DBR-09): membresias exactas del modo y estado a nivel de base (dueño, CONNECT, ddl_breakglass, esquema breakglass exacto). Cualquier diferencia aborta (fail-closed). Corre FUERA de la transaccion que confirmo los REVOKE (F-PR7D-07). */
async function assertDeployState(superuser: Queryable, mode: DbRoleMode, stage: string): Promise<void> {
  const problems = [...(await checkRoleMemberships(superuser, mode)), ...(await checkDatabaseLevel(superuser, mode, { breakglassMustBeClosed: true }))];
  if (problems.length > 0) throw new MigrationError(`Aserción de membresía de roles y de nivel de base ${stage} falló (INV-DBR-03, INV-DBR-09): ${problems.join("; ")}.`);
}

/**
 * ADR-010 rev. 6 PR-7d (F-PR7D-07/F-PR7-05): PRECONDICIONES de la fase posterior, verificadas ANTES de tocar nada (antes de la fase cluster, que re-otorga SET): ddl_breakglass sin LOGIN y sin ceremonia abierta. Un deploy con una
 * ceremonia abierta falla cerrado SIN haber cambiado el catalogo (no queda un SET re-otorgado ni a medio revocar). Superusuario conectado a la base de la aplicacion.
 */
export async function assertDeployPreconditions(superuser: Queryable): Promise<void> {
  const state = await superuser.query<{ can_login: boolean | null; ceremony_table: boolean }>(
    `SELECT (SELECT r.rolcanlogin FROM pg_catalog.pg_roles r WHERE r.rolname = 'ddl_breakglass') AS can_login,
            pg_catalog.to_regclass('breakglass.ceremony') IS NOT NULL AS ceremony_table`,
  );
  const row = state.rows[0];
  const problems: string[] = [];
  if (row?.can_login === true) problems.push("ddl_breakglass tiene LOGIN (ceremonia de break-glass abierta)");
  if (row?.ceremony_table === true) {
    const open = await superuser.query<{ n: string | number }>("SELECT pg_catalog.count(*) AS n FROM breakglass.ceremony WHERE closed_at IS NULL");
    if (Number(open.rows[0]?.n) > 0) problems.push("hay una ceremonia de break-glass sin cerrar en breakglass.ceremony");
  }
  if (problems.length > 0) throw new MigrationError(`Precondición del deploy no cumplida (nada se aplicó): ${problems.join("; ")}. Cierre la ceremonia con db/ceremonies/close.sql y reintente (INV-DBR-09).`);
}

/**
 * ADR-010 rev. 6 PR-7d (F-PR7D-07, F-PR7-05): transaccion PROPIA que solo REVOCA. Se ejecuta si la fase posterior falla: el ROLLBACK de esa fase deshace el REVOKE y consent_owner conservaria el SET que re-otorga la fase
 * cluster (0026) sobre integrity_owner. Revoca integrity_owner y breakglass_log_owner a consent_owner en ambos modos y, en REAL_DATA, todo SET de consent_owner sobre los 17 owners y consent_migrator -> outbox_claimer.
 */
export async function revokeOnlyFailsafe(superuser: Queryable, mode: DbRoleMode): Promise<void> {
  const owners = mode === "REAL_DATA" ? [...BREAKGLASS_OWNER_ROLES] : ["integrity_owner"];
  const targets = [...new Set([...owners, "breakglass_log_owner"])];
  await inTransaction(superuser, async () => {
    const stmts = await superuser.query<{ stmt: string }>(
      `SELECT pg_catalog.format('REVOKE %I FROM %I', r.rolname, x.rolname) AS stmt
         FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
        WHERE (x.rolname = 'consent_owner' AND r.rolname = ANY($1::pg_catalog.text[]))
           OR ($2::pg_catalog.bool AND x.rolname = 'consent_migrator' AND r.rolname = 'outbox_claimer')`,
      [targets, mode === "REAL_DATA"],
    );
    for (const row of stmts.rows) await superuser.query(row.stmt);
  });
}

/** Si la fase posterior falla, ejecuta la transaccion que solo revoca y relanza el error original; si el solo-REVOKE tambien falla, lo anota (no enmascara el original). */
async function failsafeAfter(superuser: Queryable, mode: DbRoleMode, error: unknown): Promise<never> {
  try {
    await revokeOnlyFailsafe(superuser, mode);
  } catch (failsafeError) {
    const detail = failsafeError instanceof Error ? failsafeError.message : "error desconocido";
    throw new MigrationError(`La fase posterior falló Y la transacción de solo-REVOKE también (consent_owner puede conservar SET sobre integrity_owner; R-22): ${detail}. Error original: ${error instanceof Error ? error.message : "desconocido"}`);
  }
  throw error;
}

/**
 * ADR-010 rev. 6 PR-7d: ANTES de los archivos cluster se revocan las membresias de ddl_breakglass (si el rol ya existe). Varios archivos cluster ya mergeados (0034, 0046, 0064, 0080) asertan que consent_owner es el UNICO miembro
 * de su owner; las membresias de ddl_breakglass de un deploy anterior las harian fallar. La fase `cluster-post` (0086) las restablece en la misma transaccion (o justo despues de las migraciones de base), asi que el estado visible
 * al terminar siempre las incluye. SQL del runner, no de una migracion: no se registra ni se versiona.
 */
export const CLUSTER_PREFLIGHT_SQL = `DO $preflight$
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

/** Migraciones de base pendientes segun ops.schema_migration (superusuario conectado a la base de la aplicacion). Sin la tabla, todas estan pendientes. */
async function readDatabaseScopeState(superuser: Queryable, migrations: readonly Migration[]): Promise<{ tableExists: boolean; pending: number }> {
  const dbMigrations = migrations.filter((x) => x.scope === "database");
  const present = await superuser.query<{ present: boolean }>("SELECT pg_catalog.to_regclass('ops.schema_migration') IS NOT NULL AS present");
  if (present.rows[0]?.present !== true) return { tableExists: false, pending: dbMigrations.length };
  const recorded = await superuser.query<{ version: string }>("SELECT version FROM ops.schema_migration");
  const applied = new Set(recorded.rows.map((r) => r.version));
  return { tableExists: true, pending: dbMigrations.filter((m) => !applied.has(m.version)).length };
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
 * ADR-010 rev. 6 PR-7d (F-PR7-05, T-11; P1 de la revision de seguridad de PR #109): 1) PRECONDICIONES antes de todo (ceremonia cerrada); 2) la fase va en UNA transaccion (un fallo a mitad no deja un SET re-otorgado por 0026 ni roles
 * a medio crear) y, sin diferimiento, incluye los archivos `cluster-post`; 3) la aserción final va FUERA de la transaccion que confirma los REVOKE; 4) si la fase falla, una transaccion propia que solo revoca. Solo se difiere si hay
 * migraciones de base pendientes (ver `deferPost`). Los dos modos (IT0B_SYNTHETIC y REAL_DATA) estan activos como modos verificables; REAL_DATA NO autoriza datos reales (F-PR7-12).
 */
export async function applyClusterScope(
  superuser: Queryable,
  migrations: readonly Migration[],
  options: ClusterScopeOptions = {},
): Promise<string[]> {
  const mode = options.mode ?? resolveDbRoleMode(process.env, options.environment);
  const applied: string[] = [];
  await withClusterRoleLock(
    superuser,
    async () => {
      await withDeclaredMode(superuser, mode, async () => {
        await assertDeployPreconditions(superuser);
        const state = await readDatabaseScopeState(superuser, migrations);
        const defer = options.deferPost === true || (state.pending > 0 && !(mode === "REAL_DATA" && state.tableExists));
        try {
          await inTransaction(superuser, async () => {
            await superuser.query(CLUSTER_PREFLIGHT_SQL);
            for (const m of migrations.filter((x) => x.scope === "cluster")) {
              await superuser.query(m.sql);
              applied.push(m.version);
            }
            if (defer) return;
            for (const m of migrations.filter((x) => x.scope === "cluster-post")) {
              await superuser.query(m.sql);
              applied.push(m.version);
            }
          });
        } catch (error) {
          // Sin diferimiento la fase posterior forma parte de esta transaccion: su ROLLBACK deja el estado previo; el solo-REVOKE protege el caso en que el estado previo aun tenia el SET.
          if (!defer) await failsafeAfter(superuser, mode, error);
          throw error;
        }
        if (!defer) await assertDeployState(superuser, mode, "posterior al cluster");
      });
    },
    options.lockTimeoutMs,
  );
  return applied;
}

/**
 * Fase `cluster-post` (ADR-010 rev. 6 PR-7d): despues de las migraciones de base. Transaccion con los archivos `-- scope: cluster-post` (esquema breakglass y REVOKE/GRANT/dueño de la base) y, FUERA de ella, la aserción de membresía
 * y de nivel de base (que tambien repite la aserción tras la fase database, F-A10-11; una ceremonia de break-glass abierta falla cerrado). Si la transaccion falla, una transaccion propia que solo revoca deja a consent_owner sin SET
 * sobre integrity_owner (F-PR7D-07); si falla la aserción los REVOKE ya estan confirmados. `superuser` debe estar conectado a la base de la aplicacion (ALTER DATABASE actua sobre la base de la conexion).
 */
export async function applyClusterPostScope(
  superuser: Queryable,
  migrations: readonly Migration[],
  options: Pick<ClusterScopeOptions, "mode" | "environment" | "lockTimeoutMs"> = {},
): Promise<string[]> {
  const mode = options.mode ?? resolveDbRoleMode(process.env, options.environment);
  const applied: string[] = [];
  await withClusterRoleLock(
    superuser,
    async () => {
      await withDeclaredMode(superuser, mode, async () => {
        try {
          await assertDeployPreconditions(superuser);
          await inTransaction(superuser, async () => {
            for (const m of migrations.filter((x) => x.scope === "cluster-post")) {
              await superuser.query(m.sql);
              applied.push(m.version);
            }
          });
        } catch (error) {
          await failsafeAfter(superuser, mode, error);
        }
        await assertDeployState(superuser, mode, "posterior a la fase database");
      });
    },
    options.lockTimeoutMs,
  );
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
  const lock = options.lockTimeoutMs === undefined ? {} : { lockTimeoutMs: options.lockTimeoutMs };
  const cluster = await applyClusterScope(superuser, migrations, { mode, ...(options.deferPost === undefined ? {} : { deferPost: options.deferPost }), ...lock });
  let database: string[] = [];
  let primary: unknown;
  try {
    database = await applyDatabaseScope(migrator, migrations, { ...(options.databaseEnvironment === undefined ? {} : { environment: options.databaseEnvironment }), ...lock });
  } catch (error) {
    primary = error;
  }
  try {
    const post = await applyClusterPostScope(superuser, migrations, { mode, ...lock });
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
  /** Tope de espera del lock del runner (ms). Por defecto DEFAULT_LOCK_TIMEOUT_MS. */
  lockTimeoutMs?: number;
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
  await acquireAdvisoryLock(migrator, ADVISORY_LOCK_KEY, options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS);
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
