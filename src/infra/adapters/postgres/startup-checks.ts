// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (synthetic_only_environment, ERR-CM-11),
// ADR-002 §2/§8, SEC-CNS-012 N2-06; TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño).
// SEC-CNS-021 PR-1 (CA-146 / P-34; INV-21-06): la lista de owners incluye security_event_owner (0028).
// SEC-CNS-021 PR-3 (INV-21-10/19): en STAGING la configuracion CNS_RETENTION_* es obligatoria y debe coincidir con ops.retention_policy
// (via ops.retention_status(); el runtime no lee la tabla); checkRetentionPurgeFreshness emite la senal retention_purge_stale.
//
// Chequeo de arranque del rol de runtime (P2 de CI del diseño de CA-124): el servicio NO
// arranca si el rol de la conexión es superusuario, BYPASSRLS, miembro de un owner, puede
// CREAR en algún esquema o cambiar session_replication_role, o si el catálogo de la base no
// es SYNTHETIC/LOCAL|DEV|STAGING (o difiere del environment configurado).
//
// API-CNS-116 (SEC-CNS-018 rev. 2, R2/F-7): además exige que el rol de runtime NO sea miembro de
// staff_roster_owner; que app_rw sea miembro de staff_roster_reader solo WITH INHERIT FALSE, SET TRUE;
// que staff_roster_reader solo pueda SELECT sobre la vista app.staff_roster_invitation_status (ningún
// otro objeto, ninguna escritura, ningún CREATE) y que el rol de runtime no pueda leer la vista sin SET
// ROLE; y que el reloj de la BD (now() de la vista) y el del proceso (Date.now() del dominio) difieran
// como máximo 2 s.

import type { RetentionConfig } from "../../../server/modules/common/retention.config.ts";
import type { Queryable } from "./pool.ts";

/** F-7: tolerancia entre el reloj de la BD (vista del roster) y el del proceso (dominio). */
export const MAX_CLOCK_SKEW_MS = 2000;

/** Vista de la proyeccion del roster del colegio (0019) y roles de R1/R2. */
export const STAFF_ROSTER_VIEW = "app.staff_roster_invitation_status";

export interface StartupCheckOptions {
  /** Reloj del proceso para el chequeo F-7 (inyectable en tests); por defecto Date.now. */
  nowMs?: () => number;
  /** Environment declarado por la configuración; si difiere del catálogo, no arranca (SEC N2-06). */
  expectedEnvironment?: "LOCAL" | "DEV" | "STAGING";
  /** SEC-CNS-017 F6: rol de runtime esperado (`current_user` exacto). El proceso web exige `app_rw`. */
  expectedRole?: string;
  /** SEC-CNS-021 PR-3: retencion configurada (retention.config.ts). Obligatoria en STAGING; si se pasa, debe coincidir con ops.retention_policy. */
  retention?: RetentionConfig;
}

export interface StartupCheckResult {
  ok: boolean;
  failures: string[];
}

export class StartupCheckError extends Error {
  readonly failures: string[];
  constructor(failures: string[]) {
    super(`ERR-CM-11: chequeo de arranque de la base falló: ${failures.join("; ")}`);
    this.name = "StartupCheckError";
    this.failures = failures;
  }
}

const ALLOWED_ENVIRONMENTS = new Set(["LOCAL", "DEV", "STAGING"]);

export interface ClockSkewResult {
  ok: boolean;
  /** dbMs - procesoMs (ms); NaN si la BD no devolvió un instante legible. */
  skewMs: number;
}

/**
 * F-7: compara clock_timestamp() de la BD con el reloj del proceso (punto medio de la ventana de la consulta, para
 * no contar la latencia). Falla si |delta| > maxSkewMs o si no se puede leer (fail-closed). Sirve de chequeo de
 * arranque y de salud (el GET /staff/roster lo repite dentro de su tx).
 */
export async function checkClockSkew(db: Queryable, nowMs: () => number = Date.now, maxSkewMs: number = MAX_CLOCK_SKEW_MS): Promise<ClockSkewResult> {
  const before = nowMs();
  const r = await db.query<{ db_ms: string }>("SELECT (extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint::text AS db_ms");
  const after = nowMs();
  const dbMs = Number(r.rows[0]?.db_ms);
  if (!Number.isFinite(dbMs)) return { ok: false, skewMs: Number.NaN };
  const skewMs = dbMs - (before + after) / 2;
  return { ok: Math.abs(skewMs) <= maxSkewMs, skewMs };
}

export async function runStartupChecks(db: Queryable, options: StartupCheckOptions = {}): Promise<StartupCheckResult> {
  const failures: string[] = [];

  const role = await db.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean }>(
    "SELECT rolname, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
  );
  const me = role.rows[0];
  if (me === undefined) {
    failures.push("no se pudo leer el rol de la conexión");
  } else {
    if (options.expectedRole !== undefined && me.rolname !== options.expectedRole) {
      failures.push(`el rol de la conexión no es ${options.expectedRole}`);
    }
    if (me.rolsuper) failures.push("el rol de la conexión es superusuario");
    if (me.rolbypassrls) failures.push("el rol de la conexión tiene BYPASSRLS");
  }

  const membership = await db.query<{ owner: string; member: boolean }>(
    `SELECT o.rolname AS owner, pg_catalog.pg_has_role(current_user, o.oid, 'MEMBER') AS member
       FROM pg_catalog.pg_roles o WHERE o.rolname IN ('consent_owner', 'tenant_resolve_owner', 'staff_roster_owner', 'integrity_owner', 'security_event_owner')`,
  );
  if (membership.rows.length < 5) failures.push("faltan los roles owner (base sin migrar)");
  for (const row of membership.rows) {
    if (row.member) failures.push(`el rol de la conexión es miembro de ${row.owner}`);
  }

  await checkStaffRosterRoles(db, me?.rolname, failures);

  const clock = await checkClockSkew(db, options.nowMs ?? Date.now).catch(() => ({ ok: false, skewMs: Number.NaN }));
  if (!clock.ok) failures.push(`el reloj de la base difiere del proceso en más de ${MAX_CLOCK_SKEW_MS / 1000} s o no se pudo leer (F-7)`);

  const create = await db.query<{ nspname: string }>(
    `SELECT nspname FROM pg_catalog.pg_namespace
      WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
        AND pg_catalog.has_schema_privilege(current_user, oid, 'CREATE')`,
  );
  for (const row of create.rows) failures.push(`el rol de la conexión tiene CREATE en el esquema ${row.nspname}`);

  const replication = await db.query<{ can_set: boolean }>(
    "SELECT pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET') AS can_set",
  );
  if (replication.rows[0]?.can_set === true) failures.push("el rol de la conexión puede fijar session_replication_role");

  try {
    const catalog = await db.query<{ data_class: string; environment: string }>("SELECT data_class, environment FROM ops.db_catalog");
    const row = catalog.rows[0];
    if (catalog.rows.length !== 1 || row === undefined) {
      failures.push("ops.db_catalog debe tener exactamente una fila");
    } else {
      if (row.data_class !== "SYNTHETIC") failures.push("el catálogo de la base no es SYNTHETIC");
      if (!ALLOWED_ENVIRONMENTS.has(row.environment)) failures.push("el environment del catálogo no es LOCAL, DEV ni STAGING");
      if (options.expectedEnvironment !== undefined && options.expectedEnvironment !== row.environment) {
        failures.push("el environment configurado difiere del catálogo de la base");
      }
    }
  } catch {
    failures.push("no se pudo leer ops.db_catalog");
  }

  await checkRetentionConfig(db, options, failures);
  await checkPurgeExecuteIsolation(db, failures);

  return { ok: failures.length === 0, failures };
}

/** SEC-CNS-021 PR-3 (P2-F): solo worker puede ejecutar ops.purge_p34; app_rw y platform_rw no. Fail-closed si no se puede verificar. */
async function checkPurgeExecuteIsolation(db: Queryable, failures: string[]): Promise<void> {
  try {
    const r = await db.query<{ app_rw: boolean | null; platform_rw: boolean | null }>(
      `SELECT pg_catalog.has_function_privilege('app_rw', pg_catalog.to_regprocedure('ops.purge_p34(text, interval)'), 'EXECUTE') AS app_rw,
              pg_catalog.has_function_privilege('platform_rw', pg_catalog.to_regprocedure('ops.purge_p34(text, interval)'), 'EXECUTE') AS platform_rw`,
    );
    const row = r.rows[0];
    if (row !== undefined && (row.app_rw === true || row.platform_rw === true)) failures.push("app_rw o platform_rw pueden ejecutar ops.purge_p34 (solo worker, P-34)");
  } catch {
    failures.push("no se pudo verificar el EXECUTE de ops.purge_p34");
  }
}

/** Etiqueta de la senal de purga atrasada (sin etiquetas de tenant). */
export const RETENTION_PURGE_STALE_SIGNAL = "retention_purge_stale";
/** INV-21-19: una corrida de purga debe tener menos de 26 h (job diario + holgura). */
export const MAX_PURGE_AGE_MS = 26 * 60 * 60_000;

interface RetentionStatusRow { store: string; retention_days: string | number; last_run_at: Date | string | null }

function expectedRetentionDays(config: RetentionConfig): Readonly<Record<string, number>> {
  return { security_event: config.securityEventDays, otp_verification: config.otpVerificationDays, purge_run: config.purgeRunDays };
}

/** SEC-CNS-021 PR-3: la retencion configurada debe existir (STAGING) y coincidir con ops.retention_policy. Fail-closed. */
async function checkRetentionConfig(db: Queryable, options: StartupCheckOptions, failures: string[]): Promise<void> {
  if (options.retention === undefined) {
    if (options.expectedEnvironment === "STAGING") failures.push("falta la configuracion de retencion CNS_RETENTION_* (obligatoria en STAGING, P-34)");
    return;
  }
  try {
    const status = await db.query<RetentionStatusRow>("SELECT store, retention_days, last_run_at FROM ops.retention_status()");
    const byStore = new Map(status.rows.map((r) => [r.store, Number(r.retention_days)]));
    for (const [store, days] of Object.entries(expectedRetentionDays(options.retention))) {
      const actual = byStore.get(store);
      if (actual === undefined) failures.push(`ops.retention_policy no tiene politica para ${store}`);
      else if (actual !== days) failures.push(`la retencion configurada de ${store} difiere de ops.retention_policy`);
    }
  } catch {
    failures.push("no se pudo verificar ops.retention_policy");
  }
}

/**
 * INV-21-19 (STAGING): devuelve los stores sin corrida de purga de menos de 26 h segun ops.retention_status(). Es una SENAL, no un fallo
 * de arranque (un deploy nuevo aun no tiene corridas); el llamador emite RETENTION_PURGE_STALE_SIGNAL con los nombres de store, nunca de tenant.
 */
export async function checkRetentionPurgeFreshness(
  db: Queryable,
  nowMs: () => number = Date.now,
  maxAgeMs: number = MAX_PURGE_AGE_MS,
): Promise<{ ok: boolean; stale: string[] }> {
  try {
    const status = await db.query<RetentionStatusRow>("SELECT store, retention_days, last_run_at FROM ops.retention_status()");
    const now = nowMs();
    const stale = status.rows
      .filter((r) => r.last_run_at === null || now - new Date(r.last_run_at).getTime() >= maxAgeMs)
      .map((r) => r.store);
    return { ok: stale.length === 0 && status.rows.length > 0, stale };
  } catch {
    return { ok: false, stale: ["unknown"] };
  }
}

/** R2: membresías y privilegios de staff_roster_owner / staff_roster_reader (ver cabecera). */
async function checkStaffRosterRoles(db: Queryable, runtimeRole: string | undefined, failures: string[]): Promise<void> {
  try {
    const reader = await db.query<{ inherit_option: boolean; set_option: boolean }>(
      `SELECT m.inherit_option, m.set_option
         FROM pg_catalog.pg_auth_members m
         JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
         JOIN pg_catalog.pg_roles u ON u.oid = m.member
        WHERE r.rolname = 'staff_roster_reader' AND u.rolname = current_user`,
    );
    if (runtimeRole === "app_rw") {
      const row = reader.rows[0];
      if (reader.rows.length !== 1 || row === undefined || row.inherit_option !== false || row.set_option !== true) {
        failures.push("app_rw debe ser miembro de staff_roster_reader WITH INHERIT FALSE, SET TRUE");
      }
    } else if (reader.rows.length > 0) {
      failures.push("solo app_rw puede ser miembro de staff_roster_reader");
    }

    // Objetos sobre los que staff_roster_reader tiene privilegios que no debe tener (nombre de objeto, sin datos).
    const grants = await db.query<{ rel: string }>(
      `SELECT n.nspname || '.' || c.relname AS rel
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
          AND (
            pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'INSERT')
            OR pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'UPDATE')
            OR pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'DELETE')
            OR pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'TRUNCATE')
            OR pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'REFERENCES')
            OR pg_catalog.has_table_privilege('staff_roster_reader', c.oid, 'TRIGGER')
            OR (pg_catalog.has_any_column_privilege('staff_roster_reader', c.oid, 'SELECT')
                AND n.nspname || '.' || c.relname <> '${STAFF_ROSTER_VIEW}')
          )`,
    );
    for (const row of grants.rows) failures.push(`staff_roster_reader tiene privilegios indebidos sobre ${row.rel} (solo SELECT sobre la vista del roster)`);

    const view = await db.query<{ reader_select: boolean; runtime_select: boolean; schema_create: boolean }>(
      `SELECT pg_catalog.has_table_privilege('staff_roster_reader', '${STAFF_ROSTER_VIEW}', 'SELECT') AS reader_select,
              pg_catalog.has_any_column_privilege(current_user, '${STAFF_ROSTER_VIEW}', 'SELECT') AS runtime_select,
              EXISTS (SELECT 1 FROM pg_catalog.pg_namespace s
                       WHERE s.nspname !~ '^pg_' AND s.nspname <> 'information_schema'
                         AND (pg_catalog.has_schema_privilege('staff_roster_reader', s.oid, 'CREATE')
                              OR pg_catalog.has_schema_privilege('staff_roster_owner', s.oid, 'CREATE'))) AS schema_create`,
    );
    const v = view.rows[0];
    if (v === undefined || v.reader_select !== true) failures.push("staff_roster_reader no tiene SELECT sobre la vista del roster");
    if (v === undefined || v.runtime_select !== false) failures.push("el rol de la conexión puede leer la vista del roster sin SET ROLE");
    if (v === undefined || v.schema_create !== false) failures.push("staff_roster_owner o staff_roster_reader tienen CREATE en algún esquema");
  } catch {
    failures.push("no se pudieron verificar los roles del roster (staff_roster_owner / staff_roster_reader)");
  }
}

export async function assertStartupChecks(db: Queryable, options: StartupCheckOptions = {}): Promise<void> {
  const result = await runStartupChecks(db, options);
  if (!result.ok) throw new StartupCheckError(result.failures);
}
