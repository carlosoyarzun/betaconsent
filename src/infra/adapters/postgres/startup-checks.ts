// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (synthetic_only_environment, ERR-CM-11),
// ADR-002 §2/§8, SEC-CNS-012 N2-06; TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño).
// SEC-CNS-021 PR-1 (CA-146 / P-34; INV-21-06): la lista de owners incluye security_event_owner (0028).
// ADR-010 PR-2 (INV-DBR-01/03, Q-19): la lista de owners incluye outbox_claimer, platform_schema_owner, grant_owner, membership_owner,
// case_state_owner y transition_owner; ademas la membresia de los roles gobernados debe coincidir EXACTAMENTE con la del modo
// (role-membership.ts), fail-closed. integrity_verifier es un rol de runtime mas.
// ADR-010 PR-3 (INV-DBR-01; Q4, Q-17): el rol de runtime no tiene ningun privilegio sobre las tablas del esquema platform (sin DML: solo funciones
// SECURITY DEFINER) y solo puede ejecutar las funciones de platform que su rol declara (PLATFORM_RUNTIME_EXECUTE).
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
import { checkRoleMemberships, OWNER_ROLES, resolveDbRoleMode, RoleModeError } from "./role-membership.ts";
import type { DbRoleMode } from "./role-membership.ts";

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
  /** ADR-010 PR-2: modo de roles declarado por el deploy (nunca por la request). Por defecto resolveDbRoleMode(process.env, expectedEnvironment); REAL_DATA no esta activado hasta PR-7. */
  roleMode?: DbRoleMode;
}

export interface StartupCheckResult {
  ok: boolean;
  failures: string[];
}

export class StartupCheckError extends Error {
  readonly code = "STARTUP_CHECK_FAILED";
  readonly failures: string[];
  constructor(failures: string[]) {
    super(`ERR-CM-11: chequeo de arranque de la base falló: ${failures.join("; ")}`);
    this.name = "StartupCheckError";
    this.failures = failures;
  }
}

/**
 * ADR-010 PR-3 (specs/db-roles.spec.yaml): funciones de platform ejecutables por cada rol de runtime. app_rw (web, consola STAFF, Q-17) solo SOLICITA
 * membership de TENANT_ADMIN; platform_rw (equipo de LectorPro) el resto. ADR-010 PR-6b (rev. 5 §2): platform_rw inicia y completa la autorizacion OIDC
 * (begin_oidc_authorization / complete_oidc_callback, sin SELECT ni DML sobre oidc_exchange; reemplazan a enqueue_oidc_exchange), consulta el estado con (ref, state)
 * y registra los limites P-49/P-50; el worker purga las solicitudes vencidas; integrity_verifier toma el canje y registra las aserciones (UNICO que atesta: step-up y login).
 * consume_login_assertion es INTERNA (sin EXECUTE de runtime). ADR-010 PR-6c (0053): platform_rw abre, valida y revoca las sesiones PLATFORM y CASE
 * (open_platform_session / open_case_session / validate_session / revoke_session); revoke_session_internal es INTERNA.
 */
export const PLATFORM_RUNTIME_EXECUTE: Readonly<Record<string, readonly string[]>> = {
  app_rw: ["request_membership"],
  platform_rw: ["request_membership", "approve_membership", "request_role_assignment", "approve_role_assignment", "authorize", "issue_action_nonce", "begin_oidc_authorization", "complete_oidc_callback", "exchange_status", "record_limit_event", "open_platform_session", "open_case_session", "validate_session", "revoke_session"],
  worker: ["purge_expired_oidc_exchange"],
  integrity_verifier: ["claim_oidc_exchange", "record_assertion", "record_login_assertion"],
  // ADR-010 rev. 5 PR-6e (G-9, P2(e)): el reconciler solo lee (SELECT por columnas); sin EXECUTE en platform ni acceso a sus tablas.
  integrity_reconciler: [],
};

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

  const role = await db.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean; session_user_name: string; session_super: boolean | null }>(
    `SELECT rolname, rolsuper, rolbypassrls, session_user::pg_catalog.text AS session_user_name,
            (SELECT s.rolsuper FROM pg_catalog.pg_roles s WHERE s.rolname = session_user) AS session_super
       FROM pg_catalog.pg_roles WHERE rolname = current_user`,
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
    // INV-DBR-02: la identidad de autenticacion (session_user) debe ser el rol esperado Y coincidir con current_user: un `options=-c role=...` o `?user=` no puede disfrazar otra identidad.
    if (me.session_user_name !== me.rolname) failures.push("session_user difiere de current_user (la conexión asumió otro rol, INV-DBR-02)");
    if (options.expectedRole !== undefined && me.session_user_name !== options.expectedRole) failures.push(`session_user no es ${options.expectedRole} (INV-DBR-02)`);
    if (me.session_super !== false) failures.push("session_user es superusuario o no se pudo verificar");
  }
  await checkNoClientGucOverrides(db, failures);

  const membership = await db.query<{ owner: string; member: boolean }>(
    `SELECT o.rolname AS owner, pg_catalog.pg_has_role(current_user, o.oid, 'MEMBER') AS member
       FROM pg_catalog.pg_roles o WHERE o.rolname = ANY($1::text[])`,
    [[...OWNER_ROLES]],
  );
  if (membership.rows.length < OWNER_ROLES.length) failures.push("faltan los roles owner (base sin migrar)");
  for (const row of membership.rows) {
    if (row.member) failures.push(`el rol de la conexión es miembro de ${row.owner}`);
  }

  try {
    // El modo lo declara el deploy (CNS_DB_ROLE_MODE), el mismo que usa el runner; vacio solo vale en LOCAL/DEV. Sin modo valido, no arranca.
    const roleMode = options.roleMode ?? resolveDbRoleMode(process.env, options.expectedEnvironment);
    for (const problem of await checkRoleMemberships(db, roleMode)) failures.push(`${problem} (INV-DBR-03)`);
  } catch (error) {
    failures.push(error instanceof RoleModeError ? `${error.message} (INV-DBR-03)` : "no se pudo verificar la membresía de los roles (INV-DBR-03)");
  }

  await checkStaffRosterRoles(db, me?.rolname, failures);
  await checkPlatformSchemaExposure(db, me?.rolname, failures);
  await checkNoAppGucDefaults(db, failures);

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
      await checkTransitionExecuteIsolation(db, row.environment, failures);
    }
  } catch {
    failures.push("no se pudo leer ops.db_catalog");
  }

  await checkRetentionConfig(db, options, failures);
  await checkPurgeExecuteIsolation(db, failures);

  return { ok: failures.length === 0, failures };
}

/**
 * ADR-010 PR-5a (F-A10-26, mitigacion): en IT0 el EXECUTE de las funciones de operador (FN-RV-07..11, FN-RC-06 close_case), SYSTEM (FN-RV-12..15) y de siembra de
 * `case_state` se concede tambien a app_rw porque el codigo corre en el proceso web (entrypoints worker/platform: PR-6). Ese interino solo es
 * admisible en LOCAL/CI: fuera de LOCAL el proceso NO arranca si su rol puede ejecutarlas (salvo `worker` y sus funciones SYSTEM). Fail-closed.
 */
async function checkTransitionExecuteIsolation(db: Queryable, environment: string, failures: string[]): Promise<void> {
  if (environment === "LOCAL") return;
  try {
    const r = await db.query<{ name: string }>(
      `SELECT p.proname::pg_catalog.text AS name
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'case_state' AND pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
          AND p.proname = ANY($1::text[])
          AND NOT (current_user = 'worker' AND p.proname = ANY($2::text[]))`,
      [INTERIM_EXECUTE_FUNCTIONS, SYSTEM_TRANSITION_FUNCTIONS],
    );
    for (const row of r.rows) failures.push(`el rol de la conexión puede ejecutar case_state.${row.name} fuera de LOCAL (F-A10-26: EXECUTE interino de IT0 solo LOCAL/CI)`);
  } catch {
    failures.push("no se pudo verificar el EXECUTE de las funciones case_state (F-A10-26)");
  }
}

const SYSTEM_TRANSITION_FUNCTIONS: readonly string[] = ["apply_revocation", "mark_downstream_emitted", "record_downstream_ack", "record_erasure_attestation"];
const INTERIM_EXECUTE_FUNCTIONS: readonly string[] = [
  ...SYSTEM_TRANSITION_FUNCTIONS,
  "propose_case_verification",
  "approve_case_verification",
  "withdraw_case_verification_proposal",
  "record_case_confirmation",
  "cosign_case_confirmation",
  "seed_local_revocation",
  // ADR-010 PR-5b (0038): cierre del caso (FN-RC-06, operador) y siembra LOCAL del contrato `save` de rights_case.
  "close_case",
  "seed_local_rights_case",
];

/**
 * ADR-010 PR-3 (P2-7): el principal y el tenant los fija el adapter con set_config(..., true) por transaccion. Ningun default de rol o de base
 * (pg_db_role_setting) puede traer una GUC app.* para los roles de runtime: fijaria un principal o un tenant fuera de la transaccion.
 */
async function checkNoAppGucDefaults(db: Queryable, failures: string[]): Promise<void> {
  try {
    const r = await db.query<{ scope: string; setting: string }>(
      `SELECT COALESCE(r.rolname::pg_catalog.text, '(todos los roles)') AS scope, pg_catalog.split_part(c, '=', 1) AS setting
         FROM pg_catalog.pg_db_role_setting s
         LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
         CROSS JOIN LATERAL pg_catalog.unnest(s.setconfig) AS c
        WHERE pg_catalog.lower(c) LIKE 'app.%'
          AND s.setdatabase IN (0, (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()))
          AND (s.setrole = 0 OR r.rolname = ANY($1::text[]))`,
      [Object.keys(PLATFORM_RUNTIME_EXECUTE)],
    );
    for (const row of r.rows) failures.push(`pg_db_role_setting fija la GUC ${row.setting} para ${row.scope}: las GUC app.* solo se fijan por transaccion (ADR-010 PR-3)`);
  } catch {
    failures.push("no se pudo verificar pg_db_role_setting (GUC app.*)");
  }
}

/** INV-DBR-02: ningun GUC `role`, `session_authorization` ni `app.*` puede venir del cliente (options/PGOPTIONS en la conexion). Fail-closed si no se puede verificar. */
async function checkNoClientGucOverrides(db: Queryable, failures: string[]): Promise<void> {
  try {
    const r = await db.query<{ name: string }>(
      // Los placeholders `app.*` fijados por options NO aparecen en pg_settings: se leen por nombre (los unicos app.* del sistema: tenant_id, principal_ref, session_ref, session_sid).
      `SELECT name FROM pg_catalog.pg_settings WHERE source = 'client' AND (name IN ('role', 'session_authorization') OR name LIKE 'app.%')
       UNION ALL
       SELECT n FROM pg_catalog.unnest(ARRAY['app.tenant_id', 'app.principal_ref', 'app.session_ref', 'app.session_sid']) AS n WHERE COALESCE(pg_catalog.current_setting(n, true), '') <> ''`,
    );
    for (const row of r.rows) failures.push(`la conexión fija el GUC ${row.name} desde el cliente (options/PGOPTIONS, INV-DBR-02)`);
  } catch {
    failures.push("no se pudo verificar los GUC fijados por el cliente");
  }
}

/** ADR-010 PR-3: sin privilegios sobre tablas de platform y EXECUTE solo de las funciones declaradas para el rol. Fail-closed si no se puede verificar. */
async function checkPlatformSchemaExposure(db: Queryable, runtimeRole: string | undefined, failures: string[]): Promise<void> {
  try {
    const r = await db.query<{ kind: string; name: string }>(
      `SELECT 'table' AS kind, c.relname::pg_catalog.text AS name
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'platform' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (pg_catalog.has_table_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
               OR pg_catalog.has_any_column_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))
       UNION ALL
       SELECT 'function' AS kind, p.proname::pg_catalog.text AS name
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'platform' AND pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')`,
    );
    const allowed = new Set(PLATFORM_RUNTIME_EXECUTE[runtimeRole ?? ""] ?? []);
    for (const row of r.rows) {
      if (row.kind === "table") failures.push(`el rol de la conexión tiene privilegios sobre la tabla platform.${row.name} (sin DML, ADR-010 §4.4)`);
      else if (!allowed.has(row.name)) failures.push(`el rol de la conexión puede ejecutar platform.${row.name}() y no le corresponde (ADR-010 PR-3)`);
    }
  } catch {
    failures.push("no se pudo verificar la exposición del esquema platform");
  }
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
  return { security_event: config.securityEventDays, otp_budget: config.otpBudgetDays, otp_verification: config.otpVerificationDays, purge_run: config.purgeRunDays };
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
