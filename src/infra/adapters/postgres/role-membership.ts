// Gobierna: ADR-010 rev. 4 §4.1.1 (aserción de membresía por modo), specs/db-roles.spec.yaml membershipAssertion / INV-DBR-03,
// decisiones de Carlos del 2026-10-11 (Q-19: security_event_owner, tenant_resolve_owner, staff_roster_owner y outbox_claimer
// entran en la aserción). PR-2 de ADR-010.
//
// Lista exacta de membresías de roles (pg_auth_members) por modo de despliegue y su comparación. La usan el runner (migrate.ts,
// posterior a la fase de cluster) y startup-checks.ts. Igualdad EXACTA y fail-closed: cualquier fila extra o faltante que toque un
// rol gobernado falla. El modo lo declara el deploy (variable de entorno CNS_DB_ROLE_MODE), nunca la request.
//
// Estado de activación: ADR-010 rev. 6 PR-7d activa AMBOS modos como modos VERIFICABLES (la aserción de membresía de REAL_DATA existe y el runner puede aplicarla). REAL_DATA NO autoriza datos reales
// (F-PR7-12): resolveDbRoleMode lo rechaza mientras REAL_DATA_BLOCKERS no este vacio (F-PR7-01) y el catalogo sigue exigiendo data_class = SYNTHETIC. PR-7d revoca integrity_owner a consent_owner en AMBOS modos (C-1, Carlos 2026-10-16),
// agrega ddl_breakglass (miembro de los owners salvo consent_owner) y, en REAL_DATA, el REVOKE explicito de todas las membresias SET de consent_owner/consent_migrator (F-PRB-06, F-PR7C-06).
// Cambiar el modo o una membresía es human gate (specs/db-roles.spec.yaml humanGate).

import type { Queryable } from "./pool.ts";

export type DbRoleMode = "IT0B_SYNTHETIC" | "REAL_DATA";

export const DB_ROLE_MODE_ENV = "CNS_DB_ROLE_MODE";
export const DEFAULT_DB_ROLE_MODE: DbRoleMode = "IT0B_SYNTHETIC";
/** Modos con aserción activa (ADR-010 rev. 6 PR-7d). Activo = VERIFICABLE; no implica autorizacion de datos reales (F-PR7-12). */
export const ACTIVE_DB_ROLE_MODES: readonly DbRoleMode[] = ["IT0B_SYNTHETIC", "REAL_DATA"];

/**
 * ADR-010 rev. 6 PR-7c (decision de Carlos del 2026-10-16, C-3): hallazgos que BLOQUEAN el modo REAL_DATA mientras sigan abiertos. F-PR7-01 (P1 hoy, P0 antes de datos reales): consent_owner (el migrador) sigue
 * siendo dueño de las tablas app.* y ops.* que escriben las funciones de otros owners (detectado por el inventario de consent-owner-inventory.ts, no prevenido). Se retira de esta lista solo cuando C-3 (a)
 * este implementado (el migrador no es dueño de nada en REAL_DATA) y lo apruebe Carlos. startup-checks.ts y resolveDbRoleMode rechazan REAL_DATA mientras la lista no este vacia.
 */
export const REAL_DATA_BLOCKERS: readonly string[] = ["F-PR7-01"];

export interface MembershipEdge {
  readonly member: string;
  readonly role: string;
  readonly inherit: boolean;
  readonly set: boolean;
  /** admin_option de pg_auth_members: quien lo tiene puede conceder el rol a otros (escalada de membresia). Esperado false en toda fila. */
  readonly admin: boolean;
}

const edge = (member: string, role: string, inherit: boolean, set: boolean, admin = false): MembershipEdge => ({ member, role, inherit, set, admin });

/**
 * Owners de §4.1.1 que consent_owner puede asumir con SET (INHERIT FALSE) en IT0B_SYNTHETIC. ADR-010 rev. 6 PR-7d (C-1): integrity_owner YA NO esta en la lista (en ninguno de los dos modos): toda DDL sobre integrity.* va por
 * ceremonia de break-glass (ddl_breakglass).
 */
export const CONSENT_OWNER_SET_ROLES: readonly string[] = [
  "tenant_resolve_owner",
  "staff_roster_owner",
  "security_event_owner",
  "platform_schema_owner",
  "grant_owner",
  "membership_owner",
  "case_state_owner",
  "transition_owner",
  "ledger_gen_owner",
  "ledger_writer",
  "rights_case_lookup_owner", // ADR-010 rev. 5 PR-6d parte 1 (0064, F-PR6-45): dueño de app.rights_case_tenant_of
  "app_schema_owner", // ADR-010 rev. 6 PR-7c (0080, F-PR7-01, C-2): dueño del esquema app (consent_owner conserva USAGE, CREATE)
  "ops_schema_owner", // ADR-010 rev. 6 PR-7c (0080, F-PR7-01, R-21-1): dueño del esquema ops
  "shared_fn_owner", // ADR-010 rev. 6 PR-7c (0080, F-PR7-01, C-3): dueño de app.current_tenant_id(), app.is_reserved_email(text), ops.catalog_environment()
  "revocation_recovery_reader", // ADR-010 rev. 6 PR-7c (0080, F-6D3-SEC-08): dueño de case_state.list_confirmed_unapplied y de su policy cross-tenant
];

/** Owners NOLOGIN de los que ningun rol de runtime puede ser miembro (spec INV-DBR-01; incluye consent_owner y outbox_claimer). */
export const OWNER_ROLES: readonly string[] = [
  "consent_owner",
  "tenant_resolve_owner",
  "staff_roster_owner",
  "integrity_owner",
  "security_event_owner",
  "outbox_claimer",
  "platform_schema_owner",
  "grant_owner",
  "membership_owner",
  "case_state_owner",
  "transition_owner",
  "ledger_gen_owner", // ADR-010 rev. 5 PR-b (LG-8, F-PR6-11): doce owners cubiertos
  "ledger_writer",
  "rights_case_lookup_owner",
  "app_schema_owner", // PR-7c (0080)
  "ops_schema_owner",
  "shared_fn_owner",
  "revocation_recovery_reader",
];

/** Roles de runtime (INV-DBR-01). */
export const RUNTIME_ROLES: readonly string[] = ["app_rw", "platform_rw", "worker", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier"]; // ADR-010 rev. 5 PR-6e (G-9): sexto rol; rev. 6 PR-6f (D-1 (b)): septimo rol de runtime

/**
 * ADR-010 rev. 6 PR-7d (0084): roles de nivel de base. NO son OWNER_ROLES (ddl_breakglass no es miembro de ellos; db_owner_nologin y breakglass_log_owner no tienen miembros ni se pueden asumir): db_owner_nologin (dueño de la base),
 * breakglass_log_owner (dueño de breakglass.ceremony) y ddl_breakglass (NOLOGIN fuera de ceremonia; asume los owners).
 */
export const DB_LEVEL_ROLES: readonly string[] = ["db_owner_nologin", "breakglass_log_owner", "ddl_breakglass"];

/** Owners que asume ddl_breakglass (INHERIT FALSE, SET TRUE): lista DERIVADA de OWNER_ROLES menos consent_owner (T-13; F-PR7-06: ni "diez" ni "doce"). db/migrations/0084 repite esta lista y un test las compara. */
export const BREAKGLASS_OWNER_ROLES: readonly string[] = OWNER_ROLES.filter((r) => r !== "consent_owner");

/** Roles cuyas membresías (como miembro o como rol concedido) gobierna la aserción. */
export const GOVERNED_ROLES: readonly string[] = [
  ...OWNER_ROLES,
  ...DB_LEVEL_ROLES,
  ...RUNTIME_ROLES,
  "consent_migrator",
  "staff_roster_reader",
  "rights_operator",
];

/** ADR-010 rev. 6 PR-7d (0084, INV-DBR-09): ddl_breakglass asume cada owner (menos consent_owner) con INHERIT FALSE, SET TRUE, sin ADMIN, en AMBOS modos. */
const BREAKGLASS_EDGES: readonly MembershipEdge[] = BREAKGLASS_OWNER_ROLES.map((r) => edge("ddl_breakglass", r, false, true));

/**
 * Membresías esperadas por modo (INV-DBR-03). PR-7d: sin integrity_owner para consent_owner en ningun modo (C-1) y con ddl_breakglass -> los 17 owners en ambos. REAL_DATA: consent_owner sin ninguna membresia SET y
 * consent_migrator sin outbox_claimer (REVOKE explicito en 0086).
 */
export const EXPECTED_MEMBERSHIPS: Readonly<Record<DbRoleMode, readonly MembershipEdge[]>> = {
  IT0B_SYNTHETIC: [
    edge("consent_migrator", "consent_owner", true, true),
    edge("consent_migrator", "outbox_claimer", false, true),
    ...CONSENT_OWNER_SET_ROLES.map((r) => edge("consent_owner", r, false, true)),
    edge("app_rw", "staff_roster_reader", false, true),
    edge("platform_rw", "rights_operator", false, true), // ADR-010 rev. 5 PR-6d parte 2 (0068)
    ...BREAKGLASS_EDGES,
  ],
  REAL_DATA: [
    edge("consent_migrator", "consent_owner", true, true),
    edge("app_rw", "staff_roster_reader", false, true),
    edge("platform_rw", "rights_operator", false, true), // ADR-010 rev. 5 PR-6d parte 2 (0068)
    ...BREAKGLASS_EDGES,
  ],
};

export class RoleModeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RoleModeError";
  }
}

export function assertModeActive(mode: DbRoleMode): void {
  if (!ACTIVE_DB_ROLE_MODES.includes(mode)) {
    throw new RoleModeError(`El modo ${mode} no está activado; no hay aserción de membresía para él.`);
  }
}

/** Entornos en los que CNS_DB_ROLE_MODE vacio equivale a IT0B_SYNTHETIC (LOCAL y DEV sinteticos). En cualquier otro, o sin entorno, el modo es obligatorio. */
export const ENVIRONMENTS_WITH_DEFAULT_MODE: readonly string[] = ["LOCAL", "DEV"];

/**
 * Resuelve el modo desde el entorno del deploy (nunca la request). Vacio = IT0B_SYNTHETIC SOLO si `environment` es LOCAL o DEV;
 * en STAGING, sin entorno declarado o cualquier otro, falta de CNS_DB_ROLE_MODE es error (fail-closed). Valor desconocido o no activado = error.
 */
export function resolveDbRoleMode(env: Readonly<Record<string, string | undefined>>, environment: string | undefined): DbRoleMode {
  const raw = env[DB_ROLE_MODE_ENV];
  if (raw === undefined || raw === "") {
    if (environment !== undefined && ENVIRONMENTS_WITH_DEFAULT_MODE.includes(environment)) return DEFAULT_DB_ROLE_MODE;
    throw new RoleModeError(`${DB_ROLE_MODE_ENV} es obligatorio fuera de LOCAL/DEV (entorno: ${environment ?? "no declarado"}).`);
  }
  if (raw !== "IT0B_SYNTHETIC" && raw !== "REAL_DATA") throw new RoleModeError(`${DB_ROLE_MODE_ENV} desconocido: "${raw}".`);
  if (raw === "REAL_DATA" && REAL_DATA_BLOCKERS.length > 0) throw new RoleModeError(`El modo REAL_DATA está bloqueado mientras sigan abiertos: ${REAL_DATA_BLOCKERS.join(", ")}.`);
  assertModeActive(raw);
  return raw;
}

const keyOf = (e: MembershipEdge): string => `${e.member} -> ${e.role} {inherit: ${e.inherit}, set: ${e.set}, admin: ${e.admin}}`;

/**
 * Compara membresias reales con las esperadas del modo como MULTICONJUNTO (una fila duplicada, p. ej. con otro grantor, es una diferencia).
 * Devuelve una descripcion por diferencia (vacio = coincide). Solo nombres de rol.
 */
export function diffMemberships(actual: readonly MembershipEdge[], mode: DbRoleMode): string[] {
  const count = (edges: readonly MembershipEdge[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const e of edges) m.set(keyOf(e), (m.get(keyOf(e)) ?? 0) + 1);
    return m;
  };
  const expected = count(EXPECTED_MEMBERSHIPS[mode]);
  const found = count(actual);
  const problems: string[] = [];
  for (const [k, n] of [...found].sort(([x], [y]) => x.localeCompare(y))) {
    const want = expected.get(k) ?? 0;
    if (want === 0) problems.push(`membresía no esperada en modo ${mode}: ${k}`);
    else if (n > want) problems.push(`membresía duplicada (${n} filas) en modo ${mode}: ${k}`);
  }
  for (const k of [...expected.keys()].sort()) if (!found.has(k)) problems.push(`falta la membresía esperada en modo ${mode}: ${k}`);
  return problems;
}

/** Lee de pg_auth_members toda fila que toque un rol gobernado (como miembro o como rol concedido). */
export async function readGovernedMemberships(db: Queryable): Promise<MembershipEdge[]> {
  const r = await db.query<{ member: string; role: string; inherit_option: boolean; set_option: boolean; admin_option: boolean }>(
    `SELECT u.rolname AS member, g.rolname AS role, m.inherit_option, m.set_option, m.admin_option
       FROM pg_catalog.pg_auth_members m
       JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
       JOIN pg_catalog.pg_roles u ON u.oid = m.member
      WHERE g.rolname = ANY($1::text[]) OR u.rolname = ANY($1::text[])`,
    [[...GOVERNED_ROLES]],
  );
  return r.rows.map((x) => edge(x.member, x.role, x.inherit_option, x.set_option, x.admin_option));
}

/** Verifica la igualdad exacta de membresías para el modo; devuelve las diferencias (vacío = ok). Modo no activado = una diferencia. */
export async function checkRoleMemberships(db: Queryable, mode: DbRoleMode = DEFAULT_DB_ROLE_MODE): Promise<string[]> {
  if (!ACTIVE_DB_ROLE_MODES.includes(mode)) return [`el modo ${mode} no está activado`];
  return diffMemberships(await readGovernedMemberships(db), mode);
}
