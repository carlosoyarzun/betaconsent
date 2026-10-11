// Gobierna: ADR-010 rev. 4 §4.1.1 (aserción de membresía por modo), specs/db-roles.spec.yaml membershipAssertion / INV-DBR-03,
// decisiones de Carlos del 2026-10-11 (Q-19: security_event_owner, tenant_resolve_owner, staff_roster_owner y outbox_claimer
// entran en la aserción). PR-2 de ADR-010.
//
// Lista exacta de membresías de roles (pg_auth_members) por modo de despliegue y su comparación. La usan el runner (migrate.ts,
// posterior a la fase de cluster) y startup-checks.ts. Igualdad EXACTA y fail-closed: cualquier fila extra o faltante que toque un
// rol gobernado falla. El modo lo declara el deploy (variable de entorno CNS_DB_ROLE_MODE), nunca la request.
//
// Estado de activación (PR-2): solo IT0B_SYNTHETIC está activo. REAL_DATA está definido pero NO se activa hasta PR-7 (que revoca
// las membresías de consent_owner/consent_migrator y crea ddl_breakglass); pedirlo hoy falla cerrado. Cambiar el modo o una
// membresía es human gate (specs/db-roles.spec.yaml humanGate).

import type { Queryable } from "./pool.ts";

export type DbRoleMode = "IT0B_SYNTHETIC" | "REAL_DATA";

export const DB_ROLE_MODE_ENV = "CNS_DB_ROLE_MODE";
export const DEFAULT_DB_ROLE_MODE: DbRoleMode = "IT0B_SYNTHETIC";
/** Modos con aserción activa. REAL_DATA se activa en PR-7 (ADR-010 §7). */
export const ACTIVE_DB_ROLE_MODES: readonly DbRoleMode[] = ["IT0B_SYNTHETIC"];

export interface MembershipEdge {
  readonly member: string;
  readonly role: string;
  readonly inherit: boolean;
  readonly set: boolean;
}

const edge = (member: string, role: string, inherit: boolean, set: boolean): MembershipEdge => ({ member, role, inherit, set });

/** Owners de §4.1.1 que consent_owner puede asumir con SET (INHERIT FALSE) en IT0B_SYNTHETIC. */
export const CONSENT_OWNER_SET_ROLES: readonly string[] = [
  "tenant_resolve_owner",
  "staff_roster_owner",
  "integrity_owner",
  "security_event_owner",
  "platform_schema_owner",
  "grant_owner",
  "membership_owner",
  "case_state_owner",
  "transition_owner",
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
];

/** Roles de runtime (INV-DBR-01). */
export const RUNTIME_ROLES: readonly string[] = ["app_rw", "platform_rw", "worker", "integrity_verifier"];

/** Roles cuyas membresías (como miembro o como rol concedido) gobierna la aserción. */
export const GOVERNED_ROLES: readonly string[] = [
  ...OWNER_ROLES,
  ...RUNTIME_ROLES,
  "consent_migrator",
  "staff_roster_reader",
  "rights_operator",
];

/**
 * Membresías esperadas por modo. PR-2: no incluye platform_rw -> rights_operator (PR-5) ni ddl_breakglass (PR-7); esos PR las
 * agregan. REAL_DATA queda definido (sin activar) con los roles que existen hoy.
 */
export const EXPECTED_MEMBERSHIPS: Readonly<Record<DbRoleMode, readonly MembershipEdge[]>> = {
  IT0B_SYNTHETIC: [
    edge("consent_migrator", "consent_owner", true, true),
    edge("consent_migrator", "outbox_claimer", false, true),
    ...CONSENT_OWNER_SET_ROLES.map((r) => edge("consent_owner", r, false, true)), // integrity_owner: solo hasta PR-7
    edge("app_rw", "staff_roster_reader", false, true),
  ],
  REAL_DATA: [
    edge("consent_migrator", "consent_owner", true, true),
    edge("app_rw", "staff_roster_reader", false, true),
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
    throw new RoleModeError(`El modo ${mode} no está activado (se activa en ADR-010 PR-7); no hay aserción de membresía para él.`);
  }
}

/** Resuelve el modo desde el entorno del deploy. Vacío = IT0B_SYNTHETIC; valor desconocido o no activado = error (fail-closed). */
export function resolveDbRoleMode(env: Readonly<Record<string, string | undefined>>): DbRoleMode {
  const raw = env[DB_ROLE_MODE_ENV];
  if (raw === undefined || raw === "") return DEFAULT_DB_ROLE_MODE;
  if (raw !== "IT0B_SYNTHETIC" && raw !== "REAL_DATA") throw new RoleModeError(`${DB_ROLE_MODE_ENV} desconocido: "${raw}".`);
  assertModeActive(raw);
  return raw;
}

const keyOf = (e: MembershipEdge): string => `${e.member} -> ${e.role} {inherit: ${e.inherit}, set: ${e.set}}`;

/** Compara membresías reales con las esperadas del modo; devuelve una descripción por diferencia (vacío = coincide). Solo nombres de rol. */
export function diffMemberships(actual: readonly MembershipEdge[], mode: DbRoleMode): string[] {
  const expected = new Set(EXPECTED_MEMBERSHIPS[mode].map(keyOf));
  const found = new Set(actual.map(keyOf));
  const problems: string[] = [];
  for (const k of [...found].sort()) if (!expected.has(k)) problems.push(`membresía no esperada en modo ${mode}: ${k}`);
  for (const k of [...expected].sort()) if (!found.has(k)) problems.push(`falta la membresía esperada en modo ${mode}: ${k}`);
  return problems;
}

/** Lee de pg_auth_members toda fila que toque un rol gobernado (como miembro o como rol concedido). */
export async function readGovernedMemberships(db: Queryable): Promise<MembershipEdge[]> {
  const r = await db.query<{ member: string; role: string; inherit_option: boolean; set_option: boolean }>(
    `SELECT u.rolname AS member, g.rolname AS role, m.inherit_option, m.set_option
       FROM pg_catalog.pg_auth_members m
       JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
       JOIN pg_catalog.pg_roles u ON u.oid = m.member
      WHERE g.rolname = ANY($1::text[]) OR u.rolname = ANY($1::text[])`,
    [[...GOVERNED_ROLES]],
  );
  return r.rows.map((x) => edge(x.member, x.role, x.inherit_option, x.set_option));
}

/** Verifica la igualdad exacta de membresías para el modo; devuelve las diferencias (vacío = ok). Modo no activado = una diferencia. */
export async function checkRoleMemberships(db: Queryable, mode: DbRoleMode = DEFAULT_DB_ROLE_MODE): Promise<string[]> {
  if (!ACTIVE_DB_ROLE_MODES.includes(mode)) return [`el modo ${mode} no está activado (ADR-010 PR-7)`];
  return diffMemberships(await readGovernedMemberships(db), mode);
}
