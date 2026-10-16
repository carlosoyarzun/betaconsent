// Gobierna: ADR-010 rev. 5 PR-6c (platform_session, F-PR6-36); db/migrations/0052. Helper de TESTS (no es codigo de produccion): siembra, con una conexion de superusuario (fixtureAdmin), una sesion
// PLATFORM o CASE viva sin pasar por el login, para los tests que ejercitan funciones que EXIGEN una sesion (begin LOGIN_CASE, validate_session...). Solo sinteticos.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

export interface SeededSession {
  readonly sid: string;
  readonly sessionRef: string;
}

/** Inserta una asercion LOGIN consumida (la unica FK de la sesion) y la sesion PLATFORM viva del principal. */
export async function seedPlatformSession(admin: Client, principal: string, opts: { absoluteSeconds?: number; idleSeconds?: number } = {}): Promise<SeededSession> {
  const assertion = await seedConsumedAssertion(admin, principal, "LOGIN_PLATFORM", null);
  const sid = randomBytes(32).toString("hex");
  const row = (await admin.query<{ session_ref: string }>(
    `INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, expires_at, idle_seconds)
     VALUES ($1, 'PLATFORM', $2, $3, now() + make_interval(secs => $4), $5) RETURNING session_ref`,
    [sha(sid), principal, assertion, opts.absoluteSeconds ?? 3600, opts.idleSeconds ?? 600],
  )).rows[0]!;
  return { sid, sessionRef: row.session_ref };
}

/** Siembra (superusuario) un caso REAL en case_state.rights_case (ADR-010 0059: el tenant de los grants y sesiones CASE se deriva de el). Idempotente por (tenant, case_ref). Solo tests. */
export async function seedRightsCase(admin: Client, tenantId: string, caseRef: string, status = "OPEN"): Promise<void> {
  await admin.query("BEGIN");
  try {
    await admin.query("SELECT set_config('case_state.effect', 'seed_local_rights_case', true)");
    await admin.query(
      "INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, $2, $3, $4, $5, 'LIMIT_REACHED') ON CONFLICT (tenant_id, case_ref) DO NOTHING",
      [tenantId, caseRef, `chain-${caseRef}`, `dec-${caseRef}`, status],
    );
    await admin.query("COMMIT");
  } catch (error) {
    await admin.query("ROLLBACK");
    throw error;
  }
}

/** Un UUIDv4 estable derivado de un texto (aprobador sintetico por defecto). */
const uuidFrom = (label: string): string => {
  const h = createHash("sha256").update(label, "utf8").digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

/**
 * Siembra (superusuario) un grant VALIDO: el caso real, la grant_request APPROVED (el doble control de 0059 exige la solicitud) y el rights_case_grant. Camino de siembra de tests; el de runtime es
 * platform.request_grant/approve_grant. Devuelve el grant_ref. Solo tests.
 */
export async function seedApprovedGrant(
  admin: Client,
  o: { tenantId: string; caseRef: string; operator: string; seconds?: number; approver?: string },
): Promise<string> {
  await seedRightsCase(admin, o.tenantId, o.caseRef);
  const approver = o.approver ?? uuidFrom(`approver-${o.operator}`);
  const request = (await admin.query<{ request_ref: string }>(
    `INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, expires_at, status, approved_by_ref, approved_at)
     VALUES ($1, $2, $3, $3, now() + interval '1 hour', 'APPROVED', $4, now()) RETURNING request_ref`,
    [o.tenantId, o.caseRef, o.operator, approver],
  )).rows[0]!;
  return (await admin.query<{ grant_ref: string }>(
    `INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at, request_ref, approved_by_ref)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6) RETURNING grant_ref`,
    [o.tenantId, o.caseRef, o.operator, o.seconds ?? 3600, request.request_ref, approver],
  )).rows[0]!.grant_ref;
}

/** Sesion CASE viva (con su grant) colgada de `parent`. */
export async function seedCaseSession(admin: Client, principal: string, parent: SeededSession, caseRef: string, tenantId: string, opts: { grantSeconds?: number } = {}): Promise<SeededSession & { grantRef: string }> {
  const assertion = await seedConsumedAssertion(admin, principal, "LOGIN_CASE", sha(caseRef));
  const grantRef = await seedApprovedGrant(admin, { tenantId, caseRef, operator: principal, seconds: opts.grantSeconds ?? 3600 });
  const sid = randomBytes(32).toString("hex");
  const row = (await admin.query<{ session_ref: string }>(
    `INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, parent_session_ref, tenant_id, case_ref, grant_ref, expires_at, idle_seconds)
     VALUES ($1, 'CASE', $2, $3, $4, $5, $6, $7, now() + interval '1 hour', 600) RETURNING session_ref`,
    [sha(sid), principal, assertion, parent.sessionRef, tenantId, caseRef, grantRef],
  )).rows[0]!;
  return { sid, sessionRef: row.session_ref, grantRef };
}

async function seedConsumedAssertion(admin: Client, principal: string, kind: string, target: string | null): Promise<string> {
  const ref = randomUUID();
  const row = (await admin.query<{ assertion_ref: string }>(
    `INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, target_ref_hash, principal_ref, decision, assertion_hash, auth_time, expires_at, consumed_at)
     VALUES ($1, $2, $3, $4, $5, 'ATTESTED', $6, now(), now() + interval '5 minutes', now()) RETURNING assertion_ref`,
    [ref, kind, sha(`state-${ref}`), target, principal, sha(`assertion-${ref}`)],
  )).rows[0]!;
  return row.assertion_ref;
}
