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

/** Sesion CASE viva (con su grant) colgada de `parent`. */
export async function seedCaseSession(admin: Client, principal: string, parent: SeededSession, caseRef: string, tenantId: string, opts: { grantSeconds?: number } = {}): Promise<SeededSession & { grantRef: string }> {
  const assertion = await seedConsumedAssertion(admin, principal, "LOGIN_CASE", sha(caseRef));
  const grant = (await admin.query<{ grant_ref: string }>(
    "INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4)) RETURNING grant_ref",
    [tenantId, caseRef, principal, opts.grantSeconds ?? 3600],
  )).rows[0]!;
  const sid = randomBytes(32).toString("hex");
  const row = (await admin.query<{ session_ref: string }>(
    `INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, parent_session_ref, tenant_id, case_ref, grant_ref, expires_at, idle_seconds)
     VALUES ($1, 'CASE', $2, $3, $4, $5, $6, $7, now() + interval '1 hour', 600) RETURNING session_ref`,
    [sha(sid), principal, assertion, parent.sessionRef, tenantId, caseRef, grant.grant_ref],
  )).rows[0]!;
  return { sid, sessionRef: row.session_ref, grantRef: grant.grant_ref };
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
