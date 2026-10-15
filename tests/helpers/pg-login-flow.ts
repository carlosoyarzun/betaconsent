// Gobierna: ADR-010 rev. 5 §5.2 pasos 1-4 y 6 (PR-6b/6c), db/migrations/0050-0054. Helper de TESTS (no es codigo de produccion): recorre en SQL, con los roles reales (platform_rw e integrity_verifier),
// el camino begin -> callback -> canje del verifier -> record_login_assertion hasta dejar una asercion LOGIN ATTESTED lista para open_platform_session / open_case_session. Solo sinteticos.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";

export const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const PKCE = "D".repeat(64);

export async function call<T = Record<string, unknown>>(client: Client, principal: string | null, sql: string, params: unknown[] = [], sid: string | null = null): Promise<T[]> {
  await client.query("BEGIN");
  try {
    if (principal !== null) await client.query("SELECT set_config('app.principal_ref', $1, true)", [principal]);
    if (sid !== null) await client.query("SELECT set_config('app.session_sid', $1, true)", [sid]);
    const r = await client.query(sql, params);
    await client.query("COMMIT");
    return r.rows as T[];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

/** Operador sintetico con un rol ACTIVE (doble control sembrado por superusuario) y su identidad (sub_hmac); devuelve el sub_hmac. */
export async function seedOperator(admin: Client, principal: string, role: string, version = 1): Promise<string> {
  const req = createHash("sha256").update(`req-${principal}`).digest("hex").slice(0, 32);
  const reqRef = `${req.slice(0, 8)}-${req.slice(8, 12)}-4${req.slice(13, 16)}-8${req.slice(17, 20)}-${req.slice(20, 32)}`;
  const aprRef = reqRef.replace(/^./, (c) => (c === "a" ? "b" : "a"));
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, approver_class, status, requested_by_ref) VALUES ($1, $2, CASE WHEN $2 = 'APPROVER' THEN 'SECURITY' END, 'PENDING', $3)", [principal, role, reqRef]);
  await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $3, approved_at = now() WHERE principal_ref = $1 AND platform_role = $2", [principal, role, aprRef]);
  const subHmac = sha(`sub-${principal}-${version}`);
  const known = await admin.query("SELECT 1 FROM platform.principal_identity WHERE principal_ref = $1 AND key_version = $2", [principal, version]);
  if (known.rowCount === 0) await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, $3)", [principal, subHmac, version]);
  return subHmac;
}

export interface LoginFlow {
  readonly ref: string;
  readonly state: string;
}

/**
 * Deja ATTESTED una asercion LOGIN del operador cuyo sub_hmac es `subHmac`. Para LOGIN_CASE hay que pasar la sesion PLATFORM (`sid`) y el hash del caso. Devuelve null si `begin` o `record_login_assertion`
 * denegaron (el motivo queda en la base). `authTime` por defecto: ahora.
 */
export async function loginFlow(
  clients: { platform: Client; verifier: Client },
  kind: "LOGIN_PLATFORM" | "LOGIN_CASE",
  subHmac: string,
  opts: { sid?: string; targetRefHash?: string; authTime?: Date } = {},
): Promise<LoginFlow | null> {
  const state = randomBytes(24).toString("base64url");
  const binding = sha(randomUUID());
  const ref = (await call<{ r: string | null }>(
    clients.platform, null, "SELECT platform.begin_oidc_authorization($1, $2, $3, $4, $5, 300, NULL, NULL, NULL) AS r",
    [kind, sha(state), binding, PKCE, kind === "LOGIN_CASE" ? (opts.targetRefHash ?? null) : null], kind === "LOGIN_CASE" ? (opts.sid ?? null) : null,
  ))[0]?.r;
  if (typeof ref !== "string") return null;
  const done = (await call<{ r: string | null }>(clients.platform, null, "SELECT platform.complete_oidc_callback($1, $2) AS r", [state, `code-${randomUUID()}`]))[0]?.r;
  if (done !== ref) return null;
  // La cola de canje es global: se toma hasta encontrar la propia (el lease dura 60 s).
  let claimed = false;
  for (let i = 0; i < 200 && !claimed; i++) {
    const rows = await call<{ o_exchange_ref: string }>(clients.verifier, null, "SELECT o_exchange_ref FROM platform.claim_oidc_exchange(60)");
    if (rows.length === 0) break;
    claimed = rows.some((r) => r.o_exchange_ref === ref);
  }
  if (!claimed) return null;
  const ok = (await call<{ ok: boolean }>(
    clients.verifier, null, "SELECT platform.record_login_assertion($1::uuid, 'ATTESTED', NULL, $2, 1::smallint, $3, $4::timestamptz, 'urn:synthetic:test-mfa', ARRAY['pwd']::text[], 5, 900, 300) AS ok",
    [ref, subHmac, sha(`token-${ref}`), (opts.authTime ?? new Date()).toISOString()],
  ))[0]?.ok;
  return ok === true ? { ref, state } : null;
}
