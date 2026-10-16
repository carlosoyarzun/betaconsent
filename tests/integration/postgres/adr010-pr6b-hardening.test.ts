// Gobierna: ADR-010 rev. 5 PR-6b, revision de seguridad (APROBADO CON P2, 2026-10-15): P-53 solo LOGIN_PLATFORM, locks de P-51/P-53 (carrera), un evento de limite por ventana, P-48 con fallos de
// acr/auth_time con firma valida (F-PR6-33); db/migrations/0051.
// TEST-CNS-1512: carrera: N inicios concurrentes de STEP_UP del mismo operador no superan P-51; N LOGIN_PLATFORM concurrentes no superan P-53; P-53 no aplica a LOGIN_CASE ni STEP_UP.
// TEST-CNS-1515: P-48 cuenta tambien REJECTED/INVALID_CLAIMS con sub_hmac (resuelto, no persistido); un solo evento de limite por ventana aunque haya muchos rechazos.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.

import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { stepUpSid } from "../../helpers/step-up-enqueue.ts";
import { seedPlatformSession } from "../../helpers/pg-platform-session.ts";
import { pgTest } from "./harness.ts";

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const P = (label: string): string => fixtureUuid(`pr6b-hard-${label}`);
const PKCE = "C".repeat(64);

async function call<T = Record<string, unknown>>(client: Client, principal: string | null, sql: string, params: unknown[] = [], sid: string | null = null): Promise<T[]> {
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

async function seedOperator(admin: Client, principal: string, role = "PLATFORM"): Promise<string> {
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, $2, 'PENDING', $3)", [principal, role, P("req")]);
  await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $3, approved_at = now() WHERE principal_ref = $1 AND platform_role = $2", [principal, role, P("apr")]);
  const sub = sha(`sub-${principal}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [principal, sub]);
  return sub;
}

const beginLogin = async (c: Client, kind: string, principal: string | null, maxAwaiting: number | null, target: string | null = null, sid: string | null = null): Promise<string | null> =>
  (await call<{ r: string | null }>(c, principal, "SELECT platform.begin_oidc_authorization($1, $2, $3, $4, $5, 300, $6, NULL, NULL) AS r", [kind, sha(randomUUID()), sha(randomUUID()), PKCE, target, maxAwaiting], sid))[0]?.r ?? null;

pgTest("TEST-CNS-1512 pg carrera: N inicios concurrentes no superan P-51 (por operador) ni P-53 (global); P-53 solo frena LOGIN_PLATFORM", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const clients: Client[] = [];
  for (let i = 0; i < 6; i++) clients.push(await ctx.connectAs("platform_rw"));
  const B = P("1512-b");
  await seedOperator(admin, B, "RIGHTS_OPERATOR");
  const A = P("1512-a");
  await seedOperator(admin, A);

  // P-51: 6 nonces del mismo operador; 6 inicios concurrentes con max = 2 => exactamente 2.
  const nonces: string[] = [];
  for (let i = 0; i < 6; i++) nonces.push((await call<{ n: string }>(clients[0]!, A, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [`${P(`t-${i}`)}:CONTEXT_OWNER`]))[0]!.n);
  const stepUp = async (c: Client, nonce: string): Promise<string | null> =>
    call<{ r: string | null }>(c, A, "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, 300, NULL, 2, 600) AS r", [sha(randomBytes(24).toString("base64url")), sha(nonce), PKCE], await stepUpSid(A)).then((r) => r[0]?.r ?? null);
  const results = await Promise.all(nonces.map((n, i) => stepUp(clients[i]!, n)));
  assert.equal(results.filter((r) => r !== null).length, 2, "P-51: exactamente 2 de 6 concurrentes");
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'STEP_UP_BEGIN' AND principal_ref = $1", [A])).rows[0]!.n), 2);
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'LIMIT_EXCEEDED' AND limit_kind = 'P-51' AND principal_ref = $1", [A])).rows[0]!.n), 1, "un solo evento de limite por ventana");

  // P-53: cupo para 2 mas; 6 LOGIN_PLATFORM concurrentes => exactamente 2.
  const awaiting = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.oidc_exchange WHERE status = 'AWAITING_CALLBACK' AND expires_at > now()")).rows[0]!.n);
  const cap = awaiting + 2;
  const logins = await Promise.all(clients.map((c) => beginLogin(c, "LOGIN_PLATFORM", null, cap)));
  assert.equal(logins.filter((r) => r !== null).length, 2, "P-53: exactamente 2 de 6 concurrentes");
  // Con el tope excedido, mas rechazos no generan mas eventos (uno por ventana).
  for (let i = 0; i < 4; i++) assert.equal(await beginLogin(clients[0]!, "LOGIN_PLATFORM", null, cap), null);
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'LIMIT_EXCEEDED' AND limit_kind = 'P-53'")).rows[0]!.n), 1);

  // P-53 NO aplica a LOGIN_CASE ni a STEP_UP (exigen principal con rol; un flood anonimo no debe bloquearlos).
  const sessB = await seedPlatformSession(admin, B);
  assert.ok(await beginLogin(clients[0]!, "LOGIN_CASE", null, 1, sha("caso"), sessB.sid), "LOGIN_CASE entra aun con P-53 excedido");
  const n7 = (await call<{ n: string }>(clients[0]!, A, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [`${P("t-x")}:CONTEXT_OWNER`]))[0]!.n;
  const other = P("1512-c");
  await seedOperator(admin, other);
  const n8 = (await call<{ n: string }>(clients[0]!, other, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [`${P("t-y")}:CONTEXT_OWNER`]))[0]!.n;
  void n7;
  const su = (await call<{ r: string | null }>(clients[0]!, other, "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, 300, 1, 5, 600) AS r", [sha(randomUUID()), sha(n8), PKCE], await stepUpSid(other)))[0]?.r;
  assert.ok(typeof su === "string", "STEP_UP entra aun con P-53 excedido");
});

pgTest("TEST-CNS-1515 pg: P-48 cuenta fallos REJECTED/INVALID_CLAIMS con sub_hmac (principal resuelto, hmac no persistido); sub desconocido no cuenta; un solo evento de limite por ventana", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("1515-a");
  const subA = await seedOperator(admin, A);
  const claim = async (ref: string): Promise<void> => {
    for (let i = 0; i < 100; i++) {
      const rows = await call<{ o_exchange_ref: string }>(verifier, null, "SELECT o_exchange_ref FROM platform.claim_oidc_exchange(60)");
      if (rows.length === 0 || rows.some((r) => r.o_exchange_ref === ref)) return;
    }
  };
  const flow = async (): Promise<string> => {
    const state = randomBytes(24).toString("base64url");
    const ref = (await call<{ r: string }>(platform, null, "SELECT platform.begin_oidc_authorization('LOGIN_PLATFORM', $1, $2, $3, NULL, 300, NULL, NULL, NULL) AS r", [sha(state), sha(randomUUID()), PKCE]))[0]!.r;
    await call(platform, null, "SELECT platform.complete_oidc_callback($1, 'code-1')", [state]);
    await claim(ref);
    return ref;
  };
  const reject = async (sub: string | null): Promise<void> => {
    const ref = await flow();
    const ok = (await call<{ ok: boolean }>(verifier, null, "SELECT platform.record_login_assertion($1::uuid, 'REJECTED', 'INVALID_CLAIMS', $2, $3::smallint, NULL, NULL, NULL, NULL, NULL, NULL, NULL) AS ok", [ref, sub, sub === null ? null : 1]))[0]?.ok;
    assert.equal(ok, false);
  };
  const attempt = async (): Promise<{ ok: boolean; reason: string | null }> => {
    const ref = await flow();
    const ok = (await call<{ ok: boolean }>(verifier, null, "SELECT platform.record_login_assertion($1::uuid, 'ATTESTED', NULL, $2, 1::smallint, $3, now(), 'urn:t', ARRAY['pwd'], 3, 900, 300) AS ok", [ref, subA, sha(randomUUID())]))[0]!.ok;
    return { ok, reason: (await admin.query<{ r: string | null }>("SELECT reason_code AS r FROM platform.login_assertion WHERE exchange_ref = $1", [ref])).rows[0]?.r ?? null };
  };
  // Un fallo con sub desconocido o sin sub no cuenta por identidad.
  await reject(null);
  await reject(sha("desconocido"));
  assert.deepEqual(await attempt(), { ok: true, reason: null });
  // Tres fallos con firma valida (acr/auth_time) del mismo principal: la fila guarda el principal, NO el sub_hmac.
  for (let i = 0; i < 3; i++) await reject(subA);
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.login_assertion WHERE principal_ref = $1 AND decision = 'REJECTED' AND reason_code = 'INVALID_CLAIMS'", [A])).rows[0]!.n), 3);
  for (const t of ["login_assertion", "session_event", "oidc_exchange"]) assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [subA])).rowCount, 0, `${t} no contiene el sub_hmac`);
  // Con P-48 = 3: el siguiente intento (legitimo) queda RATE_LIMITED; varios intentos seguidos generan UN solo evento de limite en la ventana.
  assert.deepEqual(await attempt(), { ok: false, reason: "RATE_LIMITED" });
  assert.deepEqual(await attempt(), { ok: false, reason: "RATE_LIMITED" });
  assert.deepEqual(await attempt(), { ok: false, reason: "RATE_LIMITED" });
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'LIMIT_EXCEEDED' AND limit_kind = 'P-48' AND principal_ref = $1", [A])).rows[0]!.n), 1);
});
