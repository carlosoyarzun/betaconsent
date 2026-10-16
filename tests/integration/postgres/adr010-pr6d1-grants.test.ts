// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (principal del nonce desde la sesion validada), §5.4 (P-51, P-52), §6 (grants P6-3), §10 filas 6c/6d; GRD-RC-10 y
// GRD-RC-12; SEC-CNS-006 rev. 5 §1 (P-23, P-37, P-51, P-52); F-PR6-39 (nota STEP_UP), F-PR6-40; db/migrations/0059-0063.
// TEST-CNS-1650: camino real: issue_step_up_nonce (principal de la sesion) -> begin STEP_UP -> callback -> claim -> record_assertion -> request_grant consume el nonce en la misma tx; P-37 (1 h); evento.
// TEST-CNS-1651: approve_grant: aprobador distinto del solicitante, sin step-up rechazado, valid_seconds (defecto 2 h, > 4 h rechazado), doble aprobacion = grant con aprobador; un solo grant por solicitud.
// TEST-CNS-1652: solicitud vencida no es aprobable y se registra (REQUEST_EXPIRED); tampoco se emite nonce para ella.
// TEST-CNS-1653: aserciones de step-up: reutilizada, de otra accion, de otro destino, de otro operador o rancia (P-52) = rechazadas (STEP_UP_REJECTED).
// TEST-CNS-1654: P-51 concurrente: N confirmaciones fallidas concurrentes del mismo operador no superan el limite; un solo evento LIMIT_EXCEEDED por ventana.
// TEST-CNS-1655: tenant y caso ajenos: el tenant sale del caso REAL; caso inexistente/cerrado/ambiguo rechazado; open_case_session y validate_session re-verifican.
// TEST-CNS-1656: sesion CASE solo con grant vigente (antes de aprobar: NO_GRANT; tras aprobar: abre; grant revocado: deja de validar).
// TEST-CNS-1657: privilegios: ACL exacta, internas sin EXECUTE, sin principal ni tenant como parametro, grant solo desde solicitud aprobada (trigger + FK), sin acceso de tabla.
// TEST-CNS-1658: begin STEP_UP ya no toma el principal de app.principal_ref: sin sesion o con principal declarado distinto = DENY.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos. Los tests de un archivo comparten base: todo se filtra por refs propias.

import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { call, loginFlow, seedOperator } from "../../helpers/pg-login-flow.ts";
import { seedApprovedGrant, seedCaseSession, seedPlatformSession, seedRightsCase } from "../../helpers/pg-platform-session.ts";
import { pgTest } from "./harness.ts";
import type { PgRole, PgTestContext } from "./harness.ts";

const shared = new Map<string, Promise<Client>>();
const connect = (ctx: PgTestContext, role: PgRole): Promise<Client> => {
  const key = `${ctx.dbName}|${role}`;
  let c = shared.get(key);
  if (c === undefined) { c = ctx.connectAs(role); shared.set(key, c); }
  return c;
};

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const P = (l: string): string => fixtureUuid(`pr6d1-principal-${l}`);
const TENANT = fixtureUuid("pr6d1-tenant");
const OTHER_TENANT = fixtureUuid("pr6d1-tenant-other");
const PKCE = "E".repeat(64);
const P51 = [5, 600] as const;

interface Op { principal: string; sub: string; sid: string }
async function operator(admin: Client, label: string, role: string): Promise<Op> {
  const principal = P(label);
  const sub = await seedOperator(admin, principal, role);
  const { sid } = await seedPlatformSession(admin, principal, { absoluteSeconds: 14400, idleSeconds: 900 });
  return { principal, sub, sid };
}

const issue = async (platform: Client, sid: string, action: string, target: string): Promise<string | null> =>
  (await call<{ n: string | null }>(platform, null, "SELECT platform.issue_step_up_nonce($1, $2, 300) AS n", [action, target], sid))[0]?.n ?? null;

const requestGrant = async (platform: Client, sid: string, caseRef: string, p51: readonly [number, number] = P51): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.request_grant($1, $2, $3) AS r", [caseRef, p51[0], p51[1]], sid))[0]?.r ?? null;

const approveGrant = async (platform: Client, sid: string, caseRef: string, request: string, seconds: number | null = null, p51: readonly [number, number] = P51): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.approve_grant($1, $2::uuid, $3, $4, $5) AS r", [caseRef, request, seconds, p51[0], p51[1]], sid))[0]?.r ?? null;

/** Siembra (superusuario) un nonce de step-up ATTESTED con su aserción del IdP (auth_time = hace `authAgoSeconds`): stand-in del verifier para las reglas de consumo. */
async function seedAttestedStepUp(admin: Client, principal: string, action: string, target: string, authAgoSeconds = 0): Promise<string> {
  const hash = sha(randomUUID());
  await admin.query(
    `INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at) VALUES ($1, 'PLATFORM', NULL, $2, $3, $4, now() + interval '5 minutes')`,
    [hash, action, sha(target), principal],
  );
  await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE nonce_hash = $1", [hash]);
  await admin.query(
    `INSERT INTO platform.grant_assertion (exchange_ref, binding, principal_ref, decision, sub_hmac, assertion_hash, auth_time) VALUES ($1, $2, $3, 'ATTESTED', $4, $5, now() - make_interval(secs => $6))`,
    [randomUUID(), hash, principal, sha(`sub-${principal}`), sha(randomUUID()), authAgoSeconds],
  );
  return hash;
}

const events = async (admin: Client, principal: string, type?: string): Promise<Array<{ event_type: string; reason_code: string | null }>> =>
  (await admin.query<{ event_type: string; reason_code: string | null }>(
    "SELECT event_type, reason_code FROM platform.session_event WHERE principal_ref = $1 AND ($2::text IS NULL OR event_type = $2) ORDER BY at, event_ref", [principal, type ?? null],
  )).rows;

const consumed = async (admin: Client, hash: string): Promise<boolean> =>
  (await admin.query<{ c: boolean }>("SELECT consumed_at IS NOT NULL AS c FROM platform.action_nonce WHERE nonce_hash = $1", [hash])).rows[0]!.c;

/** Camino real hasta ATTESTED: issue_step_up_nonce -> begin STEP_UP (sid) -> callback -> claim -> record_assertion. Devuelve el hash del nonce. */
async function realStepUp(clients: { platform: Client; verifier: Client }, op: Op, action: string, target: string): Promise<string> {
  const nonce = (await issue(clients.platform, op.sid, action, target))!;
  assert.ok(typeof nonce === "string" && nonce.length >= 32, "nonce emitido");
  const state = randomBytes(24).toString("base64url");
  const ref = (await call<{ r: string | null }>(clients.platform, null, "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, 300, NULL, $4, $5) AS r", [sha(state), sha(nonce), PKCE, P51[0], P51[1]], op.sid))[0]?.r;
  assert.ok(typeof ref === "string", "begin STEP_UP");
  assert.equal((await call<{ r: string | null }>(clients.platform, null, "SELECT platform.complete_oidc_callback($1, $2) AS r", [state, `code-${randomUUID()}`]))[0]?.r, ref);
  let claimed = false;
  for (let i = 0; i < 200 && !claimed; i++) {
    const rows = await call<{ o_exchange_ref: string }>(clients.verifier, null, "SELECT o_exchange_ref FROM platform.claim_oidc_exchange(30)");
    if (rows.length === 0) break;
    claimed = rows.some((r) => r.o_exchange_ref === ref);
  }
  assert.ok(claimed, "el verifier toma la solicitud");
  const ok = (await call<{ ok: boolean }>(clients.verifier, null, "SELECT platform.record_assertion($1::uuid, 'ATTESTED', NULL, $2, $3, now(), 'urn:synthetic:acr', ARRAY['pwd']) AS ok", [ref, op.sub, sha(`token-${ref}`)]))[0]?.ok;
  assert.equal(ok, true, "atestado");
  return sha(nonce);
}

pgTest("TEST-CNS-1650 pg: camino real de step-up (principal de la sesion) y request_grant consume el nonce en la misma tx; P-37 (1 h); evento sin IP", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const R = await operator(admin, "1650-r", "RIGHTS_OPERATOR");
  const CASE = fixtureUuid("pr6d1-1650-case");
  await seedRightsCase(admin, TENANT, CASE);

  // Sin step-up: rechazado, con evidencia (STEP_UP_REJECTED + GRANT_REJECTED), sin solicitud.
  assert.equal(await requestGrant(platform, R.sid, CASE), null);
  assert.deepEqual((await events(admin, R.principal, "STEP_UP_REJECTED")).map((e) => e.reason_code), ["STEP_UP_MISSING"]);
  assert.deepEqual((await events(admin, R.principal, "GRANT_REJECTED")).map((e) => e.reason_code), ["STEP_UP_MISSING"]);
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_request WHERE operator_principal_ref = $1", [R.principal])).rowCount, 0);

  // Camino real.
  const hash = await realStepUp({ platform, verifier }, R, "REQUEST_GRANT", CASE);
  assert.equal(await consumed(admin, hash), false, "atestado pero no consumido hasta la accion");
  const request = await requestGrant(platform, R.sid, CASE);
  assert.ok(typeof request === "string");
  assert.equal(await consumed(admin, hash), true, "el nonce se consume en la misma tx que el efecto");
  const row = (await admin.query<{ tenant_id: string; operator_principal_ref: string; requested_by_ref: string; status: string; secs: string }>(
    "SELECT tenant_id, operator_principal_ref, requested_by_ref, status, extract(epoch FROM expires_at - requested_at)::int::text AS secs FROM platform.grant_request WHERE request_ref = $1", [request])).rows[0]!;
  assert.deepEqual({ ...row, secs: Number(row.secs) }, { tenant_id: TENANT, operator_principal_ref: R.principal, requested_by_ref: R.principal, status: "PENDING", secs: 3600 });
  assert.deepEqual((await events(admin, R.principal, "GRANT_REQUESTED")).length, 1);
  // El nonce es de un solo uso: otra solicitud (tras vencer la pendiente no aplica) no reusa el consumido; la pendiente vigente bloquea una segunda.
  await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CASE);
  assert.equal(await requestGrant(platform, R.sid, CASE), null, "ya hay una solicitud pendiente vigente para (caso, operador)");
  assert.ok((await events(admin, R.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "REQUEST_PENDING"));
  // Ningun evento de sesion lleva IP ni sub_hmac: no existen columnas para ello.
  assert.equal((await admin.query("SELECT 1 FROM information_schema.columns WHERE table_schema = 'platform' AND table_name = 'session_event' AND column_name ~ '^(ip|ip_.*|.*_ip|sub_hmac)$'")).rowCount, 0);
});

pgTest("TEST-CNS-1651 pg: approve_grant: aprobador distinto del solicitante, step-up obligatorio, defecto 2 h, > 4 h rechazado, un grant por solicitud con aprobador", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const R = await operator(admin, "1651-r", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1651-a", "APPROVER");
  const B = await operator(admin, "1651-b", "APPROVER");
  const C1 = fixtureUuid("pr6d1-1651-c1");
  const C2 = fixtureUuid("pr6d1-1651-c2");
  const C3 = fixtureUuid("pr6d1-1651-c3");
  for (const c of [C1, C2, C3]) await seedRightsCase(admin, TENANT, c);
  const req = async (c: string): Promise<string> => {
    await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", c);
    return (await requestGrant(platform, R.sid, c))!;
  };
  const r1 = await req(C1);
  assert.ok(typeof r1 === "string");

  // Sin step-up: aprobacion rechazada (GRD-RC-12), sin grant, la solicitud sigue PENDING.
  assert.equal(await approveGrant(platform, A.sid, C1, r1), null);
  assert.ok((await events(admin, A.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "STEP_UP_MISSING"));
  assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [r1])).rowCount, 0);
  assert.equal((await admin.query<{ status: string }>("SELECT status FROM platform.grant_request WHERE request_ref = $1", [r1])).rows[0]!.status, "PENDING");

  // Aprobador = solicitante: SELF_APPROVAL (el operador con rol APPROVER tambien); el nonce ni siquiera se emite.
  const both = await operator(admin, "1651-both", "RIGHTS_OPERATOR");
  await seedOperator(admin, both.principal, "APPROVER");
  await seedAttestedStepUp(admin, both.principal, "REQUEST_GRANT", C2);
  const rSelf = (await requestGrant(platform, both.sid, C2))!;
  assert.ok(typeof rSelf === "string");
  assert.equal(await issue(platform, both.sid, "APPROVE_GRANT", rSelf), null, "no se emite el nonce de aprobacion al propio solicitante");
  await seedAttestedStepUp(admin, both.principal, "APPROVE_GRANT", rSelf);
  assert.equal(await approveGrant(platform, both.sid, C2, rSelf), null, "aprobador = solicitante");
  assert.ok((await events(admin, both.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "SELF_APPROVAL"));
  assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [rSelf])).rowCount, 0);

  // Un RIGHTS_OPERATOR no aprueba (NO_ROLE).
  assert.equal(await approveGrant(platform, R.sid, C1, r1), null);
  assert.ok((await events(admin, R.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "NO_ROLE"));

  // valid_seconds: > 4 h (P-23) rechazado SIN consumir el nonce; 4 h exactas ok; defecto 2 h.
  const nonceA = await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", r1);
  assert.equal(await approveGrant(platform, A.sid, C1, r1, 14401), null, "grant > 4 h");
  assert.equal(await approveGrant(platform, A.sid, C1, r1, 59), null, "grant sin vida util");
  assert.equal(await consumed(admin, nonceA), false);
  assert.ok((await events(admin, A.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "INVALID_INPUT"));
  const g1 = await approveGrant(platform, A.sid, C1, r1);
  assert.ok(typeof g1 === "string");
  assert.equal(await consumed(admin, nonceA), true);
  const grant = (await admin.query<{ secs: string; approved_by_ref: string; tenant_id: string; operator_principal_ref: string; request_ref: string }>(
    "SELECT extract(epoch FROM expires_at - attested_at)::int::text AS secs, approved_by_ref, tenant_id, operator_principal_ref, request_ref FROM platform.rights_case_grant WHERE grant_ref = $1", [g1])).rows[0]!;
  assert.deepEqual({ ...grant, secs: Number(grant.secs) }, { secs: 7200, approved_by_ref: A.principal, tenant_id: TENANT, operator_principal_ref: R.principal, request_ref: r1 });
  assert.deepEqual((await admin.query<{ status: string; approved_by_ref: string }>("SELECT status, approved_by_ref FROM platform.grant_request WHERE request_ref = $1", [r1])).rows[0], { status: "APPROVED", approved_by_ref: A.principal });
  assert.equal((await events(admin, A.principal, "GRANT_APPROVED")).length, 1);
  // Un solo grant por solicitud: B (con step-up valido) no puede aprobar de nuevo.
  await seedAttestedStepUp(admin, B.principal, "APPROVE_GRANT", r1);
  assert.equal(await approveGrant(platform, B.sid, C1, r1), null);
  assert.ok((await events(admin, B.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "REQUEST_NOT_PENDING"));

  // 4 h exactas aceptadas.
  const r3 = await req(C3);
  await seedAttestedStepUp(admin, B.principal, "APPROVE_GRANT", r3);
  const g3 = (await approveGrant(platform, B.sid, C3, r3, 14400))!;
  assert.ok(typeof g3 === "string");
  assert.equal(Number((await admin.query<{ s: string }>("SELECT extract(epoch FROM expires_at - attested_at)::int::text AS s FROM platform.rights_case_grant WHERE grant_ref = $1", [g3])).rows[0]!.s), 14400);
});

pgTest("TEST-CNS-1652 pg: una solicitud vencida (P-37) no es aprobable y se registra; tampoco se emite nonce", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const R = await operator(admin, "1652-r", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1652-a", "APPROVER");
  const CASE = fixtureUuid("pr6d1-1652-case");
  await seedRightsCase(admin, TENANT, CASE);
  const old = (await admin.query<{ request_ref: string }>(
    `INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, requested_at, expires_at) VALUES ($1, $2, $3, $3, now() - interval '2 hours', now() - interval '1 hour') RETURNING request_ref`,
    [TENANT, CASE, R.principal])).rows[0]!.request_ref;
  assert.equal(await issue(platform, A.sid, "APPROVE_GRANT", old), null, "no se emite nonce para una solicitud vencida");
  const nonce = await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", old);
  assert.equal(await approveGrant(platform, A.sid, CASE, old), null);
  const ev = (await admin.query<{ reason_code: string; request_ref: string; peer_principal_ref: string }>(
    "SELECT reason_code, request_ref, peer_principal_ref FROM platform.session_event WHERE principal_ref = $1 AND event_type = 'GRANT_REJECTED'", [A.principal])).rows;
  assert.deepEqual(ev, [{ reason_code: "REQUEST_EXPIRED", request_ref: old, peer_principal_ref: R.principal }], "la vencida se registra");
  assert.equal(await consumed(admin, nonce), false, "el nonce no se quema");
  assert.equal((await admin.query<{ status: string }>("SELECT status FROM platform.grant_request WHERE request_ref = $1", [old])).rows[0]!.status, "PENDING");
  assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [old])).rowCount, 0);
});

pgTest("TEST-CNS-1653 pg: aserciones de step-up reutilizada, de otra accion, de otro destino, de otro operador o rancia (P-52) son rechazadas", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const R = await operator(admin, "1653-r", "RIGHTS_OPERATOR");
  const R2 = await operator(admin, "1653-r2", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1653-a", "APPROVER");
  const CX = fixtureUuid("pr6d1-1653-cx");
  const CY = fixtureUuid("pr6d1-1653-cy");
  await seedRightsCase(admin, TENANT, CX);
  await seedRightsCase(admin, TENANT, CY);
  const rejections = async (p: string): Promise<number> => (await events(admin, p, "STEP_UP_REJECTED")).length;

  // Otra accion: una aserción APPROVE_GRANT no sirve para request_grant.
  await seedAttestedStepUp(admin, R.principal, "APPROVE_GRANT", CX);
  assert.equal(await requestGrant(platform, R.sid, CX), null);
  // Otro destino: la de CX no sirve para CY.
  const nx = await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CX);
  assert.equal(await requestGrant(platform, R.sid, CY), null);
  assert.equal(await consumed(admin, nx), false);
  // Otro operador: la aserción de R no la usa R2.
  assert.equal(await requestGrant(platform, R2.sid, CX), null);
  assert.equal(await consumed(admin, nx), false);
  assert.equal(await rejections(R.principal), 2);
  assert.equal(await rejections(R2.principal), 1);
  // Rancia: auth_time hace 6 min (> P-52 = 5 min): ASSERTION_STALE y el nonce no se consume.
  const stale = await seedAttestedStepUp(admin, R2.principal, "REQUEST_GRANT", CY, 360);
  assert.equal(await requestGrant(platform, R2.sid, CY), null);
  assert.ok((await events(admin, R2.principal, "STEP_UP_REJECTED")).some((e) => e.reason_code === "ASSERTION_STALE"));
  assert.equal(await consumed(admin, stale), false);
  // Fresca (hace 4 min, dentro de P-52): acepta y se consume; reutilizada: rechazada.
  const fresh = await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CY, 240);
  const rq = await requestGrant(platform, R.sid, CY);
  assert.ok(typeof rq === "string");
  assert.equal(await consumed(admin, fresh), true);
  const before = await rejections(R.principal);
  // La solicitud pendiente vigente impide otra; se vence artificialmente (superusuario puede mover expires_at? no: es inmutable) -> otro caso para el replay.
  const CZ = fixtureUuid("pr6d1-1653-cz");
  await seedRightsCase(admin, TENANT, CZ);
  assert.equal(await requestGrant(platform, R.sid, CZ), null, "el nonce consumido (de CY) no sirve para otro destino ni se reusa");
  assert.equal(await rejections(R.principal), before + 1);
  // Aprobacion: aserción de otra solicitud no sirve.
  const rq2 = await (async () => { await seedAttestedStepUp(admin, R2.principal, "REQUEST_GRANT", CX); return requestGrant(platform, R2.sid, CX); })();
  assert.ok(typeof rq2 === "string");
  const na = await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rq!);
  assert.equal(await approveGrant(platform, A.sid, CX, rq2!), null, "aserción de otra solicitud");
  assert.equal(await consumed(admin, na), false);
  assert.ok(typeof (await approveGrant(platform, A.sid, CY, rq!)) === "string");
  assert.equal(await consumed(admin, na), true);
});

pgTest("TEST-CNS-1654 pg carrera: N confirmaciones fallidas concurrentes del mismo operador no superan P-51; un solo evento de limite por ventana", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const clients: Client[] = [];
  for (let i = 0; i < 8; i++) clients.push(await ctx.connectAs("platform_rw"));
  try {
    const R = await operator(admin, "1654-r", "RIGHTS_OPERATOR");
    const CASE = fixtureUuid("pr6d1-1654-case");
    await seedRightsCase(admin, TENANT, CASE);
    const max = 3;
    const results = await Promise.all(clients.map((c) => requestGrant(c, R.sid, CASE, [max, 600])));
    assert.ok(results.every((r) => r === null));
    // P2-b: un fallo con conteo >= P-51 es RATE_LIMITED sin otro STEP_UP_REJECTED: exactamente `max` intentos fallidos se registran y el resto es RATE_LIMITED.
    const rejected = (await events(admin, R.principal, "STEP_UP_REJECTED")).length;
    assert.equal(rejected, max, "P-51: ningun conteo supera el limite bajo concurrencia");
    const reasons = (await events(admin, R.principal, "GRANT_REJECTED")).map((e) => e.reason_code);
    assert.equal(reasons.filter((r) => r === "STEP_UP_MISSING").length, max);
    assert.equal(reasons.filter((r) => r === "RATE_LIMITED").length, clients.length - max);
    assert.equal((await events(admin, R.principal, "LIMIT_EXCEEDED")).length, 1, "un solo evento de limite por ventana");
    // Sin configuracion valida de P-51 se rechaza (fail-closed).
    const p = clients[0]!;
    assert.equal((await call<{ r: string | null }>(p, null, "SELECT platform.request_grant($1, NULL, NULL) AS r", [CASE], R.sid))[0]?.r, null);
  } finally {
    for (const c of clients) await c.end();
  }
});

pgTest("TEST-CNS-1655 pg: tenant y caso salen del caso REAL; inexistente, cerrado, ambiguo o de otro tenant rechazados; open_case_session y validate_session re-verifican", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const R = await operator(admin, "1655-r", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1655-a", "APPROVER");
  const GHOST = fixtureUuid("pr6d1-1655-ghost");
  const CLOSED = fixtureUuid("pr6d1-1655-closed");
  const REAL = fixtureUuid("pr6d1-1655-real");
  await seedRightsCase(admin, TENANT, CLOSED, "RESOLVED");
  await seedRightsCase(admin, TENANT, REAL);
  // Caso inexistente / cerrado / mal formado.
  for (const c of [GHOST, CLOSED]) await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", c);
  assert.equal(await requestGrant(platform, R.sid, GHOST), null);
  assert.equal(await requestGrant(platform, R.sid, CLOSED), null);
  assert.equal(await requestGrant(platform, R.sid, "no-es-uuid"), null);
  assert.deepEqual((await events(admin, R.principal, "GRANT_REJECTED")).map((e) => e.reason_code).sort(), ["CASE_CLOSED", "CASE_NOT_FOUND", "INVALID_INPUT"]);
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_request WHERE operator_principal_ref = $1", [R.principal])).rowCount, 0);
  // El tenant de la solicitud sale del caso real, no de la request (no hay parametro de tenant).
  await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", REAL);
  const rq = (await requestGrant(platform, R.sid, REAL))!;
  assert.equal((await admin.query<{ t: string }>("SELECT tenant_id AS t FROM platform.grant_request WHERE request_ref = $1", [rq])).rows[0]!.t, TENANT);
  // Aprobar con el caso equivocado: REQUEST_NOT_FOUND (el caso de la solicitud es otro).
  await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rq);
  assert.equal(await approveGrant(platform, A.sid, CLOSED, rq), null);
  assert.ok((await events(admin, A.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "REQUEST_NOT_FOUND"));

  // open_case_session / validate_session re-verifican: un grant de OTRO tenant para un caso que existe solo en TENANT no abre sesion (CASE_MISMATCH).
  const FOREIGN = fixtureUuid("pr6d1-1655-foreign");
  await seedRightsCase(admin, TENANT, FOREIGN);
  const approver = P("1655-approver-foreign");
  const rqF = (await admin.query<{ request_ref: string }>(
    `INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, expires_at, status, approved_by_ref, approved_at) VALUES ($1, $2, $3, $3, now() + interval '1 hour', 'APPROVED', $4, now()) RETURNING request_ref`,
    [OTHER_TENANT, FOREIGN, R.principal, approver])).rows[0]!.request_ref;
  await admin.query("INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at, request_ref, approved_by_ref) VALUES ($1, $2, $3, now() + interval '1 hour', $4, $5)", [OTHER_TENANT, FOREIGN, R.principal, rqF, approver]);
  const flow = (await loginFlow({ platform, verifier }, "LOGIN_CASE", R.sub, { sid: R.sid, targetRefHash: sha(FOREIGN) }))!;
  assert.ok(flow !== null);
  assert.equal((await call<{ s: string | null }>(platform, null, "SELECT platform.open_case_session($1::uuid, $2, $3, $4, 3600, 600, NULL) AS s", [flow.ref, flow.state, FOREIGN, R.sid]))[0]?.s, null);
  assert.ok((await events(admin, R.principal, "LOGIN_REJECTED")).some((e) => e.reason_code === "CASE_MISMATCH"));
  // Caso AMBIGUO (mismo case_ref en dos tenants): rights_case_of no devuelve filas -> CASE_MISMATCH.
  await seedRightsCase(admin, OTHER_TENANT, FOREIGN);
  const flow2 = (await loginFlow({ platform, verifier }, "LOGIN_CASE", R.sub, { sid: R.sid, targetRefHash: sha(FOREIGN) }))!;
  assert.equal((await call<{ s: string | null }>(platform, null, "SELECT platform.open_case_session($1::uuid, $2, $3, $4, 3600, 600, NULL) AS s", [flow2.ref, flow2.state, FOREIGN, R.sid]))[0]?.s, null);
});

pgTest("TEST-CNS-1656 pg: la sesion CASE solo abre con un grant vigente (antes de aprobar: NO_GRANT; tras aprobar abre; grant revocado deja de validar)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const R = await operator(admin, "1656-r", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1656-a", "APPROVER");
  const CASE = fixtureUuid("pr6d1-1656-case");
  await seedRightsCase(admin, TENANT, CASE);
  const openCase = async (): Promise<string | null> => {
    const f = (await loginFlow({ platform, verifier }, "LOGIN_CASE", R.sub, { sid: R.sid, targetRefHash: sha(CASE) }))!;
    return (await call<{ s: string | null }>(platform, null, "SELECT platform.open_case_session($1::uuid, $2, $3, $4, 3600, 600, NULL) AS s", [f.ref, f.state, CASE, R.sid]))[0]?.s ?? null;
  };
  assert.equal(await openCase(), null, "sin grant");
  assert.ok((await events(admin, R.principal, "LOGIN_REJECTED")).some((e) => e.reason_code === "NO_GRANT"));
  await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CASE);
  const rq = (await requestGrant(platform, R.sid, CASE))!;
  assert.equal(await openCase(), null, "solicitud pendiente no es grant");
  await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rq);
  const grant = (await approveGrant(platform, A.sid, CASE, rq))!;
  assert.ok(typeof grant === "string");
  const sidCase = await openCase();
  assert.match(sidCase ?? "", /^[0-9a-f]{64}$/);
  const s = (await admin.query<{ tenant_id: string; ok: boolean }>(
    "SELECT s.tenant_id, s.expires_at <= g.expires_at AS ok FROM platform.platform_session s JOIN platform.rights_case_grant g ON g.grant_ref = s.grant_ref WHERE s.sid_hash = $1", [sha(sidCase!)])).rows[0]!;
  assert.deepEqual(s, { tenant_id: TENANT, ok: true });
  const valid = async (): Promise<number> => (await call(platform, null, "SELECT * FROM platform.validate_session($1, 'CASE')", [sidCase!])).length;
  assert.equal(await valid(), 1);
  await admin.query("UPDATE platform.rights_case_grant SET revoked_at = now() WHERE grant_ref = $1", [grant]);
  assert.equal(await valid(), 0, "grant revocado: la sesion CASE deja de validar");
  // Un grant sembrado con tenant ajeno al del caso real deja de validar la sesion (re-verificacion de tenant en cada llamada).
  const R2 = await operator(admin, "1656-r2", "RIGHTS_OPERATOR");
  const parent = await seedPlatformSession(admin, R2.principal);
  const C2 = fixtureUuid("pr6d1-1656-case2");
  await seedRightsCase(admin, TENANT, C2);
  const cs = await seedCaseSession(admin, R2.principal, parent, C2, TENANT);
  assert.equal((await call(platform, null, "SELECT * FROM platform.validate_session($1, 'CASE')", [cs.sid])).length, 1);
  await seedApprovedGrant(admin, { tenantId: TENANT, caseRef: fixtureUuid("pr6d1-1656-other"), operator: R2.principal });
  await seedRightsCase(admin, OTHER_TENANT, C2); // ahora el case_ref es ambiguo entre dos tenants
  assert.equal((await call(platform, null, "SELECT * FROM platform.validate_session($1, 'CASE')", [cs.sid])).length, 0, "caso ambiguo: la sesion no valida");
});

pgTest("TEST-CNS-1657 pg: privilegios de step-up y grants: ACL exacta, internas sin EXECUTE, sin principal ni tenant como parametro, grant solo desde solicitud aprobada, sin acceso de tabla", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const app = await connect(ctx, "app_rw");
  const worker = await connect(ctx, "worker");
  const verifier = await connect(ctx, "integrity_verifier");
  const acl = async (fn: string): Promise<string> => (await admin.query<{ r: string }>(
    `SELECT COALESCE(string_agg(DISTINCT pg_get_userbyid(a.grantee), ',' ORDER BY pg_get_userbyid(a.grantee)), '') AS r FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       LEFT JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a ON a.grantee <> p.proowner WHERE n.nspname = 'platform' AND p.proname = $1`, [fn])).rows[0]!.r;
  for (const fn of ["issue_step_up_nonce", "request_grant", "approve_grant"]) assert.equal(await acl(fn), "platform_rw", fn);
  for (const fn of ["session_principal", "rights_case_of", "consume_step_up", "rights_case_grant_insert_guard"]) assert.equal(await acl(fn), "", fn);
  for (const c of [app, worker, verifier]) {
    await assert.rejects(c.query("SELECT platform.request_grant($1, 5, 600)", [fixtureUuid("x")]), (e) => codeOf(e) === "42501");
    await assert.rejects(c.query("SELECT platform.approve_grant($1, $2::uuid, NULL, 5, 600)", [fixtureUuid("x"), randomUUID()]), (e) => codeOf(e) === "42501");
    await assert.rejects(c.query("SELECT platform.issue_step_up_nonce('REQUEST_GRANT', $1, 60)", [fixtureUuid("x")]), (e) => codeOf(e) === "42501");
  }
  await assert.rejects(platform.query("SELECT platform.consume_step_up($1, 'REQUEST_GRANT', $1, 5, 600)", [P("x")]), (e) => codeOf(e) === "42501");
  await assert.rejects(platform.query("SELECT platform.session_principal($1)", ["0".repeat(64)]), (e) => codeOf(e) === "42501");
  await assert.rejects(platform.query("SELECT platform.rights_case_of($1)", [fixtureUuid("x")]), (e) => codeOf(e) === "42501");
  await assert.rejects(platform.query("SELECT * FROM app.rights_case_tenant_of($1)", [fixtureUuid("x")]), (e) => codeOf(e) === "42501", "app.rights_case_tenant_of solo para grant_owner");
  assert.equal((await admin.query<{ r: string }>("SELECT COALESCE(string_agg(DISTINCT pg_get_userbyid(a.grantee), ',' ORDER BY pg_get_userbyid(a.grantee)), '') AS r FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace LEFT JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a ON a.grantee <> p.proowner WHERE n.nspname = 'app' AND p.proname = 'rights_case_tenant_of'")).rows[0]!.r, "grant_owner");
  // Sin principal ni tenant como parametro.
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.proname IN ('issue_step_up_nonce', 'request_grant', 'approve_grant') AND pg_get_function_arguments(p.oid) ~* '(principal|tenant)'")).rowCount, 0);
  // platform_rw no ve app.rights_case ni las tablas de grants.
  for (const t of ["app.rights_case", "platform.grant_request", "platform.rights_case_grant", "platform.action_nonce"]) await assert.rejects(platform.query(`SELECT 1 FROM ${t}`), (e) => codeOf(e) === "42501", t);
  // grant_owner no tiene ningun privilegio sobre app.rights_case (solo EXECUTE de app.rights_case_tenant_of).
  assert.equal((await admin.query<{ r: boolean }>("SELECT has_table_privilege('grant_owner', 'app.rights_case', 'SELECT') AS r")).rows[0]!.r, false);
  assert.equal((await admin.query<{ r: boolean }>("SELECT has_any_column_privilege('grant_owner', 'app.rights_case', 'SELECT') AS r")).rows[0]!.r, false);
  assert.equal((await admin.query<{ r: boolean }>("SELECT has_any_column_privilege('grant_owner', 'app.rights_case', 'INSERT,UPDATE') AS r")).rows[0]!.r, false);
  assert.equal((await admin.query<{ r: boolean }>("SELECT has_column_privilege('grant_owner', 'app.rights_case', 'chain_ref', 'SELECT') AS r")).rows[0]!.r, false);
  // Un grant solo nace de una solicitud APPROVED por ese aprobador (trigger + FK compuesta), incluso para el superusuario.
  const R = P("1657-r");
  const C = fixtureUuid("pr6d1-1657-case");
  const pending = (await admin.query<{ request_ref: string }>("INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, expires_at) VALUES ($1, $2, $3, $3, now() + interval '1 hour') RETURNING request_ref", [TENANT, C, R])).rows[0]!.request_ref;
  const ins = (request: string, tenant: string, approver: string): Promise<unknown> =>
    admin.query("INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at, request_ref, approved_by_ref) VALUES ($1, $2, $3, now() + interval '1 hour', $4, $5)", [tenant, C, R, request, approver]);
  await assert.rejects(ins(pending, TENANT, P("1657-apr")), (e) => codeOf(e) === "23000", "solicitud PENDING");
  await assert.rejects(ins(randomUUID(), TENANT, P("1657-apr")), (e) => codeOf(e) === "23000" || codeOf(e) === "23503", "solicitud inexistente");
  await assert.rejects(ins(pending, OTHER_TENANT, P("1657-apr")), (e) => codeOf(e) === "23000" || codeOf(e) === "23503", "tenant distinto al de la solicitud");
  await admin.query("UPDATE platform.grant_request SET status = 'APPROVED', approved_by_ref = $2, approved_at = now() WHERE request_ref = $1", [pending, P("1657-apr")]);
  await assert.rejects(ins(pending, TENANT, P("1657-otro")), (e) => codeOf(e) === "23000", "otro aprobador");
  await assert.rejects(ins(pending, TENANT, R), (e) => codeOf(e) === "23000" || codeOf(e) === "23514", "aprobador = operador");
  await ins(pending, TENANT, P("1657-apr"));
  await assert.rejects(ins(pending, TENANT, P("1657-apr")), (e) => codeOf(e) === "23505", "un grant por solicitud");
});

pgTest("TEST-CNS-1658 pg: begin STEP_UP ya no toma el principal de app.principal_ref: sin sesion o con principal declarado distinto = DENY; el nonce es del principal de la sesion", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const A = await operator(admin, "1658-a", "RIGHTS_OPERATOR");
  const B = await operator(admin, "1658-b", "RIGHTS_OPERATOR");
  const CASE = fixtureUuid("pr6d1-1658-case");
  const nonce = (await issue(platform, A.sid, "REQUEST_GRANT", CASE))!;
  assert.ok(typeof nonce === "string");
  assert.equal((await admin.query<{ p: string }>("SELECT principal_ref AS p FROM platform.action_nonce WHERE nonce_hash = $1", [sha(nonce)])).rows[0]!.p, A.principal, "el nonce es del operador de la sesion");
  const begin = async (declared: string | null, sid: string | null): Promise<string | null> =>
    (await call<{ r: string | null }>(platform, declared, "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, 300, NULL, 5, 600) AS r", [sha(randomBytes(24).toString("base64url")), sha(nonce), PKCE], sid))[0]?.r ?? null;
  assert.equal(await begin(A.principal, null), null, "principal declarado sin sesion");
  assert.equal(await begin(null, null), null);
  assert.equal(await begin(A.principal, B.sid), null, "principal declarado distinto del de la sesion");
  assert.equal(await begin(null, B.sid), null, "el nonce es de A: la sesion de B no lo usa");
  assert.equal(await begin(null, "0".repeat(64)), null, "sid desconocido");
  assert.ok(typeof (await begin(null, A.sid)) === "string", "sesion de A");
  // issue_step_up_nonce: sin sesion, accion o rol equivocados, destino mal formado, TTL fuera de rango.
  assert.equal(await issue(platform, "0".repeat(64), "REQUEST_GRANT", CASE), null);
  assert.equal(await issue(platform, A.sid, "APPROVE_GRANT", randomUUID()), null, "RIGHTS_OPERATOR no aprueba");
  assert.equal(await issue(platform, A.sid, "REQUEST_ROLE_ASSIGNMENT", CASE), null, "accion fuera del alcance");
  assert.equal(await issue(platform, A.sid, "REQUEST_GRANT", "x"), null);
  assert.equal((await call<{ n: string | null }>(platform, null, "SELECT platform.issue_step_up_nonce('REQUEST_GRANT', $1, 601) AS n", [CASE], A.sid))[0]?.n, null);
});

pgTest("TEST-CNS-1661 pg carrera: approve || approve (un solo grant; el perdedor no quema su nonce) y approve || vencimiento (nunca se aprueba pasado expires_at)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const c1 = await ctx.connectAs("platform_rw");
  const c2 = await ctx.connectAs("platform_rw");
  try {
    const R = await operator(admin, "1661-r", "RIGHTS_OPERATOR");
    const A = await operator(admin, "1661-a", "APPROVER");
    const B = await operator(admin, "1661-b", "APPROVER");
    const CASE = fixtureUuid("pr6d1-1661-case");
    await seedRightsCase(admin, TENANT, CASE);
    await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CASE);
    const rq = (await requestGrant(platform, R.sid, CASE))!;
    const nA = await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rq);
    const nB = await seedAttestedStepUp(admin, B.principal, "APPROVE_GRANT", rq);
    const [ra, rb] = await Promise.all([approveGrant(c1, A.sid, CASE, rq), approveGrant(c2, B.sid, CASE, rq)]);
    assert.equal([ra, rb].filter((r) => r !== null).length, 1, "exactamente una aprobacion gana");
    assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.rights_case_grant WHERE request_ref = $1", [rq])).rows[0]!.n), 1);
    const [winner, loser] = ra !== null ? [nA, nB] : [nB, nA];
    assert.equal(await consumed(admin, winner), true);
    assert.equal(await consumed(admin, loser), false, "el perdedor no consume su nonce");
    assert.equal((await admin.query("SELECT 1 FROM platform.session_event WHERE event_type = 'GRANT_REJECTED' AND reason_code = 'REQUEST_NOT_PENDING' AND request_ref = $1", [rq])).rowCount, 1);

    // approve || vencimiento: la solicitud vence ~1.5 s despues; dos aprobadores disparan justo en el borde.
    const CE = fixtureUuid("pr6d1-1661-case-exp");
    await seedRightsCase(admin, TENANT, CE);
    const exp = (await admin.query<{ request_ref: string }>(
      `INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, requested_at, expires_at) VALUES ($1, $2, $3, $3, now() - interval '59 minutes 58 seconds', now() + interval '1500 milliseconds') RETURNING request_ref`,
      [TENANT, CE, R.principal])).rows[0]!.request_ref;
    await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", exp);
    await seedAttestedStepUp(admin, B.principal, "APPROVE_GRANT", exp);
    await new Promise((r) => setTimeout(r, 1440));
    await Promise.all([approveGrant(c1, A.sid, CE, exp), approveGrant(c2, B.sid, CE, exp)]);
    const row = (await admin.query<{ status: string; ok: boolean | null }>("SELECT status, approved_at <= expires_at AS ok FROM platform.grant_request WHERE request_ref = $1", [exp])).rows[0]!;
    assert.ok(row.status === "PENDING" ? row.ok === null : row.ok === true, "una aprobacion nunca queda fechada despues de expires_at");
    assert.ok(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.rights_case_grant WHERE request_ref = $1", [exp])).rows[0]!.n) <= 1);
  } finally {
    await c1.end();
    await c2.end();
  }
});

pgTest("TEST-CNS-1662 pg: F-PR6-44 interino (no se pide grant mientras haya uno vigente), Membership TENANT (request/approve/open) y caso terminal cortan (F-PR6-46)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const R = await operator(admin, "1662-r", "RIGHTS_OPERATOR");
  const A = await operator(admin, "1662-a", "APPROVER");
  const CASE = fixtureUuid("pr6d1-1662-case");
  await seedRightsCase(admin, TENANT, CASE);
  await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CASE);
  const rq = (await requestGrant(platform, R.sid, CASE))!;
  await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rq);
  assert.ok(typeof (await approveGrant(platform, A.sid, CASE, rq)) === "string");
  // Grant vigente: no se pide otro (interino), y el nonce no se quema.
  const nonce = await seedAttestedStepUp(admin, R.principal, "REQUEST_GRANT", CASE);
  assert.equal(await requestGrant(platform, R.sid, CASE), null);
  assert.ok((await events(admin, R.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "GRANT_ACTIVE"));
  assert.equal(await consumed(admin, nonce), false);

  // Membership TENANT sobrevenida: approve la rechaza (TENANT_MEMBER) y open_case_session tambien.
  const M = await operator(admin, "1662-m", "RIGHTS_OPERATOR");
  const CM = fixtureUuid("pr6d1-1662-case-m");
  await seedRightsCase(admin, TENANT, CM);
  await seedAttestedStepUp(admin, M.principal, "REQUEST_GRANT", CM);
  const rqM = (await requestGrant(platform, M.sid, CM))!;
  assert.ok(typeof rqM === "string");
  await admin.query("INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3)", [TENANT, M.principal, A.principal]);
  const nM = await seedAttestedStepUp(admin, A.principal, "APPROVE_GRANT", rqM);
  assert.equal(await approveGrant(platform, A.sid, CM, rqM), null);
  assert.ok((await events(admin, A.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "TENANT_MEMBER"));
  assert.equal(await consumed(admin, nM), false);
  const CO = fixtureUuid("pr6d1-1662-case-o");
  await seedApprovedGrant(admin, { tenantId: TENANT, caseRef: CO, operator: M.principal });
  const flow = (await loginFlow({ platform, verifier }, "LOGIN_CASE", M.sub, { sid: M.sid, targetRefHash: sha(CO) }))!;
  assert.equal((await call<{ s: string | null }>(platform, null, "SELECT platform.open_case_session($1::uuid, $2, $3, $4, 3600, 600, NULL) AS s", [flow.ref, flow.state, CO, M.sid]))[0]?.s, null);
  assert.ok((await events(admin, M.principal, "LOGIN_REJECTED")).some((e) => e.reason_code === "TENANT_MEMBER"));
  // Una sesion CASE existente deja de validar si el operador obtiene Membership TENANT.
  const Q = await operator(admin, "1662-q", "RIGHTS_OPERATOR");
  const CQ = fixtureUuid("pr6d1-1662-case-q");
  const parent = await seedPlatformSession(admin, Q.principal);
  const cs = await seedCaseSession(admin, Q.principal, parent, CQ, TENANT);
  const valid = async (sid: string): Promise<number> => (await call(platform, null, "SELECT * FROM platform.validate_session($1, 'CASE')", [sid])).length;
  assert.equal(await valid(cs.sid), 1);
  await admin.query("INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3)", [TENANT, Q.principal, A.principal]);
  assert.equal(await valid(cs.sid), 0, "Membership TENANT corta la sesion CASE");

  // F-PR6-46: caso terminal = la sesion CASE no valida (fail-closed); con el caso abierto si.
  const T = await operator(admin, "1662-t", "RIGHTS_OPERATOR");
  const tParent = await seedPlatformSession(admin, T.principal);
  const CT = fixtureUuid("pr6d1-1662-case-t");
  const CTO = fixtureUuid("pr6d1-1662-case-to");
  await seedRightsCase(admin, TENANT, CT, "RESOLVED");
  const csDone = await seedCaseSession(admin, T.principal, tParent, CT, TENANT);
  const csOpen = await seedCaseSession(admin, T.principal, tParent, CTO, TENANT);
  assert.equal(await valid(csDone.sid), 0, "caso RESOLVED: la sesion CASE no valida");
  assert.equal(await valid(csOpen.sid), 1, "caso abierto: valida");
});
