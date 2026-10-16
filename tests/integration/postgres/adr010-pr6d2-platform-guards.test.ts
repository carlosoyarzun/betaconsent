// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.d, §5.4 (P-50, P-51, P-52), §6 (P6-3, P6-5), §10 fila 6d; GRD-RC-10, GRD-RC-12; decisiones de Carlos: F-PR6-43 (condicion de merge: aprobador del grant != aprobador
// RH2) y F-PR6-44 opcion A (GRANT_ACTIVE, sin renovaciones); API-CNS-136/137. SYNTHETIC ONLY. Requiere Postgres real (harness.ts). Cada test usa su propio mundo (refs y tenant propios).
// TEST-CNS-1707 GRD-RC-10 en ambos sentidos, 1708 step-up y principal PLATFORM de RH2, 1709 GRANT_ACTIVE, 1712 guards HTTP de RH2/RH3.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { call } from "../../helpers/pg-login-flow.ts";
import { attestRh2, casePath, rh2Target, seedAttestedStepUp, seedCaseWorld, seedOperator, seedPlatformSession, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import type { CaseWorld } from "../../helpers/pg-case-world.ts";
import { seedApprovedGrant } from "../../helpers/pg-platform-session.ts";
import { pgTest } from "./harness.ts";

const LIMIT = { max: 50, windowSeconds: 600 } as const;
const P51 = [50, 600] as const;

const revRow = async (admin: Client, w: CaseWorld) =>
  (await admin.query<{ status: string; proposal_ref: string | null; second_approver_ref: string | null }>("SELECT status, proposal_ref, second_approver_ref FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0]!;
const sessionEvents = async (admin: Client, principal: string, type?: string): Promise<Array<{ event_type: string; reason_code: string | null }>> =>
  (await admin.query<{ event_type: string; reason_code: string | null }>("SELECT event_type, reason_code FROM platform.session_event WHERE principal_ref = $1 AND ($2::text IS NULL OR event_type = $2) ORDER BY at, event_ref", [principal, type ?? null])).rows;
const requestGrant = async (platform: Client, sid: string, caseRef: string): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.request_grant($1, $2, $3) AS r", [caseRef, P51[0], P51[1]], sid))[0]?.r ?? null;
const approveGrant = async (platform: Client, sid: string, caseRef: string, request: string): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.approve_grant($1, $2::uuid, NULL, $3, $4) AS r", [caseRef, request, P51[0], P51[1]], sid))[0]?.r ?? null;

async function extraOperator(admin: Client, label: string, role: string) {
  const principal = fixtureUuid(label);
  await seedOperator(admin, principal, role);
  return { principal, sid: (await seedPlatformSession(admin, principal, { absoluteSeconds: 14400, idleSeconds: 900 })).sid };
}

pgTest("TEST-CNS-1707 pg: GRD-RC-10 / F-PR6-43 (condicion de merge de Carlos): el aprobador del grant no puede ser el aprobador de RH2 del caso, en ambos sentidos, por approve_grant, por el trigger del grant y por approve_case_verification", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await ctx.connectAs("platform_rw");
  const http = await startPlatformHttp(ctx);
  try {
    // Sentido A: primero RH2 (aprobador = w.approver), despues un grant del caso.
    const a = await seedCaseWorld(ctx, "1707a");
    await attestRh2(admin, http, a);
    const op3 = await extraOperator(admin, "world-1707a-op3", "RIGHTS_OPERATOR");
    await seedAttestedStepUp(admin, op3.principal, "REQUEST_GRANT", a.caseRef);
    const request = await requestGrant(platform, op3.sid, a.caseRef);
    assert.ok(typeof request === "string", "solicitud de grant creada");
    await seedAttestedStepUp(admin, a.approver.principal, "APPROVE_GRANT", request!);
    // F-6D2-QA-03 (cerrado): el motivo RH_TWO_APPROVER respeta session_event_reason_shape; approve_grant devuelve NULL (sin lanzar) y deja la evidencia GRANT_REJECTED.
    const approved = await approveGrant(platform, a.approver.platform.sid, a.caseRef, request!);
    assert.equal(approved, null, "el aprobador de RH2 no aprueba el grant del caso");
    assert.ok((await sessionEvents(admin, a.approver.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "RH_TWO_APPROVER"), "evidencia GRANT_REJECTED / RH_TWO_APPROVER");
    assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [request])).rowCount, 0);
    // Red de seguridad en la base: ni siquiera sembrando el grant con ese aprobador.
    await assert.rejects(() => seedApprovedGrant(admin, { tenantId: a.tenantId, caseRef: a.caseRef, operator: op3.principal, approver: a.approver.principal }), (e: unknown) => (e as { code?: string }).code === "23000");
    // Control: otro APPROVER distinto si puede.
    const approver2 = await extraOperator(admin, "world-1707a-approver2", "APPROVER");
    await seedAttestedStepUp(admin, approver2.principal, "APPROVE_GRANT", request!);
    assert.ok(typeof (await approveGrant(platform, approver2.sid, a.caseRef, request!)) === "string", "otro aprobador (no RH2) aprueba");

    // Sentido B: primero un grant (aprobado por X), despues X intenta aprobar RH2 del mismo caso.
    const b = await seedCaseWorld(ctx, "1707b");
    const opB = await extraOperator(admin, "world-1707b-op3", "RIGHTS_OPERATOR");
    await seedAttestedStepUp(admin, opB.principal, "REQUEST_GRANT", b.caseRef);
    const reqB = (await requestGrant(platform, opB.sid, b.caseRef))!;
    await seedAttestedStepUp(admin, b.approver.principal, "APPROVE_GRANT", reqB);
    assert.ok(typeof (await approveGrant(platform, b.approver.platform.sid, b.caseRef, reqB)) === "string");
    const proposalRef = fixtureUuid("proposal-1707b");
    await seedAttestedStepUp(admin, b.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(b.caseRef, proposalRef));
    assert.equal((await http.cases.propose({ sid: b.op1.caseSession.sid, caseRef: b.caseRef, proposalRef, scriptVersion: "g", limit: LIMIT })).ok, true);
    await seedAttestedStepUp(admin, b.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(b.caseRef, proposalRef));
    const refused = await http.cases.approve({ sid: b.approver.platform.sid, caseRef: b.caseRef, proposalRef, limit: LIMIT });
    assert.deepEqual(refused, { ok: false, reason: "ERR-RV-07" }, "el aprobador del grant no aprueba RH2 del caso (ERR-RV-07)");
    assert.deepEqual(await revRow(admin, b), { status: "REQUESTED", proposal_ref: proposalRef, second_approver_ref: null });
    assert.equal((await admin.query("SELECT 1 FROM platform.case_verification WHERE tenant_id = $1 AND case_ref = $2", [b.tenantId, b.caseRef])).rowCount, 0);
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1708 pg platform: RH2 exige step-up (misma tx, GRD-RC-12) y la aprobacion exige sesion PLATFORM de un APPROVER; un step-up ajeno, de otra accion, de otro destino o rancio, o una cookie del tipo equivocado, = 404 sin cambio de estado", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1708");
  const http = await startPlatformHttp(ctx);
  try {
    const p = casePath(w.caseRef);
    const proposalRef = fixtureUuid("proposal-1708");
    const body = { proposalRef, verificationScriptVersion: "g" };
    const propose = (sid: string, kind: "CASE" | "PLATFORM" = "CASE") => http.post(p.proposals, sid, body, { kind });
    // Sin step-up.
    assert.equal((await propose(w.op1.caseSession.sid)).status, 404);
    assert.ok((await sessionEvents(admin, w.op1.principal, "STEP_UP_REJECTED")).some((e) => e.reason_code === "STEP_UP_MISSING"));
    // Step-up de otra accion, de otro destino, de otro principal y rancio (> 5 min desde auth_time, P-52).
    await seedAttestedStepUp(admin, w.op1.principal, "WITHDRAW_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, fixtureUuid("otra-propuesta")));
    await seedAttestedStepUp(admin, w.op2.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await propose(w.op1.caseSession.sid)).status, 404);
    // Rancio (otro destino propio: una asercion rancia no consumida es la mas antigua y taparia a una vigente del mismo destino).
    const staleRef = fixtureUuid("proposal-1708-rancia");
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, staleRef), 400);
    assert.equal((await http.post(p.proposals, w.op1.caseSession.sid, { proposalRef: staleRef, verificationScriptVersion: "g" })).status, 404);
    assert.ok((await sessionEvents(admin, w.op1.principal, "STEP_UP_REJECTED")).some((e) => e.reason_code === "ASSERTION_STALE"));
    assert.deepEqual(await revRow(admin, w), { status: "REQUESTED", proposal_ref: null, second_approver_ref: null });
    // Cookie del tipo equivocado y principal declarado en el cuerpo.
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await propose(w.op1.platform.sid, "CASE")).status, 404, "sesion PLATFORM en la cookie CASE");
    assert.equal((await http.post(p.proposals, w.op1.caseSession.sid, { ...body, principalRef: w.op2.principal })).status, 409, "el principal nunca viene del cuerpo");
    // Con el step-up valido (el unico vigente y propio) la propuesta pasa y consume el nonce.
    assert.equal((await propose(w.op1.caseSession.sid)).status, 201);

    // Aprobacion: sin step-up, con sesion CASE, con sesion PLATFORM de quien no es APPROVER.
    assert.equal((await http.post(p.approval(proposalRef), w.approver.platform.sid, {}, { kind: "PLATFORM" })).status, 404, "sin step-up");
    await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await http.post(p.approval(proposalRef), w.op1.caseSession.sid, {}, { kind: "PLATFORM" })).status, 404, "una sesion CASE no aprueba");
    assert.equal((await http.post(p.approval(proposalRef), w.approver.platform.sid, {}, { kind: "CASE" })).status, 404, "la aprobacion no usa la cookie CASE");
    await seedAttestedStepUp(admin, w.op1.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await http.post(p.approval(proposalRef), w.op1.platform.sid, {}, { kind: "PLATFORM" })).status, 404, "PLATFORM de un RIGHTS_OPERATOR no aprueba");
    assert.equal((await revRow(admin, w)).status, "REQUESTED");
    assert.equal((await http.post(p.approval(proposalRef), w.approver.platform.sid, {}, { kind: "PLATFORM" })).status, 200, "APPROVER con sesion PLATFORM y step-up propio");
    assert.deepEqual(await revRow(admin, w), { status: "VERIFIED", proposal_ref: proposalRef, second_approver_ref: w.approver.principal });
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1709 pg: GRANT_ACTIVE (F-PR6-44 opcion A de Carlos): con un grant vigente request_grant se rechaza; sin renovaciones: vencido el grant, la nueva solicitud exige otra doble aprobacion", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await ctx.connectAs("platform_rw");
  const w = await seedCaseWorld(ctx, "1709");
  const grantsOf = async (principal: string): Promise<number> => (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM platform.rights_case_grant WHERE tenant_id = $1 AND case_ref = $2 AND operator_principal_ref = $3", [w.tenantId, w.caseRef, principal])).rows[0]!.n;
  const requestsOf = async (principal: string): Promise<number> => (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM platform.grant_request WHERE tenant_id = $1 AND case_ref = $2 AND operator_principal_ref = $3", [w.tenantId, w.caseRef, principal])).rows[0]!.n;
  // op1 ya tiene un grant vigente (sesion CASE sembrada).
  const reqBefore = await requestsOf(w.op1.principal);
  await seedAttestedStepUp(admin, w.op1.principal, "REQUEST_GRANT", w.caseRef);
  assert.equal(await requestGrant(platform, w.op1.platform.sid, w.caseRef), null);
  assert.ok((await sessionEvents(admin, w.op1.principal, "GRANT_REJECTED")).some((e) => e.reason_code === "GRANT_ACTIVE"));
  assert.equal(await requestsOf(w.op1.principal), reqBefore, "sin solicitud nueva (no hay renovacion)");
  assert.equal(await grantsOf(w.op1.principal), 1);

  // Un operador cuyo grant vence: recien entonces puede pedir otro, y sigue necesitando aprobacion.
  const op3 = await extraOperator(admin, "world-1709-op3", "RIGHTS_OPERATOR");
  await seedApprovedGrant(admin, { tenantId: w.tenantId, caseRef: w.caseRef, operator: op3.principal, seconds: 1 });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  await seedAttestedStepUp(admin, op3.principal, "REQUEST_GRANT", w.caseRef);
  const request = await requestGrant(platform, op3.sid, w.caseRef);
  assert.ok(typeof request === "string", "vencido el grant se puede pedir otro");
  assert.equal(await grantsOf(op3.principal), 1, "la solicitud no renueva por si sola: el grant nuevo nace solo de la aprobacion");
  await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_GRANT", request!);
  assert.ok(typeof (await approveGrant(platform, w.approver.platform.sid, w.caseRef, request!)) === "string");
  assert.equal(await grantsOf(op3.principal), 2);
});

pgTest("TEST-CNS-1712 pg platform HTTP: guards de RH2/RH3 y de ruta: cuatro ojos (409), RH3 sin RH2 (409), sesion de otro caso, sin cookie, origen ajeno, GET y cuerpos con claves ajenas = 404/409 sin cambio de estado", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1712");
  const other = await seedCaseWorld(ctx, "1712x");
  const http = await startPlatformHttp(ctx);
  try {
    const p = casePath(w.caseRef);
    // RH3 sin RH2 atestada.
    const noRh2 = await http.post(p.confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: true });
    assert.equal(noRh2.status, 409);
    assert.equal(JSON.parse(noRh2.body).code, "RH3_NOT_BOUND_TO_RH2");
    await attestRh2(admin, http, w);
    // Co-firma sin registro previo y co-firma por el mismo registrador: cuatro ojos.
    const early = await http.post(p.cosign, w.op2.caseSession.sid, {});
    assert.equal(early.status, 409);
    assert.equal(JSON.parse(early.body).code, "RH3_FOUR_EYES_REQUIRED");
    assert.equal((await http.post(p.confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: true })).status, 200);
    const same = await http.post(p.cosign, w.op1.caseSession.sid, {});
    assert.equal(same.status, 409);
    assert.equal(JSON.parse(same.body).code, "RH3_FOUR_EYES_REQUIRED");
    assert.equal((await revRow(admin, w)).status, "VERIFIED");
    // Ruta: sesion CASE de otro caso, sin cookie, origen ajeno, Sec-Fetch cruzado, GET, query, cuerpo con claves ajenas o no booleano.
    assert.equal((await http.post(p.cosign, other.op2.caseSession.sid, {})).status, 404);
    assert.equal((await http.post(p.cosign, null, {})).status, 404);
    assert.equal((await http.post(p.cosign, w.op2.caseSession.sid, {}, { headers: { origin: "https://evil.example" } })).status, 404);
    assert.equal((await http.post(p.cosign, w.op2.caseSession.sid, {}, { headers: { "sec-fetch-site": "cross-site" } })).status, 404);
    assert.equal((await fetch(`${http.base}${p.cosign}`, { headers: { cookie: `__Host-cns-case=${w.op2.caseSession.sid}` } })).status, 404);
    assert.equal((await http.post(`${p.cosign}?x=1`, w.op2.caseSession.sid, {})).status, 404);
    assert.equal((await http.post(p.cosign, w.op2.caseSession.sid, { principalRef: w.op2.principal })).status, 409);
    assert.equal((await http.post(p.confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: "true" })).status, 409);
    assert.equal((await http.post(p.close, w.op1.caseSession.sid, { outcome: "OTRO" })).status, 409);
    assert.equal((await revRow(admin, w)).status, "VERIFIED", "ningun rechazo cambia el estado");
    assert.equal((await revRow(admin, other)).status, "REQUESTED");
    // La co-firma legitima del segundo operador sigue funcionando.
    assert.equal((await http.post(p.cosign, w.op2.caseSession.sid, {})).status, 200);
    assert.equal((await revRow(admin, w)).status, "APPLIED");
  } finally {
    await http.close();
  }
});
