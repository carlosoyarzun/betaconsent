// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §6 (GRD-RC-10, INV-14), §4.2.a puntos 4 y 5 (G-3); decisiones de Carlos del 2026-10-16: INV-14 opcion A (quien aprueba RH2 de un caso no recibe grants de ese caso
// ni registra ni co-firma RH3) y alcance de G-3 opcion A (alerta ante cualquier fallo que NO sea un guard de dominio al aplicar una revocacion). db/migrations/0067, 0069, 0070. SYNTHETIC ONLY. Requiere Postgres real.
// TEST-CNS-1727 aprobador de RH2 no recibe grant (approve_grant, trigger), 1728 orden inverso (grant antes de RH2), 1729 record/cosign RH3, 1730 concurrencia grant vs RH2 del mismo principal,
// 1731 G-3 platform (XX000 -> alerta), 1732 G-3 web R3 (XX000 -> alerta), 1733 (unit) guardia, 1734 G-3 web R3r (XX000 -> alerta).

import assert from "node:assert/strict";
import type { Client } from "pg";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createApplyGuardConfig, createTenantAlertSink } from "../../../src/infra/adapters/postgres/apply-guard.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { confirmRevocation, hashRecoveryToken, issueRecoveryLinkBearer, requestRevocation, revokeWithRecoveryLinkByHash, verifyRevocationOtp } from "../../../src/server/modules/revocation/revocation.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { call } from "../../helpers/pg-login-flow.ts";
import { attestRh2, casePath, injectOutboxFailure, recordRh3, rh2Target, seedAttestedStepUp, seedCaseWorld, seedOperator, seedPlatformSession, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import type { CaseWorld } from "../../helpers/pg-case-world.ts";
import { seedApprovedGrant } from "../../helpers/pg-platform-session.ts";
import { enableLedgerMechanicsAppend, pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const LIMIT = { max: 50, windowSeconds: 600 } as const;

const requestGrant = async (platform: Client, sid: string, caseRef: string): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.request_grant($1, 50, 600) AS r", [caseRef], sid))[0]?.r ?? null;
const approveGrant = async (platform: Client, sid: string, caseRef: string, request: string): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.approve_grant($1, $2::uuid, NULL, 50, 600) AS r", [caseRef, request], sid))[0]?.r ?? null;
const rejections = async (admin: Client, principal: string, request: string): Promise<string[]> =>
  (await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.session_event WHERE principal_ref = $1 AND event_type = 'GRANT_REJECTED' AND request_ref = $2 ORDER BY at, event_ref", [principal, request])).rows.map((r) => r.reason_code);
const revStatus = async (admin: Client, w: CaseWorld) =>
  (await admin.query<{ status: string; recorded_by_ref: string | null; cosigned_by_ref: string | null }>("SELECT status, recorded_by_ref, cosigned_by_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0]!;
const alerts = async (admin: Client, w: CaseWorld): Promise<string[]> =>
  (await admin.query<{ alert_reason: string }>("SELECT alert_reason FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_APPLY_ALERT' ORDER BY event_seq", [w.tenantId])).rows.map((r) => r.alert_reason);

async function newApprover(admin: Client, label: string) {
  const principal = fixtureUuid(label);
  await seedOperator(admin, principal, "APPROVER");
  return { principal, sid: (await seedPlatformSession(admin, principal, { absoluteSeconds: 14400, idleSeconds: 900 })).sid };
}

pgTest("TEST-CNS-1727 pg (INV-14, Carlos 2026-10-16 opcion A): quien aprobo RH2 del caso no puede RECIBIR un grant del caso: approve_grant devuelve NULL con GRANT_REJECTED / RH_TWO_APPROVER_OPERATOR y el trigger del grant lo rechaza; otro operador si recibe", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await ctx.connectAs("platform_rw");
  const http = await startPlatformHttp(ctx);
  try {
    const w = await seedCaseWorld(ctx, "1727");
    await seedOperator(admin, w.approver.principal, "RIGHTS_OPERATOR"); // el aprobador de RH2 tambien tiene el rol de operador
    await attestRh2(admin, http, w);
    await seedAttestedStepUp(admin, w.approver.principal, "REQUEST_GRANT", w.caseRef);
    const request = await requestGrant(platform, w.approver.platform.sid, w.caseRef);
    assert.ok(typeof request === "string", "la solicitud nace (la base la rechaza al aprobar)");
    const other = await newApprover(admin, "world-1727-approver2");
    await seedAttestedStepUp(admin, other.principal, "APPROVE_GRANT", request!);
    assert.equal(await approveGrant(platform, other.sid, w.caseRef, request!), null);
    assert.deepEqual(await rejections(admin, other.principal, request!), ["RH_TWO_APPROVER_OPERATOR"], "evidencia GRANT_REJECTED con motivo valido");
    assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [request])).rowCount, 0);
    // Red de seguridad en la base: tampoco sembrando el grant.
    await assert.rejects(() => seedApprovedGrant(admin, { tenantId: w.tenantId, caseRef: w.caseRef, operator: w.approver.principal, approver: other.principal }), (e: unknown) => (e as { code?: string }).code === "23000");
    // Control: un operador que no aprobo RH2 recibe su grant.
    const op3 = fixtureUuid("world-1727-op3");
    await seedOperator(admin, op3, "RIGHTS_OPERATOR");
    const op3Sid = (await seedPlatformSession(admin, op3, { absoluteSeconds: 14400, idleSeconds: 900 })).sid;
    await seedAttestedStepUp(admin, op3, "REQUEST_GRANT", w.caseRef);
    const req3 = (await requestGrant(platform, op3Sid, w.caseRef))!;
    await seedAttestedStepUp(admin, other.principal, "APPROVE_GRANT", req3);
    assert.ok(typeof (await approveGrant(platform, other.sid, w.caseRef, req3)) === "string");
  } finally {
    await platform.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1728 pg (INV-14, orden inverso): si el grant se concedio ANTES de RH2 (vigente o vencido), la misma persona no puede aprobar RH2 del caso (ERR-RV-07) y no queda case_verification", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const http = await startPlatformHttp(ctx);
  try {
    for (const variant of ["vigente", "vencido"] as const) {
      const w = await seedCaseWorld(ctx, `1728-${variant}`);
      await seedOperator(admin, w.approver.principal, "RIGHTS_OPERATOR");
      await seedApprovedGrant(admin, { tenantId: w.tenantId, caseRef: w.caseRef, operator: w.approver.principal, seconds: variant === "vigente" ? 3600 : 1 });
      if (variant === "vencido") await new Promise((r) => setTimeout(r, 1500));
      const proposalRef = fixtureUuid(`proposal-1728-${variant}`);
      await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
      assert.equal((await http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: "g", limit: LIMIT })).ok, true);
      await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
      assert.deepEqual(await http.cases.approve({ sid: w.approver.platform.sid, caseRef: w.caseRef, proposalRef, limit: LIMIT }), { ok: false, reason: "ERR-RV-07" }, variant);
      assert.equal((await admin.query("SELECT 1 FROM platform.case_verification WHERE tenant_id = $1 AND case_ref = $2", [w.tenantId, w.caseRef])).rowCount, 0);
      assert.equal((await revStatus(admin, w)).status, "REQUESTED");
    }
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1729 pg (INV-14): el aprobador de RH2 del caso (por platform.case_verification) no registra RH3 ni co-firma RH3: ERR-RV-07 (403), la Revocation sigue VERIFIED sin registrador ni co-firmante; un guard de dominio no alerta", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1729");
  const http = await startPlatformHttp(ctx);
  try {
    await attestRh2(admin, http, w);
    const p = casePath(w.caseRef);
    // op1 figura como aprobador de otra RH2 del caso (via case_verification): no registra.
    await admin.query(
      "INSERT INTO platform.case_verification (tenant_id, case_ref, revocation_ref, proposal_ref, proposed_by_ref, approved_by_ref) VALUES ($1, $2, $3, $4, $5, $6)",
      [w.tenantId, w.caseRef, w.revocationRef, fixtureUuid("proposal-1729-x"), w.approver.principal, w.op1.principal],
    );
    const record1 = await http.post(p.confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: true });
    assert.equal(record1.status, 403, record1.body);
    assert.equal(JSON.parse(record1.body).code, "RH2_SEPARATION_OF_DUTIES_VIOLATION");
    assert.deepEqual(await revStatus(admin, w), { status: "VERIFIED", recorded_by_ref: null, cosigned_by_ref: null });
    // op2 registra; op1 (aprobador de RH2) no co-firma.
    assert.equal((await http.post(p.confirmation, w.op2.caseSession.sid, { confirmationGivenOnCasePage: true })).status, 200);
    const cosign1 = await http.post(p.cosign, w.op1.caseSession.sid, {});
    assert.equal(cosign1.status, 403, cosign1.body);
    assert.equal(JSON.parse(cosign1.body).code, "RH2_SEPARATION_OF_DUTIES_VIOLATION");
    assert.deepEqual(await revStatus(admin, w), { status: "VERIFIED", recorded_by_ref: w.op2.principal, cosigned_by_ref: null });
    assert.deepEqual(await alerts(admin, w), [], "un guard de dominio no alerta (G-3)");
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1730 pg concurrencia (INV-14): un grant al principal X aprobado por Y (sin commit) vs la RH2 de X sobre el mismo caso: la RH2 espera el lock del caso, ve el grant y se rechaza (ERR-RV-07); no quedan ambos", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1730");
  const http = await startPlatformHttp(ctx);
  const platform = await ctx.connectAs("platform_rw");
  const a = await ctx.connectAs("platform_rw");
  const b = await ctx.connectAs("platform_rw");
  try {
    await seedOperator(admin, w.approver.principal, "RIGHTS_OPERATOR");
    const proposalRef = fixtureUuid("proposal-1730");
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: "g", limit: LIMIT })).ok, true);
    const y = await newApprover(admin, "world-1730-y");
    await seedAttestedStepUp(admin, w.approver.principal, "REQUEST_GRANT", w.caseRef);
    const request = (await requestGrant(platform, w.approver.platform.sid, w.caseRef))!;
    assert.ok(typeof request === "string");
    await seedAttestedStepUp(admin, y.principal, "APPROVE_GRANT", request);
    await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    // A: Y aprueba el grant de X, SIN commit (retiene el lock del caso).
    await a.query("BEGIN");
    await a.query("SELECT set_config('app.session_sid', $1, true)", [y.sid]);
    const granted = await a.query("SELECT platform.approve_grant($1, $2::uuid, NULL, 50, 600) AS r", [w.caseRef, request]);
    assert.ok(typeof (granted.rows[0] as { r: string | null }).r === "string", "el grant se crea (aun sin commit)");
    // B: X aprueba su RH2: espera el lock del caso (record_rh2_approval).
    let settled = false;
    await b.query("BEGIN");
    await b.query("SELECT set_config('app.session_sid', $1, true)", [w.approver.platform.sid]);
    const rh2Outcome = b.query("SELECT case_state.approve_case_verification($1, $2, 50, 600) AS r", [w.caseRef, proposalRef]).then(
      () => "ok",
      (e: { code?: string }) => e.code ?? "error",
    ).then((r) => { settled = true; return r; });
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(settled, false, "la RH2 espera al grant");
    await a.query("COMMIT");
    assert.equal(await rh2Outcome, "RV004", "ERR-RV-07: el receptor del grant no aprueba RH2");
    await b.query("ROLLBACK");
    assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [request])).rowCount, 1);
    assert.equal((await admin.query("SELECT 1 FROM platform.case_verification WHERE tenant_id = $1 AND case_ref = $2", [w.tenantId, w.caseRef])).rowCount, 0);
    assert.equal((await revStatus(admin, w)).status, "REQUESTED");
  } finally {
    await a.end();
    await b.end();
    await platform.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1731 pg platform (G-3 alcance, Carlos 2026-10-16 opcion A): un fallo NO transitorio (XX000) en la co-firma RH3 + R4 persiste la alerta R4_APPLY_FAILED (tx separada, sin PII), se propaga sin acuse de exito y la Revocation sigue VERIFIED; no se reintenta", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1731");
  const logs: string[] = [];
  const http = await startPlatformHttp(ctx, { applyGuard: { maxAttempts: 3, log: (l) => logs.push(l) } });
  try {
    await recordRh3(admin, http, w);
    const failure = await injectOutboxFailure(admin, { name: "f1731", tenantId: w.tenantId, failures: 1_000, sqlstate: "XX000" });
    await assert.rejects(() => http.cases.cosign({ sid: w.op2.caseSession.sid, caseRef: w.caseRef }), /fallo inyectado/);
    assert.equal(await failure.attempts(), 1, "no transitorio: sin reintentos");
    assert.deepEqual(await alerts(admin, w), ["R4_APPLY_FAILED"]);
    assert.deepEqual(await revStatus(admin, w), { status: "VERIFIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: null });
    assert.ok(logs.every((l) => !l.includes(w.op2.principal) && !l.includes(w.op2.caseSession.sid)), "sin PII ni sid en el log");
    // Respuesta HTTP: respuesta uniforme de error del handler (no un 200) y sin acuse de aplicacion.
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.notEqual(res.status, 200, res.body);
    assert.ok(!/APPLIED|COSIGNED/i.test(res.body));
    assert.deepEqual(await alerts(admin, w), ["R4_APPLY_FAILED", "R4_APPLY_FAILED"], "una alerta por fallo");
    await failure.remove();
    assert.equal((await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {})).status, 200);
  } finally {
    await http.close();
  }
});

interface WebEnv {
  readonly ports: RevocationPorts;
  readonly sink: ReturnType<typeof createInMemoryRecoveryLinkChannelSink>;
  readonly logs: string[];
}

async function withWeb<R>(ctx: PgTestContext, body: (env: WebEnv) => Promise<R>): Promise<R> {
  await enableLedgerMechanicsAppend(ctx);
  const raw = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(raw as never);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const logs: string[] = [];
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(raw),
      downstreamStub: createInMemoryDownstreamStub(),
      applyGuard: createApplyGuardConfig(createTenantAlertSink(uow), { maxAttempts: 3, sleep: async () => {}, log: (l) => logs.push(l) }),
    };
    return await body({ ports, sink, logs });
  } finally {
    await raw.end();
  }
}

const tenantAlerts = async (ctx: PgTestContext, T: string): Promise<string[]> =>
  (await (await ctx.fixtureAdmin()).query<{ alert_reason: string }>("SELECT alert_reason FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_APPLY_ALERT' ORDER BY event_seq", [T])).rows.map((r) => r.alert_reason);
const decisionState = async (ctx: PgTestContext, T: string, D: string): Promise<string> =>
  (await (await ctx.fixtureAdmin()).query<{ state: string }>("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [T, D])).rows[0]!.state;

pgTest("TEST-CNS-1732 pg web (R3, G-3 alcance): un fallo NO transitorio (XX000) alerta R4_APPLY_FAILED una vez (tx de tenant separada), se propaga sin acuse y la Revocation sigue VERIFIED; sin reintentos", async (ctx) => {
  const T = fixtureUuid("t1732");
  await withWeb(ctx, async (env) => {
    const D = fixtureUuid("d-1732");
    await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: "chain-1732" });
    const revocationRef = fixtureUuid("r-1732");
    await requestRevocation(env.ports, T, { revocationRef, chainRef: "chain-1732", revokedDecisionRef: D });
    await verifyRevocationOtp(env.ports, T, revocationRef, fixtureUuid("v-1732"));
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1732", tenantId: T, failures: 1_000, sqlstate: "XX000" });
    await assert.rejects(confirmRevocation(env.ports, T, revocationRef), /fallo inyectado/);
    assert.equal(await failure.attempts(), 1);
    assert.deepEqual(await tenantAlerts(ctx, T), ["R4_APPLY_FAILED"]);
    assert.equal(await decisionState(ctx, T, D), "GRANTED");
    assert.ok(env.logs.every((l) => !l.includes(D)));
    await failure.remove();
    assert.equal((await confirmRevocation(env.ports, T, revocationRef)).status, "APPLIED");
    assert.deepEqual(await tenantAlerts(ctx, T), ["R4_APPLY_FAILED"], "sin alerta nueva si el reintento aplica");
  });
});

pgTest("TEST-CNS-1734 pg web (R3r, G-3 alcance): un fallo NO transitorio (XX000) alerta R4_APPLY_FAILED con la ref generada, se propaga sin acuse, token SIN consumir; el mismo enlace sirve despues", async (ctx) => {
  const T = fixtureUuid("t1734");
  await withWeb(ctx, async (env) => {
    const D = fixtureUuid("d-1734");
    await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: "chain-1734" });
    await issueRecoveryLinkBearer(env.ports, T, "chain-1734", D, "REQUESTER_ASKED");
    const tokenHash = hashRecoveryToken(env.sink.sent[env.sink.sent.length - 1]!.recoveryPath.replace("/r/", ""));
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1734", tenantId: T, failures: 1_000, sqlstate: "XX000" });
    await assert.rejects(revokeWithRecoveryLinkByHash(env.ports, tokenHash), /fallo inyectado/);
    assert.equal(await failure.attempts(), 1);
    assert.deepEqual(await tenantAlerts(ctx, T), ["R4_APPLY_FAILED"]);
    assert.equal(await decisionState(ctx, T, D), "GRANTED");
    await failure.remove();
    assert.equal((await revokeWithRecoveryLinkByHash(env.ports, tokenHash)).kind, "CONFIRMED", "el token no se consumio");
  });
});
