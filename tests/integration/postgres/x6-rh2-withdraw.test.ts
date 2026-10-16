// Gobierna: CA-128 X6 P2 (Carlos 2026-10-01), API-CNS-140 withdraw_case_verification_proposal, db/migrations/0016 (RLS FORCE por tenant de app.revocation), 0017 (REVOCATION_PROPOSAL_WITHDRAWN en la lista blanca
// del ledger) y 0070 (ADR-010 rev. 5, 6d parte 2: la funcion corre solo por platform con sesion CASE, actor desde la sesion, step-up en la misma tx), INV-6. SYNTHETIC ONLY.
// TEST-CNS-1019 (retiro/propuesta nueva/aprobacion en Postgres real, ledger y CHECK), TEST-CNS-1020 (aislamiento cross-tenant), TEST-CNS-1022 (repeticion del retiro en Postgres real).
// Reescritos sobre platform (createPgPlatformCase del pool de platform_rw): mismas aserciones de estado, ledger, codigos de dominio y aislamiento que cuando corrian con app_rw y el actor declarado.
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { seedAttestedStepUp, seedCaseWorld, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import type { CaseWorld, PlatformHttp } from "../../helpers/pg-case-world.ts";
import { pgTest } from "./harness.ts";

const LIMIT = { max: 50, windowSeconds: 600 } as const;

interface Ledger { eventType: string; payload: Record<string, unknown> }

const ledgerOf = async (admin: Client, tenantId: string, revocationRef: string): Promise<Ledger[]> =>
  (await admin.query<{ event_type: string; payload: Record<string, unknown> }>(
    "SELECT event_type, payload FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_type = 'Revocation' AND aggregate_id = $2 ORDER BY sequence", [tenantId, revocationRef],
  )).rows.map((r) => ({ eventType: r.event_type, payload: r.payload }));

/** RH2 paso 1 por platform (step-up sembrado para el proponente) y devuelve la propuesta. */
async function propose(admin: Client, http: PlatformHttp, w: CaseWorld, proposalRef: string, script = "guion-1"): Promise<void> {
  await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", proposalRef);
  const r = await http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: script, limit: LIMIT });
  assert.equal(r.ok, true, JSON.stringify(r));
}

async function withdraw(admin: Client, http: PlatformHttp, w: CaseWorld, who: "op1" | "op2", proposalRef: string) {
  const actor = w[who];
  await seedAttestedStepUp(admin, actor.principal, "WITHDRAW_CASE_VERIFICATION", proposalRef);
  return http.cases.withdraw({ sid: actor.caseSession.sid, caseRef: w.caseRef, proposalRef, limit: LIMIT });
}

async function approve(admin: Client, http: PlatformHttp, w: CaseWorld, proposalRef: string) {
  await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", proposalRef);
  return http.cases.approve({ sid: w.approver.platform.sid, caseRef: w.caseRef, proposalRef, limit: LIMIT });
}

const revocationRow = async (admin: Client, w: CaseWorld) =>
  (await admin.query("SELECT status, proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0]!;

pgTest("TEST-CNS-1019 pg platform: retiro RH2 limpia la propuesta (columnas NULL), registra REVOCATION_PROPOSAL_WITHDRAWN (CHECK de 0017), no cambia el estado; aprobar tras retiro falla y una propuesta nueva se aprueba hasta VERIFIED", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1019");
  const http = await startPlatformHttp(ctx);
  try {
    const proposalRef = fixtureUuid("p-1019");
    await propose(admin, http, w, proposalRef);
    // Otro operador (sesion CASE propia, step-up propio) no es el proponente: ERR-RV-07, la propuesta sigue PENDING.
    const other = await withdraw(admin, http, w, "op2", proposalRef);
    assert.deepEqual(other, { ok: false, reason: "ERR-RV-07" });
    assert.equal((await revocationRow(admin, w)).proposal_ref, proposalRef);

    const done = await withdraw(admin, http, w, "op1", proposalRef);
    assert.equal(done.ok, true, JSON.stringify(done));
    assert.deepEqual(await revocationRow(admin, w), { status: "REQUESTED", proposal_ref: null, proposed_by_ref: null, verification_script_version: null, second_approver_ref: null });
    const events = await ledgerOf(admin, w.tenantId, w.revocationRef);
    assert.deepEqual(events.map((e) => e.eventType), ["REVOCATION_REQUESTED", "REVOCATION_PROPOSAL_WITHDRAWN"], "el caso sembrado ya trae R1; el retiro agrega un solo evento");
    assert.deepEqual(events[1]!.payload, { revocationRef: w.revocationRef, caseRef: w.caseRef, proposalRef, verificationScriptVersion: "guion-1", withdrawnByRef: w.op1.principal });

    // Aprobar una propuesta ya retirada: propuesta ajena (ERR-CM-01).
    assert.deepEqual(await approve(admin, http, w, proposalRef), { ok: false, reason: "ERR-CM-01" });

    const next = fixtureUuid("p-1019-nueva");
    await propose(admin, http, w, next, "guion-2");
    const approved = await approve(admin, http, w, next);
    assert.equal(approved.ok, true, JSON.stringify(approved));
    assert.equal((await revocationRow(admin, w)).status, "VERIFIED");
    // VERIFIED: ya no PENDING; y una propuesta sobre una Revocation VERIFIED es transicion invalida (ERR-CM-06).
    assert.deepEqual(await withdraw(admin, http, w, "op1", next), { ok: false, reason: "ERR-CM-06" });
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", proposalRef);
    assert.deepEqual(await http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: "guion-1", limit: LIMIT }), { ok: false, reason: "ERR-CM-06" });
    assert.deepEqual((await ledgerOf(admin, w.tenantId, w.revocationRef)).map((e) => e.eventType), ["REVOCATION_REQUESTED", "REVOCATION_PROPOSAL_WITHDRAWN", "REVOCATION_VERIFIED"]);
    // 0017: el tipo nuevo esta en el CHECK; uno fuera de lista sigue rechazado.
    const def = (await admin.query("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'integrity.audit_event'::regclass AND conname = 'audit_event_event_type_allowlist'")).rows[0]?.d as string;
    assert.ok(def.includes("REVOCATION_PROPOSAL_WITHDRAWN") && def.includes("REVOCATION_VERIFIED") && !def.includes("NOT_IN_VOCABULARY"));
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1022 pg platform: repetir el retiro RH2 no produce un segundo evento ni cambia la fila (replay idempotente de revocation.spec RH2w, F-6D2-QA-01 cerrado: mismo resultado, un solo evento); otro principal ERR-CM-01", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1022");
  const http = await startPlatformHttp(ctx);
  try {
    const proposalRef = fixtureUuid("p-1022");
    await propose(admin, http, w, proposalRef);
    assert.equal((await withdraw(admin, http, w, "op1", proposalRef)).ok, true);
    const first = (await ledgerOf(admin, w.tenantId, w.revocationRef)).length;
    const replay = await withdraw(admin, http, w, "op1", proposalRef);
    assert.equal(replay.ok, true, JSON.stringify(replay));
    assert.equal(first, 2);
    assert.equal((await ledgerOf(admin, w.tenantId, w.revocationRef)).length, 2, "sin segundo evento (REQUESTED + un solo retiro)");
    assert.deepEqual(await revocationRow(admin, w), { status: "REQUESTED", proposal_ref: null, proposed_by_ref: null, verification_script_version: null, second_approver_ref: null });
    assert.deepEqual(await withdraw(admin, http, w, "op2", proposalRef), { ok: false, reason: "ERR-CM-01" });
    assert.equal((await ledgerOf(admin, w.tenantId, w.revocationRef)).length, 2);
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1020 pg platform: aislamiento cross-tenant del retiro RH2 (RLS FORCE + sesion CASE ligada al caso): el tenant B no ve ni retira la propuesta del tenant A y la fila de A queda intacta", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const a = await seedCaseWorld(ctx, "1020a");
  const b = await seedCaseWorld(ctx, "1020b");
  assert.notEqual(a.tenantId, b.tenantId);
  const http = await startPlatformHttp(ctx);
  try {
    const pa = fixtureUuid("p-1020a");
    const pb = fixtureUuid("p-1020b");
    await propose(admin, http, a, pa);
    await propose(admin, http, b, pb);
    // La sesion CASE de B (su caso) sobre el caso de A: la base no la acepta (RC004 -> NOT_FOUND uniforme); el step-up queda sin efecto.
    await seedAttestedStepUp(admin, b.op1.principal, "WITHDRAW_CASE_VERIFICATION", pa);
    assert.deepEqual(await http.cases.withdraw({ sid: b.op1.caseSession.sid, caseRef: a.caseRef, proposalRef: pa, limit: LIMIT }), { ok: false, reason: "NOT_FOUND" });
    // Refs mezclados dentro del caso de B: la propuesta de A sobre la Revocation de B es ajena (ERR-CM-01).
    assert.deepEqual(await withdraw(admin, http, b, "op1", pa), { ok: false, reason: "ERR-CM-01" });
    // Operador de A sobre el caso de B: igual NOT_FOUND.
    await seedAttestedStepUp(admin, a.op1.principal, "WITHDRAW_CASE_VERIFICATION", pb);
    assert.deepEqual(await http.cases.withdraw({ sid: a.op1.caseSession.sid, caseRef: b.caseRef, proposalRef: pb, limit: LIMIT }), { ok: false, reason: "NOT_FOUND" });
    assert.equal((await revocationRow(admin, a)).proposal_ref, pa, "la propuesta de A sigue PENDING");
    assert.equal((await revocationRow(admin, b)).proposal_ref, pb, "la propuesta de B sigue PENDING");
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE event_type = 'REVOCATION_PROPOSAL_WITHDRAWN' AND tenant_id = ANY($1)", [[a.tenantId, b.tenantId]])).rows[0]?.n, 0, "ningun retiro cruzado registrado");
    // El retiro legitimo en A sigue funcionando y no toca a B.
    assert.equal((await withdraw(admin, http, a, "op1", pa)).ok, true);
    assert.equal((await revocationRow(admin, b)).proposal_ref, pb);
    assert.deepEqual((await ledgerOf(admin, b.tenantId, b.revocationRef)).map((e) => e.eventType), ["REVOCATION_REQUESTED"]);
  } finally {
    await http.close();
  }
});
