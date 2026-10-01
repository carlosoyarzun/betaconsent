// Gobierna: revocation.spec.yaml RH2 (propose_case_verification + approve_case_verification), GRD-RV-09
// (rh2_dual_control_three_humans, onFail ERR-RV-07), GRD-RC-15 (ERR-RC-10), ledger REVOCATION_VERIFIED HUMAN_ASSISTED
// (verifiedByRef, secondApproverRef), CA-128 X6. TEST-CNS-980..983. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { approveCaseVerification, proposeCaseVerification, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { RH2_APPROVER, RH2_OPERATOR, RH2_ROSTER } from "../../contract/rh2-helper.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { makeX6Env } from "../../contract/x6-revocation-scenarios.ts";

const T = "tenant-x6-980";
const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

async function seedCase(label: string): Promise<{ ports: RevocationPorts; revocationRef: string; caseRef: string; proposalRef: string }> {
  const env = makeX6Env();
  const revocationRef = fixtureUuid(`r-${label}`);
  const caseRef = fixtureUuid(`c-${label}`);
  await env.ports.revocationRepo.save({ revocationRef, tenantId: T, chainRef: `chain-${label}`, caseRef, revokedDecisionRef: fixtureUuid(`d-${label}`), status: "REQUESTED" });
  return { ports: env.ports, revocationRef, caseRef, proposalRef: fixtureUuid(`p-${label}`) };
}
const events = async (ports: RevocationPorts, ref: string) => (await ports.ledger.listByAggregate(T, "Revocation", ref)).map((e) => e.eventType);

test("TEST-CNS-980 RH2: propone el RIGHTS_OPERATOR (sin efecto) y aprueba otro principal APPROVER: VERIFIED HUMAN_ASSISTED con verifiedByRef y secondApproverRef distintos, payload válido; repetir es idempotente", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seedCase("980");
  const proposed = await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" });
  assert.equal(proposed.status, "REQUESTED", "el paso 1 no transiciona");
  assert.deepEqual(await events(ports, revocationRef), [], "ni evento en el paso 1");
  assert.equal((await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" })).proposal?.proposalRef, proposalRef);

  const approved = await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true);
  assert.equal(approved.attestation, "ATTESTED");
  assert.equal(approved.record.status, "VERIFIED");
  assert.deepEqual([approved.record.verifiedAuthPath, approved.record.verifiedRecoveryMethod], ["RECOVERY", "HUMAN_ASSISTED"]);
  const verified = (await ports.ledger.listByAggregate(T, "Revocation", revocationRef)).filter((e) => e.eventType === "REVOCATION_VERIFIED");
  assert.equal(verified.length, 1);
  const payload = verified[0]!.payload as Record<string, unknown>;
  assert.equal(payload.verifiedByRef, RH2_OPERATOR);
  assert.equal(payload.secondApproverRef, RH2_APPROVER);
  assert.notEqual(payload.verifiedByRef, payload.secondApproverRef);
  assert.ok(validateLedgerEventPayload("REVOCATION_VERIFIED", payload).ok);
  // Idempotente por (revocationRef, proposalRef): el mismo aprobador no duplica el evento.
  assert.equal((await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true)).record.status, "VERIFIED");
  assert.equal((await events(ports, revocationRef)).filter((e) => e === "REVOCATION_VERIFIED").length, 1);
});

test("TEST-CNS-981 RH2 GRD-RV-09: rol inválido, principal desconocido o aprobador = proponente -> ERR-RV-07 sin efecto ni evento", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seedCase("981");
  // Propone un APPROVER / un desconocido: ERR-RV-07.
  await assert.rejects(() => proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_APPROVER }, { proposalRef, verificationScriptVersion: "g" }), code("ERR-RV-07"));
  await assert.rejects(() => proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: fixtureUuid("desconocido") }, { proposalRef, verificationScriptVersion: "g" }), code("ERR-RV-07"));
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.proposal, undefined);
  await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "g" });
  // Aprueba un RIGHTS_OPERATOR (incluido el propio proponente) o un desconocido: ERR-RV-07.
  for (const who of [RH2_OPERATOR, fixtureUuid("rh2-operator-2"), fixtureUuid("desconocido")]) {
    await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: who }, true), code("ERR-RV-07"));
  }
  // Aprobador igual al proponente (propuesta sembrada con un APPROVER como proponente): ERR-RV-07.
  const current = (await ports.revocationRepo.findByRef(T, revocationRef))!;
  await ports.revocationRepo.save({ ...current, proposal: { ...current.proposal!, proposedByRef: RH2_APPROVER } });
  await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-RV-07"));
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "REQUESTED");
  assert.deepEqual(await events(ports, revocationRef), []);
});

test("TEST-CNS-982 RH2: aserción no ATTESTED = PENDING sin efecto; propuesta ajena/inexistente y caso ajeno = ERR-CM-01; dotación < 4 = ERR-RC-10", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seedCase("982");
  await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-CM-01"), "sin propuesta");
  await assert.rejects(() => proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, fixtureUuid("otro-caso"), { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "g" }), code("ERR-CM-01"));
  await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "g" });
  await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, fixtureUuid("otra-propuesta"), { principalRef: RH2_APPROVER }, true), code("ERR-CM-01"));
  const pending = await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, false);
  assert.equal(pending.attestation, "PENDING");
  assert.equal(pending.record.status, "REQUESTED");
  assert.deepEqual(await events(ports, revocationRef), []);
  const small = createInMemoryStaffIdentityAdapter([{ principalRef: RH2_OPERATOR, role: "RIGHTS_OPERATOR" }, { principalRef: RH2_APPROVER, role: "APPROVER" }]);
  await assert.rejects(() => approveCaseVerification(ports, small, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-RC-10"));
});

test("TEST-CNS-983 RH2: REVOCATION_VERIFIED HUMAN_ASSISTED NUNCA se emite sin verifiedByRef y secondApproverRef (comprobación explícita del emisor, ERR-RV-13)", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seedCase("983");
  await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "g" });
  const current = (await ports.revocationRepo.findByRef(T, revocationRef))!;
  // Registro corrupto: proponente vacío. El validador de esquema no evalúa el if/then HUMAN_ASSISTED; el emisor sí.
  await ports.revocationRepo.save({ ...current, proposal: { ...current.proposal!, proposedByRef: "" } });
  await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-RV-13"));
  assert.equal((await events(ports, revocationRef)).includes("REVOCATION_VERIFIED"), false);
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "REQUESTED");
});
