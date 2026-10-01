// Gobierna: CA-128 X6 P2 (Carlos 2026-10-01), API-CNS-140 withdraw_case_verification_proposal, revocation.spec RH2,
// GRD-RV-09, INV-6 (FAILED solo por R8), ledger REVOCATION_PROPOSAL_WITHDRAWN (solo refs). TEST-CNS-1013..1017. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { assertLedgerPayload, LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";
import {
  approveCaseVerification,
  proposeCaseVerification,
  withdrawCaseVerificationProposal,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { RH2_APPROVER, RH2_OPERATOR, RH2_ROSTER } from "../../contract/rh2-helper.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { makeX6Env } from "../../contract/x6-revocation-scenarios.ts";

const T = "tenant-x6-1013";
const OP2 = fixtureUuid("rh2-operator-2");
const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

async function seed(label: string): Promise<{ ports: RevocationPorts; revocationRef: string; caseRef: string; proposalRef: string }> {
  const env = makeX6Env();
  const revocationRef = fixtureUuid(`r-${label}`);
  const caseRef = fixtureUuid(`c-${label}`);
  await env.ports.revocationRepo.save({ revocationRef, tenantId: T, chainRef: fixtureUuid(`chain-${label}`), caseRef, revokedDecisionRef: fixtureUuid(`d-${label}`), status: "REQUESTED" });
  const proposalRef = fixtureUuid(`p-${label}`);
  await proposeCaseVerification(env.ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" });
  return { ports: env.ports, revocationRef, caseRef, proposalRef };
}
const types = async (ports: RevocationPorts, ref: string) => (await ports.ledger.listByAggregate(T, "Revocation", ref)).map((e) => e.eventType);

test("TEST-CNS-1013 retiro RH2: el proponente retira su propuesta PENDING; queda WITHDRAWN, la Revocation sigue REQUESTED (nunca FAILED) y el ledger registra solo refs con payload válido", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seed("1013");
  const record = await withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR });
  assert.equal(record.status, "REQUESTED");
  assert.equal(record.proposal, undefined);
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.proposal, undefined);
  const events = (await ports.ledger.listByAggregate(T, "Revocation", revocationRef)).filter((e) => e.eventType === "REVOCATION_PROPOSAL_WITHDRAWN");
  assert.equal(events.length, 1);
  assert.deepEqual(events[0]!.payload, { revocationRef, caseRef, proposalRef, verificationScriptVersion: "guion-1", withdrawnByRef: RH2_OPERATOR });
  assert.ok(validateLedgerEventPayload("REVOCATION_PROPOSAL_WITHDRAWN", events[0]!.payload).ok);
  assert.deepEqual(await types(ports, revocationRef), ["REVOCATION_PROPOSAL_WITHDRAWN"], "ningun REVOCATION_FAILED ni otro evento");
  // Contrato: la whitelist derivada y assertLedgerPayload lo validan; PII o campo extra no.
  assert.doesNotThrow(() => assertLedgerPayload("REVOCATION_PROPOSAL_WITHDRAWN", events[0]!.payload as Record<string, unknown>));
  const p = events[0]!.payload as Record<string, unknown>;
  assert.throws(() => assertLedgerPayload("REVOCATION_PROPOSAL_WITHDRAWN", { ...p, withdrawnByRef: "operador@example.invalid" }), LedgerPayloadViolationError);
  assert.throws(() => assertLedgerPayload("REVOCATION_PROPOSAL_WITHDRAWN", { ...p, reason: "texto libre" }), LedgerPayloadViolationError);
  assert.throws(() => assertLedgerPayload("REVOCATION_PROPOSAL_WITHDRAWN", { ...p, verificationScriptVersion: "guion con espacios" }), LedgerPayloadViolationError);
  const { withdrawnByRef: _w, ...incomplete } = p;
  assert.throws(() => assertLedgerPayload("REVOCATION_PROPOSAL_WITHDRAWN", incomplete), LedgerPayloadViolationError);
});

test("TEST-CNS-1014 retiro RH2: otro staff (otro RIGHTS_OPERATOR, APPROVER, desconocido) -> ERR-RV-07; proposalRef/caso ajeno -> ERR-CM-01; sin efecto ni evento", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seed("1014");
  for (const who of [OP2, RH2_APPROVER, fixtureUuid("desconocido")]) {
    await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: who }), code("ERR-RV-07"));
  }
  await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, fixtureUuid("otra-propuesta"), { principalRef: RH2_OPERATOR }), code("ERR-CM-01"));
  await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, fixtureUuid("otro-caso"), proposalRef, { principalRef: RH2_OPERATOR }), code("ERR-CM-01"));
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.proposal?.proposalRef, proposalRef, "la propuesta sigue PENDING");
  assert.deepEqual(await types(ports, revocationRef), []);
});

test("TEST-CNS-1015 retiro RH2: una propuesta no PENDING (ya aprobada, Revocation VERIFIED) o ya retirada se rechaza (ERR-CM-06 / ERR-CM-01) sin evento nuevo", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seed("1015");
  await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true);
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "VERIFIED");
  await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR }), code("ERR-CM-06"));
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "VERIFIED", "el retiro rechazado no toca la Revocation");
  assert.deepEqual(await types(ports, revocationRef), ["REVOCATION_VERIFIED"]);

  const second = await seed("1015b");
  await withdrawCaseVerificationProposal(second.ports, RH2_ROSTER, T, second.revocationRef, second.caseRef, second.proposalRef, { principalRef: RH2_OPERATOR });
  await assert.rejects(
    () => withdrawCaseVerificationProposal(second.ports, RH2_ROSTER, T, second.revocationRef, second.caseRef, second.proposalRef, { principalRef: RH2_OPERATOR }),
    code("ERR-CM-01"),
    "WITHDRAWN es terminal: no se retira dos veces",
  );
  assert.equal((await types(second.ports, second.revocationRef)).length, 1);
});

test("TEST-CNS-1016 retiro RH2: aprobar una propuesta retirada se rechaza (ERR-CM-01) y la Revocation no se verifica; la misma proposalRef no se puede reproponer (ERR-CM-06)", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seed("1016");
  await withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR });
  await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-CM-01"));
  assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "REQUESTED");
  assert.ok(!(await types(ports, revocationRef)).includes("REVOCATION_VERIFIED"));
  await assert.rejects(
    () => proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" }),
    code("ERR-CM-06"),
  );
});

test("TEST-CNS-1017 retiro RH2: tras el retiro la Revocation admite una propuesta nueva (otro proponente incluido) que se aprueba hasta VERIFIED", async () => {
  const { ports, revocationRef, caseRef, proposalRef } = await seed("1017");
  await withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR });
  const next = fixtureUuid("p-1017-nueva");
  const proposed = await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: OP2 }, { proposalRef: next, verificationScriptVersion: "guion-2" });
  assert.equal(proposed.proposal?.proposalRef, next);
  assert.equal(proposed.proposal?.proposedByRef, OP2);
  const approved = await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, next, { principalRef: RH2_APPROVER }, true);
  assert.equal(approved.record.status, "VERIFIED");
  assert.deepEqual(await types(ports, revocationRef), ["REVOCATION_PROPOSAL_WITHDRAWN", "REVOCATION_VERIFIED"]);
});
