// Gobierna: specs/state-machines/revocation.spec.yaml R4 (emits CONSENT_REVOKED, RECEIPT_CREATED;
// GRD-RV-29: authPath/recoveryMethod derivados del registro, INV-RV-07), y
// contracts/schemas/ledger-event-payloads.schema.json CONSENT_REVOKED / RECEIPT_CREATED;
// contracts/schemas/api-payloads.schema.json CaseConfirmationAck. CA-127 (FINDING P1;
// decisión de Carlos 2026-09-28, opción (a)). TEST-CNS-680..685.
// El outbox consent.revoked de R4 se prueba en outbox-consent-revoked.test.ts (TEST-CNS-688..697).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";

import {
  attestHumanAssistedVerification,
  confirmRevocation,
  cosignCaseConfirmation,
  applyRevocation,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  requestRevocation,
  resolveRecoveryTokenForRedeem,
  revokeWithRecoveryLink,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { withSyntheticFallback } from "../../contract/synthetic-decision.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import { validateApiPayload, validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const T = "tenant-1";
const D1 = "680a3c52-8d4e-4a7b-9c21-0e5a7d3b9f01"; // revokedDecisionRef sintético (UUIDv4)

function makePorts(revocationRepo: RevocationRepositoryPort = createInMemoryRevocationRepository()) {
  const ports = withInMemoryTenancy({
    revocationRepo,
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo: withSyntheticFallback(createInMemoryConsentDecisionRepository()),
  });
  return ports;
}

const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
]);

async function selfService(ref: string) {
  const ports = makePorts();
  await requestRevocation(ports, T, { revocationRef: ref, chainRef: `chain-${ref}`, revokedDecisionRef: D1 });
  await verifyRevocationOtp(ports, T, ref, fixtureUuid("ver-680"));
  return ports;
}

async function rh3(ref: string, ports: RevocationPorts = makePorts()) {
  await ports.revocationRepo.save({ revocationRef: ref, tenantId: T, chainRef: `chain-${ref}`, caseRef: fixtureUuid(`case-${ref}`), revokedDecisionRef: D1, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, T, ref, fixtureUuid(`case-${ref}`));
  await recordCaseConfirmationPendingCosign(ports, staff, T, ref, fixtureUuid(`case-${ref}`), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
  return ports;
}

test("TEST-CNS-680: CONSENT_REVOKED de autoservicio valida contra el schema con authPath OTP, sin recoveryMethod, effectiveAt de servidor", async () => {
  const REV = "680b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = await selfService(REV);
  const before = Date.now();
  await confirmRevocation(ports, T, REV);
  const event = (await ports.ledger.listByAggregate(T, "Revocation", REV)).find((e) => e.eventType === "CONSENT_REVOKED");
  assert.ok(event);
  const result = validateLedgerEventPayload("CONSENT_REVOKED", event.payload);
  assert.ok(result.ok, result.errors.join("\n"));
  const payload = event.payload as Record<string, unknown>;
  assert.deepEqual(
    { authPath: payload.authPath, recoveryMethod: payload.recoveryMethod, scope: payload.scope, originPurposeRef: payload.originPurposeRef, revokedDecisionRef: payload.revokedDecisionRef },
    { authPath: "OTP", recoveryMethod: undefined, scope: "ALL", originPurposeRef: "ALL", revokedDecisionRef: D1 },
  );
  assert.ok(Date.parse(payload.effectiveAt as string) >= before - 1000);
});

test("TEST-CNS-681: CONSENT_REVOKED por enlace de recuperación valida contra el schema con authPath RECOVERY y recoveryMethod CHANNEL_LINK", async () => {
  const ports = makePorts();
  await ports.consentDecisionRepo.save({
    consentId: D1, tenantId: T, contextRef: "ctx-test", productRef: "prod-test", subjectRef: fixtureUuid("subject-test"), decisionMakerRef: "dm-test",
    invitationRef: "inv-test", verificationRef: "ver-test", chainRef: fixtureUuid("chain-681"), state: "GRANTED", purposes: [], priorStepsComplete: true, stepsRecorded: [],
  });
  await issueRecoveryLinkBearer(ports, T, fixtureUuid("chain-681"), D1, "REQUESTER_ASKED");
  const token = ports.recoveryLinkChannel.sent[ports.recoveryLinkChannel.sent.length - 1]!.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);
  const outcome = await revokeWithRecoveryLink(ports, T, fixtureUuid("chain-681"), D1, resolved.tokenHash);
  assert.equal(outcome.kind, "CONFIRMED");
  const ref = (outcome as { revocationRef: string }).revocationRef;
  assertRevocationEvidence(await ports.ledger.listByAggregate(T, "Revocation", ref), { revocationRef: ref, authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", revokedDecisionRef: D1 });
});

test("TEST-CNS-682: CONSENT_REVOKED por co-firma RH3 valida contra el schema con authPath RECOVERY y recoveryMethod HUMAN_ASSISTED (caso humano)", async () => {
  const REV = "682b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = await rh3(REV);
  await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assertRevocationEvidence(await ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED", revokedDecisionRef: D1 });
});

test("TEST-CNS-683: RECEIPT_CREATED de la revocación valida contra el schema y su receiptRef coincide con el revocationRef mostrado como comprobante", async () => {
  const REV = "683b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = await selfService(REV);
  const shown = (await confirmRevocation(ports, T, REV)).revocationRef; // el "Comprobante" de la UI es revocationRef
  const receipt = (await ports.ledger.listByAggregate(T, "Revocation", REV)).find((e) => e.eventType === "RECEIPT_CREATED");
  assert.ok(receipt);
  const result = validateLedgerEventPayload("RECEIPT_CREATED", receipt.payload);
  assert.ok(result.ok, result.errors.join("\n"));
  assert.deepEqual(receipt.payload, { receiptRef: shown, managementLinkIssued: false });
});

test("TEST-CNS-684: aplicar dos veces (autoservicio y RH3) no duplica CONSENT_REVOKED ni RECEIPT_CREATED", async () => {
  const REV = "684b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = await selfService(REV);
  await confirmRevocation(ports, T, REV);
  await confirmRevocation(ports, T, REV);
  assertRevocationEvidence(await ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "OTP" });

  const REV2 = "684c3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const p2 = await rh3(REV2);
  await cosignCaseConfirmation(p2, staff, T, REV2, fixtureUuid(`case-${REV2}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  await cosignCaseConfirmation(p2, staff, T, REV2, fixtureUuid(`case-${REV2}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assertRevocationEvidence(await p2.ledger.listByAggregate(T, "Revocation", REV2), { revocationRef: REV2, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });
});

test("TEST-CNS-685: la ack de co-firma devuelve APPLIED (valida contra CaseConfirmationAck); si R4 falla el error se propaga y la Revocation queda como antes del cosign (VERIFIED, todo-o-nada)", async () => {
  assert.ok(validateApiPayload("CaseConfirmationAck", { cosign: "COSIGNED", revocationState: "APPLIED" }).ok);

  const REV = "685b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const inner = createInMemoryRevocationRepository();
  let failApply = true;
  const flaky: RevocationRepositoryPort = {
    ...inner,
    findByRef: (t, r) => inner.findByRef(t, r),
    async save(record) {
      if (record.status === "APPLIED" && failApply) throw new Error("R4 falló (simulado)");
      await inner.save(record);
    },
  };
  const ports = await rh3(REV, makePorts(flaky));
  await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") }), /R4 falló/);
  // CA-124 (P2 de lampone-security): cosign + R4 son UNA unidad de trabajo; si R4 falla no queda
  // ninguna escritura (la Revocation sigue VERIFIED, sin REVOCATION_CONFIRMED ni CONSENT_REVOKED).
  assert.equal((await inner.findByRef(T, REV))?.status, "VERIFIED");
  assert.equal((await ports.ledger.listByAggregate(T, "Revocation", REV)).filter((e) => e.eventType === "CONSENT_REVOKED" || e.eventType === "REVOCATION_CONFIRMED").length, 0);

  failApply = false; // reintento: repite cosign + R4 completos y converge sin duplicar eventos
  const retried = await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(retried.status, "APPLIED");
  assertRevocationEvidence(await ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });
});

test("TEST-CNS-686: R4 sin authPath/revokedDecisionRef en el registro falla cerrado (ERR-CM-06), sin CONSENT_REVOKED ni valores inventados", async () => {
  const REV = "686b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = makePorts();
  await ports.revocationRepo.save({ revocationRef: REV, tenantId: T, chainRef: fixtureUuid("chain-686"), status: "CONFIRMED" });
  await assert.rejects(() => applyRevocation(ports, T, REV), (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-06");
  assert.equal((await ports.ledger.listByAggregate(T, "Revocation", REV)).length, 0);
  assert.equal((await ports.revocationRepo.findByRef(T, REV))?.status, "CONFIRMED");
});
