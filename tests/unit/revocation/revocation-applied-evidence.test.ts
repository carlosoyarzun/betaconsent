// Gobierna: specs/state-machines/revocation.spec.yaml R4 (emits CONSENT_REVOKED, RECEIPT_CREATED;
// GRD-RV-29: authPath/recoveryMethod derivados del registro, INV-RV-07), y
// contracts/schemas/ledger-event-payloads.schema.json CONSENT_REVOKED / RECEIPT_CREATED;
// contracts/schemas/api-payloads.schema.json CaseConfirmationAck. CA-127 (FINDING P1;
// decisión de Carlos 2026-09-28, opción (a)). TEST-CNS-680..685.
// El outbox consent.revoked de R4 NO se prueba aquí: el dominio no tiene puerto de outbox
// (FINDING P1 reportado; no se crea infraestructura nueva).

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
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import { validateApiPayload, validateLedgerEventPayload } from "../../contract/schema-lite.ts";

const T = "tenant-1";
const D1 = "680a3c52-8d4e-4a7b-9c21-0e5a7d3b9f01"; // revokedDecisionRef sintético (UUIDv4)

function makePorts(revocationRepo: RevocationRepositoryPort = createInMemoryRevocationRepository()) {
  const ports = {
    revocationRepo,
    ledger: createInMemoryLedgerAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
  };
  return ports;
}

const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-03", role: "APPROVER" },
  { principalRef: "staff-synthetic-04", role: "APPROVER" },
]);

function selfService(ref: string) {
  const ports = makePorts();
  requestRevocation(ports, T, { revocationRef: ref, chainRef: `chain-${ref}`, revokedDecisionRef: D1 });
  verifyRevocationOtp(ports, T, ref, "ver-680");
  return ports;
}

function rh3(ref: string, ports: RevocationPorts = makePorts()) {
  ports.revocationRepo.save({ revocationRef: ref, tenantId: T, chainRef: `chain-${ref}`, caseRef: `case-${ref}`, revokedDecisionRef: D1, status: "REQUESTED" });
  attestHumanAssistedVerification(ports, T, ref, `case-${ref}`);
  recordCaseConfirmationPendingCosign(ports, staff, T, ref, `case-${ref}`, { recordedByPrincipalRef: "staff-synthetic-01" });
  return ports;
}

test("TEST-CNS-680: CONSENT_REVOKED de autoservicio valida contra el schema con authPath OTP, sin recoveryMethod, effectiveAt de servidor", () => {
  const REV = "680b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = selfService(REV);
  const before = Date.now();
  confirmRevocation(ports, T, REV);
  const event = ports.ledger.listByAggregate(T, "Revocation", REV).find((e) => e.eventType === "CONSENT_REVOKED");
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

test("TEST-CNS-681: CONSENT_REVOKED por enlace de recuperación valida contra el schema con authPath RECOVERY y recoveryMethod CHANNEL_LINK", () => {
  const ports = makePorts();
  ports.consentDecisionRepo.save({
    consentId: D1, tenantId: T, contextRef: "ctx-test", productRef: "prod-test", subjectRef: "subject-test@example.invalid", decisionMakerRef: "dm-test",
    invitationRef: "inv-test", verificationRef: "ver-test", chainRef: "chain-681", state: "GRANTED", purposes: [], priorStepsComplete: true, stepsRecorded: [],
  });
  issueRecoveryLinkBearer(ports, T, "chain-681", D1, "REQUESTER_ASKED");
  const token = ports.recoveryLinkChannel.sent[ports.recoveryLinkChannel.sent.length - 1]!.recoveryPath.replace("/r/", "");
  const resolved = resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);
  const outcome = revokeWithRecoveryLink(ports, T, "chain-681", D1, resolved.tokenHash);
  assert.equal(outcome.kind, "CONFIRMED");
  const ref = (outcome as { revocationRef: string }).revocationRef;
  assertRevocationEvidence(ports.ledger.listByAggregate(T, "Revocation", ref), { revocationRef: ref, authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", revokedDecisionRef: D1 });
});

test("TEST-CNS-682: CONSENT_REVOKED por co-firma RH3 valida contra el schema con authPath RECOVERY y recoveryMethod HUMAN_ASSISTED (caso humano)", () => {
  const REV = "682b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = rh3(REV);
  cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, { cosignedByPrincipalRef: "staff-synthetic-02" });
  assertRevocationEvidence(ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED", revokedDecisionRef: D1 });
});

test("TEST-CNS-683: RECEIPT_CREATED de la revocación valida contra el schema y su receiptRef coincide con el revocationRef mostrado como comprobante", () => {
  const REV = "683b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = selfService(REV);
  const shown = confirmRevocation(ports, T, REV).revocationRef; // el "Comprobante" de la UI es revocationRef
  const receipt = ports.ledger.listByAggregate(T, "Revocation", REV).find((e) => e.eventType === "RECEIPT_CREATED");
  assert.ok(receipt);
  const result = validateLedgerEventPayload("RECEIPT_CREATED", receipt.payload);
  assert.ok(result.ok, result.errors.join("\n"));
  assert.deepEqual(receipt.payload, { receiptRef: shown, managementLinkIssued: false });
});

test("TEST-CNS-684: aplicar dos veces (autoservicio y RH3) no duplica CONSENT_REVOKED ni RECEIPT_CREATED", () => {
  const REV = "684b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = selfService(REV);
  confirmRevocation(ports, T, REV);
  confirmRevocation(ports, T, REV);
  assertRevocationEvidence(ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "OTP" });

  const REV2 = "684c3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const p2 = rh3(REV2);
  cosignCaseConfirmation(p2, staff, T, REV2, `case-${REV2}`, { cosignedByPrincipalRef: "staff-synthetic-02" });
  cosignCaseConfirmation(p2, staff, T, REV2, `case-${REV2}`, { cosignedByPrincipalRef: "staff-synthetic-02" });
  assertRevocationEvidence(p2.ledger.listByAggregate(T, "Revocation", REV2), { revocationRef: REV2, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });
});

test("TEST-CNS-685: la ack de co-firma devuelve APPLIED (valida contra CaseConfirmationAck); si R4 falla el error se propaga y la Revocation queda CONFIRMED", () => {
  assert.ok(validateApiPayload("CaseConfirmationAck", { cosign: "COSIGNED", revocationState: "APPLIED" }).ok);

  const REV = "685b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const inner = createInMemoryRevocationRepository();
  let failApply = true;
  const flaky: RevocationRepositoryPort = {
    ...inner,
    findByRef: (t, r) => inner.findByRef(t, r),
    save(record) {
      if (record.status === "APPLIED" && failApply) throw new Error("R4 falló (simulado)");
      inner.save(record);
    },
  };
  const ports = rh3(REV, makePorts(flaky));
  assert.throws(() => cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, { cosignedByPrincipalRef: "staff-synthetic-02" }), /R4 falló/);
  assert.equal(inner.findByRef(T, REV)?.status, "CONFIRMED");
  assert.equal(ports.ledger.listByAggregate(T, "Revocation", REV).filter((e) => e.eventType === "CONSENT_REVOKED").length, 0);

  failApply = false; // reintento: reaplica R4 sin duplicar REVOCATION_CONFIRMED
  const retried = cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, { cosignedByPrincipalRef: "staff-synthetic-02" });
  assert.equal(retried.status, "APPLIED");
  assertRevocationEvidence(ports.ledger.listByAggregate(T, "Revocation", REV), { revocationRef: REV, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });
});

test("TEST-CNS-686: R4 sin authPath/revokedDecisionRef en el registro falla cerrado (ERR-CM-06), sin CONSENT_REVOKED ni valores inventados", () => {
  const REV = "686b3c52-8d4e-4a7b-9c21-0e5a7d3b9f01";
  const ports = makePorts();
  ports.revocationRepo.save({ revocationRef: REV, tenantId: T, chainRef: "chain-686", status: "CONFIRMED" });
  assert.throws(() => applyRevocation(ports, T, REV), (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-06");
  assert.equal(ports.ledger.listByAggregate(T, "Revocation", REV).length, 0);
  assert.equal(ports.revocationRepo.findByRef(T, REV)?.status, "CONFIRMED");
});
