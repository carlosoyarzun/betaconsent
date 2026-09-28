// Gobierna: contracts/schemas/ledger-event-payloads.schema.json (lista blanca de payloads del
// ledger por eventType, INV-CM-05) y contracts/openapi/consent-it0.openapi.yaml (API-CNS-127
// DecisionRecorded.receiptRef). Fix P1 (CA-116, seguimiento del fix de contrato HTTP): el
// evento RECEIPT_CREATED (consent-decision.ts) usaba un receiptRef con formato
// `receipt:${consentId}` (no Ref/UUID) y no incluía `managementLinkIssued`
// (ledger-event-payloads.schema.json:415-430), y el mismo receiptRef nunca coincidía con el
// que ahora expone POST /decision/submit (DecisionRecorded.receiptRef). Además, al validar
// contra el schema los demás eventos que el dominio ya emite, INVITATION_READY,
// RIGHTS_CASE_CONTACTING y RIGHTS_CASE_CLOSED resultaron incompletos (faltaban campos ya
// disponibles en el dominio, sin necesidad de ninguna decisión nueva); se corrigen en el mismo
// commit. Los demás eventos emitidos con discrepancias (INVITATION_CREATED, INVITATION_SENT,
// INVITATION_VERIFIED, DECISION_MAKER_CHANNEL_VERIFIED, CONSENT_VERSION_VIEWED,
// DECISION_MAKER_AUTHORITY_DECLARED, CONSENT_GRANTED, CONSENT_DECLINED, REVOCATION_VERIFIED,
// REVOCATION_REQUESTED, CONSENT_REVOKED, REVOCATION_CONFIRMED) requieren datos que el dominio
// IT0 de este alcance no produce (bindingResult OPEN-CT-03, relationshipRef DEC-BR-003/LD-01,
// consentTextHash LD-06, assuranceLevel LD-02/OPEN-RV-01, verifiedByRef/secondApproverRef del
// doble control RH2 aún no implementado, authPath/scope/initiatedVia de R1/R3): quedan fuera
// de este archivo y se reportan como finding, no se fuerza un valor inventado.
// TEST-CNS-525..TEST-CNS-531 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";

import {
  createInvitation,
  markInvitationReady,
  openInvitation,
  sendInvitation,
} from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, submitOtp } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { recordDecisionStep, startDecision, submitDecision } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import type { ConsentDecisionPorts } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import type { OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { confirmCaseReturnViaHandle, closeCase, type RightsCasePorts } from "../../../src/server/modules/rights-case/rights-case.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import {
  createInMemoryTenantHandleAdapter,
  type InMemoryTenantHandleAdapter,
} from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { validateLedgerEventPayload, type ValidationResult } from "../schema-lite.ts";

const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+ledger-channel@example.invalid";
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));
const DECLINE_FIRST = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose, i) => ({
  purpose,
  choice: i === 0 ? ("DECLINE" as const) : ("GRANT" as const),
}));

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

interface Ports {
  readonly ledger: ReturnType<typeof createInMemoryLedgerAdapter>;
  readonly invitation: InvitationPorts;
  readonly otp: OtpChallengePorts;
  readonly decision: ConsentDecisionPorts;
}

function buildPorts(): Ports {
  const ledger = createInMemoryLedgerAdapter();
  const invitation: InvitationPorts = {
    invitationRepo: createInMemoryInvitationRepository(),
    eligibility: createInMemoryEligibilityAdapter(),
    ledger,
  };
  const otp: OtpChallengePorts = {
    otpRepo: createInMemoryOtpVerificationRepository(),
    channel: createInMemoryOtpChannelSink(),
    ledger,
    invitation,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
  const decision: ConsentDecisionPorts = {
    repo: createInMemoryConsentDecisionRepository(),
    ledger,
    invitation,
    config: LECTORPRO_BETA_CONFIG,
    // LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
    relationships: { allowedRelationshipRefs: ["IT0_SYNTHETIC_GUARDIAN"] },
  };
  return { ledger, invitation, otp, decision };
}

interface PendingDecision {
  readonly invitationRef: string;
  readonly consentId: string;
  readonly decisionMakerRef: string;
}

/** Recorre I1..I4 -> V1/V3 -> C1/C2 hasta dejar la decisión lista para C3/C5 (submitDecision).
 * invitationRef/consentId/subjectRef son UUIDv4 reales (common.schema.json#/$defs/Ref exige el
 * patrón; los demás refs de este archivo no se validan contra Ref, así que se mantienen
 * legibles para depurar). */
function bringToPendingDecision(ports: Ports, suffix: string): PendingDecision {
  const invitationRef = randomUUID();
  const verificationRef = `ver-${suffix}`;
  const consentId = randomUUID();
  const decisionMakerRef = `dm-${suffix}`;

  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: randomUUID(),
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
  openInvitation(ports.invitation, TENANT_ID, token);

  requestOtp(ports.otp, TENANT_ID, verificationRef, invitationRef, CHANNEL_REF);
  const sink = ports.otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const code = sink.sent[sink.sent.length - 1]?.code ?? "";
  submitOtp(ports.otp, TENANT_ID, verificationRef, code, decisionMakerRef);

  startDecision(ports.decision, TENANT_ID, "DECISION_MAKER", {
    consentId,
    invitationRef,
    verificationRef,
    decisionMakerRef,
  });
  recordDecisionStep(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, { stepKind: "CONTEXT_INFORMATION_VIEWED" });
  recordDecisionStep(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, { stepKind: "CONSENT_VERSION_VIEWED" });
  recordDecisionStep(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, {
    stepKind: "DECISION_MAKER_AUTHORITY_DECLARED",
    relationshipRef: "IT0_SYNTHETIC_GUARDIAN",
    authorityDeclared: true,
  });
  recordDecisionStep(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, {
    stepKind: "SUBJECT_CONFIRMED",
    subjectConfirmed: true,
  });
  return { invitationRef, consentId, decisionMakerRef };
}

// ---------------------------------------------------------------------------
// RECEIPT_CREATED (ledger-event-payloads.schema.json:415-430) — el P1 de este fix.
// ---------------------------------------------------------------------------

test("TEST-CNS-525: RECEIPT_CREATED (C3 GRANTED) valida contra el schema y usa el mismo receiptRef (UUID) que expone POST /decision/submit", () => {
  const ports = buildPorts();
  const { consentId, decisionMakerRef } = bringToPendingDecision(ports, "525");
  const decided = submitDecision(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, GRANT_ALL);

  const receiptEvents = ports.ledger.listByAggregate(TENANT_ID, "ConsentDecision", consentId).filter((e) => e.eventType === "RECEIPT_CREATED");
  assert.equal(receiptEvents.length, 1);
  const payload = receiptEvents[0]?.payload as { receiptRef: string; managementLinkIssued: boolean };
  assertValid(validateLedgerEventPayload("RECEIPT_CREATED", payload));
  // El receiptRef del ledger es el MISMO que expone la respuesta HTTP (decided.receiptRef), no
  // uno distinto derivado por separado.
  assert.equal(payload.receiptRef, decided.receiptRef);
  // IT0 nunca emite management_token en este slice (x-scope-note consent-flow.handler.ts): el
  // valor factual es false, no un placeholder.
  assert.equal(payload.managementLinkIssued, false);
});

test("TEST-CNS-526: RECEIPT_CREATED (C5 DECLINED) también valida contra el schema con su propio receiptRef (UUID)", () => {
  const ports = buildPorts();
  const { consentId, decisionMakerRef } = bringToPendingDecision(ports, "526");
  const decided = submitDecision(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, DECLINE_FIRST);

  const receiptEvents = ports.ledger.listByAggregate(TENANT_ID, "ConsentDecision", consentId).filter((e) => e.eventType === "RECEIPT_CREATED");
  assert.equal(receiptEvents.length, 1);
  const payload = receiptEvents[0]?.payload as { receiptRef: string; managementLinkIssued: boolean };
  assertValid(validateLedgerEventPayload("RECEIPT_CREATED", payload));
  assert.equal(payload.receiptRef, decided.receiptRef);
  assert.equal(payload.managementLinkIssued, false);
});

// ---------------------------------------------------------------------------
// Otros eventos ya emitidos por el dominio: validados contra el mismo schema.
// ---------------------------------------------------------------------------

test("TEST-CNS-527: INVITATION_READY valida contra el schema (expiresAt y recipientBinding, antes ausentes)", () => {
  const ports = buildPorts();
  const invitationRef = randomUUID();
  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: randomUUID(),
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const event = ports.ledger.listByAggregate(TENANT_ID, "Invitation", invitationRef).find((e) => e.eventType === "INVITATION_READY");
  assert.ok(event);
  assertValid(validateLedgerEventPayload("INVITATION_READY", event.payload));
});

test("TEST-CNS-528: INVITATION_OPENED, INVITATION_COMPLETED y INVITATION_DECLINED ya cumplían el schema (regresión)", () => {
  const grantedPorts = buildPorts();
  const granted = bringToPendingDecision(grantedPorts, "528g");
  submitDecision(grantedPorts.decision, TENANT_ID, "DECISION_MAKER", granted.decisionMakerRef, granted.consentId, GRANT_ALL);
  const grantedEvents = grantedPorts.ledger.listByAggregate(TENANT_ID, "Invitation", granted.invitationRef);
  const opened = grantedEvents.find((e) => e.eventType === "INVITATION_OPENED");
  const completed = grantedEvents.find((e) => e.eventType === "INVITATION_COMPLETED");
  assert.ok(opened && completed);
  assertValid(validateLedgerEventPayload("INVITATION_OPENED", opened.payload));
  assertValid(validateLedgerEventPayload("INVITATION_COMPLETED", completed.payload));

  const declinedPorts = buildPorts();
  const declined = bringToPendingDecision(declinedPorts, "528d");
  submitDecision(declinedPorts.decision, TENANT_ID, "DECISION_MAKER", declined.decisionMakerRef, declined.consentId, DECLINE_FIRST);
  const declinedEvent = declinedPorts.ledger
    .listByAggregate(TENANT_ID, "Invitation", declined.invitationRef)
    .find((e) => e.eventType === "INVITATION_DECLINED");
  assert.ok(declinedEvent);
  assertValid(validateLedgerEventPayload("INVITATION_DECLINED", declinedEvent.payload));
});

test("TEST-CNS-529: CONTEXT_INFORMATION_VIEWED, SUBJECT_CONFIRMED y PURPOSE_DECISION_RECORDED ya cumplían el schema (regresión)", () => {
  const ports = buildPorts();
  const { consentId, decisionMakerRef } = bringToPendingDecision(ports, "529");
  submitDecision(ports.decision, TENANT_ID, "DECISION_MAKER", decisionMakerRef, consentId, GRANT_ALL);
  const events = ports.ledger.listByAggregate(TENANT_ID, "ConsentDecision", consentId);

  const contextViewed = events.find((e) => e.eventType === "CONTEXT_INFORMATION_VIEWED");
  const subjectConfirmed = events.find((e) => e.eventType === "SUBJECT_CONFIRMED");
  const purposeEvents = events.filter((e) => e.eventType === "PURPOSE_DECISION_RECORDED");
  assert.ok(contextViewed && subjectConfirmed);
  assert.equal(purposeEvents.length, GRANT_ALL.length);
  assertValid(validateLedgerEventPayload("CONTEXT_INFORMATION_VIEWED", contextViewed.payload));
  assertValid(validateLedgerEventPayload("SUBJECT_CONFIRMED", subjectConfirmed.payload));
  for (const event of purposeEvents) {
    assertValid(validateLedgerEventPayload("PURPOSE_DECISION_RECORDED", event.payload));
  }
});

// ---------------------------------------------------------------------------
// rights-case.ts: RIGHTS_CASE_CONTACTING y RIGHTS_CASE_CLOSED (faltaba caseRef, requerido).
// ---------------------------------------------------------------------------

interface RightsCaseTestPorts extends RightsCasePorts {
  readonly tenantHandle: InMemoryTenantHandleAdapter;
}

function buildRightsCasePorts(): RightsCaseTestPorts {
  return {
    tenantHandle: createInMemoryTenantHandleAdapter(),
    rightsCaseRepo: createInMemoryRightsCaseRepository(),
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
  };
}

test("TEST-CNS-530: RIGHTS_CASE_CONTACTING valida contra el schema (caseRef, antes ausente y requerido)", () => {
  const ports = buildRightsCasePorts();
  const caseRef = randomUUID();
  ports.tenantHandle.issue({ handle: "handle-530", tenantId: TENANT_ID, chainRef: "chain-530", revokedDecisionRef: "decision-530" });
  ports.rightsCaseRepo.save({
    caseRef,
    tenantId: TENANT_ID,
    chainRef: "chain-530",
    revokedDecisionRef: "decision-530",
    status: "OPEN",
    origin: "CHANNEL_UNREACHABLE",
  });
  confirmCaseReturnViaHandle(ports, "handle-530");
  const event = ports.ledger.listByAggregate(TENANT_ID, "RightsCase", caseRef).find((e) => e.eventType === "RIGHTS_CASE_CONTACTING");
  assert.ok(event);
  assertValid(validateLedgerEventPayload("RIGHTS_CASE_CONTACTING", event.payload));
});

test("TEST-CNS-531: RIGHTS_CASE_CLOSED valida contra el schema (caseRef, antes ausente y requerido)", () => {
  const ports = buildRightsCasePorts();
  const caseRef = randomUUID();
  ports.rightsCaseRepo.save({
    caseRef,
    tenantId: TENANT_ID,
    chainRef: "chain-531",
    revokedDecisionRef: "decision-531",
    status: "CONTACTING",
    origin: "CHANNEL_UNREACHABLE",
  });
  closeCase(ports, TENANT_ID, caseRef, "RESOLVED");
  const event = ports.ledger.listByAggregate(TENANT_ID, "RightsCase", caseRef).find((e) => e.eventType === "RIGHTS_CASE_CLOSED");
  assert.ok(event);
  assertValid(validateLedgerEventPayload("RIGHTS_CASE_CLOSED", event.payload));
});
