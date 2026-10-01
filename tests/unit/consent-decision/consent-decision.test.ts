// Gobierna: specs/state-machines/consent-decision.spec.yaml C1 (StartDecision), C2
// (RecordDecisionStep, subconjunto), C3 (SubmitDecision all_required_granted), C5
// (SubmitDecision required_declined); specs/adapters/lectorpro-beta.spec.yaml (finalidades).
// GRD-CM-02, GRD-CM-05, GRD-CD-01/02/05/06/07/08/11. TEST-CNS-490..TEST-CNS-496.

import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, submitOtp } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { recordDecisionStep, startDecision, submitDecision } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import type { ConsentDecisionPorts } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import type { OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";

const CHANNEL_REF = "test+channel-1@example.invalid";
const TENANT_ID = "tenant-1";

const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));
const DECLINE_ONE = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose, i) => ({
  purpose,
  choice: i === 0 ? ("DECLINE" as const) : ("GRANT" as const),
}));

function makeAllPorts() {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const decisionRepo = createInMemoryConsentDecisionRepository();
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, consentDecisionRepo: decisionRepo });
  const invitationPorts: InvitationPorts = {
    invitationRepo,
    eligibility: createInMemoryEligibilityAdapter(),
    ledger,
    ...tenancy,
  };
  const otpPorts: OtpChallengePorts = {
    otpRepo,
    channel: createInMemoryOtpChannelSink(),
    ledger,
    uow: tenancy.uow,
    invitation: invitationPorts,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
  const consentPorts: ConsentDecisionPorts = {
    repo: decisionRepo,
    ledger,
    uow: tenancy.uow,
    invitation: invitationPorts,
    config: LECTORPRO_BETA_CONFIG,
    // LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
    relationships: { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] },
    chainRefKey: deriveChainRefKey(Buffer.alloc(32, 9)),
  };
  return { invitationPorts, otpPorts, consentPorts };
}

/** Recorre C2 completo (los 3 pasos exigidos por GRD-CD-05: CONSENT_VERSION_VIEWED,
 * DECISION_MAKER_AUTHORITY_DECLARED, SUBJECT_CONFIRMED); CONTEXT_INFORMATION_VIEWED no es
 * requerido y se omite aquí a propósito (ver REQUIRED_STEP_KINDS en consent-decision.ts). */
async function recordRequiredSteps(
  consentPorts: ConsentDecisionPorts,
  tenantId: string,
  consentId: string,
  decisionMakerRef = "dm-1",
): Promise<void> {
  await recordDecisionStep(consentPorts, tenantId, "DECISION_MAKER", decisionMakerRef, consentId, { stepKind: "CONSENT_VERSION_VIEWED" });
  await recordDecisionStep(consentPorts, tenantId, "DECISION_MAKER", decisionMakerRef, consentId, {
    stepKind: "DECISION_MAKER_AUTHORITY_DECLARED",
    relationshipRef: "SYNTHETIC_GUARDIAN",
    authorityDeclared: true,
  });
  await recordDecisionStep(consentPorts, tenantId, "DECISION_MAKER", decisionMakerRef, consentId, {
    stepKind: "SUBJECT_CONFIRMED",
    subjectConfirmed: true,
  });
}

/** Recorre invitación -> OTP hasta dejar la Invitation VERIFIED con un decisionMakerRef. */
async function verifiedInvitation(
  ports: ReturnType<typeof makeAllPorts>,
  decisionMakerRef = "dm-1",
  invitationRef = "inv-1",
  verificationRef = "ver-1",
  subjectRef = "test+subject-1@example.invalid",
) {
  await createInvitation(ports.invitationPorts, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  await markInvitationReady(ports.invitationPorts, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(ports.invitationPorts, TENANT_ID, "INVITER", invitationRef);
  await openInvitation(ports.invitationPorts, TENANT_ID, token);
  await requestOtp(ports.otpPorts, TENANT_ID, verificationRef, invitationRef, CHANNEL_REF);
  const sink = ports.otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const code = sink.sent[sink.sent.length - 1]?.code ?? "";
  await submitOtp(ports.otpPorts, TENANT_ID, verificationRef, code, decisionMakerRef);
}

test("TEST-CNS-490: C1 crea PENDING solo si la Invitation está VERIFIED con este decisionMakerRef (GRD-CD-01/02)", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  const decision = await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  assert.equal(decision.state, "PENDING");

  await assert.rejects(
    () =>
      startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
        consentId: "consent-2",
        invitationRef: "inv-1",
        verificationRef: "ver-1",
        decisionMakerRef: "otro-decisor",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CD-07",
  );
});

test("TEST-CNS-491: C3 sin los pasos previos de C2 -> ERR-CD-04 (GRD-CD-05, INV-2)", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await assert.rejects(
    () => submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", GRANT_ALL),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CD-04",
  );
});

test("TEST-CNS-492: C3 con GRANT explícito en las 4 finalidades requeridas -> GRANTED, dispara I6 y emite el receipt", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-1");

  const granted = await submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", GRANT_ALL);
  assert.equal(granted.state, "GRANTED");

  const invitation = await ports.invitationPorts.invitationRepo.findByRef(TENANT_ID, "inv-1");
  assert.equal(invitation?.state, "COMPLETED");

  const events = (await ports.consentPorts.ledger.listByAggregate(TENANT_ID, "ConsentDecision", "consent-1")).map((e) => e.eventType);
  assert.ok(events.includes("CONSENT_GRANTED"));
  assert.ok(events.includes("RECEIPT_CREATED"));
  assert.equal(events.filter((e) => e === "PURPOSE_DECISION_RECORDED").length, GRANT_ALL.length);
});

test("TEST-CNS-493: C5 con >=1 finalidad requerida en DECLINE -> DECLINED y dispara I7 (invitation DECLINED)", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-1");

  const declined = await submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", DECLINE_ONE);
  assert.equal(declined.state, "DECLINED");

  const invitation = await ports.invitationPorts.invitationRepo.findByRef(TENANT_ID, "inv-1");
  assert.equal(invitation?.state, "DECLINED");
});

test("TEST-CNS-494: C3 con una finalidad requerida faltante o una prohibida -> ERR-CD-02 (GRD-CD-06/07)", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-1");

  const missingOne = GRANT_ALL.slice(1);
  await assert.rejects(
    () => submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", missingOne),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CD-02",
  );

  const withProhibited = [...GRANT_ALL, { purpose: "AI_TRAINING", choice: "GRANT" as const }];
  await assert.rejects(
    () => submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", withProhibited),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CD-02",
  );
});

test("TEST-CNS-495: C3/C5 solo por el DecisionMaker de la cadena; otro actor -> ERR-CM-10 (GRD-CD-11)", async () => {
  const ports = makeAllPorts();
  await verifiedInvitation(ports);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-1");

  await assert.rejects(
    () => submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "otro-decisor", "consent-1", GRANT_ALL),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-10",
  );
});

test("TEST-CNS-496: como máximo una decisión GRANTED activa por decisionChainKey (GRD-CD-08, INV-1)", async () => {
  const ports = makeAllPorts();
  const subjectRef = "test+subject-1@example.invalid";

  // Primer ciclo de la misma cadena (tenant, contexto, sujeto, decisionMaker) -> GRANTED.
  await verifiedInvitation(ports, "dm-1", "inv-1", "ver-1", subjectRef);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-1",
    invitationRef: "inv-1",
    verificationRef: "ver-1",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-1");
  const granted = await submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-1", GRANT_ALL);
  assert.equal(granted.state, "GRANTED");

  // Segundo ciclo: invitación nueva del mismo sujeto (la primera ya es terminal, GRD-IV-01 lo permite),
  // misma decisionChainKey -> el segundo GRANT choca con GRD-CD-08 (INV-1: como máximo uno activo).
  await verifiedInvitation(ports, "dm-1", "inv-2", "ver-2", subjectRef);
  await startDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: "consent-2",
    invitationRef: "inv-2",
    verificationRef: "ver-2",
    decisionMakerRef: "dm-1",
  });
  await recordRequiredSteps(ports.consentPorts, TENANT_ID, "consent-2");
  await assert.rejects(
    () => submitDecision(ports.consentPorts, TENANT_ID, "DECISION_MAKER", "dm-1", "consent-2", GRANT_ALL),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CD-01",
  );
});
