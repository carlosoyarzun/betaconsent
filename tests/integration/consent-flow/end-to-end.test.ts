// Gobierna: specs/state-machines/invitation.spec.yaml (I1..I6), otp-challenge.spec.yaml
// (V1, V3), consent-decision.spec.yaml (C1, C2, C3) y common.spec.yaml (ledgerEnvelope,
// tenancy.isolationKey). Recorre el camino feliz completo invitación -> OTP -> decisión en
// memoria y verifica que la cadena del ledger (sequence consecutivo por agregado) y
// tenant_id están presentes en cada evento de los tres agregados. TEST-CNS-497.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

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
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";

const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+channel-1@example.invalid";
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

test("TEST-CNS-497: invitación -> OTP -> decisión en memoria; cadena del ledger consecutiva y tenant_id en cada evento de los tres agregados", async () => {
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

  // Invitation: I1 -> I2 -> I3 -> I4.
  await createInvitation(invitationPorts, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: fixtureUuid("inv-1"),
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-1"),
  });
  await markInvitationReady(invitationPorts, TENANT_ID, "INVITER", fixtureUuid("inv-1"), {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(invitationPorts, TENANT_ID, "INVITER", fixtureUuid("inv-1"), { deliveryChannel: "CONSENT_APP_EMAIL" });
  await openInvitation(invitationPorts, TENANT_ID, token);

  // otp-challenge: V1 -> V3 (dispara I5 sobre Invitation).
  await requestOtp(otpPorts, TENANT_ID, fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const code = sink.sent[0]?.code ?? "";
  await submitOtp(otpPorts, TENANT_ID, fixtureUuid("ver-1"), code, fixtureUuid("dm-1"), 2);

  // consent-decision: C1 -> C2 -> C3 (dispara I6 sobre Invitation).
  await startDecision(consentPorts, TENANT_ID, "DECISION_MAKER", {
    consentId: fixtureUuid("consent-1"),
    invitationRef: fixtureUuid("inv-1"),
    verificationRef: fixtureUuid("ver-1"),
    decisionMakerRef: fixtureUuid("dm-1"),
  });
  await recordDecisionStep(consentPorts, TENANT_ID, "DECISION_MAKER", fixtureUuid("dm-1"), fixtureUuid("consent-1"), { stepKind: "CONSENT_VERSION_VIEWED" });
  await recordDecisionStep(consentPorts, TENANT_ID, "DECISION_MAKER", fixtureUuid("dm-1"), fixtureUuid("consent-1"), {
    stepKind: "DECISION_MAKER_AUTHORITY_DECLARED",
    relationshipRef: "SYNTHETIC_GUARDIAN",
    authorityDeclared: true,
  });
  await recordDecisionStep(consentPorts, TENANT_ID, "DECISION_MAKER", fixtureUuid("dm-1"), fixtureUuid("consent-1"), { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true });
  const decision = await submitDecision(consentPorts, TENANT_ID, "DECISION_MAKER", fixtureUuid("dm-1"), fixtureUuid("consent-1"), GRANT_ALL);

  assert.equal(decision.state, "GRANTED");
  assert.equal((await invitationPorts.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-1")))?.state, "COMPLETED");
  assert.equal((await otpPorts.otpRepo.findByRef(TENANT_ID, fixtureUuid("ver-1")))?.state, "VERIFIED");

  for (const [aggregateType, aggregateId] of [
    ["Invitation", fixtureUuid("inv-1")],
    ["DecisionMakerVerification", fixtureUuid("ver-1")],
    ["ConsentDecision", fixtureUuid("consent-1")],
  ] as const) {
    const events = await ledger.listByAggregate(TENANT_ID, aggregateType, aggregateId);
    assert.ok(events.length > 0, `${aggregateType} debía tener eventos en el ledger`);
    for (const event of events) {
      // tenant_id es la única clave de aislamiento (DEC-BR-015 §1; INV-CM-02): presente en cada evento.
      assert.equal(event.tenantId, TENANT_ID);
    }
    // Cadena consecutiva por agregado (sequence, ADR-002 §2): 1..N sin huecos.
    const sequences = events.map((e) => e.sequence).sort((a, b) => a - b);
    assert.deepEqual(sequences, Array.from({ length: sequences.length }, (_, i) => i + 1));
  }

  const invitationEventTypes = (await ledger.listByAggregate(TENANT_ID, "Invitation", fixtureUuid("inv-1"))).map((e) => e.eventType);
  assert.deepEqual(invitationEventTypes, [
    "INVITATION_CREATED",
    "INVITATION_READY",
    "INVITATION_SENT",
    "INVITATION_OPENED",
    "INVITATION_VERIFIED",
    "INVITATION_COMPLETED",
  ]);
});
