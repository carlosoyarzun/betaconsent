// Gobierna: CA-124 (PR-D), SEC-CNS-015 P2-E (lock de fila + expectedSequence capturado ANTES del lock en toda
// transicion que decide estado), common/ledger-append.ts (regla y sequencedAppender), otp-challenge.spec V3,
// consent-decision.spec C3/C5, rights-case.spec RC2u/RC4-6.
// TEST-CNS-842 (otp), TEST-CNS-843 (decision), TEST-CNS-844 (rights-case): si el agregado avanza entre la lectura de
// la base y el lock de fila, el append falla con LedgerSequenceConflictError y la unidad no deja nada; en el camino
// feliz cada append declara base + k. SYNTHETIC DATA ONLY.

import { rightsCaseOpenedPayload } from "../../contract/ledger-payload-fixtures.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, submitOtp, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { recordDecisionStep, startDecision, submitDecision, type ConsentDecisionPorts } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { closeCase, confirmCaseReturnViaHandle, type RightsCasePorts } from "../../../src/server/modules/rights-case/rights-case.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { LedgerSequenceConflictError, type LedgerEventInput, type LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const T = "tenant-842";
const CHANNEL_REF = "test+channel-842@example.invalid";
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

/** Ledger que registra los appends y deja pasar. */
function recordingLedger(): { ledger: ReturnType<typeof createInMemoryLedgerAdapter>; seen: LedgerEventInput[] } {
  const inner = createInMemoryLedgerAdapter();
  const seen: LedgerEventInput[] = [];
  const ledger = {
    ...inner,
    async append(event: LedgerEventInput) {
      seen.push(event);
      return inner.append(event);
    },
  } as typeof inner;
  return { ledger, seen };
}

/** Simula "otra unidad avanzo el agregado" justo cuando se pide el lock de fila (despues de capturar la base). */
async function advanceAggregate(ledger: LedgerPort, aggregateId: string, aggregateType: string): Promise<void> {
  const current = await ledger.currentSequence(T, aggregateId);
  await ledger.append({
    expectedSequence: current,
    eventType: "TENANT_STATUS_CHANGED",
    tenantId: T,
    aggregateType,
    aggregateId,
    actorType: "SYSTEM_GUARD",
    payload: { reasonCode: "FOREIGN_UNIT" },
    idempotencyKey: `foreign:${aggregateId}:${current}`,
  });
}

function makeFlow(ledger: LedgerPort, hooks: { otpLock?: () => Promise<void>; decisionLock?: () => Promise<void> } = {}) {
  const invitationRepo = createInMemoryInvitationRepository();
  const baseOtp = createInMemoryOtpVerificationRepository();
  const otpRepo: typeof baseOtp = { ...baseOtp, async findByRefForUpdate(t, ref) { await hooks.otpLock?.(); return baseOtp.findByRefForUpdate(t, ref); } };
  const baseDecision = createInMemoryConsentDecisionRepository();
  const decisionRepo: typeof baseDecision = { ...baseDecision, async findByConsentIdForUpdate(t, id) { await hooks.decisionLock?.(); return baseDecision.findByConsentIdForUpdate(t, id); } };
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, consentDecisionRepo: decisionRepo });
  const invitation: InvitationPorts = { invitationRepo, eligibility: createInMemoryEligibilityAdapter(), ledger, ...tenancy };
  const otp: OtpChallengePorts = {
    otpRepo,
    channel: createInMemoryOtpChannelSink(),
    ledger,
    uow: tenancy.uow,
    invitation,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
  const decision: ConsentDecisionPorts = {
    repo: decisionRepo,
    ledger,
    uow: tenancy.uow,
    invitation,
    config: LECTORPRO_BETA_CONFIG,
    relationships: { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] },
    chainRefKey: deriveChainRefKey(Buffer.alloc(32, 9)),
  };
  return { invitation, otp, decision, invitationRepo, otpRepo, decisionRepo };
}

async function openedWithOtp(flow: ReturnType<typeof makeFlow>): Promise<string> {
  await createInvitation(flow.invitation, T, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: fixtureUuid("inv-842"),
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-842"),
  });
  await markInvitationReady(flow.invitation, T, "INVITER", fixtureUuid("inv-842"), {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(flow.invitation, T, "INVITER", fixtureUuid("inv-842"), { deliveryChannel: "CONSENT_APP_EMAIL" });
  await openInvitation(flow.invitation, T, token);
  await requestOtp(flow.otp, T, fixtureUuid("ver-842"), fixtureUuid("inv-842"), CHANNEL_REF);
  const sink = flow.otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  return sink.sent[sink.sent.length - 1]!.code;
}

test("TEST-CNS-842: otp V3: expectedSequence = base capturada antes del lock (OTP e Invitation I5); si el agregado avanza tras la base, LedgerSequenceConflictError y no queda VERIFIED", async () => {
  // Camino feliz: base declarada.
  {
    const { ledger, seen } = recordingLedger();
    const flow = makeFlow(ledger);
    const code = await openedWithOtp(flow);
    seen.length = 0;
    await submitOtp(flow.otp, T, fixtureUuid("ver-842"), code, fixtureUuid("dm-842"));
    const byType = Object.fromEntries(seen.map((e) => [e.eventType, e.expectedSequence]));
    assert.equal(byType.DECISION_MAKER_CHANNEL_VERIFIED, 1, "tras OTP_ISSUED (seq 1)");
    assert.equal(typeof byType.INVITATION_VERIFIED, "number");
    assert.equal(byType.INVITATION_VERIFIED, await ledger.currentSequence(T, fixtureUuid("inv-842")) - 1, "I5 declara la base de la Invitation");
  }
  // Carrera: otra unidad avanza el challenge entre la base y el lock.
  {
    const { ledger } = recordingLedger();
    let interfere = false;
    const flow = makeFlow(ledger, { otpLock: async () => { if (interfere) { interfere = false; await advanceAggregate(ledger, fixtureUuid("ver-842"), "DecisionMakerVerification"); } } });
    const code = await openedWithOtp(flow);
    interfere = true;
    await assert.rejects(() => submitOtp(flow.otp, T, fixtureUuid("ver-842"), code, fixtureUuid("dm-842")), (e: unknown) => e instanceof LedgerSequenceConflictError);
    const rec = await flow.otpRepo.findByRef(T, fixtureUuid("ver-842"));
    assert.equal(rec?.state, "CODE_SENT");
    assert.equal(rec?.attempts, 0);
    assert.equal((await flow.invitationRepo.findByRef(T, fixtureUuid("inv-842")))?.state, "OPENED");
    const types = (await ledger.listByAggregate(T, "DecisionMakerVerification", fixtureUuid("ver-842"))).map((e) => e.eventType);
    assert.equal(types.includes("DECISION_MAKER_CHANNEL_VERIFIED"), false);
  }
});

test("TEST-CNS-843: decision C3/C5: eventos del agregado declaran base + k (sequencedAppender); si avanza tras la base, LedgerSequenceConflictError y la decision sigue PENDING", async () => {
  const setup = async (hooks: Parameters<typeof makeFlow>[1] = {}) => {
    const { ledger, seen } = recordingLedger();
    const flow = makeFlow(ledger, hooks);
    const code = await openedWithOtp(flow);
    await submitOtp(flow.otp, T, fixtureUuid("ver-842"), code, fixtureUuid("dm-842"));
    await startDecision(flow.decision, T, "DECISION_MAKER", { consentId: fixtureUuid("consent-842"), invitationRef: fixtureUuid("inv-842"), verificationRef: fixtureUuid("ver-842"), decisionMakerRef: fixtureUuid("dm-842") });
    await recordDecisionStep(flow.decision, T, "DECISION_MAKER", fixtureUuid("dm-842"), fixtureUuid("consent-842"), { stepKind: "CONSENT_VERSION_VIEWED" });
    await recordDecisionStep(flow.decision, T, "DECISION_MAKER", fixtureUuid("dm-842"), fixtureUuid("consent-842"), { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true });
    await recordDecisionStep(flow.decision, T, "DECISION_MAKER", fixtureUuid("dm-842"), fixtureUuid("consent-842"), { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true });
    return { ledger, seen, flow };
  };
  {
    const { ledger, seen, flow } = await setup();
    assert.deepEqual(
      seen.filter((e) => e.aggregateId === fixtureUuid("consent-842")).map((e) => e.expectedSequence),
      [0, 1, 2],
      "C2: cada paso declara la base vigente",
    );
    seen.length = 0;
    await submitDecision(flow.decision, T, "DECISION_MAKER", fixtureUuid("dm-842"), fixtureUuid("consent-842"), GRANT_ALL);
    const mine = seen.filter((e) => e.aggregateId === fixtureUuid("consent-842"));
    const n = GRANT_ALL.length;
    // base 3; n finalidades, CONSENT_GRANTED y RECEIPT_CREATED: 3, 4, ..., 3 + n + 1
    assert.deepEqual(mine.map((e) => e.expectedSequence), Array.from({ length: n + 2 }, (_, k) => 3 + k));
    assert.equal(await ledger.currentSequence(T, fixtureUuid("consent-842")), 3 + n + 2);
    assert.equal((await flow.invitationRepo.findByRef(T, fixtureUuid("inv-842")))?.state, "COMPLETED", "I6 en la misma tx");
  }
  {
    let interfere = false;
    const { ledger, flow } = await setup({ decisionLock: async () => { if (interfere) { interfere = false; await advanceAggregate(ledger2(), fixtureUuid("consent-842"), "ConsentDecision"); } } });
    function ledger2(): LedgerPort { return flowLedger; }
    const flowLedger = ledger;
    interfere = true;
    await assert.rejects(() => submitDecision(flow.decision, T, "DECISION_MAKER", fixtureUuid("dm-842"), fixtureUuid("consent-842"), GRANT_ALL), (e: unknown) => e instanceof LedgerSequenceConflictError);
    assert.equal((await flow.decisionRepo.findByConsentId(T, fixtureUuid("consent-842")))?.state, "PENDING");
    assert.equal((await flow.invitationRepo.findByRef(T, fixtureUuid("inv-842")))?.state, "VERIFIED");
    const types = (await ledger.listByAggregate(T, "ConsentDecision", fixtureUuid("consent-842"))).map((e) => e.eventType);
    assert.equal(types.includes("CONSENT_GRANTED"), false);
  }
});

test("TEST-CNS-844: rights-case RC2u y RC4-6: expectedSequence = base previa al lock; si el caso avanza tras la base, LedgerSequenceConflictError y el caso no cambia", async () => {
  const build = async (interferingLock: () => Promise<void>) => {
    const { ledger, seen } = recordingLedger();
    const baseRepo = createInMemoryRightsCaseRepository();
    const rightsCaseRepo: typeof baseRepo = { ...baseRepo, async findByRefForUpdate(t, ref) { await interferingLock(); return baseRepo.findByRefForUpdate(t, ref); } };
    const revocationRepo = createInMemoryRevocationRepository();
    const tenancy = createInMemoryTenancy({ ledger, rightsCaseRepo, revocationRepo });
    const tenantHandle = createInMemoryTenantHandleAdapter([{ handle: "h-844", tenantId: T, chainRef: fixtureUuid("chain-844"), revokedDecisionRef: fixtureUuid("dec-844") }]);
    const ports: RightsCasePorts = { tenantHandle, rightsCaseRepo, revocationRepo, ledger, uow: tenancy.uow };
    await baseRepo.save({ caseRef: fixtureUuid("case-844"), tenantId: T, chainRef: fixtureUuid("chain-844"), revokedDecisionRef: fixtureUuid("dec-844"), status: "OPEN", origin: "CHANNEL_UNREACHABLE" });
    await ledger.append({ expectedSequence: 0, eventType: "RIGHTS_CASE_OPENED", tenantId: T, aggregateType: "RightsCase", aggregateId: fixtureUuid("case-844"), actorType: "HUMAN", payload: { ...rightsCaseOpenedPayload("844"), caseRef: fixtureUuid("case-844") }, idempotencyKey: "opened-844" });
    return { ledger, seen, ports, baseRepo };
  };
  // Camino feliz: base 1 para RC2u y 2 para el cierre.
  {
    const { ledger, seen, ports } = await build(async () => {});
    seen.length = 0;
    await confirmCaseReturnViaHandle(ports, "h-844");
    await closeCase(ports, T, fixtureUuid("case-844"), "RESOLVED");
    assert.deepEqual(seen.map((e) => [e.eventType, e.expectedSequence]), [["RIGHTS_CASE_CONTACTING", 1], ["RIGHTS_CASE_CLOSED", 2]]);
    assert.equal(await ledger.currentSequence(T, fixtureUuid("case-844")), 3);
  }
  // Carrera en RC2u y en el cierre.
  for (const op of ["RC2u", "close"] as const) {
    let interfere = false;
    const ref: { ledger?: LedgerPort } = {};
    const { ledger, ports, baseRepo } = await build(async () => {
      if (interfere) { interfere = false; await advanceAggregate(ref.ledger!, fixtureUuid("case-844"), "RightsCase"); }
    });
    ref.ledger = ledger;
    if (op === "close") await baseRepo.save({ caseRef: fixtureUuid("case-844"), tenantId: T, chainRef: fixtureUuid("chain-844"), revokedDecisionRef: fixtureUuid("dec-844"), status: "CONTACTING", origin: "CHANNEL_UNREACHABLE" });
    interfere = true;
    await assert.rejects(
      () => (op === "RC2u" ? confirmCaseReturnViaHandle(ports, "h-844") : closeCase(ports, T, fixtureUuid("case-844"), "RESOLVED")),
      (e: unknown) => e instanceof LedgerSequenceConflictError,
      op,
    );
    assert.equal((await baseRepo.findByRef(T, fixtureUuid("case-844")))?.status, op === "RC2u" ? "OPEN" : "CONTACTING", op);
  }
});
