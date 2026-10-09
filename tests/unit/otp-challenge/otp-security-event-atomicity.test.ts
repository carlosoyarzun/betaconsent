// Gobierna: SEC-CNS-021 PR-2 (F-1, INV-21-02), otp-challenge.spec V1/V2/V3. TEST-CNS-1327: si ops.security_event falla (SecurityEventPort.failWith),
// la unidad de trabajo revierte el estado del challenge (no queda challenge, ni intento consumido). In-memory, sintetico.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation, type InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, submitOtp, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { SecurityEventWriteError } from "../../../src/server/ports/security-event.port.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = "tenant-1327";
const CHANNEL_REF = "test+channel-1327@example.invalid";
const INV = fixtureUuid("inv-1327");
const VER = fixtureUuid("ver-1327");

function setup() {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const securityEvents = createInMemorySecurityEventLog();
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, securityEvents });
  const invitation: InvitationPorts = { invitationRepo, eligibility: createInMemoryEligibilityAdapter(), ledger, ...tenancy };
  const channel = createInMemoryOtpChannelSink();
  const otp: OtpChallengePorts = {
    otpRepo, channel, ledger, invitation, uow: tenancy.uow,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 }, secret: randomBytes(32),
  };
  return { invitation, otp, channel, otpRepo, ledger, securityEvents };
}

async function openInv(invitation: InvitationPorts): Promise<void> {
  await createInvitation(invitation, T, "INVITER", {
    enrollmentRef: fixtureUuid("enr-1327"), participationRef: fixtureUuid("part-1327"), invitationRef: INV,
    contextRef: "BETA_2026_01", productRef: "LECTORPRO_BETA", subjectRef: fixtureUuid("subject-1327"),
  });
  await markInvitationReady(invitation, T, "INVITER", INV, { consentVersion: "v1", expiresAt: new Date(Date.now() + 60_000), recipientChannelRef: CHANNEL_REF });
  const { token } = await sendInvitation(invitation, T, "INVITER", INV, { deliveryChannel: "CONSENT_APP_EMAIL" });
  await openInvitation(invitation, T, token);
}

test("TEST-CNS-1327: si security_event falla, requestOtp y submitOtp (incorrecto) revierten el estado del challenge, sin envio ni intento consumido (INV-21-02)", async () => {
  const s = setup();
  await openInv(s.invitation);

  // V1: sin evento no hay challenge ni envio.
  s.securityEvents.failWith = () => true;
  await assert.rejects(() => requestOtp(s.otp, T, VER, INV, CHANNEL_REF), (e: unknown) => e instanceof SecurityEventWriteError);
  assert.equal(await s.otpRepo.findByRef(T, VER), null, "V1 revertido: sin challenge");
  assert.equal(s.channel.sent.length, 0, "nada enviado");
  assert.equal(s.securityEvents.listAll(T).length, 0);

  s.securityEvents.failWith = null;
  await requestOtp(s.otp, T, VER, INV, CHANNEL_REF);
  const code = s.channel.sent[0]!.code;
  const wrong = code === "000000" ? "111111" : "000000";
  assert.equal(s.securityEvents.listAll(T).length, 1);

  // V2: el OTP_FAILED falla -> el intento no se consume.
  s.securityEvents.failWith = () => true;
  await assert.rejects(() => submitOtp(s.otp, T, VER, wrong, fixtureUuid("dm-1327"), 2), (e: unknown) => e instanceof SecurityEventWriteError);
  const rec = await s.otpRepo.findByRef(T, VER);
  assert.equal(rec?.attempts, 0, "V2 revertido: intento no consumido");
  assert.equal(rec?.state, "CODE_SENT");
  assert.equal(s.securityEvents.listAll(T).filter((e) => e.eventType === "OTP_FAILED").length, 0);

  // V3 correcto: no depende de security_event (DECISION_MAKER_CHANNEL_VERIFIED va al ledger), queda VERIFIED.
  s.securityEvents.failWith = null;
  const ok = await submitOtp(s.otp, T, VER, code, fixtureUuid("dm-1327"), 2);
  assert.equal(ok.state, "VERIFIED");
  assert.equal((await s.ledger.listByAggregate(T, "DecisionMakerVerification", VER)).length, 1);
});
