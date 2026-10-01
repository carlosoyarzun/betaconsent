// Gobierna: otp-challenge.spec V1/V5 (EXPIRED terminal; "se puede crear un challenge nuevo"), GRD-OT-08, SEC-CNS-016 P2-3.
// TEST-CNS-850: V1 con el challenge activo ya expirado lo vence y emite uno nuevo (ref fresca); con uno vigente es idempotente.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const T = "tenant-850";
const CH = "test+channel-850@example.invalid";

test("TEST-CNS-850: V1 con el activo expirado: pasa a EXPIRED y se emite uno nuevo con ref fresca; con el activo vigente devuelve el mismo", async () => {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo });
  const invitation: InvitationPorts = { invitationRepo, eligibility: createInMemoryEligibilityAdapter(), ledger, ...tenancy };
  const channel = createInMemoryOtpChannelSink();
  const otp: OtpChallengePorts = { otpRepo, channel, ledger, uow: tenancy.uow, invitation, policy: { codeLength: 6, maxAttempts: 3, ttlMs: 30, maxResends: 3 }, secret: randomBytes(32) };
  await createInvitation(invitation, T, "INVITER", { invitationRef: "inv-850", contextRef: "BETA_2026_01", productRef: "LECTORPRO", subjectRef: "test+s850@example.invalid" });
  await markInvitationReady(invitation, T, "INVITER", "inv-850", { consentVersion: "v1", expiresAt: new Date(Date.now() + 60_000), recipientChannelRef: CH });
  const { token } = await sendInvitation(invitation, T, "INVITER", "inv-850");
  await openInvitation(invitation, T, token);

  const first = await requestOtp(otp, T, "ver-850", "inv-850", CH);
  assert.equal((await requestOtp(otp, T, "ver-850", "inv-850", CH)).verificationRef, first.verificationRef, "vigente: idempotente");
  assert.equal(channel.sent.length, 1);

  await new Promise((r) => setTimeout(r, 60));
  const second = await requestOtp(otp, T, "ver-850", "inv-850", CH);
  assert.notEqual(second.verificationRef, first.verificationRef, "ref fresca (la expirada no se reutiliza)");
  assert.equal(second.state, "CODE_SENT");
  assert.equal((await otpRepo.findByRef(T, first.verificationRef))?.state, "EXPIRED");
  assert.equal(channel.sent.length, 2, "se envia el codigo del challenge nuevo");
});
