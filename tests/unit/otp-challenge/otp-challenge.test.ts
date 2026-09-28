// Gobierna: specs/state-machines/otp-challenge.spec.yaml V1 (RequestOtp), V3 (SubmitOtp
// correct_code), V2 (SubmitOtp wrong_code), V4 (LOCKED); GRD-CM-02, GRD-CM-05, GRD-OT-01,
// GRD-OT-02, GRD-OT-04, GRD-OT-05, GRD-OT-07; INV-OT-02. TEST-CNS-483..TEST-CNS-489.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, resendOtp, submitOtp } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import type { OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";

const CHANNEL_REF = "test+channel-1@example.invalid";

function makeOtpPorts(ledger = createInMemoryLedgerAdapter()): { invitationPorts: InvitationPorts; otpPorts: OtpChallengePorts } {
  const invitationPorts: InvitationPorts = {
    invitationRepo: createInMemoryInvitationRepository(),
    eligibility: createInMemoryEligibilityAdapter(),
    ledger,
  };
  const otpPorts: OtpChallengePorts = {
    otpRepo: createInMemoryOtpVerificationRepository(),
    channel: createInMemoryOtpChannelSink(),
    ledger,
    invitation: invitationPorts,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
  return { invitationPorts, otpPorts };
}

function openedInvitation(invitationPorts: InvitationPorts, tenantId = "tenant-1") {
  createInvitation(invitationPorts, tenantId, "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  markInvitationReady(invitationPorts, tenantId, "INVITER", "inv-1", {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(invitationPorts, tenantId, "INVITER", "inv-1");
  openInvitation(invitationPorts, tenantId, token);
}

test("TEST-CNS-483: V1 emite un código al canal ligado y el ledger nunca contiene el código en claro (INV-OT-02)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);

  const record = requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);
  assert.equal(record.state, "CODE_SENT");

  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  assert.equal(sink.sent.length, 1);
  const code = sink.sent[0]?.code ?? "";
  assert.equal(code.length, 6);

  const events = otpPorts.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", "ver-1");
  assert.equal(events.length, 1);
  assert.equal(events[0]?.eventType, "OTP_ISSUED");
  assert.equal(JSON.stringify(events[0]?.payload).includes(code), false);
});

test("TEST-CNS-484: V1 con channelRef distinto del ligado a la invitación -> ERR-OT-08 (GRD-OT-02)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);

  assert.throws(
    () => requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", "test+otro-canal@example.invalid"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-08",
  );
});

test("TEST-CNS-485: V1 sobre una Invitation que no está OPENED/VERIFIED -> ERR-OT-01 (GRD-OT-01)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  createInvitation(invitationPorts, "tenant-1", "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  assert.throws(
    () => requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-01",
  );
});

test("TEST-CNS-486: V3 con el código correcto verifica, dispara I5 (INVITATION_VERIFIED) y consume el challenge una sola vez", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const code = sink.sent[0]?.code ?? "";

  const verified = submitOtp(otpPorts, "tenant-1", "ver-1", code, "dm-1");
  assert.equal(verified.state, "VERIFIED");

  const invitation = invitationPorts.invitationRepo.findByRef("tenant-1", "inv-1");
  assert.equal(invitation?.state, "VERIFIED");
  assert.equal(invitation?.boundDecisionMakerRef, "dm-1");

  // Un solo consumo (INV-OT-07): reintentar tras VERIFIED se rechaza sin volver a comparar.
  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", code, "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-03",
  );
});

test("TEST-CNS-487: V3 con código incorrecto reserva el intento antes de comparar y responde ERR-OT-02 (V2, GRD-OT-04/07)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);

  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const record = otpPorts.otpRepo.findByRef("tenant-1", "ver-1");
  assert.equal(record?.attempts, 1);
  assert.equal(record?.state, "CODE_SENT");
});

test("TEST-CNS-488: agotar los intentos (P-03) bloquea el challenge -> LOCKED / ERR-OT-04 (V4, GRD-OT-04)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);

  for (let i = 0; i < otpPorts.policy.maxAttempts - 1; i += 1) {
    assert.throws(() => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"));
  }
  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
  const record = otpPorts.otpRepo.findByRef("tenant-1", "ver-1");
  assert.equal(record?.state, "LOCKED");

  // LOCKED no tiene salidas (INV-18): ni siquiera con el código correcto.
  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
});

test("TEST-CNS-489: V3 con verificationRef de otro tenant -> 404 uniforme ERR-CM-01 (GRD-CM-02)", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);

  assert.throws(
    () => submitOtp(otpPorts, "tenant-2", "ver-1", "000000", "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-545: V2r reemplaza el código sin reiniciar attempts ni el canal ligado (GRD-OT-06); el código viejo deja de servir", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const oldCode = sink.sent[0]?.code ?? "";

  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const afterOneFail = otpPorts.otpRepo.findByRef("tenant-1", "ver-1");
  assert.equal(afterOneFail?.attempts, 1);

  const resent = resendOtp(otpPorts, "tenant-1", "ver-1");
  assert.equal(resent.state, "CODE_SENT");
  assert.equal(resent.attempts, 1); // NO reinicia attempts (GRD-OT-06)
  assert.equal(resent.resendCount, 1);
  assert.equal(sink.sent.length, 2);
  const newCode = sink.sent[1]?.code ?? "";
  assert.notEqual(newCode, oldCode);

  // El código viejo ya no verifica; el nuevo sí.
  assert.throws(
    () => submitOtp(otpPorts, "tenant-1", "ver-1", oldCode, "dm-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const verified = submitOtp(otpPorts, "tenant-1", "ver-1", newCode, "dm-1");
  assert.equal(verified.state, "VERIFIED");
});

test("TEST-CNS-546: V2r agota el límite de reenvíos (P-06, maxResends) -> ERR-OT-09, sin tocar el challenge", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);

  for (let i = 0; i < otpPorts.policy.maxResends; i += 1) {
    resendOtp(otpPorts, "tenant-1", "ver-1");
  }
  assert.throws(
    () => resendOtp(otpPorts, "tenant-1", "ver-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-09",
  );
  const record = otpPorts.otpRepo.findByRef("tenant-1", "ver-1");
  assert.equal(record?.resendCount, otpPorts.policy.maxResends);
  assert.equal(record?.state, "CODE_SENT");
});

test("TEST-CNS-547: V2r sobre un challenge LOCKED responde ERR-OT-04 sin reemitir código", () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  openedInvitation(invitationPorts);
  requestOtp(otpPorts, "tenant-1", "ver-1", "inv-1", CHANNEL_REF);
  for (let i = 0; i < otpPorts.policy.maxAttempts; i += 1) {
    assert.throws(() => submitOtp(otpPorts, "tenant-1", "ver-1", "000000", "dm-1"));
  }
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const sentBefore = sink.sent.length;

  assert.throws(
    () => resendOtp(otpPorts, "tenant-1", "ver-1"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
  assert.equal(sink.sent.length, sentBefore);
});
