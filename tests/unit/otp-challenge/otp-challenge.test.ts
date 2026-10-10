// Gobierna: specs/state-machines/otp-challenge.spec.yaml V1 (RequestOtp), V3 (SubmitOtp
// correct_code), V2 (SubmitOtp wrong_code), V4 (LOCKED); GRD-CM-02, GRD-CM-05, GRD-OT-01,
// GRD-OT-02, GRD-OT-04, GRD-OT-05, GRD-OT-07; INV-OT-02. TEST-CNS-483..TEST-CNS-489.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
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

import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const CHANNEL_REF = "test+channel-1@example.invalid";

// SEC-CNS-021 PR-4: reloj inyectable (`now`) para P-06 (>= 60 s entre envios) y ttl de 2 h para poder avanzarlo sin expirar el challenge.
function makeOtpPorts(ledger = createInMemoryLedgerAdapter(), securityEvents = createInMemorySecurityEventLog()): { invitationPorts: InvitationPorts; otpPorts: OtpChallengePorts; securityEvents: typeof securityEvents; clock: { ms: number } } {
  const clock = { ms: Date.now() };
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, securityEvents });
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
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 7_200_000 },
    secret: randomBytes(32),
    now: () => clock.ms,
  };
  return { invitationPorts, otpPorts, securityEvents, clock };
}

async function openedInvitation(invitationPorts: InvitationPorts, tenantId = "tenant-1") {
  await createInvitation(invitationPorts, tenantId, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: fixtureUuid("inv-1"),
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: fixtureUuid("subject-1"),
  });
  await markInvitationReady(invitationPorts, tenantId, "INVITER", fixtureUuid("inv-1"), {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(invitationPorts, tenantId, "INVITER", fixtureUuid("inv-1"), { deliveryChannel: "CONSENT_APP_EMAIL" });
  await openInvitation(invitationPorts, tenantId, token);
}

test("TEST-CNS-483: V1 emite un código al canal ligado y ni el ledger ni ops.security_event contienen el código en claro (INV-OT-02); OTP_ISSUED va a security_event, no al ledger (SEC-CNS-021 PR-2)", async () => {
  const { invitationPorts, otpPorts, securityEvents } = makeOtpPorts();
  await openedInvitation(invitationPorts);

  const record = await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  assert.equal(record.state, "CODE_SENT");

  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  assert.equal(sink.sent.length, 1);
  const code = sink.sent[0]?.code ?? "";
  assert.equal(code.length, 6);

  const events = await otpPorts.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", fixtureUuid("ver-1"));
  assert.equal(events.length, 0, "INV-21-02: 0 filas OTP_* en el ledger");
  const sec = securityEvents.listAll("tenant-1");
  assert.equal(sec.length, 1, "INV-21-02: exactamente 1 OTP_ISSUED en security_event");
  assert.equal(sec[0]?.eventType, "OTP_ISSUED");
  assert.equal(JSON.stringify(sec[0]).includes(code), false);
  assert.equal(JSON.stringify(sec[0]).includes(CHANNEL_REF), false, "el canal real nunca sale: solo channelRef opaco");
});

test("TEST-CNS-484: V1 con channelRef distinto del ligado a la invitación -> ERR-OT-08 (GRD-OT-02)", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);

  await assert.rejects(
    () => requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), "test+otro-canal@example.invalid"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-08",
  );
});

test("TEST-CNS-485: V1 sobre una Invitation que no está OPENED/VERIFIED -> ERR-OT-01 (GRD-OT-01)", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await createInvitation(invitationPorts, "tenant-1", "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: fixtureUuid("inv-1"),
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: fixtureUuid("subject-1"),
  });
  await assert.rejects(
    () => requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-01",
  );
});

test("TEST-CNS-486: V3 con el código correcto verifica, dispara I5 (INVITATION_VERIFIED) y consume el challenge una sola vez", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const code = sink.sent[0]?.code ?? "";

  const verified = await submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), code, fixtureUuid("dm-1"), 2);
  assert.equal(verified.state, "VERIFIED");

  const invitation = await invitationPorts.invitationRepo.findByRef("tenant-1", fixtureUuid("inv-1"));
  assert.equal(invitation?.state, "VERIFIED");
  assert.equal(invitation?.boundDecisionMakerRef, fixtureUuid("dm-1"));

  // Un solo consumo (INV-OT-07): reintentar tras VERIFIED se rechaza sin volver a comparar.
  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), code, fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-03",
  );
});

test("TEST-CNS-487: V3 con código incorrecto reserva el intento antes de comparar y responde ERR-OT-02 (V2, GRD-OT-04/07)", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);

  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const record = await otpPorts.otpRepo.findByRef("tenant-1", fixtureUuid("ver-1"));
  assert.equal(record?.attempts, 1);
  assert.equal(record?.state, "CODE_SENT");
});

test("TEST-CNS-488: agotar los intentos (P-03) bloquea el challenge -> LOCKED / ERR-OT-04 (V4, GRD-OT-04)", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);

  for (let i = 0; i < otpPorts.policy.maxAttempts - 1; i += 1) {
    await assert.rejects(() => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2));
  }
  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
  const record = await otpPorts.otpRepo.findByRef("tenant-1", fixtureUuid("ver-1"));
  assert.equal(record?.state, "LOCKED");

  // LOCKED no tiene salidas (INV-18): ni siquiera con el código correcto.
  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
});

test("TEST-CNS-489: V3 con verificationRef de otro tenant -> 404 uniforme ERR-CM-01 (GRD-CM-02)", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);

  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-2", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-545: V2r reemplaza el código sin reiniciar attempts ni el canal ligado (GRD-OT-06); el código viejo deja de servir", async () => {
  const { invitationPorts, otpPorts, clock } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const oldCode = sink.sent[0]?.code ?? "";

  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const afterOneFail = await otpPorts.otpRepo.findByRef("tenant-1", fixtureUuid("ver-1"));
  assert.equal(afterOneFail?.attempts, 1);

  clock.ms += 60_000; // P-06: >= 60 s desde el envio inicial
  const resent = await resendOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"));
  assert.equal(resent.state, "CODE_SENT");
  assert.equal(resent.attempts, 1); // NO reinicia attempts (GRD-OT-06)
  assert.equal(resent.resendCount, 1);
  assert.equal(sink.sent.length, 2);
  const newCode = sink.sent[1]?.code ?? "";
  assert.notEqual(newCode, oldCode);

  // El código viejo ya no verifica; el nuevo sí.
  await assert.rejects(
    () => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), oldCode, fixtureUuid("dm-1"), 2),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-02",
  );
  const verified = await submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), newCode, fixtureUuid("dm-1"), 2);
  assert.equal(verified.state, "VERIFIED");
});

test("TEST-CNS-546: V2r aplica P-06 con D8 (el envio inicial cuenta): V1 + 2 reenvios caben, el 3.o -> ERR-OT-09 sin tocar el challenge", async () => {
  const { invitationPorts, otpPorts, clock } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);

  for (let i = 0; i < 2; i += 1) {
    clock.ms += 60_000;
    await resendOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"));
  }
  clock.ms += 60_000;
  const before = await otpPorts.otpRepo.findByRef("tenant-1", fixtureUuid("ver-1"));
  await assert.rejects(
    () => resendOtp(otpPorts, "tenant-1", fixtureUuid("ver-1")),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-09",
  );
  const record = await otpPorts.otpRepo.findByRef("tenant-1", fixtureUuid("ver-1"));
  assert.deepEqual(record, before, "el rechazo no cambia el challenge");
  assert.equal(record?.resendCount, 2);
  assert.equal(record?.sendsInWindow, 3);
  assert.equal(record?.state, "CODE_SENT");
});

test("TEST-CNS-547: V2r sobre un challenge LOCKED responde ERR-OT-04 sin reemitir código", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  for (let i = 0; i < otpPorts.policy.maxAttempts; i += 1) {
    await assert.rejects(() => submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), "000000", fixtureUuid("dm-1"), 2));
  }
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  const sentBefore = sink.sent.length;

  await assert.rejects(
    () => resendOtp(otpPorts, "tenant-1", fixtureUuid("ver-1")),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-OT-04",
  );
  assert.equal(sink.sent.length, sentBefore);
});

test("TEST-CNS-1215 OPEN-CM-09 P2-3: submitOtp (DECISION) emite decisionMakerRefKeyVersion en INVITATION_VERIFIED y DECISION_MAKER_CHANNEL_VERIFIED desde la clave recibida", async () => {
  const { invitationPorts, otpPorts } = makeOtpPorts();
  await openedInvitation(invitationPorts);
  await requestOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), fixtureUuid("inv-1"), CHANNEL_REF);
  const sink = otpPorts.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
  await submitOtp(otpPorts, "tenant-1", fixtureUuid("ver-1"), sink.sent[0]?.code ?? "", fixtureUuid("dm-1"), 3);
  const chan = (await otpPorts.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", fixtureUuid("ver-1"))).find((e) => e.eventType === "DECISION_MAKER_CHANNEL_VERIFIED");
  const inv = (await otpPorts.ledger.listByAggregate("tenant-1", "Invitation", fixtureUuid("inv-1"))).find((e) => e.eventType === "INVITATION_VERIFIED");
  assert.equal(chan?.payload.decisionMakerRefKeyVersion, 3);
  assert.equal(inv?.payload.decisionMakerRefKeyVersion, 3);
});
