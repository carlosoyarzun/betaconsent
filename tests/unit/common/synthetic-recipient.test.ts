// Gobierna: DEC-BR-014 rev. 8 §4 y X3 (D8 (a), Carlos 2026-10-01): allowlist de destinatarios de los
// sinks de canal de IT0 (misma regla que app.is_reserved_email). Un destinatario no reservado se
// rechaza SIN registrar el envio; el error no incluye el valor. Solo datos sinteticos.
// TEST-CNS-950.

import test from "node:test";
import assert from "node:assert/strict";

import { NonSyntheticRecipientError, isReservedEmail, isSyntheticRecipient } from "../../../src/server/modules/common/synthetic-recipient.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryInvitationLinkChannelSink } from "../../../src/infra/adapters/in-memory-invitation-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";

const REAL_LOOKING = ["alguien@gmail.com", "padre@colegio.cl", "x@example.com.evil.cl", "x@evil-example.com", "a@b.test.cl", "a b@example.com"];

test("TEST-CNS-950 isReservedEmail: dominios reservados si; dominios reales y casi-reservados no", () => {
  for (const ok of ["a@example.invalid", "a+b@x.y.test", "A@EXAMPLE.COM", "a@example.org", "a@example.net", "a@sub.dom.invalid"]) {
    assert.equal(isReservedEmail(ok), true, ok);
  }
  for (const bad of REAL_LOOKING) assert.equal(isReservedEmail(bad), false, bad);
});

test("TEST-CNS-950 isSyntheticRecipient: refs opacos si (UUID, mgmt:<chain>); telefonos, URLs y direcciones reales no", () => {
  for (const ok of ["f1a5c9e3-4d27-4b68-9e30-2c4e6a8b0d51", "mgmt:chain-831", "a@example.invalid"]) assert.equal(isSyntheticRecipient(ok), true, ok);
  for (const bad of [...REAL_LOOKING, "+56912345678", "56912345678", "https://x.cl", "", "a@b"]) assert.equal(isSyntheticRecipient(bad), false, bad);
});

test("TEST-CNS-950 sink OTP: destinatario no reservado -> rechazo sin envio y sin el valor en el error", async () => {
  const sink = createInMemoryOtpChannelSink();
  await sink.send({ channelRef: "ok@example.invalid", verificationRef: "v1", code: "123456" });
  await assert.rejects(
    () => sink.send({ channelRef: "alguien@gmail.com", verificationRef: "v2", code: "654321" }),
    (e: unknown) => e instanceof NonSyntheticRecipientError && !e.message.includes("gmail") && e.code === "NON_SYNTHETIC_RECIPIENT",
  );
  assert.equal(sink.sent.length, 1);
  assert.equal(sink.sent[0]?.verificationRef, "v1");
});

test("TEST-CNS-950 sink de invitacion: recipientChannelRef no reservado -> rechazo sin envio; ausente (UNBOUND) u opaco -> admitido", async () => {
  const sink = createInMemoryInvitationLinkChannelSink();
  await sink.send({ invitationRef: "i1", invitationPath: "/i/t1", deliveryChannel: "SCHOOL_CHANNEL" });
  await sink.send({ invitationRef: "i2", invitationPath: "/i/t2", deliveryChannel: "SCHOOL_CHANNEL", recipientChannelRef: "f1a5c9e3-4d27-4b68-9e30-2c4e6a8b0d51" });
  await assert.rejects(
    () => sink.send({ invitationRef: "i3", invitationPath: "/i/t3", deliveryChannel: "CONSENT_APP_EMAIL", recipientChannelRef: "padre@colegio.cl" }),
    NonSyntheticRecipientError,
  );
  assert.equal(sink.sent.length, 2);
});

test("TEST-CNS-950 sink de recuperacion: el mensaje no tiene destinatario (solo recoveryPath), nada que allowlistear", async () => {
  const sink = createInMemoryRecoveryLinkChannelSink();
  await sink.send({ recoveryPath: "/r/t" });
  assert.deepEqual(Object.keys(sink.sent[0] ?? {}), ["recoveryPath"]);
});
