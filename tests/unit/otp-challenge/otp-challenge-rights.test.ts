// Gobierna: specs/state-machines/otp-challenge.spec.yaml V1/V3 guardsByScope
// REVOCATION/MANAGE (routeClass RIGHTS), GRD-OT-04 (V4 LOCKED), INV-OT-06 (RIGHTS nunca
// deniega la vía de revocación: se prueba en la capa HTTP, ver revocation-http.test.ts).
// TEST-CNS-571..TEST-CNS-574.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { requestRightsOtp, submitRightsOtp } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";

function makePorts() {
  return {
    otpRepo: createInMemoryOtpVerificationRepository(),
    channel: createInMemoryOtpChannelSink(),
    ledger: createInMemoryLedgerAdapter(),
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
}

test("TEST-CNS-571: requestRightsOtp scope MANAGE emite OTP_ISSUED y el código nunca sale en claro del sink más allá del code (INV-OT-02)", () => {
  const ports = makePorts();
  const record = requestRightsOtp(ports, "tenant-1", "ver-manage-1", "MANAGE", "chain-1", "mgmt:chain-1");
  assert.equal(record.scope, "MANAGE");
  assert.equal(record.state, "CODE_SENT");
  assert.equal(record.parentRef, "chain-1");
  assert.ok(!("code" in record));
  const events = ports.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", "ver-manage-1");
  assert.equal(events[0]?.eventType, "OTP_ISSUED");
});

test("TEST-CNS-572: submitRightsOtp con el código correcto (scope REVOCATION) -> VERIFIED, emite DECISION_MAKER_CHANNEL_VERIFIED", () => {
  const ports = makePorts();
  requestRightsOtp(ports, "tenant-1", "ver-rev-1", "REVOCATION", "chain-1", "mgmt:chain-1");
  const code = ports.channel.sent[0]?.code ?? "";
  assert.ok(code.length > 0);
  const verified = submitRightsOtp(ports, "tenant-1", "ver-rev-1", "REVOCATION", code);
  assert.equal(verified.state, "VERIFIED");
  const events = ports.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", "ver-rev-1");
  assert.ok(events.some((e) => e.eventType === "DECISION_MAKER_CHANNEL_VERIFIED"));
});

test("TEST-CNS-573: submitRightsOtp agota los intentos (maxAttempts) -> LOCKED (V4), nunca FAILED de la Revocation (INV-OT-05)", () => {
  const ports = makePorts();
  requestRightsOtp(ports, "tenant-1", "ver-rev-2", "REVOCATION", "chain-1", "mgmt:chain-1");
  for (let i = 0; i < 3; i += 1) {
    assert.throws(
      () => submitRightsOtp(ports, "tenant-1", "ver-rev-2", "REVOCATION", "000000"),
      (err: unknown) => err instanceof DomainError,
    );
  }
  const record = ports.otpRepo.findByRef("tenant-1", "ver-rev-2");
  assert.equal(record?.state, "LOCKED");
});

test("TEST-CNS-574: submitRightsOtp con el scope equivocado (VERIFIED MANAGE no sirve para REVOCATION) -> rechazo determinista (ERR-OT-05/scope misuse)", () => {
  const ports = makePorts();
  requestRightsOtp(ports, "tenant-1", "ver-manage-2", "MANAGE", "chain-1", "mgmt:chain-1");
  const code = ports.channel.sent[0]?.code ?? "";
  assert.throws(
    () => submitRightsOtp(ports, "tenant-1", "ver-manage-2", "REVOCATION", code),
    (err: unknown) => err instanceof DomainError,
  );
});
