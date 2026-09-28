// Gobierna: specs/state-machines/revocation.spec.yaml R1 (RequestRevocation), R2
// (VerifyRevocationOtp), R3 (ConfirmRevocation), R8 (WithdrawRevocationRequest), RV0
// guardsBySource.BEARER. Subconjunto mínimo IT0 (ver revocation.ts). TEST-CNS-575..TEST-CNS-579.

import test from "node:test";
import assert from "node:assert/strict";

import {
  confirmRevocation,
  issueRecoveryLinkBearer,
  requestRevocation,
  verifyRevocationOtp,
  withdrawRevocation,
} from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";

const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };

function makePorts() {
  return {
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY,
  };
}

test("TEST-CNS-575: R1 -> R2 -> R3 recorre REQUESTED -> VERIFIED -> CONFIRMED -> APPLIED (R4 síncrono) y encola un solo CONSENT_REVOKED", () => {
  const ports = makePorts();
  const requested = requestRevocation(ports, "tenant-1", {
    revocationRef: "rv-575",
    chainRef: "chain-575",
    revokedDecisionRef: "consent-575",
  });
  assert.equal(requested.status, "REQUESTED");

  const verified = verifyRevocationOtp(ports, "tenant-1", "rv-575", "ver-575");
  assert.equal(verified.status, "VERIFIED");

  const applied = confirmRevocation(ports, "tenant-1", "rv-575");
  assert.equal(applied.status, "APPLIED");

  const events = ports.ledger.listByAggregate("tenant-1", "Revocation", "rv-575");
  const revokedEvents = events.filter((e) => e.eventType === "CONSENT_REVOKED");
  assert.equal(revokedEvents.length, 1);
  assert.deepEqual(
    events.map((e) => e.eventType),
    ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED"],
  );
});

test("TEST-CNS-576: R1 es idempotente por revocationRef (una sola solicitud abierta, sin duplicar el evento)", () => {
  const ports = makePorts();
  const input = { revocationRef: "rv-576", chainRef: "chain-576", revokedDecisionRef: "consent-576" };
  requestRevocation(ports, "tenant-1", input);
  requestRevocation(ports, "tenant-1", input);
  const events = ports.ledger.listByAggregate("tenant-1", "Revocation", "rv-576");
  assert.equal(events.filter((e) => e.eventType === "REVOCATION_REQUESTED").length, 1);
});

test("TEST-CNS-577: R8 desde REQUESTED, VERIFIED o CONFIRMED retira la solicitud (FAILED, WITHDRAWN_BY_REQUESTER)", () => {
  const ports = makePorts();
  requestRevocation(ports, "tenant-1", { revocationRef: "rv-577", chainRef: "chain-577", revokedDecisionRef: "consent-577" });
  const withdrawn = withdrawRevocation(ports, "tenant-1", "rv-577");
  assert.equal(withdrawn.status, "FAILED");
  assert.equal(withdrawn.reasonCode, "WITHDRAWN_BY_REQUESTER");
});

test("TEST-CNS-578: R8 sobre una Revocation ya APPLIED no tiene efecto (GRD-RV-15, R4 ya ganó la carrera)", () => {
  const ports = makePorts();
  requestRevocation(ports, "tenant-1", { revocationRef: "rv-578", chainRef: "chain-578", revokedDecisionRef: "consent-578" });
  verifyRevocationOtp(ports, "tenant-1", "rv-578", "ver-578");
  confirmRevocation(ports, "tenant-1", "rv-578");
  assert.throws(
    () => withdrawRevocation(ports, "tenant-1", "rv-578"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-06",
  );
});

test("TEST-CNS-579: issueRecoveryLinkBearer (RV0 fuente BEARER) emite RECOVERY_TOKEN_ISSUED sin transicionar la Revocation (kind EMISSION)", () => {
  const ports = makePorts();
  const result = issueRecoveryLinkBearer(ports, "tenant-1", "chain-579", "consent-579", "LIMIT_REACHED");
  assert.equal(result.sent, true);
  const events = ports.ledger.listByAggregate("tenant-1", "Revocation", "chain-579");
  assert.equal(events[0]?.eventType, "RECOVERY_TOKEN_ISSUED");
});

test("TEST-CNS-580: un revocationRef inexistente en R2/R3/R8 da 404 uniforme (ERR-CM-01), mismo criterio que RH2/RH3", () => {
  const ports = makePorts();
  assert.throws(
    () => verifyRevocationOtp(ports, "tenant-1", "rv-missing", "ver-x"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});
