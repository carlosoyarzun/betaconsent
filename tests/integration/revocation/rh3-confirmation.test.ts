// Gobierna: specs/state-machines/revocation.spec.yaml RH3 (GRD-RV-10, ERR-RV-20; GRD-CM-01/06;
// F-R14-04/INV-RV-11). TEST-CNS-463, TEST-CNS-464, TEST-CNS-465.

import test from "node:test";
import assert from "node:assert/strict";

import { attestHumanAssistedVerification, recordCaseConfirmation, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";

/** CA-116 PR 2: RevocationPorts ganó recoveryTokenRepo/recoveryLinkChannel/recoveryTokenPolicy
 * (RV0 BEARER + GET /r/{token} + POST /recovery/revoke), ajenos a RH2/RH3 (fuente RECOVERY
 * HUMAN_ASSISTED); este helper completa el tipo sin que cada test tenga que repetirlo. */
function makePorts(revocationRepo: RevocationRepositoryPort, ledger: LedgerPort): RevocationPorts {
  return {
    revocationRepo,
    ledger,
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
  };
}

test("TEST-CNS-463: RH3 sin una RH2/RH2v ATTESTED previa de la misma (revocationRef, caseRef) -> ERR-RV-20 (GRD-RV-10)", () => {
  const revocationRepo = createInMemoryRevocationRepository();
  revocationRepo.save({
    revocationRef: "rv-1",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    caseRef: "case-1",
    status: "REQUESTED", // nunca pasó por RH2
  });
  const ledger = createInMemoryLedgerAdapter();

  assert.throws(
    () =>
      recordCaseConfirmation(makePorts(revocationRepo, ledger), "tenant-1", "rv-1", "case-1", {
        recordedByPrincipalRef: "operator-a",
        cosignedByPrincipalRef: "operator-b",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-RV-20",
  );
});

test("TEST-CNS-464: RH2 y RH3 con caseRef/revocationRef de otro tenant -> 404 uniforme (GRD-CM-01/06)", () => {
  const revocationRepo = createInMemoryRevocationRepository();
  revocationRepo.save({
    revocationRef: "rv-tenant-a",
    tenantId: "tenant-a",
    chainRef: "chain-a",
    caseRef: "case-a",
    status: "REQUESTED",
  });
  const ledger = createInMemoryLedgerAdapter();

  assert.throws(
    () => attestHumanAssistedVerification(makePorts(revocationRepo, ledger), "tenant-b", "rv-tenant-a", "case-a"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
    "RH2 con revocationRef de otro tenant debía dar 404 uniforme",
  );

  assert.throws(
    () =>
      recordCaseConfirmation(makePorts(revocationRepo, ledger), "tenant-b", "rv-tenant-a", "case-a", {
        recordedByPrincipalRef: "operator-a",
        cosignedByPrincipalRef: "operator-b",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
    "RH3 con revocationRef de otro tenant debía dar 404 uniforme",
  );
});

test("TEST-CNS-465: recordedByRef/cosignedByRef de RH3 se derivan de la sesión del ejecutor, nunca de un campo enviado en el request", () => {
  const revocationRepo = createInMemoryRevocationRepository();
  revocationRepo.save({
    revocationRef: "rv-2",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    caseRef: "case-2",
    status: "REQUESTED",
  });
  const ledger = createInMemoryLedgerAdapter();

  attestHumanAssistedVerification(makePorts(revocationRepo, ledger), "tenant-1", "rv-2", "case-2");

  const confirmed = recordCaseConfirmation(
    makePorts(revocationRepo, ledger),
    "tenant-1",
    "rv-2",
    "case-2",
    { recordedByPrincipalRef: "session-operator-a", cosignedByPrincipalRef: "session-operator-b" },
    // Campos "del request": un cliente que intente suplantar al firmante.
    { recordedByRef: "attacker-claims-operator-x", cosignedByRef: "attacker-claims-operator-y" },
  );

  assert.equal(confirmed.recordedByRef, "session-operator-a");
  assert.equal(confirmed.cosignedByRef, "session-operator-b");

  const events = ledger.listByAggregate("tenant-1", "Revocation", "rv-2");
  const confirmedEvent = events.find((e) => e.eventType === "REVOCATION_CONFIRMED");
  assert.ok(confirmedEvent);
  assert.equal(confirmedEvent?.recordedByRef, "session-operator-a");
  assert.equal(confirmedEvent?.cosignedByRef, "session-operator-b");
});
