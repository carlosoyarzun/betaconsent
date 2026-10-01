// Gobierna: specs/state-machines/revocation.spec.yaml RH3 paso 1 (record_case_confirmation,
// GRD-RV-10/ERR-RV-20, x-state-transition step:record effect:none);
// specs/state-machines/rights-case.spec.yaml GRD-RC-15 (nominal_roster_minimum, ERR-RC-10);
// contracts/openapi/consent-it0.openapi.yaml API-CNS-138. CA-128.
// TEST-CNS-630..636.

import test from "node:test";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import assert from "node:assert/strict";

import { attestHumanAssistedVerification, recordCaseConfirmationPendingCosign, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { withSyntheticFallback } from "../../contract/synthetic-decision.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import type { StaffIdentityPort, StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

function makePorts(revocationRepo: RevocationRepositoryPort, ledger: LedgerPort): RevocationPorts {
  return withInMemoryTenancy({
    revocationRepo,
    ledger,
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo: withSyntheticFallback(createInMemoryConsentDecisionRepository()),
  });
}

/** LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos, 2026-09-28 opción (ii)): 4
 * personas ficticias distintas, sin reutilización entre roles (NF-19, GRD-RC-15). */
const FULL_ROSTER: readonly StaffPrincipal[] = [
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
];

function makeStaffIdentity(roster: readonly StaffPrincipal[] = FULL_ROSTER): StaffIdentityPort {
  return createInMemoryStaffIdentityAdapter(roster);
}

async function seedVerifiedRevocation(revocationRepo: RevocationRepositoryPort, ledger: LedgerPort, revocationRef: string, caseRef: string, tenantId = "tenant-1"): Promise<void> {
  await revocationRepo.save({ revocationRef, tenantId, chainRef: `chain-${revocationRef}`, caseRef, status: "REQUESTED" });
  await attestHumanAssistedVerification(makePorts(revocationRepo, ledger), tenantId, revocationRef, caseRef);
}

test("TEST-CNS-630: record_case_confirmation sin RH2/RH2v ATTESTED previa -> ERR-RV-20 (GRD-RV-10)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  await revocationRepo.save({ revocationRef: fixtureUuid("rv-630"), tenantId: "tenant-1", chainRef: fixtureUuid("chain-630"), caseRef: fixtureUuid("case-630"), status: "REQUESTED" });
  const ledger = createInMemoryLedgerAdapter();

  await assert.rejects(
    () =>
      recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(), "tenant-1", fixtureUuid("rv-630"), fixtureUuid("case-630"), {
        recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-RV-20",
  );
});

test("TEST-CNS-631: revocationRef/caseRef de otro tenant -> ERR-CM-01 (GRD-CM-01)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-631"), fixtureUuid("case-631"), "tenant-a");

  await assert.rejects(
    () =>
      recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(), "tenant-b", fixtureUuid("rv-631"), fixtureUuid("case-631"), {
        recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-632: caseRef que no coincide con el de la Revocation -> ERR-CM-01 (GRD-CM-01)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-632"), fixtureUuid("case-632"));

  await assert.rejects(
    () =>
      recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(), "tenant-1", fixtureUuid("rv-632"), fixtureUuid("case-otro"), {
        recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-633: dotación <4 personas (menos de 2 RIGHTS_OPERATOR) -> ERR-RC-10 (GRD-RC-15), fail-closed", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-633"), fixtureUuid("case-633"));
  const shortRoster: readonly StaffPrincipal[] = [
    { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
    { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
    { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
  ];

  await assert.rejects(
    () =>
      recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(shortRoster), "tenant-1", fixtureUuid("rv-633"), fixtureUuid("case-633"), {
        recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-RC-10",
  );

  // El caso sigue abierto: la Revocation conserva VERIFIED (failClosed: "nunca FAILED").
  const stillVerified = await revocationRepo.findByRef("tenant-1", fixtureUuid("rv-633"));
  assert.equal(stillVerified?.status, "VERIFIED");
});

test("TEST-CNS-634: dotación con reutilización de rol (un mismo principal como único RIGHTS_OPERATOR y único aprobador) -> ERR-RC-10 (GRD-RC-15)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-634"), fixtureUuid("case-634"));
  const reusedRoster: readonly StaffPrincipal[] = [
    { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
    { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
    { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  ]; // solo 1 APPROVER distinto: < 2 (mínimo NF-19).

  await assert.rejects(
    () =>
      recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(reusedRoster), "tenant-1", fixtureUuid("rv-634"), fixtureUuid("case-634"), {
        recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-RC-10",
  );
});

test("TEST-CNS-635: registro válido (paso 1) NO transiciona la Revocation ni emite REVOCATION_CONFIRMED (x-state-transition effect: none)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-635"), fixtureUuid("case-635"));

  const recorded = await recordCaseConfirmationPendingCosign(makePorts(revocationRepo, ledger), makeStaffIdentity(), "tenant-1", fixtureUuid("rv-635"), fixtureUuid("case-635"), {
    recordedByPrincipalRef: fixtureUuid("staff-synthetic-01"),
  });

  assert.equal(recorded.status, "VERIFIED");
  assert.equal(recorded.recordedByRef, fixtureUuid("staff-synthetic-01"));
  assert.equal(recorded.cosignedByRef, undefined);

  const stored = await revocationRepo.findByRef("tenant-1", fixtureUuid("rv-635"));
  assert.equal(stored?.status, "VERIFIED");
  assert.equal(stored?.recordedByRef, fixtureUuid("staff-synthetic-01"));

  const confirmedEvents = (await ledger.listByAggregate("tenant-1", "Revocation", fixtureUuid("rv-635"))).filter((e) => e.eventType === "REVOCATION_CONFIRMED");
  assert.equal(confirmedEvents.length, 0);
});

test("TEST-CNS-636: idempotente por revocationRef — un segundo registro (mismo operador) no revierte el estado ni falla", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await seedVerifiedRevocation(revocationRepo, ledger, fixtureUuid("rv-636"), fixtureUuid("case-636"));
  const ports = makePorts(revocationRepo, ledger);
  const staffIdentity = makeStaffIdentity();

  await recordCaseConfirmationPendingCosign(ports, staffIdentity, "tenant-1", fixtureUuid("rv-636"), fixtureUuid("case-636"), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
  const second = await recordCaseConfirmationPendingCosign(ports, staffIdentity, "tenant-1", fixtureUuid("rv-636"), fixtureUuid("case-636"), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });

  assert.equal(second.status, "VERIFIED");
  assert.equal(second.recordedByRef, fixtureUuid("staff-synthetic-01"));
});
