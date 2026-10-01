// Gobierna: specs/state-machines/revocation.spec.yaml RH3 paso 2 (cosign_case_confirmation,
// GRD-RV-10/ERR-RV-20, GRD-RV-26/ERR-RV-18, INV-RV-11, REVOCATION_CONFIRMED);
// specs/state-machines/rights-case.spec.yaml GRD-RC-15 (ERR-RC-10);
// contracts/schemas/ledger-event-payloads.schema.json REVOCATION_CONFIRMED;
// contracts/openapi/consent-it0.openapi.yaml API-CNS-139. CA-128.
// TEST-CNS-660..666.

import { attestHumanAssistedVerification } from "../../contract/rh2-helper.ts";
import test from "node:test";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import assert from "node:assert/strict";

import { cosignCaseConfirmation, recordCaseConfirmationPendingCosign, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
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
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
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

/** SYNTHETIC DATA ONLY: 4 personas ficticias, sin reutilización entre roles (GRD-RC-15). */
const FULL_ROSTER: readonly StaffPrincipal[] = [
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
];
const staff = createInMemoryStaffIdentityAdapter(FULL_ROSTER);

/** Ref UUIDv4 sintética del ciclo de decisión revocado (fuente de CONSENT_REVOKED.revokedDecisionRef). */
const DECISION_UUID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

async function seed(ref: string, opts: { record?: boolean } = {}) {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  const ports = makePorts(revocationRepo, ledger);
  await revocationRepo.save({ revocationRef: ref, tenantId: "tenant-1", chainRef: `chain-${ref}`, caseRef: fixtureUuid(`case-${ref}`), revokedDecisionRef: DECISION_UUID, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, "tenant-1", ref, fixtureUuid(`case-${ref}`));
  if (opts.record !== false) {
    await recordCaseConfirmationPendingCosign(ports, staff, "tenant-1", ref, fixtureUuid(`case-${ref}`), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
  }
  return { revocationRepo, ledger, ports };
}

async function errCode(fn: () => unknown): Promise<string | undefined> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof DomainError) return err.code;
    throw err;
  }
  return undefined;
}

async function confirmedEvents(ledger: LedgerPort, ref: string) {
  return (await ledger.listByAggregate("tenant-1", "Revocation", ref)).filter((e) => e.eventType === "REVOCATION_CONFIRMED");
}

async function revokedEvents(ledger: LedgerPort, ref: string) {
  return (await ledger.listByAggregate("tenant-1", "Revocation", ref)).filter((e) => e.eventType === "CONSENT_REVOKED");
}

test("TEST-CNS-660: cosign sin RH2/RH2v ATTESTED previa -> ERR-RV-20 (GRD-RV-10)", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await revocationRepo.save({ revocationRef: fixtureUuid("rv-660"), tenantId: "tenant-1", chainRef: fixtureUuid("chain-660"), caseRef: fixtureUuid("case-660"), status: "REQUESTED" });
  const code = await errCode(() => cosignCaseConfirmation(makePorts(revocationRepo, ledger), staff, "tenant-1", fixtureUuid("rv-660"), fixtureUuid("case-660"), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") }));
  assert.equal(code, "ERR-RV-20");
});

test("TEST-CNS-661: cosign con revocationRef de otro tenant o caseRef distinto -> ERR-CM-01 (GRD-CM-01, tenant_id)", async () => {
  const { ports } = await seed(fixtureUuid("rv-661"));
  assert.equal(await errCode(() => cosignCaseConfirmation(ports, staff, "tenant-b", fixtureUuid("rv-661"), fixtureUuid(`case-${fixtureUuid("rv-661")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") })), "ERR-CM-01");
  assert.equal(await errCode(() => cosignCaseConfirmation(ports, staff, "tenant-1", fixtureUuid("rv-661"), fixtureUuid("case-otro"), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") })), "ERR-CM-01");
});

test("TEST-CNS-662: cosign sin confirmación previa registrada (paso 1) -> ERR-RV-18, sin efecto", async () => {
  const { ports, revocationRepo, ledger } = await seed(fixtureUuid("rv-662"), { record: false });
  assert.equal(await errCode(() => cosignCaseConfirmation(ports, staff, "tenant-1", fixtureUuid("rv-662"), fixtureUuid(`case-${fixtureUuid("rv-662")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") })), "ERR-RV-18");
  assert.equal((await revocationRepo.findByRef("tenant-1", fixtureUuid("rv-662")))?.status, "VERIFIED");
  assert.equal((await confirmedEvents(ledger, fixtureUuid("rv-662"))).length, 0);
});

test("TEST-CNS-663: cosign por la misma persona que registró -> ERR-RV-18 (cosignedByRef <> recordedByRef), sin efecto", async () => {
  const { ports, revocationRepo, ledger } = await seed(fixtureUuid("rv-663"));
  assert.equal(await errCode(() => cosignCaseConfirmation(ports, staff, "tenant-1", fixtureUuid("rv-663"), fixtureUuid(`case-${fixtureUuid("rv-663")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-01") })), "ERR-RV-18");
  const stored = await revocationRepo.findByRef("tenant-1", fixtureUuid("rv-663"));
  assert.equal(stored?.status, "VERIFIED");
  assert.equal(stored?.cosignedByRef, undefined);
  assert.equal((await confirmedEvents(ledger, fixtureUuid("rv-663"))).length, 0);
});

test("TEST-CNS-664: dotación insuficiente -> ERR-RC-10 (GRD-RC-15), fail-closed", async () => {
  const { ports } = await seed(fixtureUuid("rv-664"));
  const shortStaff = createInMemoryStaffIdentityAdapter([
    { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
    { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
    { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  ]);
  assert.equal(await errCode(() => cosignCaseConfirmation(ports, shortStaff, "tenant-1", fixtureUuid("rv-664"), fixtureUuid(`case-${fixtureUuid("rv-664")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") })), "ERR-RC-10");
});

/** Refs UUIDv4 sintéticas: el schema exige Ref = UUIDv4 opaco (common.schema.json). Las refs
 * "staff-synthetic-NN" del roster de dev NO cumplen ese patrón (FINDING P2 en el reporte). */
const REV_UUID = "6f1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f10";
const OP_A_UUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const OP_B_UUID = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e";
const APR_C_UUID = "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f";
const APR_D_UUID = "d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80";

test("TEST-CNS-665: cosign válido -> CONFIRMED y REVOCATION_CONFIRMED con recordedByRef/cosignedByRef distintos, válido contra el schema", async () => {
  const uuidStaff = createInMemoryStaffIdentityAdapter([
    { principalRef: OP_A_UUID, role: "RIGHTS_OPERATOR" },
    { principalRef: OP_B_UUID, role: "RIGHTS_OPERATOR" },
    { principalRef: APR_C_UUID, role: "APPROVER" },
    { principalRef: APR_D_UUID, role: "APPROVER" },
  ]);
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  const ports = makePorts(revocationRepo, ledger);
  await revocationRepo.save({ revocationRef: REV_UUID, tenantId: "tenant-1", chainRef: fixtureUuid("chain-665"), caseRef: fixtureUuid("case-665"), revokedDecisionRef: DECISION_UUID, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, "tenant-1", REV_UUID, fixtureUuid("case-665"));
  await recordCaseConfirmationPendingCosign(ports, uuidStaff, "tenant-1", REV_UUID, fixtureUuid("case-665"), { recordedByPrincipalRef: OP_A_UUID });

  const confirmed = await cosignCaseConfirmation(ports, uuidStaff, "tenant-1", REV_UUID, fixtureUuid("case-665"), { cosignedByPrincipalRef: OP_B_UUID });
  assert.equal(confirmed.status, "APPLIED"); // R4 síncrono en IT0 (Carlos 2026-09-28)
  assert.equal(confirmed.recordedByRef, OP_A_UUID);
  assert.equal(confirmed.cosignedByRef, OP_B_UUID);
  assert.equal((await revocationRepo.findByRef("tenant-1", REV_UUID))?.status, "APPLIED");

  const event = (await confirmedEvents(ledger, REV_UUID))[0];
  assert.ok(event);
  assert.equal(event.recordedByRef, OP_A_UUID);
  assert.equal(event.cosignedByRef, OP_B_UUID);
  assert.notEqual(event.recordedByRef, event.cosignedByRef);
  const result = validateLedgerEventPayload("REVOCATION_CONFIRMED", event.payload);
  assert.ok(result.ok, result.errors.join("\n"));
});

test("TEST-CNS-666: cosign idempotente por revocationRef — repetir no duplica REVOCATION_CONFIRMED", async () => {
  const { ports, ledger } = await seed(fixtureUuid("rv-666"));
  await cosignCaseConfirmation(ports, staff, "tenant-1", fixtureUuid("rv-666"), fixtureUuid(`case-${fixtureUuid("rv-666")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  const again = await cosignCaseConfirmation(ports, staff, "tenant-1", fixtureUuid("rv-666"), fixtureUuid(`case-${fixtureUuid("rv-666")}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(again.status, "APPLIED");
  assert.equal((await confirmedEvents(ledger, fixtureUuid("rv-666"))).length, 1);
  assert.equal((await revokedEvents(ledger, fixtureUuid("rv-666"))).length, 1);
});

const REV_676 = "7a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f11";
const REV_677 = "7a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f12";
const REV_677B = "7a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f13";

test("TEST-CNS-676: cosign exitoso aplica R4 síncrono -> APPLIED con un único CONSENT_REVOKED tras REVOCATION_CONFIRMED (IT0, Carlos 2026-09-28)", async () => {
  const { ports, revocationRepo, ledger } = await seed(REV_676);
  const applied = await cosignCaseConfirmation(ports, staff, "tenant-1", REV_676, fixtureUuid(`case-${REV_676}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(applied.status, "APPLIED");
  assert.equal((await revocationRepo.findByRef("tenant-1", REV_676))?.status, "APPLIED");
  const events = await ledger.listByAggregate("tenant-1", "Revocation", REV_676);
  assert.deepEqual(events.slice(-3).map((e) => e.eventType), ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]);
  assert.equal((await revokedEvents(ledger, REV_676)).length, 1);
  // RH3 = caso humano: authPath RECOVERY / HUMAN_ASSISTED, derivado del registro (RH2); evidencia válida contra el schema.
  assertRevocationEvidence(events, { revocationRef: REV_676, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED", revokedDecisionRef: DECISION_UUID });
});

test("TEST-CNS-677: repetir cosign tras APPLIED no reaplica ni duplica eventos; CONFIRMED sin aplicar se reintenta sin reemitir REVOCATION_CONFIRMED", async () => {
  const { ports, ledger } = await seed(REV_677);
  await cosignCaseConfirmation(ports, staff, "tenant-1", REV_677, fixtureUuid(`case-${REV_677}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  const before = (await ledger.listByAggregate("tenant-1", "Revocation", REV_677)).length;
  await cosignCaseConfirmation(ports, staff, "tenant-1", REV_677, fixtureUuid(`case-${REV_677}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal((await ledger.listByAggregate("tenant-1", "Revocation", REV_677)).length, before);
  assertRevocationEvidence(await ledger.listByAggregate("tenant-1", "Revocation", REV_677), { revocationRef: REV_677, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });

  // Simula R4 fallido: CONFIRMED con co-firma pero sin aplicar.
  const { ports: p2, revocationRepo: repo2, ledger: l2 } = await seed(REV_677B);
  const rec = await repo2.findByRef("tenant-1", REV_677B);
  assert.ok(rec);
  await repo2.save({ ...rec, status: "CONFIRMED", cosignedByRef: fixtureUuid("staff-synthetic-02") });
  const retried = await cosignCaseConfirmation(p2, staff, "tenant-1", REV_677B, fixtureUuid(`case-${REV_677B}`), { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(retried.status, "APPLIED");
  assert.equal((await confirmedEvents(l2, REV_677B)).length, 0);
  assertRevocationEvidence(await l2.listByAggregate("tenant-1", "Revocation", REV_677B), { revocationRef: REV_677B, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED" });
});
