// Gobierna: specs/state-machines/common.spec.yaml INV-CM-06 (eligibility_to_participate !=
// eligibility_to_revoke), GRD-CM-06 (route_class_rights); specs/state-machines/revocation.spec.yaml
// INV-6. TEST-CNS-461, TEST-CNS-462, TEST-CNS-695 (CA-127: consent.revoked se encola aunque el tenant esté suspendido).
//
// Un registro de tenant "suspendido" se simula en un mapa separado, NUNCA pasado a las
// funciones RIGHTS bajo prueba: la propiedad verificada es que closeCase/RC3/RH2/RH3/R4 ni
// siquiera reciben un puerto capaz de leer tenant.active (revisión estática == estructural
// aquí), así que su resultado no puede depender de él.

import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import test from "node:test";
import assert from "node:assert/strict";

import { closeCase, expressRevocationIntentInCase } from "../../../src/server/modules/rights-case/rights-case.ts";
import { attestHumanAssistedVerification, cosignCaseConfirmation, recordCaseConfirmationPendingCosign } from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { syntheticDecision, withSyntheticFallback } from "../../contract/synthetic-decision.ts";
import { assertConsentRevokedOutbox } from "../../contract/outbox-evidence.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryTenancy, withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

/** Registro de tenants "vivo" fuera de las máquinas RIGHTS, solo para el fixture del test. */
const suspendedTenants = new Map<string, { active: boolean }>([["tenant-suspended", { active: false }]]);

test("TEST-CNS-461: RC4/RC5/RC6 (cierre de RightsCase) se ejecutan con tenant SUSPENDED (RIGHTS nunca lee tenant.active)", async () => {
  assert.equal(suspendedTenants.get("tenant-suspended")?.active, false);

  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await rightsCaseRepo.save({
    caseRef: "case-suspended",
    tenantId: "tenant-suspended",
    chainRef: "chain-1",
    revokedDecisionRef: "decision-1",
    status: "IN_VERIFICATION",
  });
  const ledger = createInMemoryLedgerAdapter();

  const closed = await closeCase({ rightsCaseRepo, ledger, uow: createInMemoryTenancy({ ledger, rightsCaseRepo }).uow }, "tenant-suspended", "case-suspended", "RESOLVED");

  assert.equal(closed.status, "RESOLVED");
});

test("TEST-CNS-462 (INV-6): cadena RC3->RH2->RH3->R4 con tenant SUSPENDED llega a APPLIED", async () => {
  assert.equal(suspendedTenants.get("tenant-suspended")?.active, false);

  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-suspended", tenantId: "tenant-suspended", chainRef: "chain-2", revokedDecisionRef: "decision-2" },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await rightsCaseRepo.save({
    caseRef: "case-suspended-2",
    tenantId: "tenant-suspended",
    chainRef: "chain-2",
    revokedDecisionRef: "decision-2",
    status: "CONTACTING",
  });
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  // CA-116 PR 2: RevocationPorts ganó recoveryTokenRepo/recoveryLinkChannel/recoveryTokenPolicy
  // (RV0 BEARER + GET /r/{token} + POST /recovery/revoke), ajenos a RC3/RH2/RH3/R4 (fuente
  // RECOVERY HUMAN_ASSISTED) bajo prueba aquí.
  const ports = withInMemoryTenancy({
    tenantHandle,
    rightsCaseRepo,
    revocationRepo,
    ledger,
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    // SEC-CNS-014 (FINDING P1-01): ajeno a RC3/RH2/RH3/R4 bajo prueba aquí, uno vacío basta.
    consentDecisionRepo: withSyntheticFallback(createInMemoryConsentDecisionRepository()),
  });

  // RC3
  const { revocation } = await expressRevocationIntentInCase(ports, "handle-suspended");
  assert.equal(revocation.status, "REQUESTED");

  // RH2
  const verified = await attestHumanAssistedVerification(ports, "tenant-suspended", revocation.revocationRef, "case-suspended-2");
  assert.equal(verified.status, "VERIFIED");

  // RH3
  const staffIdentity = createInMemoryStaffIdentityAdapter([
    { principalRef: "operator-a", role: "RIGHTS_OPERATOR" },
    { principalRef: "operator-b", role: "RIGHTS_OPERATOR" },
    { principalRef: "approver-c", role: "APPROVER" },
    { principalRef: "approver-d", role: "APPROVER" },
  ]);
  await recordCaseConfirmationPendingCosign(ports, staffIdentity, "tenant-suspended", revocation.revocationRef, "case-suspended-2", {
    recordedByPrincipalRef: "operator-a",
  });
  const confirmed = await cosignCaseConfirmation(ports, staffIdentity, "tenant-suspended", revocation.revocationRef, "case-suspended-2", {
    cosignedByPrincipalRef: "operator-b",
  });
  // R4 síncrono dentro del cosign en IT0 (Carlos 2026-09-28): la cadena termina en APPLIED.
  assert.equal(confirmed.status, "APPLIED");
});

test("TEST-CNS-695 (INV-6): con tenant SUSPENDED la cadena RC3->RH2->RH3->R4 encola igual un consent.revoked válido (eligibility_to_revoke)", async () => {
  const TS = fixtureUuid("tenant-suspended-695");
  const D = fixtureUuid("decision-695");
  suspendedTenants.set(TS, { active: false });
  assert.equal(suspendedTenants.get(TS)?.active, false);

  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await rightsCaseRepo.save({ caseRef: "case-695", tenantId: TS, chainRef: "chain-695", revokedDecisionRef: D, status: "CONTACTING" });
  const consentDecisionRepo = createInMemoryConsentDecisionRepository();
  await consentDecisionRepo.save(syntheticDecision(TS, D));
  const outbox = createInMemoryOutboxAdapter();
  const ports = withInMemoryTenancy({
    tenantHandle: createInMemoryTenantHandleAdapter([{ handle: "handle-695", tenantId: TS, chainRef: "chain-695", revokedDecisionRef: D }]),
    rightsCaseRepo,
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox,
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  });
  const { revocation } = await expressRevocationIntentInCase(ports, "handle-695");
  await attestHumanAssistedVerification(ports, TS, revocation.revocationRef, "case-695");
  const staffIdentity = createInMemoryStaffIdentityAdapter([
    { principalRef: "operator-a", role: "RIGHTS_OPERATOR" },
    { principalRef: "operator-b", role: "RIGHTS_OPERATOR" },
    { principalRef: "approver-c", role: "APPROVER" },
    { principalRef: "approver-d", role: "APPROVER" },
  ]);
  await recordCaseConfirmationPendingCosign(ports, staffIdentity, TS, revocation.revocationRef, "case-695", { recordedByPrincipalRef: "operator-a" });
  const confirmed = await cosignCaseConfirmation(ports, staffIdentity, TS, revocation.revocationRef, "case-695", { cosignedByPrincipalRef: "operator-b" });
  assert.equal(confirmed.status, "APPLIED");
  assert.equal(outbox.enqueued.length, 1);
  assertConsentRevokedOutbox(outbox.enqueued, await ports.ledger.listByAggregate(TS, "Revocation", revocation.revocationRef), {
    tenantId: TS,
    revocationRef: revocation.revocationRef,
    decision: syntheticDecision(TS, D),
  });
});
