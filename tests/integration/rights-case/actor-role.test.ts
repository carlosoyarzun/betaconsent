// Gobierna: specs/state-machines/rights-case.spec.yaml RC3, specs/state-machines/revocation.spec.yaml
// RC3/R12, common.spec.yaml actorModel.unverifiedBearer (R13-5). TEST-CNS-460.

import test from "node:test";
import assert from "node:assert/strict";

import { expressRevocationIntentInCase } from "../../../src/server/modules/rights-case/rights-case.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";

async function buildPorts() {
  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-1", tenantId: "tenant-1", chainRef: "chain-1", revokedDecisionRef: "decision-1" },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await rightsCaseRepo.save({
    caseRef: "case-1",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    revokedDecisionRef: "decision-1",
    status: "CONTACTING",
  });
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  return { tenantHandle, rightsCaseRepo, revocationRepo, ledger };
}

test("TEST-CNS-460: RC3 (primera Revocation del caso) registra actorRole=UNVERIFIED_BEARER en el ledger, nunca SYSTEM_GUARD ni otro actorRole", async () => {
  const ports = await buildPorts();

  const result = await expressRevocationIntentInCase(ports, "handle-1");

  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", result.revocation.revocationRef);
  assert.equal(events.length, 1);
  assert.equal(events[0]?.actorType, "HUMAN");
  assert.equal(events[0]?.actorRole, "UNVERIFIED_BEARER");
  assert.notEqual(events[0]?.actorType, "SYSTEM_GUARD");
});

test("TEST-CNS-460: R12 (Revocation ya abierta se adjunta) también registra actorRole=UNVERIFIED_BEARER", async () => {
  const ports = await buildPorts();

  // Primera llamada abre la Revocation (RC3).
  const first = await expressRevocationIntentInCase(ports, "handle-1");
  // Segunda llamada: ya hay Revocation abierta -> rama R12 (adjunta, no crea otra).
  const second = await expressRevocationIntentInCase(ports, "handle-1");

  assert.equal(second.revocation.revocationRef, first.revocation.revocationRef);
  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", first.revocation.revocationRef);
  assert.equal(events.length, 2);
  for (const event of events) {
    assert.equal(event.actorRole, "UNVERIFIED_BEARER");
    assert.notEqual(event.actorType, "SYSTEM_GUARD");
  }
});
