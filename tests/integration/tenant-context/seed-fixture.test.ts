// Gobierna: specs/state-machines/tenant-context.spec.yaml TN1/SP1, common.spec.yaml
// GRD-CM-14 (fixture_seed_channel), GRD-CM-15 (source_from_execution_identity).
// TEST-CNS-472, TEST-CNS-473.

import test from "node:test";
import assert from "node:assert/strict";

import { seedSchoolParticipation, seedTenant } from "../../../src/server/modules/tenant-context/seed.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import type { ExecutionContext } from "../../../src/server/modules/common/types.ts";

test("TEST-CNS-472: TN1/SP1 ejecutadas por el rol de seed registran actorType=FIXTURE en el ledger (nunca HUMAN ni SYSTEM_GUARD)", () => {
  const ledger = createInMemoryLedgerAdapter();
  const seedCtx: ExecutionContext = { source: "FIXTURE", environment: "LOCAL" };

  seedTenant(seedCtx, { ledger }, "tenant-1");
  seedSchoolParticipation(seedCtx, { ledger }, "tenant-1", "participation-1");

  const tenantEvents = ledger.listByAggregate("tenant-1", "Tenant", "tenant-1");
  const spEvents = ledger.listByAggregate("tenant-1", "SchoolParticipation", "participation-1");
  assert.equal(tenantEvents.length, 1);
  assert.equal(tenantEvents[0]?.actorType, "FIXTURE");
  assert.equal(spEvents.length, 1);
  assert.equal(spEvents[0]?.actorType, "FIXTURE");
  for (const event of [...tenantEvents, ...spEvents]) {
    assert.notEqual(event.actorType, "HUMAN");
    assert.notEqual(event.actorType, "SYSTEM_GUARD");
  }
});

test("TEST-CNS-473: TN1/SP1 invocadas desde app_rw (BEARER) o platform_rw (PLATFORM) se rechazan con ERR-CM-10, aunque el llamador \"declare\" FIXTURE", () => {
  const ledger = createInMemoryLedgerAdapter();
  const nonSeedSources: ExecutionContext[] = [
    { source: "BEARER", environment: "LOCAL" },
    { source: "PLATFORM", environment: "LOCAL" },
    { source: "STAFF", environment: "LOCAL" },
    { source: "SYSTEM", environment: "LOCAL" },
  ];

  for (const ctx of nonSeedSources) {
    assert.throws(
      () => seedTenant(ctx, { ledger }, "tenant-2"),
      (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-10",
      `debía rechazar seedTenant desde source=${ctx.source}`,
    );
  }

  // Sin efecto: la base nunca ve una fila (ninguna función de seed la registra tampoco).
  assert.equal(ledger.listByAggregate("tenant-2", "Tenant", "tenant-2").length, 0);
});
