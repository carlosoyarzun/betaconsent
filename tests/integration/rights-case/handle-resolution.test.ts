// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-01 (tenant_resolved_server_side),
// specs/state-machines/rights-case.spec.yaml GRD-RC-14 (case_bound_to_handle_chain).
// TEST-CNS-458, TEST-CNS-459 (traceability/test-matrix.csv).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";

import { resolveCaseForHandle } from "../../../src/server/modules/rights-case/rights-case.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import type { RightsCaseRecord } from "../../../src/server/ports/rights-case-repository.port.ts";

async function seedCase(repo: ReturnType<typeof createInMemoryRightsCaseRepository>, record: RightsCaseRecord): Promise<void> {
  await repo.save(record);
}

test("TEST-CNS-458: handle rotado en /m/ -> 404 uniforme (ERR-CM-01), sin resolver caso (GRD-RC-14/GRD-CM-01)", async () => {
  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-A", tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", chainRef: fixtureUuid("chain-1"), revokedDecisionRef: fixtureUuid("decision-1") },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await seedCase(rightsCaseRepo, {
    caseRef: fixtureUuid("case-1"),
    tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73",
    chainRef: fixtureUuid("chain-1"),
    revokedDecisionRef: fixtureUuid("decision-1"),
    status: "OPEN",
  });

  // El handle se rota: el token viejo deja de resolver.
  tenantHandle.rotate("handle-A");

  await assert.rejects(
    () => resolveCaseForHandle({ tenantHandle, uow: createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter(), rightsCaseRepo }).uow }, "handle-A"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-459: un caseRef de otro tenant enviado por el cliente se ignora; el caso resuelve SIEMPRE desde (tenant_id, chainRef) del handle", async () => {
  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-tenant-1", tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", chainRef: fixtureUuid("chain-1"), revokedDecisionRef: fixtureUuid("decision-1") },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  await seedCase(rightsCaseRepo, {
    caseRef: fixtureUuid("case-tenant-1"),
    tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73",
    chainRef: fixtureUuid("chain-1"),
    revokedDecisionRef: fixtureUuid("decision-1"),
    status: "OPEN",
  });
  // Caso de OTRO tenant, con un caseRef que un atacante podría intentar inyectar.
  await seedCase(rightsCaseRepo, {
    caseRef: fixtureUuid("case-tenant-2-victim"),
    tenantId: "e12e79d5-93ae-448c-8630-579fc3de41c3",
    chainRef: fixtureUuid("chain-2"),
    revokedDecisionRef: fixtureUuid("decision-2"),
    status: "OPEN",
  });

  const resolved = await resolveCaseForHandle({ tenantHandle, uow: createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter(), rightsCaseRepo }).uow }, "handle-tenant-1", fixtureUuid("case-tenant-2-victim"));

  assert.equal(resolved.caseRef, fixtureUuid("case-tenant-1"));
  assert.equal(resolved.tenantId, "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73");
  assert.notEqual(resolved.caseRef, fixtureUuid("case-tenant-2-victim"));
});
