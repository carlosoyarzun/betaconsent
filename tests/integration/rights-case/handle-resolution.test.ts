// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-01 (tenant_resolved_server_side),
// specs/state-machines/rights-case.spec.yaml GRD-RC-14 (case_bound_to_handle_chain).
// TEST-CNS-458, TEST-CNS-459 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";

import { resolveCaseForHandle } from "../../../src/server/modules/rights-case/rights-case.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import type { RightsCaseRecord } from "../../../src/server/ports/rights-case-repository.port.ts";

function seedCase(repo: ReturnType<typeof createInMemoryRightsCaseRepository>, record: RightsCaseRecord): void {
  repo.save(record);
}

test("TEST-CNS-458: handle rotado en /m/ -> 404 uniforme (ERR-CM-01), sin resolver caso (GRD-RC-14/GRD-CM-01)", () => {
  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-A", tenantId: "tenant-1", chainRef: "chain-1", revokedDecisionRef: "decision-1" },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  seedCase(rightsCaseRepo, {
    caseRef: "case-1",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    revokedDecisionRef: "decision-1",
    status: "OPEN",
  });

  // El handle se rota: el token viejo deja de resolver.
  tenantHandle.rotate("handle-A");

  assert.throws(
    () => resolveCaseForHandle({ tenantHandle, rightsCaseRepo }, "handle-A"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-459: un caseRef de otro tenant enviado por el cliente se ignora; el caso resuelve SIEMPRE desde (tenant_id, chainRef) del handle", () => {
  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-tenant-1", tenantId: "tenant-1", chainRef: "chain-1", revokedDecisionRef: "decision-1" },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  seedCase(rightsCaseRepo, {
    caseRef: "case-tenant-1",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    revokedDecisionRef: "decision-1",
    status: "OPEN",
  });
  // Caso de OTRO tenant, con un caseRef que un atacante podría intentar inyectar.
  seedCase(rightsCaseRepo, {
    caseRef: "case-tenant-2-victim",
    tenantId: "tenant-2",
    chainRef: "chain-2",
    revokedDecisionRef: "decision-2",
    status: "OPEN",
  });

  const resolved = resolveCaseForHandle({ tenantHandle, rightsCaseRepo }, "handle-tenant-1", "case-tenant-2-victim");

  assert.equal(resolved.caseRef, "case-tenant-1");
  assert.equal(resolved.tenantId, "tenant-1");
  assert.notEqual(resolved.caseRef, "case-tenant-2-victim");
});
