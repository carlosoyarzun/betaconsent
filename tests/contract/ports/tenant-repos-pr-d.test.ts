// Gobierna: CA-124 (PR-D). Registra la suite de contrato de los repos de tenant de PR-D contra los
// adaptadores in-memory. TEST-CNS-830..837. El registro contra Postgres vive en
// tests/integration/postgres/tenant-repos-pr-d-contract.test.ts.

import test from "node:test";

import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { runTenantReposPrDContract } from "./tenant-repos-pr-d.contract.ts";
import type { TenantReposPrDHarness } from "./tenant-repos-pr-d.contract.ts";

function makeInMemoryHarness(): TenantReposPrDHarness {
  const handles = createInMemoryTenantHandleAdapter();
  const tenancy = createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter(), tenantHandle: handles });
  return {
    uow: tenancy.uow,
    resolver: tenancy.tenantResolver,
    handlePort: handles,
    async issueHandle(tenantId, seed) {
      handles.issue({ ...seed, tenantId });
    },
    // Como la funcion SQL: solo rota handles del tenant de la unidad de trabajo.
    async rotateHandle(tenantId, handle) {
      const current = await handles.resolve(handle);
      if (current?.tenantId === tenantId) handles.rotate(handle);
    },
  };
}

runTenantReposPrDContract("in-memory", (name, body) => {
  test(name, () => body(makeInMemoryHarness()));
});

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-102, TEST-CNS-831, TEST-CNS-832, TEST-CNS-833, TEST-CNS-834, TEST-CNS-835, TEST-CNS-836, TEST-CNS-837 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
