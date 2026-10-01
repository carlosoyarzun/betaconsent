// Gobierna: CA-124 (PR-C). Registra la suite de contrato de los repos de tenant contra los
// adaptadores in-memory. TEST-CNS-800..806. El registro contra Postgres vive en
// tests/integration/postgres/tenant-repos-contract.test.ts.

import test from "node:test";

import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { createInMemoryTenantCatalogAdapter } from "../../../src/infra/adapters/in-memory-tenant-catalog.adapter.ts";
import type { TenantCatalogPort } from "../../../src/server/ports/tenant-catalog.port.ts";
import { runTenantReposContract } from "./tenant-repos-tx.contract.ts";
import type { TenantReposHarness } from "./tenant-repos-tx.contract.ts";

function makeInMemoryHarness(): TenantReposHarness {
  const catalog = createInMemoryTenantCatalogAdapter();
  const tenancy = createInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
  });
  return {
    uow: tenancy.uow,
    resolver: tenancy.tenantResolver,
    async seedSubject(tenantId, subjectRef) {
      catalog.seedSubject(tenantId, subjectRef);
    },
    async seedParticipation(tenantId, participation) {
      catalog.seedParticipation(tenantId, participation);
    },
    // El catalogo in-memory no es transaccional: se acota al tenant de la unidad de trabajo como lo
    // hace RLS en Postgres (otro tenant = false/null), igual que los scopeXRepo del UoW in-memory.
    withCatalog: async (tenantId, work) => {
      const scoped: TenantCatalogPort = {
        subjectBelongsToTenant: async (t, ref) => (t === tenantId ? catalog.subjectBelongsToTenant(t, ref) : false),
        findParticipation: async (t, ref) => (t === tenantId ? catalog.findParticipation(t, ref) : null),
      };
      return work(scoped);
    },
  };
}

runTenantReposContract("in-memory", (name, body) => {
  test(name, () => body(makeInMemoryHarness()));
});
