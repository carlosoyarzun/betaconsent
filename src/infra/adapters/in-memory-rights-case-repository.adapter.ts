// Gobierna: src/server/ports/rights-case-repository.port.ts. Adaptador in-memory IT0.

import type {
  RightsCaseRecord,
  RightsCaseRepositoryPort,
} from "../../server/ports/rights-case-repository.port.ts";

export function createInMemoryRightsCaseRepository(): RightsCaseRepositoryPort {
  const byKey = new Map<string, RightsCaseRecord>();

  function key(tenantId: string, caseRef: string): string {
    return `${tenantId}\u0000${caseRef}`;
  }

  return {
    findOpenByChain(tenantId, chainRef, revokedDecisionRef) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.chainRef === chainRef &&
          record.revokedDecisionRef === revokedDecisionRef &&
          record.status !== "RESOLVED" &&
          record.status !== "WITHDRAWN"
        ) {
          return record;
        }
      }
      return null;
    },
    findByRef(tenantId, caseRef) {
      const record = byKey.get(key(tenantId, caseRef));
      return record ?? null;
    },
    save(record) {
      byKey.set(key(record.tenantId, record.caseRef), { ...record });
    },
  };
}
