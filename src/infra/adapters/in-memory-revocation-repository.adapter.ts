// Gobierna: src/server/ports/revocation-repository.port.ts. Adaptador in-memory IT0.

import type {
  RevocationRecord,
  RevocationRepositoryPort,
} from "../../server/ports/revocation-repository.port.ts";

export function createInMemoryRevocationRepository(): RevocationRepositoryPort {
  const byKey = new Map<string, RevocationRecord>();

  function key(tenantId: string, revocationRef: string): string {
    return `${tenantId}\u0000${revocationRef}`;
  }

  return {
    findByRef(tenantId, revocationRef) {
      return byKey.get(key(tenantId, revocationRef)) ?? null;
    },
    findByCase(tenantId, caseRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.caseRef === caseRef) return record;
      }
      return null;
    },
    save(record) {
      byKey.set(key(record.tenantId, record.revocationRef), { ...record });
    },
  };
}
