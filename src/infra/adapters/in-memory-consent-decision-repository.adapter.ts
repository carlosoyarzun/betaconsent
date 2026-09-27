// Gobierna: src/server/ports/consent-decision-repository.port.ts. Adaptador in-memory IT0.

import type {
  ConsentDecisionRecord,
  ConsentDecisionRepositoryPort,
} from "../../server/ports/consent-decision-repository.port.ts";

export function createInMemoryConsentDecisionRepository(): ConsentDecisionRepositoryPort {
  const byKey = new Map<string, ConsentDecisionRecord>();

  function key(tenantId: string, consentId: string): string {
    return `${tenantId}\u0000${consentId}`;
  }

  return {
    findByConsentId(tenantId, consentId) {
      return byKey.get(key(tenantId, consentId)) ?? null;
    },
    findActiveGrantByChain(tenantId, chainRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.chainRef === chainRef && record.state === "GRANTED") {
          return record;
        }
      }
      return null;
    },
    save(record) {
      byKey.set(key(record.tenantId, record.consentId), { ...record });
    },
  };
}
