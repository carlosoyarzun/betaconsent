// Gobierna: src/server/ports/consent-decision-repository.port.ts. Adaptador in-memory IT0.

import type {
  ConsentDecisionRecord,
  ConsentDecisionRepositoryPort,
} from "../../server/ports/consent-decision-repository.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryConsentDecisionRepository = ConsentDecisionRepositoryPort & TxParticipant;

export function createInMemoryConsentDecisionRepository(): InMemoryConsentDecisionRepository {
  const byKey = new JournaledMap<string, ConsentDecisionRecord>();

  function key(tenantId: string, consentId: string): string {
    return `${tenantId}\u0000${consentId}`;
  }

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    async findByConsentId(tenantId, consentId) {
      return byKey.get(key(tenantId, consentId)) ?? null;
    },
    async findActiveGrantByChain(tenantId, chainRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.chainRef === chainRef && record.state === "GRANTED") {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.consentId), { ...record });
    },
  };
}
