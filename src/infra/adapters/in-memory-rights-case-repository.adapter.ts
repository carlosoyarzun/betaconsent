// Gobierna: src/server/ports/rights-case-repository.port.ts. Adaptador in-memory IT0.
// CA-124: participante del UnitOfWork in-memory (journal).

import type {
  RightsCaseRecord,
  RightsCaseRepositoryPort,
} from "../../server/ports/rights-case-repository.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryRightsCaseRepository = RightsCaseRepositoryPort & TxParticipant;

export function createInMemoryRightsCaseRepository(): InMemoryRightsCaseRepository {
  const byKey = new JournaledMap<string, RightsCaseRecord>();

  function key(tenantId: string, caseRef: string): string {
    return `${tenantId}\u0000${caseRef}`;
  }

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    async findOpenByChain(tenantId, chainRef, revokedDecisionRef) {
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
    async findByRef(tenantId, caseRef) {
      const record = byKey.get(key(tenantId, caseRef));
      return record ?? null;
    },
    async findByRefForUpdate(tenantId, caseRef) {
      return byKey.get(key(tenantId, caseRef)) ?? null; // la UoW in-memory ya serializa
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.caseRef), { ...record });
    },
  };
}
