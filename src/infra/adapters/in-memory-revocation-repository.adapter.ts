// Gobierna: src/server/ports/revocation-repository.port.ts. Adaptador in-memory IT0.

import type {
  RevocationRecord,
  RevocationRepositoryPort,
} from "../../server/ports/revocation-repository.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryRevocationRepository = RevocationRepositoryPort & TxParticipant;

export function createInMemoryRevocationRepository(): InMemoryRevocationRepository {
  const byKey = new JournaledMap<string, RevocationRecord>();

  function key(tenantId: string, revocationRef: string): string {
    return `${tenantId}\u0000${revocationRef}`;
  }

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    async findByRef(tenantId, revocationRef) {
      return byKey.get(key(tenantId, revocationRef)) ?? null;
    },
    async findByRefForUpdate(tenantId, revocationRef) {
      return byKey.get(key(tenantId, revocationRef)) ?? null; // la UoW in-memory ya serializa
    },
    async findByCase(tenantId, caseRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.caseRef === caseRef) return record;
      }
      return null;
    },
    async findOpenByChain(tenantId, chainRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.chainRef === chainRef && record.status !== "FAILED" && record.status !== "COMPLETED") {
          return record;
        }
      }
      return null;
    },
    async findOpenByDecision(tenantId, revokedDecisionRef) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.revokedDecisionRef === revokedDecisionRef &&
          record.status !== "FAILED" &&
          record.status !== "COMPLETED"
        ) {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.revocationRef), { ...record });
    },
  };
}
