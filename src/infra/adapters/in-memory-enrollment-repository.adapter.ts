// Gobierna: src/server/ports/enrollment-repository.port.ts. Adaptador in-memory IT0.
// CA-124: participante del UnitOfWork in-memory (journal).

import type { EnrollmentRecord, EnrollmentRepositoryPort } from "../../server/ports/enrollment-repository.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

/** Listado de LECTURA para la proyeccion in-memory del roster (API-CNS-116): NO es parte del puerto del dominio. */
export interface EnrollmentListing {
  listByTenant(tenantId: string): readonly EnrollmentRecord[];
}

export type InMemoryEnrollmentRepository = EnrollmentRepositoryPort & TxParticipant & EnrollmentListing;

export function createInMemoryEnrollmentRepository(): InMemoryEnrollmentRepository {
  const byKey = new JournaledMap<string, EnrollmentRecord>();
  const key = (tenantId: string, enrollmentRef: string): string => `${tenantId}\u0000${enrollmentRef}`;

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    async findByRef(tenantId, enrollmentRef) {
      return byKey.get(key(tenantId, enrollmentRef)) ?? null;
    },
    async findActive(tenantId, subjectRef, participationRef) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.subjectRef === subjectRef &&
          record.participationRef === participationRef &&
          record.state === "ACTIVE"
        ) {
          return record;
        }
      }
      return null;
    },
    listByTenant(tenantId) {
      return [...byKey.values()].filter((r) => r.tenantId === tenantId);
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.enrollmentRef), { ...record });
    },
  };
}
