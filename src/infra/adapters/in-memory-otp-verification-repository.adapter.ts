// Gobierna: src/server/ports/otp-verification-repository.port.ts. Adaptador in-memory IT0.
// CA-124: participante del UnitOfWork in-memory (journal).

import type {
  OtpVerificationRecord,
  OtpVerificationRepositoryPort,
} from "../../server/ports/otp-verification-repository.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryOtpVerificationRepository = OtpVerificationRepositoryPort & TxParticipant;

export function createInMemoryOtpVerificationRepository(): InMemoryOtpVerificationRepository {
  const byKey = new JournaledMap<string, OtpVerificationRecord>();
  const activeStates = new Set(["NOT_STARTED", "CODE_SENT"]);

  function key(tenantId: string, verificationRef: string): string {
    return `${tenantId}\u0000${verificationRef}`;
  }

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    async findByRef(tenantId, verificationRef) {
      return byKey.get(key(tenantId, verificationRef)) ?? null;
    },
    async findByRefForUpdate(tenantId, verificationRef) {
      return byKey.get(key(tenantId, verificationRef)) ?? null; // la UoW in-memory ya serializa
    },
    async findActiveByParent(tenantId, parentRef, scope) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.parentRef === parentRef &&
          record.scope === scope &&
          activeStates.has(record.state)
        ) {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.verificationRef), { ...record });
    },
  };
}
