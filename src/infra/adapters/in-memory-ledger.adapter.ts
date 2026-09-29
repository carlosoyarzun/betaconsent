// Gobierna: src/server/ports/ledger.port.ts, specs/state-machines/common.spec.yaml
// `ledgerEnvelope`. Adaptador in-memory para IT0 LOCAL/CI (ADR-003 rev.7: sin infraestructura
// real; el adaptador de Postgres llega con la historia de infraestructura correspondiente).
// CA-124: participante del UnitOfWork in-memory (journal, in-memory-tx.ts) y control optimista
// `expectedSequence`.

import {
  LedgerSequenceConflictError,
  type LedgerEventInput,
  type LedgerPort,
  type LedgerRecord,
} from "../../server/ports/ledger.port.ts";
import { JournaledList, JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryLedger = LedgerPort & TxParticipant;

/** FIXTURE solo válido en LOCAL/CI (R14-F); este adaptador es de uso exclusivo IT0. */
export function createInMemoryLedgerAdapter(): InMemoryLedger {
  const records = new JournaledList<LedgerRecord>();
  const sequenceByAggregate = new JournaledMap<string, number>();
  const byIdempotencyKey = new JournaledMap<string, LedgerRecord>();

  function aggregateKey(tenantId: string, aggregateType: string, aggregateId: string): string {
    return `${tenantId}\u0000${aggregateType}\u0000${aggregateId}`;
  }

  function idempotencyStoreKey(tenantId: string, aggregateType: string, aggregateId: string, idempotencyKey: string): string {
    return `${aggregateKey(tenantId, aggregateType, aggregateId)}\u0000${idempotencyKey}`;
  }

  return {
    [TX_JOURNAL](journal) {
      records.journal = journal;
      sequenceByAggregate.journal = journal;
      byIdempotencyKey.journal = journal;
    },
    async append(event: LedgerEventInput): Promise<LedgerRecord> {
      if (event.idempotencyKey) {
        const key = idempotencyStoreKey(event.tenantId, event.aggregateType, event.aggregateId, event.idempotencyKey);
        const existing = byIdempotencyKey.get(key);
        if (existing) return existing;
      }

      const aggKey = aggregateKey(event.tenantId, event.aggregateType, event.aggregateId);
      const currentSequence = sequenceByAggregate.get(aggKey) ?? 0;
      if (event.expectedSequence !== undefined && event.expectedSequence !== currentSequence) {
        throw new LedgerSequenceConflictError(event.expectedSequence, currentSequence);
      }
      const nextSequence = currentSequence + 1;
      sequenceByAggregate.set(aggKey, nextSequence);

      const { expectedSequence: _expectedSequence, ...eventFields } = event;
      const record: LedgerRecord = {
        ...eventFields,
        sequence: nextSequence,
        occurredAt: new Date(),
        environment: "LOCAL",
        evidentiary: false,
        dataClass: "SYNTHETIC",
      };
      records.push(record);

      if (event.idempotencyKey) {
        const key = idempotencyStoreKey(event.tenantId, event.aggregateType, event.aggregateId, event.idempotencyKey);
        byIdempotencyKey.set(key, record);
      }

      return record;
    },
    async listByAggregate(tenantId, aggregateType, aggregateId) {
      return records.items.filter(
        (r) => r.tenantId === tenantId && r.aggregateType === aggregateType && r.aggregateId === aggregateId,
      );
    },
  };
}
