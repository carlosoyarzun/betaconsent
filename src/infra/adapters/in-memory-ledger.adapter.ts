// Gobierna: src/server/ports/ledger.port.ts, specs/state-machines/common.spec.yaml
// `ledgerEnvelope`. Adaptador in-memory para IT0 LOCAL/CI (ADR-003 rev.7: sin infraestructura
// real; el adaptador de Postgres llega con la historia de infraestructura correspondiente).
// CA-124: participante del UnitOfWork in-memory (journal, in-memory-tx.ts) y control optimista
// `expectedSequence`.

import {
  computeEventHash,
  formatOccurredAt,
  computePayloadHash,
  LEDGER_GENESIS_HASH,
  sha256Hex,
  type ChainRow,
} from "../../server/modules/common/ledger-chain.ts";
import { assertLedgerEventType } from "../../server/modules/common/ledger-event-types.ts";
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
  // X6: cola de la cadena por tenant (ultimo chainSeq y eventHash). Journaled: un rollback la deshace.
  const chainTail = new JournaledMap<string, { readonly chainSeq: number; readonly eventHash: string }>();

  // La numeración es por (tenant, aggregate_id), igual que UNIQUE (tenant_id, aggregate_id, sequence)
  // de integrity.audit_event (common.spec.yaml ledgerEnvelope.checks); aggregateType no entra.
  function aggregateKey(tenantId: string, aggregateId: string): string {
    return `${tenantId}\u0000${aggregateId}`;
  }

  function idempotencyStoreKey(tenantId: string, aggregateType: string, aggregateId: string, idempotencyKey: string): string {
    return `${aggregateKey(tenantId, aggregateId)}\u0000${idempotencyKey}`;
  }

  return {
    [TX_JOURNAL](journal) {
      records.journal = journal;
      sequenceByAggregate.journal = journal;
      byIdempotencyKey.journal = journal;
      chainTail.journal = journal;
    },
    async append(event: LedgerEventInput): Promise<LedgerRecord> {
      assertLedgerEventType(event.eventType);
      if (event.idempotencyKey) {
        const key = idempotencyStoreKey(event.tenantId, event.aggregateType, event.aggregateId, event.idempotencyKey);
        const existing = byIdempotencyKey.get(key);
        if (existing) return existing;
      }

      const aggKey = aggregateKey(event.tenantId, event.aggregateId);
      const currentSequence = sequenceByAggregate.get(aggKey) ?? 0;
      if (event.expectedSequence !== currentSequence) {
        throw new LedgerSequenceConflictError(event.expectedSequence, currentSequence);
      }
      const nextSequence = event.expectedSequence + 1; // SEC-CNS-013 P2-3: sequence = expectedSequence + 1
      sequenceByAggregate.set(aggKey, nextSequence);

      // X6: eslabon de la cadena del tenant. Las unidades in-memory estan serializadas
      // (in-memory-unit-of-work.adapter.ts), el equivalente al lock por tenant de Postgres.
      const tail = chainTail.get(event.tenantId);
      const chainSeq = (tail?.chainSeq ?? 0) + 1;
      const previousEventHash = tail?.eventHash ?? LEDGER_GENESIS_HASH;
      const payloadHash = computePayloadHash(event.payload);
      const occurredAt = new Date();
      const eventHash = computeEventHash({
        tenantId: event.tenantId,
        chainSeq,
        aggregateType: event.aggregateType,
        aggregateId: event.aggregateId,
        sequence: nextSequence,
        eventType: event.eventType,
        actorType: event.actorType,
        actorRole: event.actorRole ?? null,
        recordedByRef: event.recordedByRef ?? null,
        cosignedByRef: event.cosignedByRef ?? null,
        idempotencyKeyHash: event.idempotencyKey !== undefined ? sha256Hex(event.idempotencyKey) : null,
        occurredAt: formatOccurredAt(occurredAt),
        environment: "LOCAL",
        payloadHash,
        previousEventHash,
      });
      chainTail.set(event.tenantId, { chainSeq, eventHash });

      const { expectedSequence: _expectedSequence, ...eventFields } = event;
      const record: LedgerRecord = {
        ...eventFields,
        chainSeq,
        payloadHash,
        previousEventHash,
        eventHash,
        sequence: nextSequence,
        occurredAt,
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
    async currentSequence(tenantId, aggregateId) {
      return sequenceByAggregate.get(aggregateKey(tenantId, aggregateId)) ?? 0;
    },
    async readChain(tenantId): Promise<readonly ChainRow[]> {
      return records.items
        .filter((r) => r.tenantId === tenantId)
        .sort((a, b) => a.chainSeq - b.chainSeq)
        .map((r) => ({
          tenantId: r.tenantId,
          chainSeq: r.chainSeq,
          aggregateType: r.aggregateType,
          aggregateId: r.aggregateId,
          sequence: r.sequence,
          eventType: r.eventType,
          actorType: r.actorType,
          actorRole: r.actorRole ?? null,
          recordedByRef: r.recordedByRef ?? null,
          cosignedByRef: r.cosignedByRef ?? null,
          idempotencyKeyHash: r.idempotencyKey !== undefined ? sha256Hex(r.idempotencyKey) : null,
          occurredAt: formatOccurredAt(r.occurredAt),
          environment: r.environment,
          payload: r.payload,
          payloadHash: r.payloadHash,
          previousEventHash: r.previousEventHash,
          eventHash: r.eventHash,
        }));
    },
    async listByAggregate(tenantId, aggregateType, aggregateId) {
      return records.items.filter(
        (r) => r.tenantId === tenantId && r.aggregateType === aggregateType && r.aggregateId === aggregateId,
      );
    },
  };
}
