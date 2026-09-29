// Gobierna: src/server/ports/ledger.port.ts, specs/state-machines/common.spec.yaml
// `ledgerEnvelope`. Adaptador in-memory para IT0 LOCAL/CI (ADR-003 rev.7: sin infraestructura
// real; el adaptador de Postgres llega con la historia de infraestructura correspondiente).

import type { LedgerEventInput, LedgerPort, LedgerRecord } from "../../server/ports/ledger.port.ts";

/** FIXTURE solo válido en LOCAL/CI (R14-F); este adaptador es de uso exclusivo IT0. */
export function createInMemoryLedgerAdapter(): LedgerPort {
  const records: LedgerRecord[] = [];
  const sequenceByAggregate = new Map<string, number>();
  const byIdempotencyKey = new Map<string, LedgerRecord>();

  function aggregateKey(tenantId: string, aggregateType: string, aggregateId: string): string {
    return `${tenantId}\u0000${aggregateType}\u0000${aggregateId}`;
  }

  function idempotencyStoreKey(tenantId: string, aggregateType: string, aggregateId: string, idempotencyKey: string): string {
    return `${aggregateKey(tenantId, aggregateType, aggregateId)}\u0000${idempotencyKey}`;
  }

  return {
    async append(event: LedgerEventInput): Promise<LedgerRecord> {
      if (event.idempotencyKey) {
        const key = idempotencyStoreKey(event.tenantId, event.aggregateType, event.aggregateId, event.idempotencyKey);
        const existing = byIdempotencyKey.get(key);
        if (existing) return existing;
      }

      const aggKey = aggregateKey(event.tenantId, event.aggregateType, event.aggregateId);
      const nextSequence = (sequenceByAggregate.get(aggKey) ?? 0) + 1;
      sequenceByAggregate.set(aggKey, nextSequence);

      const record: LedgerRecord = {
        ...event,
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
      return records.filter(
        (r) => r.tenantId === tenantId && r.aggregateType === aggregateType && r.aggregateId === aggregateId,
      );
    },
  };
}
