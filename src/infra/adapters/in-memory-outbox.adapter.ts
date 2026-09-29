// Gobierna: src/server/ports/outbox.port.ts, contracts/schemas/outbox-events.schema.json (CA-127).
// Adaptador in-memory IT0 LOCAL/CI: sin red, sin broker, sin firma (la entrega es R5). Mismo
// patrón que in-memory-recovery-link-channel-sink.adapter.ts: los tests y /__dev/outbox-sink
// leen `enqueued`.

import { randomUUID } from "node:crypto";

import type { OutboxEnqueueInput, OutboxPort, OutboxRecord } from "../../server/ports/outbox.port.ts";
import { OUTBOX_SCHEMA_VERSION } from "../../server/ports/outbox.port.ts";

export interface InMemoryOutbox extends OutboxPort {
  readonly enqueued: readonly OutboxRecord[];
}

/** FIXTURE solo válido en LOCAL/CI (R14-F); este adaptador es de uso exclusivo IT0. */
export function createInMemoryOutboxAdapter(): InMemoryOutbox {
  const enqueued: OutboxRecord[] = [];
  const byKey = new Map<string, OutboxRecord>();
  return {
    async enqueue(input: OutboxEnqueueInput): Promise<OutboxRecord> {
      const storeKey = `${input.tenantId}\u0000${input.dedupeKey}`;
      const existing = byKey.get(storeKey);
      if (existing) return existing;
      const record: OutboxRecord = {
        tenantId: input.tenantId,
        dedupeKey: input.dedupeKey,
        status: "PENDING",
        envelope: {
          eventId: randomUUID(),
          eventType: input.eventType,
          schemaVersion: OUTBOX_SCHEMA_VERSION,
          tenantRef: input.tenantId,
          contextRef: input.contextRef,
          subjectRef: input.subjectRef,
          occurredAt: input.occurredAt,
          payload: input.payload,
          environment: "LOCAL",
          dataClass: "SYNTHETIC",
        },
      };
      enqueued.push(record);
      byKey.set(storeKey, record);
      return record;
    },
    enqueued,
  };
}
