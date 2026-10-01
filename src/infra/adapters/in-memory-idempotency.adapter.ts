// Gobierna: src/server/ports/idempotency.port.ts (GRD-CM-08), CA-124 PR-E. Adaptador in-memory IT0:
// participante journaled del UnitOfWork (find + ejecutar + store atómicos: si la unidad falla, la
// entrada guardada se deshace) y aislado por tenant. El TTL P-33 NO está aprobado: el llamador lo
// pasa explícito (idempotency-policy.config.ts, fail-closed); `ttlMs` ausente = no expira dentro de
// la vida del proceso (solo para tests/fixtures que no ejercitan el TTL).

import type { IdempotencyPort, StoredIdempotentResponse } from "../../server/ports/idempotency.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryIdempotencyAdapter = IdempotencyPort & TxParticipant;

export interface InMemoryIdempotencyOptions {
  readonly ttlMs?: number;
  /** Reloj inyectable para tests del TTL. */
  readonly now?: () => number;
}

interface Entry {
  readonly response: StoredIdempotentResponse;
  readonly expiresAt: number;
}

export function createInMemoryIdempotencyAdapter(options: InMemoryIdempotencyOptions = {}): InMemoryIdempotencyAdapter {
  const entries = new JournaledMap<string, Entry>();
  const now = options.now ?? Date.now;
  const key = (tenantId: string, scopeKeyHash: string): string => `${tenantId}\u0000${scopeKeyHash}`;
  const live = (entry: Entry | undefined): Entry | undefined => (entry !== undefined && entry.expiresAt > now() ? entry : undefined);

  return {
    [TX_JOURNAL](journal) {
      entries.journal = journal;
    },
    async find(tenantId, scopeKeyHash) {
      return live(entries.get(key(tenantId, scopeKeyHash)))?.response ?? null;
    },
    async store(tenantId, scopeKeyHash, response) {
      const k = key(tenantId, scopeKeyHash);
      if (live(entries.get(k)) !== undefined) return; // la primera gana
      entries.set(k, { response, expiresAt: options.ttlMs === undefined ? Number.POSITIVE_INFINITY : now() + options.ttlMs });
    },
  };
}
