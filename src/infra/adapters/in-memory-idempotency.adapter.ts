// Gobierna: src/server/ports/idempotency.port.ts (GRD-CM-08), CA-124 PR-E. Adaptador in-memory IT0:
// participante journaled del UnitOfWork (find + ejecutar + store atómicos: si la unidad falla, la
// entrada guardada se deshace) y aislado por tenant. El TTL P-33 = 24 h está APROBADO (Carlos, 2026-10-01; approved-parameters.ts): el llamador lo
// pasa explícito (idempotency-policy.config.ts, fail-closed); SEC-CNS-017 F7: `ttlMs` es
// obligatorio (sin TTL infinito): ausente -> lanza (fail-closed).

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

/** Valor LOCAL-only/test-only de conveniencia para el cableado in-memory por defecto (= P-33 aprobado, 24 h, Carlos 2026-10-01). */
export const LOCAL_ONLY_IN_MEMORY_IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000;

export function createInMemoryIdempotencyAdapter(options: InMemoryIdempotencyOptions = {}): InMemoryIdempotencyAdapter {
  if (options.ttlMs === undefined || !(options.ttlMs > 0)) {
    throw new Error("Idempotencia in-memory: ttlMs (P-33) es obligatorio y > 0; sin politica no se crea (fail-closed, SEC-CNS-017 F7).");
  }
  const ttlMs = options.ttlMs;
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
      entries.set(k, { response, expiresAt: now() + ttlMs });
    },
  };
}
