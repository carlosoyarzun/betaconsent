// Gobierna: src/server/ports/idempotency.port.ts (GRD-CM-08). Adaptador in-memory IT0: sin TTL
// (P-33 sin valor en el repo); vive lo que vive el proceso.

import type { IdempotencyPort, StoredIdempotentResponse } from "../../server/ports/idempotency.port.ts";

export function createInMemoryIdempotencyAdapter(): IdempotencyPort {
  const entries = new Map<string, StoredIdempotentResponse>();
  return {
    find(scopeKeyHash) {
      return entries.get(scopeKeyHash) ?? null;
    },
    store(scopeKeyHash, response) {
      if (!entries.has(scopeKeyHash)) entries.set(scopeKeyHash, response);
    },
  };
}
