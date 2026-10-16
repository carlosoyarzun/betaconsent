// Fixture de tests (SYNTHETIC DATA ONLY): cadena SHA-256 sintetica de un tenant con los helpers de ledger-chain.ts. Sin PII, sin red, sin BD.

import { computeEventHash, computePayloadHash, LEDGER_GENESIS_HASH } from "../../../src/server/modules/common/ledger-chain.ts";
import type { ChainRow } from "../../../src/server/modules/common/ledger-chain.ts";

export const TENANT_A = "11111111-1111-4111-8111-111111111111";
export const TENANT_B = "22222222-2222-4222-8222-222222222222";

export function buildChain(n: number, tenantId: string = TENANT_A, aggregateId: (i: number) => string = (i) => `agg-${i % 2}`): ChainRow[] {
  const rows: ChainRow[] = [];
  let previous = LEDGER_GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const payload = { step: i, kind: "SYNTHETIC" };
    const base = {
      tenantId,
      chainSeq: i,
      aggregateType: "Revocation",
      aggregateId: aggregateId(i),
      sequence: Math.ceil(i / 2),
      eventType: "REVOCATION_REQUESTED",
      actorType: "HUMAN",
      actorRole: null,
      recordedByRef: null,
      cosignedByRef: null,
      idempotencyKeyHash: null,
      occurredAt: `2026-10-01T12:00:${String(i % 60).padStart(2, "0")}.000000Z`,
      environment: "LOCAL",
      payloadHash: computePayloadHash(payload),
      previousEventHash: previous,
    };
    const eventHash = computeEventHash(base);
    rows.push({ ...base, payload, eventHash });
    previous = eventHash;
  }
  return rows;
}

/** Entrega las filas como lotes de `size` (AsyncIterable) para auditTenantChain. */
export async function* inBatches(rows: readonly ChainRow[], size: number): AsyncGenerator<readonly ChainRow[]> {
  for (let i = 0; i < rows.length; i += size) yield rows.slice(i, i + size);
}
