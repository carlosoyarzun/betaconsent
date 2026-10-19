// Gobierna: plan v2 H1-02 (verify-ledger de H1-11 reutilizará esta lectura). Lee la cadena del colegio en orden de chain_seq
// con occurred_at en el formato canónico del hash (UTC, microsegundos) para que el verificador TS recalcule los mismos hashes que SQL.

import type { Queryable } from "../db/assert-environment.ts";
import { verifyChainRows, type ChainRow, type LedgerChainReport } from "./ledger-chain.ts";

interface Row {
  tenant_id: string;
  chain_seq: string;
  aggregate_type: string;
  aggregate_id: string;
  sequence: number;
  event_type: string;
  actor_type: string;
  actor_role: string | null;
  recorded_by_ref: string | null;
  cosigned_by_ref: string | null;
  idempotency_key_hash: string | null;
  occurred_at: string;
  environment: string;
  payload_hash: string;
  previous_event_hash: string;
  event_hash: string;
  payload: Record<string, unknown>;
}

export async function readChain(db: Queryable): Promise<ChainRow[]> {
  const { rows } = await db.query<Row>(
    `SELECT tenant_id, chain_seq::text AS chain_seq, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role,
            recorded_by_ref, cosigned_by_ref, idempotency_key_hash,
            to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at,
            environment, payload_hash, previous_event_hash, event_hash, payload
       FROM integrity.audit_event ORDER BY integrity.audit_event.chain_seq`,
  );
  return rows.map((r) => ({
    tenantId: r.tenant_id,
    chainSeq: Number(r.chain_seq),
    aggregateType: r.aggregate_type,
    aggregateId: r.aggregate_id,
    sequence: r.sequence,
    eventType: r.event_type,
    actorType: r.actor_type,
    actorRole: r.actor_role,
    recordedByRef: r.recorded_by_ref,
    cosignedByRef: r.cosigned_by_ref,
    idempotencyKeyHash: r.idempotency_key_hash,
    occurredAt: r.occurred_at,
    environment: r.environment,
    payloadHash: r.payload_hash,
    previousEventHash: r.previous_event_hash,
    eventHash: r.event_hash,
    payload: r.payload,
  }));
}

export async function verifyLedger(db: Queryable): Promise<LedgerChainReport> {
  return verifyChainRows(await readChain(db));
}
