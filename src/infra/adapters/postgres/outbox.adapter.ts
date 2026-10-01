// Gobierna: CA-124 (H09), PR-B; src/server/ports/outbox.port.ts, db/migrations/0003_outbox.sql,
// outbox-events.schema.json (API-CNS-185), common.spec.yaml (OUTBOX at-least-once), INV-CM-01/02.
//
// enqueue opera dentro de la transaccion de PgUnitOfWork.inTenant (RLS por tenant). El claim del
// worker (`claimOutbox`) NO es parte del puerto del dominio: lo usa el proceso worker con el rol
// `worker` y la funcion SECURITY DEFINER app.outbox_claim (R5 llegara con la entrega firmada).

import type { Environment } from "../../../server/modules/common/types.ts";
import { OUTBOX_SCHEMA_VERSION } from "../../../server/ports/outbox.port.ts";
import type {
  ConsentRevokedOutboxPayload,
  OutboxEnqueueInput,
  OutboxEnvelope,
  OutboxPort,
  OutboxRecord,
} from "../../../server/ports/outbox.port.ts";
import type { Queryable } from "./pool.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface OutboxRow {
  event_id: string;
  tenant_id: string;
  dedupe_key: string;
  event_type: "consent.revoked";
  schema_version: string;
  context_ref: string;
  subject_ref: string;
  occurred_at: string;
  payload: ConsentRevokedOutboxPayload;
  environment: Exclude<Environment, "PRODUCTION">;
}

const OCCURRED_AT_SQL = `to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at`;
const SELECT_COLUMNS = `event_id, tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, ${OCCURRED_AT_SQL}, payload, environment`;

function toEnvelope(row: OutboxRow): OutboxEnvelope {
  return {
    eventId: row.event_id,
    eventType: row.event_type,
    schemaVersion: row.schema_version,
    tenantRef: row.tenant_id,
    contextRef: row.context_ref,
    subjectRef: row.subject_ref,
    occurredAt: row.occurred_at,
    payload: row.payload,
    environment: row.environment,
    dataClass: "SYNTHETIC",
  };
}

function toRecord(row: OutboxRow): OutboxRecord {
  return { tenantId: row.tenant_id, dedupeKey: row.dedupe_key, status: "PENDING", envelope: toEnvelope(row) };
}

export function createPgOutboxAdapter(tx: TenantTx): OutboxPort {
  return {
    async enqueue(input: OutboxEnqueueInput): Promise<OutboxRecord> {
      const inserted = await tx.query<OutboxRow>(
        `INSERT INTO app.outbox (tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, occurred_at, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb)
         ON CONFLICT (tenant_id, dedupe_key) DO NOTHING
         RETURNING ${SELECT_COLUMNS}`,
        [
          input.tenantId,
          input.dedupeKey,
          input.eventType,
          OUTBOX_SCHEMA_VERSION,
          input.contextRef,
          input.subjectRef,
          input.occurredAt,
          JSON.stringify(input.payload),
        ],
      );
      const fresh = inserted.rows[0];
      if (fresh) return toRecord(fresh);
      const existing = await tx.query<OutboxRow>(
        `SELECT ${SELECT_COLUMNS} FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2`,
        [input.tenantId, input.dedupeKey],
      );
      const row = existing.rows[0];
      if (!row) throw new Error("outbox: conflicto de dedupe sin fila visible");
      return toRecord(row);
    },
  };
}

export interface ClaimedOutboxEvent {
  readonly envelope: OutboxEnvelope;
  readonly attempts: number;
}

/**
 * Claim del worker (rol `worker`, sin tenant): hasta `limit` eventos PENDING o con lease vencido,
 * marcados CLAIMED. Fuera de una unidad de trabajo de tenant (cruza tenants por diseno).
 */
export async function claimOutbox(db: Queryable, limit: number, leaseSeconds: number): Promise<ClaimedOutboxEvent[]> {
  const r = await db.query<OutboxRow & { attempts: number }>(
    `SELECT event_id, tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, ${OCCURRED_AT_SQL},
            payload, environment, attempts
       FROM app.outbox_claim($1, $2)`,
    [limit, leaseSeconds],
  );
  return r.rows.map((row) => ({ envelope: toEnvelope(row), attempts: row.attempts }));
}
