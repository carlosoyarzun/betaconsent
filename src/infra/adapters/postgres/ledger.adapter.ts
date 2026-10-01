// Gobierna: CA-124 (H09), PR-B; src/server/ports/ledger.port.ts, db/migrations/0002_ledger.sql,
// common.spec.yaml ledgerEnvelope (UNIQUE tenant_id, aggregate_id, sequence; concurrency
// expectedSequence), INV-CM-01, INV-CM-02. ADR-001 §11: solo este adaptador conoce el SQL.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (tenant fijado con set_config local):
// RLS filtra por app.current_tenant_id(); aqui tenant_id solo se pasa para WITH CHECK y filtros.

import { createHash } from "node:crypto";

import {
  computeEventHash,
  computePayloadHash,
  LEDGER_GENESIS_HASH,
  type ChainRow,
} from "../../../server/modules/common/ledger-chain.ts";
import { assertLedgerEventType } from "../../../server/modules/common/ledger-event-types.ts";
import type { ActorRole, ActorType, Environment } from "../../../server/modules/common/types.ts";
import {
  LedgerSequenceConflictError,
  type LedgerEventInput,
  type LedgerPort,
  type LedgerRecord,
} from "../../../server/ports/ledger.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface AuditEventRow {
  tenant_id: string;
  aggregate_type: string;
  aggregate_id: string;
  sequence: number;
  event_type: string;
  actor_type: ActorType;
  actor_role: ActorRole | null;
  recorded_by_ref: string | null;
  cosigned_by_ref: string | null;
  payload: Record<string, unknown>;
  idempotency_key_hash: string | null;
  occurred_at: Date;
  occurred_at_txt: string;
  environment: Environment;
  chain_seq: number;
  payload_hash: string;
  previous_event_hash: string;
  event_hash: string;
}

const COLUMNS =
  "tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, " +
  "cosigned_by_ref, payload, idempotency_key_hash, occurred_at, " +
  `to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at_txt, environment, ` +
  // chain_seq es bigint (pg lo entregaria como string); float8 es exacto hasta 2^53 y llega como number.
  "chain_seq::float8 AS chain_seq, payload_hash, previous_event_hash, event_hash";

/** El ledger guarda solo el hash de la clave de idempotencia (ledgerEnvelope.idempotencyKeyHash). */
function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

function toRecord(row: AuditEventRow): LedgerRecord {
  return {
    eventType: row.event_type,
    tenantId: row.tenant_id,
    aggregateType: row.aggregate_type,
    aggregateId: row.aggregate_id,
    actorType: row.actor_type,
    ...(row.actor_role !== null ? { actorRole: row.actor_role } : {}),
    ...(row.recorded_by_ref !== null ? { recordedByRef: row.recorded_by_ref } : {}),
    ...(row.cosigned_by_ref !== null ? { cosignedByRef: row.cosigned_by_ref } : {}),
    payload: row.payload,
    sequence: row.sequence,
    occurredAt: row.occurred_at,
    environment: row.environment,
    evidentiary: false,
    dataClass: "SYNTHETIC",
    chainSeq: row.chain_seq,
    payloadHash: row.payload_hash,
    previousEventHash: row.previous_event_hash,
    eventHash: row.event_hash,
  };
}

export function createPgLedgerAdapter(tx: TenantTx): LedgerPort {
  async function currentSequence(tenantId: string, aggregateId: string): Promise<number> {
    const r = await tx.query<{ s: number }>(
      "SELECT COALESCE(MAX(sequence), 0)::int AS s FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2",
      [tenantId, aggregateId],
    );
    return r.rows[0]?.s ?? 0;
  }

  return {
    async append(event: LedgerEventInput): Promise<LedgerRecord> {
      assertLedgerEventType(event.eventType);
      const keyHash = event.idempotencyKey !== undefined ? hashKey(event.idempotencyKey) : null;
      if (keyHash !== null) {
        const existing = await tx.query<AuditEventRow>(
          `SELECT ${COLUMNS} FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND idempotency_key_hash = $3`,
          [event.tenantId, event.aggregateId, keyHash],
        );
        const row = existing.rows[0];
        if (row) return toRecord(row);
      }

      // X6: lock por tenant (advisory xact, se libera en COMMIT/ROLLBACK) ANTES de leer la secuencia y
      // la cola de la cadena: dos appends concurrentes del mismo tenant se serializan, el segundo ve
      // lo que confirmo el primero y encadena sobre el. Los UNIQUE (tenant_id, chain_seq) y
      // (tenant_id, previous_event_hash) de 0013 son la red de seguridad si alguien se salta el lock.
      // Un lock que no se obtiene a tiempo falla por lock_timeout de la tx (55P03), no espera sin fin.
      await tx.query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::text, 0))", [`ledger-chain:${event.tenantId}`]);

      const current = await currentSequence(event.tenantId, event.aggregateId);
      if (event.expectedSequence !== current) {
        throw new LedgerSequenceConflictError(event.expectedSequence, current);
      }
      const next = event.expectedSequence + 1; // SEC-CNS-013 P2-3: sequence = expectedSequence + 1

      const tailRow = (await tx.query<{ chain_seq: number; event_hash: string }>(
        `SELECT chain_seq::float8 AS chain_seq, event_hash FROM integrity.audit_event
          WHERE tenant_id = $1 AND chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`,
        [event.tenantId],
      )).rows[0];
      const chainSeq = (tailRow?.chain_seq ?? 0) + 1;
      const previousEventHash = tailRow?.event_hash ?? LEDGER_GENESIS_HASH;
      // P2-1: occurred_at (now() de la tx, UTC, microsegundos) y environment (catalogo) se leen en la MISMA tx y se
      // insertan explicitos; entran al eventHash y la base los fuerza con CHECK (0013).
      const stamp = (await tx.query<{ occurred_at: string; environment: string }>(
        `SELECT to_char(pg_catalog.now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at, ops.catalog_environment() AS environment`,
      )).rows[0];
      if (!stamp) throw new Error("ledger: no se pudo leer now()/environment");
      const payloadHash = computePayloadHash(event.payload);
      const eventHash = computeEventHash({
        tenantId: event.tenantId,
        chainSeq,
        aggregateType: event.aggregateType,
        aggregateId: event.aggregateId,
        sequence: next,
        eventType: event.eventType,
        actorType: event.actorType,
        actorRole: event.actorRole ?? null,
        recordedByRef: event.recordedByRef ?? null,
        cosignedByRef: event.cosignedByRef ?? null,
        idempotencyKeyHash: keyHash,
        occurredAt: stamp.occurred_at,
        environment: stamp.environment,
        payloadHash,
        previousEventHash,
      });

      // ON CONFLICT (secuencia) DO NOTHING (sin error) para no abortar la transaccion y poder releer
      // la secuencia real: una unidad concurrente que confirmo antes gana. El UNIQUE de idempotencia
      // si puede lanzar 23505 en una carrera: va en SAVEPOINT; por err.constraint se reintenta como
      // dedupe (relectura) y cualquier otro 23505 se relanza (diseno rev. 2 §3).
      await tx.query("SAVEPOINT ledger_append");
      let inserted;
      try {
        inserted = await tx.query<AuditEventRow>(
          `INSERT INTO integrity.audit_event
             (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role,
              recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
              chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16::timestamptz, $17)
           ON CONFLICT (tenant_id, aggregate_id, sequence) DO NOTHING
           RETURNING ${COLUMNS}`,
          [
            event.tenantId,
            event.aggregateType,
            event.aggregateId,
            next,
            event.eventType,
            event.actorType,
            event.actorRole ?? null,
            event.recordedByRef ?? null,
            event.cosignedByRef ?? null,
            JSON.stringify(event.payload),
            keyHash,
            chainSeq,
            payloadHash,
            previousEventHash,
            eventHash,
            stamp.occurred_at,
            stamp.environment,
          ],
        );
      } catch (error) {
        const e = error as { code?: string; constraint?: string };
        await tx.query("ROLLBACK TO SAVEPOINT ledger_append");
        if (e.code === "23505" && e.constraint === "audit_event_idempotency_unique" && keyHash !== null) {
          const again = await tx.query<AuditEventRow>(
            `SELECT ${COLUMNS} FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND idempotency_key_hash = $3`,
            [event.tenantId, event.aggregateId, keyHash],
          );
          const row = again.rows[0];
          if (row) return toRecord(row);
        }
        throw error;
      }
      await tx.query("RELEASE SAVEPOINT ledger_append");
      const row = inserted.rows[0];
      if (!row) {
        throw new LedgerSequenceConflictError(event.expectedSequence, await currentSequence(event.tenantId, event.aggregateId));
      }
      return toRecord(row);
    },

    currentSequence: (tenantId, aggregateId) => currentSequence(tenantId, aggregateId),

    async readChain(tenantId): Promise<readonly ChainRow[]> {
      const r = await tx.query<AuditEventRow>(
        `SELECT ${COLUMNS} FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq IS NOT NULL ORDER BY chain_seq`,
        [tenantId],
      );
      return r.rows.map((row) => ({
        tenantId: row.tenant_id,
        chainSeq: row.chain_seq,
        aggregateType: row.aggregate_type,
        aggregateId: row.aggregate_id,
        sequence: row.sequence,
        eventType: row.event_type,
        actorType: row.actor_type,
        actorRole: row.actor_role,
        recordedByRef: row.recorded_by_ref,
        cosignedByRef: row.cosigned_by_ref,
        idempotencyKeyHash: row.idempotency_key_hash,
        occurredAt: row.occurred_at_txt,
        environment: row.environment,
        payload: row.payload,
        payloadHash: row.payload_hash,
        previousEventHash: row.previous_event_hash,
        eventHash: row.event_hash,
      }));
    },

    async listByAggregate(tenantId, aggregateType, aggregateId) {
      const r = await tx.query<AuditEventRow>(
        `SELECT ${COLUMNS} FROM integrity.audit_event
          WHERE tenant_id = $1 AND aggregate_type = $2 AND aggregate_id = $3 ORDER BY sequence`,
        [tenantId, aggregateType, aggregateId],
      );
      return r.rows.map(toRecord);
    },
  };
}
