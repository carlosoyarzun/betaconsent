// Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`: SELECT cross-tenant sin PII; sin DML), §4.2.c, §10 fila 6e, G-9; db/migrations/0057 (integrity.audit_event) y 0058 (app.invitation,
// app.consent_decision: columnas tenant_id, ref y state). specs/db-roles.spec.yaml INV-DBR-08.
//
// Lectura del proceso `reconciler`. Una sola transaccion READ ONLY / REPEATABLE READ (snapshot consistente entre ledger y estado: ambos se escriben en la misma tx) sobre el pool del rol
// integrity_reconciler. NO fija app.tenant_id (el rol es NOBYPASSRLS y la lectura cross-tenant la da la policy explicita TO integrity_reconciler USING (true); el chequeo de arranque exige que
// el cliente no fije GUC app.*). Solo SELECT por las columnas concedidas: nada de tokens, canales, seudonimos del titular ni hashes de token. Sin DML y sin funciones.
// ADAPTADOR (ADR-001 §11): el dominio (modules/integrity/ledger-reconciliation.ts) no conoce Postgres.

import type { ConsentDecisionStateRow, InvitationStateRow, ReconciledEvent, TenantReconciliationInput } from "../../../server/modules/integrity/ledger-reconciliation.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike, Queryable } from "./pool.ts";

interface EventRow {
  tenant_id: string;
  aggregate_type: string;
  aggregate_id: string;
  sequence: number;
  event_type: string;
  actor_type: string;
  actor_role: string | null;
  recorded_by_ref: string | null;
  cosigned_by_ref: string | null;
  payload: Record<string, unknown>;
  idempotency_key_hash: string | null;
  occurred_at_txt: string;
  environment: string;
  chain_seq: number | null;
  payload_hash: string | null;
  previous_event_hash: string | null;
  event_hash: string | null;
}

/** Columnas de integrity.audit_event concedidas en 0057. chain_seq es bigint: float8 es exacto hasta 2^53 y llega como number (igual que ledger.adapter.ts). */
const EVENT_COLUMNS =
  "tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash, " +
  `to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at_txt, environment, chain_seq::float8 AS chain_seq, payload_hash, previous_event_hash, event_hash`;

function toEvent(row: EventRow): ReconciledEvent {
  return {
    tenantId: row.tenant_id,
    chainSeq: row.chain_seq === null ? null : Number(row.chain_seq),
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
    // Los hashes son NOT NULL cuando hay eslabon (CHECK all_or_none); sin eslabon quedan vacios y el dominio no los recomputa.
    payloadHash: row.payload_hash ?? "",
    previousEventHash: row.previous_event_hash ?? "",
    eventHash: row.event_hash ?? "",
    payload: row.payload,
  };
}

/** Tenants con al menos un evento o una fila de estado, orden estable. Solo ids opacos. */
async function listTenants(db: Queryable): Promise<string[]> {
  const r = await db.query<{ tenant_id: string }>(
    `SELECT tenant_id::text AS tenant_id FROM integrity.audit_event
     UNION SELECT tenant_id::text FROM app.invitation
     UNION SELECT tenant_id::text FROM app.consent_decision
     ORDER BY 1`,
  );
  return r.rows.map((x) => x.tenant_id);
}

async function readTenant(db: Queryable, tenantId: string): Promise<TenantReconciliationInput> {
  const events = await db.query<EventRow>(`SELECT ${EVENT_COLUMNS} FROM integrity.audit_event WHERE tenant_id = $1 ORDER BY chain_seq NULLS FIRST, aggregate_id, sequence`, [tenantId]);
  const invitations = await db.query<{ tenant_id: string; invitation_ref: string; state: string }>("SELECT tenant_id::text AS tenant_id, invitation_ref, state FROM app.invitation WHERE tenant_id = $1 ORDER BY invitation_ref", [tenantId]);
  const decisions = await db.query<{ tenant_id: string; consent_id: string; state: string }>("SELECT tenant_id::text AS tenant_id, consent_id, state FROM app.consent_decision WHERE tenant_id = $1 ORDER BY consent_id", [tenantId]);
  return {
    tenantId,
    events: events.rows.map(toEvent),
    invitations: invitations.rows.map((r): InvitationStateRow => ({ tenantId: r.tenant_id, invitationRef: r.invitation_ref, state: r.state })),
    decisions: decisions.rows.map((r): ConsentDecisionStateRow => ({ tenantId: r.tenant_id, consentId: r.consent_id, state: r.state })),
  };
}

/**
 * Lee TODOS los tenants en un snapshot y entrega cada uno al callback (sin acumular el ledger entero en memoria). Siempre READ ONLY; al terminar ROLLBACK (nada que confirmar).
 * Si el cliente trae app.tenant_id arrastrado de otra sesion, acquireCleanClient lo destruye y falla cerrado.
 */
export async function forEachTenantInSnapshot(pool: PoolLike, visit: (input: TenantReconciliationInput) => void | Promise<void>): Promise<number> {
  const client = await acquireCleanClient(pool);
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      const tenants = await listTenants(client);
      for (const tenantId of tenants) await visit(await readTenant(client, tenantId));
      return tenants.length;
    } finally {
      await client.query("ROLLBACK");
    }
  } finally {
    client.release();
  }
}
