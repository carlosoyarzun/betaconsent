// Gobierna: contracts/schemas/outbox-events.schema.json (API-CNS-185, DRAFT),
// specs/state-machines/revocation.spec.yaml R4 (emits consent.revoked; GRD-RV-11),
// specs/state-machines/common.spec.yaml (stream OUTBOX at-least-once, INV-CM-01, payloadPolicy sin
// PII), ADR-001 §11 (Ports & Adapters). CA-127.
// Puerto: solo tipos; la entrega firmada (R5), listPending y dispatch llegan con R5.
// El adaptador asigna eventId, environment y dataClass (igual que el ledger, ADR-002 §2/§8).

import type { TenantId } from "../modules/common/types.ts";

/** D4 (diseño CA-127): el schema DRAFT solo exige semver; se fija 1.0.0. */
export const OUTBOX_SCHEMA_VERSION = "1.0.0";

/** consent.granted (C3) y consent.changed (C8) quedan fuera de este puerto por ahora. */
export type OutboxEventType = "consent.revoked";

/** outbox-events.schema.json#/$defs/consent.revoked. Sin datos del apoderado (INV-CM-05). */
export interface ConsentRevokedOutboxPayload {
  readonly revocationRef: string;
  readonly scope: "ALL";
  readonly effectiveAt: string;
}

/** outbox-events.schema.json#/$defs/OutboxEvent (sobre, MP §38). Solo refs opacas y enums. */
export interface OutboxEnvelope {
  readonly eventId: string;
  readonly eventType: OutboxEventType;
  readonly schemaVersion: string;
  readonly tenantRef: TenantId;
  readonly contextRef: string;
  readonly subjectRef: string;
  readonly occurredAt: string;
  readonly payload: ConsentRevokedOutboxPayload;
  readonly environment: "LOCAL" | "DEV" | "STAGING";
  readonly dataClass: "SYNTHETIC";
}

export interface OutboxEnqueueInput {
  readonly tenantId: TenantId;
  readonly eventType: OutboxEventType;
  readonly contextRef: string;
  readonly subjectRef: string;
  readonly occurredAt: string;
  readonly payload: ConsentRevokedOutboxPayload;
  /** Dedupe del productor por (tenantId, dedupeKey), p. ej. `${revocationRef}:consent.revoked`. */
  readonly dedupeKey: string;
}

export interface OutboxRecord {
  readonly tenantId: TenantId;
  readonly dedupeKey: string;
  readonly status: "PENDING";
  readonly envelope: OutboxEnvelope;
}

export interface OutboxPort {
  /**
   * Encola el evento. Si (tenantId, dedupeKey) ya existe devuelve el registro original (mismo
   * eventId) sin duplicar. En el consumidor el dedupe es por eventId (at-least-once).
   */
  enqueue(input: OutboxEnqueueInput): Promise<OutboxRecord>;
}
