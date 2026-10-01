// Gobierna: specs/state-machines/revocation.spec.yaml R5 (consent.revoked a las EventSubscriptions
// congeladas), R6 (ACK firmado), R7 (erasure.confirmed verificado), GRD-RV-12/13/14, ERR-RV-10;
// "CARLOS r3 R5-1": en IT0 el único consumidor es el stub interno. DEC-BR-014 rev. 8 §3 X6 (CA-128).
// ADR-001 §11: el dominio solo conoce esta interfaz.
//
// PENDIENTE (FINDING P2, OPEN-CT-02 en contracts/schemas/outbox-events.schema.json x-pending): la
// spec no fija el esquema de firma ni el transporte del ACK/erasure.confirmed. Este puerto abstrae
// solo la verificación (booleana) de la evidencia; el adaptador IT0 es in-memory, sin red.

import type { TenantId } from "../modules/common/types.ts";

export type DownstreamEvidenceKind = "ACK" | "ERASURE_CONFIRMED";

/** Evidencia firmada por el consumidor para una EventSubscription congelada. Solo refs opacas. */
export interface DownstreamEvidence {
  readonly subscriptionRef: string;
  /** ackRef (R6) o attestationRef (R7): idempotencia (revocationRef, ackRef|attestationRef). */
  readonly evidenceRef: string;
  readonly signature: string;
}

export interface DownstreamStubPort {
  /** Conjunto vigente de EventSubscription (tenant_id, productRef) del tenant al emitir (R5, SEC P2-08),
   * aunque tenant.active = false. R5 lo congela en el payload de REVOCATION_DOWNSTREAM_EMITTED. */
  currentSubscriptionRefs(tenantId: TenantId): Promise<readonly string[]>;
  /** GRD-RV-13/14: true solo si la firma de la evidencia es válida para (kind, revocationRef). */
  verifyEvidence(tenantId: TenantId, kind: DownstreamEvidenceKind, revocationRef: string, evidence: DownstreamEvidence): Promise<boolean>;
}
