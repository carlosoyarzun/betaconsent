// Gobierna: specs/state-machines/invitation.spec.yaml (aggregateType Invitation).
// Puerto (ADR-001 §11): proyección del ledger para el agregado Invitation. Adaptadores:
// in-memory y Postgres (src/infra/adapters/**, CA-124 PR-D). El lookup por tokenHash SIN tenant
// (GRD-IV-07) vive en `TenantResolverPort.byInvitationTokenHash` (diseño CA-124 §5), no aquí.

import type { TenantId } from "../modules/common/types.ts";

/** El adaptador de persistencia no admite el valor de `recipientChannelRef` (p.ej. el CHECK de Postgres solo admite
 * email reservado hasta que EXT-B/LD-21 defina el canal esperado). El borde HTTP lo traduce a 422 uniforme.
 * No lleva el valor rechazado (cero PII en errores). */
export class InvalidRecipientChannelRefError extends Error {
  constructor() {
    super("recipientChannelRef no admitido por la persistencia");
    this.name = "InvalidRecipientChannelRefError";
  }
}

export type InvitationState = "DRAFT" | "READY" | "SENT" | "OPENED" | "VERIFIED" | "COMPLETED" | "DECLINED";

export interface InvitationRecord {
  readonly invitationRef: string;
  readonly tenantId: TenantId;
  readonly contextRef: string;
  readonly productRef: string;
  readonly subjectRef: string;
  readonly state: InvitationState;
  readonly consentVersion?: string;
  readonly expiresAt?: Date;
  /** Único canal habilitado a recibir el OTP de esta invitación (GRD-OT-02). */
  readonly recipientChannelRef?: string;
  /** SHA-256 del token opaco (GRD-IV-05); el token nunca persiste. */
  readonly tokenHash?: string;
  readonly boundDecisionMakerRef?: string;
  /** CA-125 (I1/I2, contrato CreateInvitationRequest/MarkInvitationReadyRequest): presentes solo
   * en invitaciones creadas por la API de staff; las sembradas por fixtures legacy no las llevan. */
  readonly enrollmentRef?: string;
  readonly participationRef?: string;
  readonly reissueOfRef?: string;
  /** I2: RECIPIENT_CHANNEL exige recipientChannelRef; UNBOUND no lo lleva (GRD-IV-03). */
  readonly recipientBinding?: "RECIPIENT_CHANNEL" | "UNBOUND";
}

export interface InvitationRepositoryPort {
  findByRef(tenantId: TenantId, invitationRef: string): Promise<InvitationRecord | null>;
  /** Como `findByRef` con lock de fila hasta el fin de la unidad de trabajo (FOR UPDATE; SEC-CNS-015
   * P2-E): toda transicion que decide estado (I2..I7) lee con este metodo tras capturar la secuencia
   * base. Solo dentro de `UnitOfWorkPort.inTenant`. In-memory: equivalente a `findByRef`. */
  findByRefForUpdate(tenantId: TenantId, invitationRef: string): Promise<InvitationRecord | null>;
  /** GRD-IV-01: no debe existir otra Invitation no terminal para (tenantId, contextRef, subjectRef). */
  findActiveBySubject(tenantId: TenantId, contextRef: string, subjectRef: string): Promise<InvitationRecord | null>;
  save(record: InvitationRecord): Promise<void>;
}
