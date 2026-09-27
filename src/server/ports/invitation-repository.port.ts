// Gobierna: specs/state-machines/invitation.spec.yaml (aggregateType Invitation).
// Puerto (ADR-001 §11): proyección del ledger para el agregado Invitation. En IT0 el
// adaptador es in-memory (src/infra/adapters/**); el adaptador de Postgres llega con la
// historia de infraestructura correspondiente.

import type { TenantId } from "../modules/common/types.ts";

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
}

export interface InvitationRepositoryPort {
  findByRef(tenantId: TenantId, invitationRef: string): InvitationRecord | null;
  /** GRD-IV-01: no debe existir otra Invitation no terminal para (tenantId, contextRef, subjectRef). */
  findActiveBySubject(tenantId: TenantId, contextRef: string, subjectRef: string): InvitationRecord | null;
  /** GRD-IV-07: resuelve por tokenHash (igualdad exacta), nunca por el token en claro. */
  findByTokenHash(tokenHash: string): InvitationRecord | null;
  save(record: InvitationRecord): void;
}
