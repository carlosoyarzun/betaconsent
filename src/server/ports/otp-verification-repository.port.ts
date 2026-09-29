// Gobierna: specs/state-machines/otp-challenge.spec.yaml (aggregateType
// DecisionMakerVerification). Puerto (ADR-001 §11): proyección del ledger para el agregado.
// Adaptador in-memory en IT0.
//
// CA-116 (revocación IT0, UX-CNS-004): scope ahora incluye REVOCATION/MANAGE (padre = chainRef,
// routeClass RIGHTS), además de DECISION (padre = invitationRef). Ver otp-challenge.ts
// requestRightsOtp/submitRightsOtp para el subconjunto mínimo implementado de V1/V3 byScope.

import type { TenantId } from "../modules/common/types.ts";

export type OtpVerificationState = "NOT_STARTED" | "CODE_SENT" | "VERIFIED" | "EXPIRED" | "LOCKED" | "FAILED";

export type OtpScope = "DECISION" | "REVOCATION" | "MANAGE";

export interface OtpVerificationRecord {
  readonly verificationRef: string;
  readonly tenantId: TenantId;
  readonly scope: OtpScope;
  /** DECISION: invitationRef. REVOCATION/MANAGE: chainRef resuelto en servidor desde el handle /m/. */
  readonly parentRef: string;
  readonly channelRef: string;
  /** HMAC/hash del código (P-08); el código en claro nunca se persiste (INV-OT-02). */
  readonly codeHash: string;
  readonly attempts: number;
  readonly expiresAt: Date;
  readonly consumedAt?: Date;
  readonly state: OtpVerificationState;
  /** V2r (ResendOtp): cuántas veces se reemplazó el código. No reinicia `attempts` ni el
   * presupuesto (GRD-OT-06); nace en 0. */
  readonly resendCount: number;
}

export interface OtpVerificationRepositoryPort {
  findByRef(tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord | null>;
  /** GRD-OT-08: uno activo por (tenantId, parentRef, scope). */
  findActiveByParent(tenantId: TenantId, parentRef: string, scope: OtpScope): Promise<OtpVerificationRecord | null>;
  save(record: OtpVerificationRecord): Promise<void>;
}
