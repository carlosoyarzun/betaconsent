// Gobierna: specs/state-machines/otp-challenge.spec.yaml (aggregateType
// DecisionMakerVerification). Puerto (ADR-001 §11): proyección del ledger para el agregado.
// Adaptador in-memory en IT0.

import type { TenantId } from "../modules/common/types.ts";

export type OtpVerificationState = "NOT_STARTED" | "CODE_SENT" | "VERIFIED" | "EXPIRED" | "LOCKED" | "FAILED";

export interface OtpVerificationRecord {
  readonly verificationRef: string;
  readonly tenantId: TenantId;
  readonly scope: "DECISION"; // REVOCATION/MANAGE: fuera de alcance de este slice.
  /** DECISION: invitationRef (SM-CNS-001 §3 V1 byScope). */
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
  findByRef(tenantId: TenantId, verificationRef: string): OtpVerificationRecord | null;
  /** GRD-OT-08: uno activo por (tenantId, parentRef, scope). */
  findActiveByParent(tenantId: TenantId, parentRef: string, scope: "DECISION"): OtpVerificationRecord | null;
  save(record: OtpVerificationRecord): void;
}
