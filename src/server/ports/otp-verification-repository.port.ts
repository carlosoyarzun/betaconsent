// Gobierna: specs/state-machines/otp-challenge.spec.yaml (aggregateType
// DecisionMakerVerification). Puerto (ADR-001 §11): proyección del ledger para el agregado.
// Adaptadores in-memory y Postgres (CA-124 PR-D).
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
  /** P-06 (SEC-CNS-021 PR-4, D8): instante del ultimo envio del codigo (V1 o V2r). Ausente en filas anteriores a 0032 (= sin envios registrados). */
  readonly lastSentAt?: Date;
  /** P-06: inicio de la ventana fija de 1 h de envios (el envio inicial de V1 la abre). Ausente junto con `lastSentAt`. */
  readonly sendsWindowStart?: Date;
  /** P-06: envios dentro de la ventana, el inicial incluido. Ausente = 0. */
  readonly sendsInWindow?: number;
}

export interface OtpVerificationRepositoryPort {
  findByRef(tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord | null>;
  /** Como `findByRef` con lock de fila hasta el fin de la unidad de trabajo (FOR UPDATE; SEC-CNS-015
   * P2-E): V2/V3/V4/V2r deciden sobre el estado bloqueado. In-memory: equivalente a `findByRef`. */
  findByRefForUpdate(tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord | null>;
  /** GRD-OT-08: uno activo por (tenantId, parentRef, scope). */
  findActiveByParent(tenantId: TenantId, parentRef: string, scope: OtpScope): Promise<OtpVerificationRecord | null>;
  /** V6a (GRD-OT-09, P-07): cuantos challenges LOCKED tiene el padre en ese scope (cuenta el que se acaba de guardar en la misma tx). */
  countLockedByParent(tenantId: TenantId, parentRef: string, scope: OtpScope): Promise<number>;
  save(record: OtpVerificationRecord): Promise<void>;
}
