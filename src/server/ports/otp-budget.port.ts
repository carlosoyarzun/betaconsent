// Gobierna: SEC-CNS-021 PR-4 (CA-146 / DF-10), otp-challenge.spec.yaml (budget: CFG-OT-BUDGET; GRD-OT-03), SEC-CNS-006 rev. 5 (P-04, P-04a/b/c, P-05, P-07),
// ADR-002 §3, ADR-001 §11 (puerto: el dominio no conoce SQL), db/migrations/0032_otp_budget_p06_v6a.sql.
// Presupuesto de FALLOS de OTP por clave opaca. Escribe dentro de la MISMA unidad de trabajo que el challenge (TenantTxPorts.otpBudget).
// Cero PII: `keyHmac` es un HMAC-SHA256 hex (subclave HKDF propia); el correo, el invitationRef y el chainRef nunca llegan aqui en claro.

import type { TenantId } from "../modules/common/types.ts";

export type OtpBudgetScopeClass = "DECISION" | "RIGHTS";
export type OtpBudgetKeyKind = "CHANNEL" | "INVITATION" | "CHAIN";
export type OtpBudgetWindowKind = "DAY_1" | "DAYS_30";

/** Una clave de presupuesto (CFG-OT-BUDGET). Espejo de la PK de ops.otp_budget salvo el tenant (lo fija la unidad de trabajo). */
export interface OtpBudgetKey {
  readonly scopeClass: OtpBudgetScopeClass;
  readonly keyKind: OtpBudgetKeyKind;
  /** HMAC-SHA256 hex de 64 caracteres (otp-budget.ts). */
  readonly keyHmac: string;
  /** Version de la clave K_otp_env (P-08); 1 hasta que haya rotacion. */
  readonly keyVersion: number;
  readonly windowKind: OtpBudgetWindowKind;
}

export interface OtpBudgetPort {
  /**
   * V1 (GRD-OT-03): SOLO lectura. Devuelve la primera clave sin cupo (ventana vigente con `failures >= limit`) o null si todas tienen cupo.
   * No reserva nada.
   */
  findExhausted(tenantId: TenantId, keys: readonly OtpBudgetKey[], at: Date, limit: number): Promise<OtpBudgetKey | null>;

  /**
   * V2/V3 (GRD-OT-03): reserva ATOMICA de un fallo en cada clave, EN EL ORDEN DADO, antes de comparar el codigo. Una sola sentencia por clave
   * (el lock de fila es el de la propia sentencia): N reservas concurrentes nunca superan `limit`. Si la ventana de una clave ya vencio
   * (`expiresAt <= at`), arranca una nueva con failures = 1 (ventana fija desde el primer fallo, no deslizante). Devuelve la primera clave
   * sin cupo (sin reservar en ella ni en las siguientes) o null si todas se reservaron. Si una clave no tiene cupo se REVIERTEN las reservas
   * hechas en esa misma llamada: sin comparacion no se consume presupuesto.
   */
  reserveFailure(tenantId: TenantId, keys: readonly OtpBudgetKey[], at: Date, windowMs: number, limit: number): Promise<OtpBudgetKey | null>;

  /** Acierto (V3): revierte la reserva de cada clave (`failures - 1`, minimo 0) en la misma tx: los aciertos no consumen presupuesto. */
  releaseFailure(tenantId: TenantId, keys: readonly OtpBudgetKey[]): Promise<void>;
}
