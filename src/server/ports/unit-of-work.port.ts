// Gobierna: CA-124 (H09 Tenancy y RLS), diseño postgres-design.md rev. 2 §4-§5 (P1-1, P1-6),
// common.spec.yaml INV-CM-01 (append + proyección + outbox en una tx), INV-CM-02 (tenant_id es
// la única clave de aislamiento), revocation.spec.yaml R4 (una tx con lock y expectedSequence).
//
// El dominio nunca importa pg ni nada de infraestructura (ADR-001 §11, guardrail CA-136): solo
// conoce este puerto. El adaptador Postgres (PR-A/B) abre BEGIN + set_config('app.tenant_id')
// local a la tx; el adaptador in-memory (src/infra/adapters/in-memory-unit-of-work.adapter.ts)
// da la misma semántica todo-o-nada con un journal de deshacer.

import type { TenantId } from "../modules/common/types.ts";
import type { AccessLogPort } from "./access-log.port.ts";
import type { ConsentDecisionRepositoryPort } from "./consent-decision-repository.port.ts";
import type { EnrollmentRepositoryPort } from "./enrollment-repository.port.ts";
import type { IdempotencyPort } from "./idempotency.port.ts";
import type { InvitationRepositoryPort } from "./invitation-repository.port.ts";
import type { LedgerPort } from "./ledger.port.ts";
import type { OtpBudgetPort } from "./otp-budget.port.ts";
import type { OtpVerificationRepositoryPort } from "./otp-verification-repository.port.ts";
import type { OutboxPort } from "./outbox.port.ts";
import type { RecoveryTokenRepositoryPort } from "./recovery-token.port.ts";
import type { SecurityEventPort } from "./security-event.port.ts";
import type { RevocationRepositoryPort } from "./revocation-repository.port.ts";
import type { RightsCaseRepositoryPort } from "./rights-case-repository.port.ts";
import type { TenantCatalogPort } from "./tenant-catalog.port.ts";

/**
 * Puertos ligados a UN tenant y a UNA unidad de trabajo. Todo lo que se escribe a través de
 * ellos dentro de `inTenant` confirma junto o no deja nada (CA-124 PR-D: todos los agregados con
 * estado de tenant: Invitation, OtpVerification, RightsCase y Enrollment se suman a los de PR-C).
 */
export interface TenantTxPorts {
  readonly revocationRepo: RevocationRepositoryPort;
  readonly consentDecisionRepo: ConsentDecisionRepositoryPort;
  readonly recoveryTokenRepo: RecoveryTokenRepositoryPort;
  readonly invitationRepo: InvitationRepositoryPort;
  readonly otpRepo: OtpVerificationRepositoryPort;
  readonly rightsCaseRepo: RightsCaseRepositoryPort;
  readonly enrollmentRepo: EnrollmentRepositoryPort;
  readonly ledger: LedgerPort;
  readonly outbox: OutboxPort;
  /** CA-124 PR-E: catálogo del tenant (solo lectura) leído BAJO RLS, dentro de la misma tx (SEC-CNS-016). */
  readonly tenantCatalog: TenantCatalogPort;
  /** CA-124 PR-E (GRD-CM-08): find + ejecutar + store de una Idempotency-Key en la misma tx. */
  readonly idempotency: IdempotencyPort;
  /** CA-128 (X6): log de acceso del operador en `ops` (append-only, sin PII), no el ledger (INV-RC-04). */
  readonly accessLog: AccessLogPort;
  /** SEC-CNS-021 PR-2 (F-1, INV-21-02): eventos de seguridad OTP_*, RECOVERY_TOKEN_ISSUED (ops.security_event, fuera del ledger y de
   * la cadena SHA-256) escritos en la MISMA tx que la transicion que los causa: si la unidad revierte, no queda ninguno. */
  readonly securityEvents: SecurityEventPort;
  /** SEC-CNS-021 PR-4 (DF-10, GRD-OT-03): presupuesto de fallos de OTP por clave (ops.otp_budget), en la MISMA tx que el challenge:
   * la reserva, su reversion en el acierto y el rechazo (V6/V6r) confirman o revierten junto con el estado del challenge. */
  readonly otpBudget: OtpBudgetPort;
}

export interface UnitOfWorkPort {
  /**
   * Ejecuta `work` en una única unidad de trabajo del tenant `tenantId`, que el llamador ya
   * resolvió en servidor (GRD-CM-01). Si `work` resuelve, todo confirma; si rechaza (o lanza),
   * NO queda ninguna escritura y el error se propaga tal cual. No se admite anidar `inTenant`.
   * Bajo RLS un `tenantId` ajeno a los datos ve 0 filas y no puede escribir (INV-3, X5).
   */
  inTenant<T>(tenantId: TenantId, work: (tx: TenantTxPorts) => Promise<T>): Promise<T>;
}
