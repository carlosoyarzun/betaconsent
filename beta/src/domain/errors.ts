// Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-04.
// Errores de dominio tipados. Los códigos son los mensajes estables que lanzan las funciones de db/migrations/0003_functions.sql
// (SQLSTATE P0001); los adaptadores PG los traducen y el adaptador en memoria lanza los mismos.

export const DOMAIN_ERROR_CODES = [
  "INVITATION_NOT_FOUND",
  "INVITATION_NOT_ARMABLE",
  "TOKEN_EXPIRY_IN_PAST",
  "PARENT_NOT_ELIGIBLE",
  "INVALID_SCOPE",
  "OTP_BUDGET_EXHAUSTED",
  "OTP_RESEND_TOO_SOON",
  "OTP_SEND_LIMIT",
  "INVALID_DECISION_MAKER_REF",
  "INVALID_OUTCOME",
  "INVALID_PURPOSES",
  "INVALID_CONSENT_VERSION",
  "OTP_EXHAUSTED",
  "INVALID_IDEMPOTENCY_KEY",
  "ALREADY_DECIDED",
  "IDEMPOTENCY_KEY_REUSED",
  "VERIFICATION_REQUIRED",
  "DECISION_NOT_FOUND",
  "NOT_REVOCABLE_DECLINED",
  "ALREADY_REVOKED",
] as const;

export type DomainErrorCode = (typeof DOMAIN_ERROR_CODES)[number];

export class DomainError extends Error {
  readonly code: DomainErrorCode;
  constructor(code: DomainErrorCode) {
    super(code);
    this.name = "DomainError";
    this.code = code;
  }
}

export function isDomainError(e: unknown, code?: DomainErrorCode): e is DomainError {
  return e instanceof DomainError && (code === undefined || e.code === code);
}
