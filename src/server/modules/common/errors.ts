// Gobierna: specs/state-machines/common.spec.yaml (sección `errors`). Códigos de error
// transversales (ERR-CM-*) usados por guards de todas las máquinas de estado IT0.

export type DomainErrorCode =
  | "ERR-CM-01" // TENANT_NOT_RESOLVED — 404 uniforme, sin evento
  | "ERR-CM-06" // INVALID_TRANSITION
  | "ERR-CM-09" // CSRF_REJECTED
  | "ERR-CM-10" // ACTOR_NOT_ALLOWED
  | "ERR-RC-01" // GRD-RC-07 onFail (origin != CHANNEL_UNREACHABLE) — respuesta uniforme sin evento
  | "ERR-RC-09" // CASE_NOT_BOUND_TO_HANDLE — respuesta uniforme sin efecto
  | "ERR-RV-20"; // GRD-RV-10 onFail (RH3 sin RH2/RH2v ATTESTED previa)

/**
 * Rechazo determinista fail-closed (SM-CNS-001 R0.3; common.spec.yaml `failClosed`). Nunca
 * lleva estado parcial ni evento de ledger, salvo que la transición lo declare explícitamente.
 */
export class DomainError extends Error {
  readonly code: DomainErrorCode;

  constructor(code: DomainErrorCode, message?: string) {
    super(message ?? code);
    this.code = code;
    this.name = "DomainError";
  }
}
