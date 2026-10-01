// Gobierna: specs/state-machines/common.spec.yaml (sección `errors`). Códigos de error
// transversales (ERR-CM-*) usados por guards de todas las máquinas de estado IT0.

export type DomainErrorCode =
  | "ERR-CM-01" // TENANT_NOT_RESOLVED — 404 uniforme, sin evento
  | "ERR-CM-02" // INVITER_TENANT_MISMATCH (GRD-CM-02, Guard T)
  | "ERR-CM-03" // INVITER_NOT_PARTICIPATING (GRD-CM-03, Guard P)
  | "ERR-CM-04" // ENROLLMENT_NOT_ACTIVE (GRD-CM-04, Guard E)
  | "ERR-CM-05" // CONTEXT_NOT_ACTIVE (GRD-CM-05, route class ISSUANCE_DECISION)
  | "ERR-CM-06" // INVALID_TRANSITION
  | "ERR-CM-07" // IDEMPOTENCY_CONFLICT (GRD-CM-08)
  | "ERR-CM-09" // CSRF_REJECTED
  | "ERR-CM-10" // ACTOR_NOT_ALLOWED
  | "ERR-CM-12" // GUARD_EVALUATOR_UNAVAILABLE (política/parámetro requerido sin valor: fail-closed)
  | "ERR-TC-03" // ENROLLMENT_ALREADY_ACTIVE (GRD-TC-03)
  | "ERR-RC-01" // GRD-RC-07 onFail (origin != CHANNEL_UNREACHABLE) — respuesta uniforme sin evento
  | "ERR-RC-09" // CASE_NOT_BOUND_TO_HANDLE — respuesta uniforme sin efecto
  | "ERR-RC-10" // GRD-RC-15 onFail (ROSTER_INSUFFICIENT) — dotación <4 personas o reutilización de rol
  | "ERR-RV-02" // CHAIN_NOT_GRANTED (GRD-RV-02 onFail) — respuesta uniforme, sin evento
  | "ERR-RV-04" // REVOCATION_ACTOR_NOT_ALLOWED (GRD-RV-07/08 onFail: actor no DecisionMaker o falta confirmación explícita). NO es el onFail de GRD-RV-04 (single_open_revocation_per_chain, onFail null: se adjunta)
  | "ERR-RV-05" // RECOVERY_TOKEN_INVALID (GRD-RV-06 onFail) — respuesta uniforme, sin consumir el token
  | "ERR-RV-07" // RH2_SEPARATION_OF_DUTIES_VIOLATION (GRD-RV-09 onFail: mismo principal, rol inválido, aprobador/receptor de un grant)
  | "ERR-RV-10" // DOWNSTREAM_ACK_INVALID (GRD-RV-13/14 onFail: el stub rechaza firma inválida o repetida)
  | "ERR-RV-13" // LEDGER_VOCABULARY_VIOLATION (GRD-RV-19/28): payload fuera de la lista blanca o sin campos exigidos
  | "ERR-RV-18" // GRD-RV-26 onFail (RH3_FOUR_EYES_REQUIRED: falta confirmación previa o co-firma el mismo principal)
  | "ERR-RV-20" // GRD-RV-10 onFail (RH3 sin RH2/RH2v ATTESTED previa)
  // specs/state-machines/invitation.spec.yaml
  | "ERR-IV-01" // INVITATION_TOKEN_NOT_RESOLVED — 404 uniforme (GRD-IV-07)
  | "ERR-IV-02" // INVITATION_ALREADY_ACTIVE (GRD-IV-01)
  | "ERR-IV-03" // INVITATION_NOT_READY (GRD-IV-03)
  | "ERR-IV-04" // VERSION_OR_MODE_GUARD_FAILED (GRD-IV-04)
  | "ERR-IV-07" // REISSUE_LIMIT_REACHED (GRD-IV-11)
  | "ERR-IV-10" // INVITATION_TERMINAL
  // specs/state-machines/otp-challenge.spec.yaml
  | "ERR-OT-01" // OTP_GENERIC_RESPONSE (GRD-OT-01/02/08)
  | "ERR-OT-02" // OTP_CODE_REJECTED (GRD-OT-07)
  | "ERR-OT-03" // OTP_EXPIRED_OR_CONSUMED (GRD-OT-05)
  | "ERR-OT-04" // OTP_LOCKED (GRD-OT-04, V4)
  | "ERR-OT-08" // OTP_CHANNEL_NOT_BOUND (GRD-OT-02)
  | "ERR-OT-09" // OTP_RESEND_LIMIT (GRD-OT-06, V2r)
  // specs/state-machines/consent-decision.spec.yaml
  | "ERR-CD-01" // ALREADY_DECIDED (GRD-CD-08)
  | "ERR-CD-02" // PURPOSE_SELECTION_INVALID (GRD-CD-06/07)
  | "ERR-CD-04" // DECISION_STEPS_INCOMPLETE (GRD-CD-05)
  | "ERR-CD-07" // DECISION_SESSION_INVALID (GRD-CD-01/02)
  | "ERR-CD-08"; // DECISION_TERMINAL

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
