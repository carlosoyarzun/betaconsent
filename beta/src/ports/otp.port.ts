// Gobierna: plan v2 H1-04. Puerto de OTP; issue_otp / verify_otp de 0003. El adaptador genera el código y calcula el HMAC; la base compara.
import type { OtpScope, OtpVerifyOutcome, VerificationRef } from "../domain/types.ts";

export interface IssueOtpInput {
  /** DECISION: invitationRef; REVOCATION|MANAGE: consentId. */
  readonly parentRef: string;
  readonly scope: OtpScope;
  /** Solo tests (p. ej. forzar vencimiento). Por defecto P-02 = 10 min; la base rechaza > 10 min. */
  readonly ttlMs?: number;
}

export interface IssuedOtp {
  readonly verificationRef: VerificationRef;
  /** Código EN CLARO, solo para el correo. Nunca se persiste ni se loguea. */
  readonly code: string;
  readonly expiresAt: Date;
}

export interface VerifyOtpInput {
  readonly verificationRef: VerificationRef;
  readonly code: string;
  /** Seudónimo del canal (deriveDecisionMakerRef); queda en el OTP y luego en la decisión. */
  readonly decisionMakerRef: string;
}

export interface VerifyOtpResult {
  readonly outcome: OtpVerifyOutcome;
  readonly attemptsLeft: number;
}

export interface OtpRepo {
  /** Un OTP vivo por (padre, scope): emitir expira el anterior. Lanza PARENT_NOT_ELIGIBLE, OTP_RESEND_TOO_SOON, OTP_SEND_LIMIT, OTP_BUDGET_EXHAUSTED. */
  issue(input: IssueOtpInput): Promise<IssuedOtp>;
  /** Reenvío: mismas reglas y mismo efecto que issue (código nuevo; el anterior queda EXPIRED); los límites P-06 los aplica la base. */
  resend(input: IssueOtpInput): Promise<IssuedOtp>;
  /** Las fallas esperables (WRONG_CODE, LOCKED, EXPIRED, …) NO lanzan: se devuelven como outcome. */
  verify(input: VerifyOtpInput): Promise<VerifyOtpResult>;
}
