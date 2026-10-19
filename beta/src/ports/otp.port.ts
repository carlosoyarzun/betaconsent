// Gobierna: plan v2 H1-04 + SEC-CNS-024 F-SB-01. Puerto de OTP; issue_otp / verify_otp de 0003. La BASE genera el código (se devuelve en claro una sola vez, para el
// correo) y la BASE lo verifica; ni el adaptador ni el llamador aportan ningún verificador.
import type { OtpScope, OtpVerifyOutcome, VerificationRef } from "../domain/types.ts";

export interface IssueOtpInput {
  /** DECISION: invitationRef; REVOCATION|MANAGE: consentId. */
  readonly parentRef: string;
  readonly scope: OtpScope;
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
  /** Un OTP vivo por (padre, scope): emitir expira el anterior. El vencimiento (P-02, 10 min) lo fija la base. Lanza PARENT_NOT_ELIGIBLE, OTP_RESEND_TOO_SOON, OTP_SEND_LIMIT, OTP_BUDGET_EXHAUSTED, OTP_EXHAUSTED. */
  issue(input: IssueOtpInput): Promise<IssuedOtp>;
  /** Reenvío: mismas reglas y mismo efecto que issue (código nuevo; el anterior queda EXPIRED); los límites P-06 los aplica la base. */
  resend(input: IssueOtpInput): Promise<IssuedOtp>;
  /**
   * Las fallas esperables (WRONG_CODE, LOCKED, EXPIRED, …) NO lanzan: se devuelven como outcome.
   * SIEMPRE corre en su PROPIA transacción, confirmada también con WRONG_CODE/LOCKED: por eso este método no admite una unidad de trabajo externa
   * (SEC-CNS-024 F-SB-02). Si se enlazara con record/revoke y un rollback posterior devolviera el conteo de intentos, habría fuerza bruta ilimitada.
   */
  verify(input: VerifyOtpInput): Promise<VerifyOtpResult>;
}
