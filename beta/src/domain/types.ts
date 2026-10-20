// Gobierna: plan v2 H1-04. Tipos de dominio mínimos: refs opacas (nunca PII), resultados y estados que cruzan los puertos.

/** Referencias opacas generadas por la base (inv-…, ver-…, con-…, rev-…) o por el colegio (studentRef). */
export type InvitationRef = string;
export type StudentRef = string;
export type VerificationRef = string;
export type ConsentId = string;
export type RevocationRef = string;

export type OtpScope = "DECISION" | "REVOCATION" | "MANAGE";
/** Resultados de verify_otp (la base decide; el adaptador solo los transporta). */
export type OtpVerifyOutcome = "VERIFIED" | "WRONG_CODE" | "LOCKED" | "EXPIRED" | "NOT_ACTIVE" | "BUDGET_EXHAUSTED";
export type OtpState = "CODE_SENT" | "VERIFIED" | "LOCKED" | "EXPIRED";

/** Resultado que el apoderado elige; REVOKED es solo el estado posterior de una decisión GRANTED. */
export type DecisionOutcome = "GRANTED" | "DECLINED";
export type DecisionState = DecisionOutcome | "REVOKED";
export type InvitationState = "READY" | "SENT" | "OPENED" | "VERIFIED" | "COMPLETED" | "DECLINED" | "CANCELLED";
export type AuthorizationStatus = "AUTHORIZED" | "NOT_AUTHORIZED";
