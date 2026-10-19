// Gobierna: plan v2 H1-04. Estado compartido de los adaptadores en memoria (para tests unitarios de H1-05). Replica la SEMÁNTICA de las funciones de
// 0003 (idempotencia, 1 OTP vivo, LOCKED a los 5 fallos, presupuesto, ventana de 30 min); la base sigue siendo la fuente de verdad: el test de
// contrato corre la misma suite contra ambos adaptadores. No es para producción.
import { DomainError } from "../../../domain/errors.ts";
import type { DecisionState, InvitationState, OtpScope, OtpState } from "../../../domain/types.ts";
import {
  APPROVED_P03_OTP_MAX_ATTEMPTS,
  APPROVED_P04_OTP_BUDGET_MAX_FAILURES,
  APPROVED_P04_OTP_BUDGET_WINDOW_MS,
  APPROVED_P06_OTP_MAX_SENDS_PER_HOUR,
  APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS,
  APPROVED_P06_OTP_SEND_WINDOW_MS,
  BETA_VERIFIED_SESSION_WINDOW_MS,
} from "../../../otp/approved-parameters.ts";

export interface InvRow {
  ref: string;
  studentRef: string;
  state: InvitationState;
  tokenHash: string | null;
  tokenExpiresAt: number | null;
  tokenConsumed: boolean;
  consentVersion: string | null;
}
export interface OtpRow {
  ref: string;
  scope: OtpScope;
  parentRef: string;
  hmac: string;
  attempts: number;
  state: OtpState;
  expiresAt: number;
  createdAt: number;
  consumedAt: number | null;
  decisionMakerRef: string | null;
}
export interface DecRow {
  consentId: string;
  invitationRef: string;
  studentRef: string;
  decisionMakerRef: string;
  state: DecisionState;
  idemKey: string;
  decidedAt: number;
}
export interface RevRow {
  ref: string;
  consentId: string;
  idemKey: string;
}

export const LIVE_INVITATION_STATES: readonly InvitationState[] = ["READY", "SENT", "OPENED", "VERIFIED"];

export class MemoryState {
  readonly invitations = new Map<string, InvRow>();
  readonly otps = new Map<string, OtpRow>();
  readonly decisions = new Map<string, DecRow>();
  readonly revocations: RevRow[] = [];
  readonly budget = new Map<string, { failures: number; expiresAt: number }>();
  private seq = 0;

  readonly now: () => number;
  constructor(now: () => number) {
    this.now = now;
  }

  newRef(prefix: string): string {
    this.seq += 1;
    return `${prefix}-mem-${this.seq}`;
  }

  budgetFailures(parentRef: string): number {
    const b = this.budget.get(parentRef);
    return b && b.expiresAt > this.now() ? b.failures : 0;
  }

  addBudgetFailure(parentRef: string): void {
    const b = this.budget.get(parentRef);
    if (b && b.expiresAt > this.now()) b.failures += 1;
    else this.budget.set(parentRef, { failures: 1, expiresAt: this.now() + APPROVED_P04_OTP_BUDGET_WINDOW_MS });
  }

  /** Espejo de issue_otp: el padre debe ser elegible, respeta presupuesto y límites de envío; expira el OTP vivo anterior. */
  checkIssue(parentRef: string, scope: OtpScope): void {
    if (scope === "DECISION") {
      if (this.invitations.get(parentRef)?.state !== "OPENED") throw new DomainError("PARENT_NOT_ELIGIBLE");
    } else if (this.decisions.get(parentRef)?.state !== "GRANTED") {
      throw new DomainError("PARENT_NOT_ELIGIBLE");
    }
    if (this.budgetFailures(parentRef) >= APPROVED_P04_OTP_BUDGET_MAX_FAILURES) throw new DomainError("OTP_BUDGET_EXHAUSTED");
    const mine = [...this.otps.values()].filter((o) => o.parentRef === parentRef && o.scope === scope);
    const last = Math.max(0, ...mine.map((o) => o.createdAt));
    if (mine.length > 0 && last > this.now() - APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS) throw new DomainError("OTP_RESEND_TOO_SOON");
    if (mine.filter((o) => o.createdAt > this.now() - APPROVED_P06_OTP_SEND_WINDOW_MS).length >= APPROVED_P06_OTP_MAX_SENDS_PER_HOUR) throw new DomainError("OTP_SEND_LIMIT");
    for (const o of mine) if (o.state === "CODE_SENT") o.state = "EXPIRED";
  }

  get maxAttempts(): number {
    return APPROVED_P03_OTP_MAX_ATTEMPTS;
  }
  get sessionWindowMs(): number {
    return BETA_VERIFIED_SESSION_WINDOW_MS;
  }
}
