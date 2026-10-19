// Gobierna: plan v2 H1-04. Adaptadores en memoria de los cinco puertos sobre un MemoryState compartido (misma semántica que las funciones de 0003).
import { computeOtpHmac, generateOtpCode } from "../../../domain/crypto.ts";
import { DomainError } from "../../../domain/errors.ts";
import { APPROVED_P02_OTP_TTL_MS } from "../../../otp/approved-parameters.ts";
import type { Ports } from "../../../ports/index.ts";
import { LIVE_INVITATION_STATES, MemoryState } from "./state.ts";

export interface MemoryPortsOptions {
  readonly otpSecret: Buffer;
  /** Reloj en ms (inyectable para avanzar el tiempo en tests). Default Date.now. */
  readonly now?: () => number;
  readonly generateCode?: () => string;
}

const validKey = (k: string): boolean => k.length >= 8 && k.length <= 200;

export function createMemoryPorts(options: MemoryPortsOptions): Ports {
  const s = new MemoryState(options.now ?? Date.now);
  const generateCode = options.generateCode ?? generateOtpCode;

  const issue: Ports["otp"]["issue"] = async (input) => {
    const ttlMs = input.ttlMs ?? APPROVED_P02_OTP_TTL_MS;
    if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > APPROVED_P02_OTP_TTL_MS) throw new RangeError("ttlMs fuera de (0, 10 min].");
    s.checkIssue(input.parentRef, input.scope);
    const code = generateCode();
    const ref = s.newRef("ver");
    const expiresAt = s.now() + ttlMs;
    s.otps.set(ref, {
      ref, scope: input.scope, parentRef: input.parentRef, hmac: computeOtpHmac(options.otpSecret, input.parentRef, input.scope, code),
      attempts: 0, state: "CODE_SENT", expiresAt, createdAt: s.now(), consumedAt: null, decisionMakerRef: null,
    });
    return { verificationRef: ref, code, expiresAt: new Date(expiresAt) };
  };

  return {
    invitations: {
      async import(input) {
        const live = [...s.invitations.values()].find((i) => i.studentRef === input.studentRef && LIVE_INVITATION_STATES.includes(i.state));
        if (live) return { invitationRef: live.ref, created: false };
        const ref = s.newRef("inv");
        s.invitations.set(ref, { ref, studentRef: input.studentRef, state: "READY", tokenHash: null, tokenExpiresAt: null, tokenConsumed: false, consentVersion: null });
        return { invitationRef: ref, created: true };
      },
      async armToken(input) {
        const inv = s.invitations.get(input.invitationRef);
        if (!inv) throw new DomainError("INVITATION_NOT_FOUND");
        if (input.expiresAt.getTime() <= s.now()) throw new DomainError("TOKEN_EXPIRY_IN_PAST");
        if (inv.state === "READY") {
          inv.state = "SENT";
          inv.consentVersion = input.consentVersion;
        } else if (inv.state !== "SENT") {
          throw new DomainError("INVITATION_NOT_ARMABLE");
        }
        inv.tokenHash = input.tokenHash;
        inv.tokenExpiresAt = input.expiresAt.getTime();
      },
      async openByTokenHash(tokenHash) {
        const inv = [...s.invitations.values()].find(
          (i) => i.tokenHash === tokenHash && !i.tokenConsumed && (i.tokenExpiresAt ?? 0) > s.now() && ["SENT", "OPENED", "VERIFIED"].includes(i.state),
        );
        if (!inv) return null;
        if (inv.state === "SENT") inv.state = "OPENED";
        return { invitationRef: inv.ref, studentRef: inv.studentRef, consentVersion: inv.consentVersion ?? "", state: inv.state };
      },
    },

    otp: {
      issue,
      resend: issue,
      async verify(input) {
        const ch = s.otps.get(input.verificationRef);
        if (!ch || ch.state !== "CODE_SENT") return { outcome: "NOT_ACTIVE", attemptsLeft: 0 };
        if (s.now() >= ch.expiresAt) {
          ch.state = "EXPIRED";
          return { outcome: "EXPIRED", attemptsLeft: 0 };
        }
        if (s.budgetFailures(ch.parentRef) >= 10) return { outcome: "BUDGET_EXHAUSTED", attemptsLeft: 0 };
        if (computeOtpHmac(options.otpSecret, ch.parentRef, ch.scope, input.code) === ch.hmac) {
          if (input.decisionMakerRef.length < 1 || input.decisionMakerRef.length > 100) throw new DomainError("INVALID_DECISION_MAKER_REF");
          ch.attempts += 1;
          ch.state = "VERIFIED";
          ch.consumedAt = s.now();
          ch.decisionMakerRef = input.decisionMakerRef;
          const inv = ch.scope === "DECISION" ? s.invitations.get(ch.parentRef) : undefined;
          if (inv?.state === "OPENED") inv.state = "VERIFIED";
          return { outcome: "VERIFIED", attemptsLeft: s.maxAttempts - ch.attempts };
        }
        s.addBudgetFailure(ch.parentRef);
        ch.attempts += 1;
        if (ch.attempts >= s.maxAttempts) {
          ch.state = "LOCKED";
          return { outcome: "LOCKED", attemptsLeft: 0 };
        }
        return { outcome: "WRONG_CODE", attemptsLeft: s.maxAttempts - ch.attempts };
      },
    },

    decisions: {
      async record(input) {
        if (input.outcome !== "GRANTED" && input.outcome !== "DECLINED") throw new DomainError("INVALID_OUTCOME");
        if (!validKey(input.idempotencyKey)) throw new DomainError("INVALID_IDEMPOTENCY_KEY");
        const inv = s.invitations.get(input.invitationRef);
        if (!inv) throw new DomainError("INVITATION_NOT_FOUND");
        const existing = [...s.decisions.values()].find((d) => d.invitationRef === input.invitationRef);
        if (existing) {
          if (existing.idemKey === input.idempotencyKey) return { consentId: existing.consentId, state: existing.state, deduped: true };
          throw new DomainError("ALREADY_DECIDED");
        }
        if ([...s.decisions.values()].some((d) => d.idemKey === input.idempotencyKey)) throw new DomainError("IDEMPOTENCY_KEY_REUSED");
        const ch = s.otps.get(input.verificationRef);
        const verified =
          ch && ch.scope === "DECISION" && ch.parentRef === input.invitationRef && ch.state === "VERIFIED" && (ch.consumedAt ?? 0) > s.now() - s.sessionWindowMs;
        if (!ch || !verified || inv.state !== "VERIFIED" || inv.tokenConsumed || inv.tokenExpiresAt === null) throw new DomainError("VERIFICATION_REQUIRED");
        const consentId = s.newRef("con");
        s.decisions.set(consentId, {
          consentId, invitationRef: inv.ref, studentRef: inv.studentRef, decisionMakerRef: ch.decisionMakerRef ?? "", state: input.outcome,
          idemKey: input.idempotencyKey, decidedAt: s.now(),
        });
        inv.state = input.outcome === "GRANTED" ? "COMPLETED" : "DECLINED";
        inv.tokenConsumed = true;
        return { consentId, state: input.outcome, deduped: false };
      },
      async getPageState(invitationRef) {
        const inv = s.invitations.get(invitationRef);
        if (!inv) return null;
        const d = [...s.decisions.values()].find((x) => x.invitationRef === invitationRef);
        return { invitationState: inv.state, consentVersion: inv.consentVersion, decision: d ? { consentId: d.consentId, state: d.state } : null };
      },
    },

    revocations: {
      async revoke(input) {
        if (!validKey(input.idempotencyKey)) throw new DomainError("INVALID_IDEMPOTENCY_KEY");
        const dec = s.decisions.get(input.consentId);
        if (!dec) throw new DomainError("DECISION_NOT_FOUND");
        const prior = s.revocations.find((r) => r.idemKey === input.idempotencyKey);
        if (prior) {
          if (prior.consentId === input.consentId) return { revocationRef: prior.ref, deduped: true };
          throw new DomainError("IDEMPOTENCY_KEY_REUSED");
        }
        if (dec.state === "DECLINED") throw new DomainError("NOT_REVOCABLE_DECLINED");
        if (dec.state === "REVOKED") throw new DomainError("ALREADY_REVOKED");
        const ch = s.otps.get(input.verificationRef);
        const ok =
          ch && (ch.scope === "REVOCATION" || ch.scope === "MANAGE") && ch.parentRef === input.consentId && ch.state === "VERIFIED" &&
          ch.decisionMakerRef === dec.decisionMakerRef && (ch.consumedAt ?? 0) > s.now() - s.sessionWindowMs;
        if (!ok) throw new DomainError("VERIFICATION_REQUIRED");
        const ref = s.newRef("rev");
        s.revocations.push({ ref, consentId: input.consentId, idemKey: input.idempotencyKey });
        dec.state = "REVOKED";
        return { revocationRef: ref, deduped: false };
      },
      async getManageState(consentId) {
        const d = s.decisions.get(consentId);
        return d ? { consentId, state: d.state, decisionMakerRef: d.decisionMakerRef, decidedAt: new Date(d.decidedAt) } : null;
      },
    },

    authorization: {
      async byStudentRef(studentRef) {
        const d = [...s.decisions.values()].find((x) => x.studentRef === studentRef && x.state === "GRANTED");
        return { status: d ? "AUTHORIZED" : "NOT_AUTHORIZED", asOf: new Date(s.now()), decisionRef: d?.consentId ?? null };
      },
    },
  };
}
