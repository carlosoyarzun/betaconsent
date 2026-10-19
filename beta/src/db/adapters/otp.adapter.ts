// Gobierna: plan v2 H1-04. Adaptador PG de OtpRepo: issue_otp / verify_otp (0003). El código se genera y el HMAC se calcula AQUÍ con CNS_OTP_SECRET;
// a la base solo va el HMAC. El código en claro se devuelve al llamador y no se persiste ni se loguea.
// origen (ideas): src/infra/adapters/postgres/otp-verification.adapter.ts@9345b78 (forma); la comparación y los contadores ya no están en TS.
import { APPROVED_P02_OTP_TTL_MS } from "../../otp/approved-parameters.ts";
import { computeOtpHmac, generateOtpCode } from "../../domain/crypto.ts";
import type { OtpScope, OtpVerifyOutcome } from "../../domain/types.ts";
import type { IssueOtpInput, IssuedOtp, OtpRepo } from "../../ports/otp.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

export interface PgOtpRepoOptions {
  /** CNS_OTP_SECRET decodificado. */
  readonly otpSecret: Buffer;
  /** Inyectable para tests deterministas. */
  readonly generateCode?: () => string;
}

export function createPgOtpRepo(uow: UnitOfWork, options: PgOtpRepoOptions): OtpRepo {
  const generateCode = options.generateCode ?? generateOtpCode;

  const issue = (input: IssueOtpInput): Promise<IssuedOtp> =>
    translating(() =>
      uow.withTransaction(async (tx) => {
        const ttlMs = input.ttlMs ?? APPROVED_P02_OTP_TTL_MS;
        if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > APPROVED_P02_OTP_TTL_MS) throw new RangeError("ttlMs fuera de (0, 10 min].");
        // El vencimiento se calcula con la hora de la base (la misma que valida issue_otp): sin sesgo de reloj entre app y base.
        const t = await tx.query<{ expires_at: Date }>("SELECT pg_catalog.now() + ($1::int * interval '1 millisecond') AS expires_at", [ttlMs]);
        const expiresAt = t.rows[0]!.expires_at;
        const code = generateCode(); // por intento: un reintento de la tx genera un código nuevo; solo se devuelve el de la tx confirmada
        const hmac = computeOtpHmac(options.otpSecret, input.parentRef, input.scope, code);
        const r = await tx.query<{ r: string }>("SELECT app.issue_otp($1, $2, $3, $4) AS r", [input.parentRef, hmac, expiresAt, input.scope]);
        return { verificationRef: r.rows[0]!.r, code, expiresAt };
      }),
    );

  return {
    issue,
    resend: issue,

    verify: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          // La base genera verification_ref, así que el HMAC se liga a (scope, parent_ref), que se leen de la fila (columnas visibles para consent_app).
          const ch = await tx.query<{ parent_ref: string; scope: OtpScope }>("SELECT parent_ref, scope FROM app.otp_challenge WHERE verification_ref = $1", [input.verificationRef]);
          const row = ch.rows[0];
          if (!row) return { outcome: "NOT_ACTIVE" as OtpVerifyOutcome, attemptsLeft: 0 };
          const hmac = computeOtpHmac(options.otpSecret, row.parent_ref, row.scope, input.code);
          const r = await tx.query<{ outcome: OtpVerifyOutcome; attempts_left: number }>("SELECT * FROM app.verify_otp($1, $2, $3)", [input.verificationRef, hmac, input.decisionMakerRef]);
          const out = r.rows[0];
          if (!out) throw new Error("verify_otp no devolvió fila.");
          return { outcome: out.outcome, attemptsLeft: out.attempts_left };
        }),
      ),
  };
}
