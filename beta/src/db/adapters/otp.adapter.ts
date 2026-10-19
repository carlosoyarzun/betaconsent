// Gobierna: plan v2 H1-04 + SEC-CNS-024 F-SB-01/F-SB-02. Adaptador PG de OtpRepo: issue_otp / verify_otp (0003). El código lo genera y lo verifica la BASE; este adaptador
// no tiene secretos, no genera códigos y no calcula ningún verificador. El código en claro que devuelve issue_otp se pasa al llamador (para el correo) y no se persiste ni se loguea.
import type { OtpVerifyOutcome } from "../../domain/types.ts";
import type { IssueOtpInput, IssuedOtp, OtpRepo } from "../../ports/otp.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

export function createPgOtpRepo(uow: UnitOfWork): OtpRepo {
  const issue = (input: IssueOtpInput): Promise<IssuedOtp> =>
    translating(() =>
      uow.withTransaction(async (tx) => {
        const r = await tx.query<{ o_verification_ref: string; o_code: string; o_expires_at: Date }>("SELECT * FROM app.issue_otp($1, $2)", [input.parentRef, input.scope]);
        const row = r.rows[0];
        if (!row) throw new Error("issue_otp no devolvió fila.");
        return { verificationRef: row.o_verification_ref, code: row.o_code, expiresAt: row.o_expires_at };
      }),
    );

  return {
    issue,
    resend: issue,

    // Una sola llamada SQL en SU PROPIA transacción (la que abre este uow y que NO se comparte con record/revoke): se confirma también con WRONG_CODE/LOCKED, así el
    // conteo de intentos y el presupuesto P-04 no se pueden revertir con un fallo posterior. Por eso `verify` no recibe una unidad de trabajo externa (F-SB-02).
    verify: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ outcome: OtpVerifyOutcome; attempts_left: number }>("SELECT * FROM app.verify_otp($1, $2, $3)", [input.verificationRef, input.code, input.decisionMakerRef]);
          const out = r.rows[0];
          if (!out) throw new Error("verify_otp no devolvió fila.");
          return { outcome: out.outcome, attemptsLeft: out.attempts_left };
        }),
      ),
  };
}
