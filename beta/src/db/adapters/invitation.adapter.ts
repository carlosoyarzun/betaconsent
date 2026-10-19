// Gobierna: plan v2 H1-04. Adaptador PG de InvitationRepo: solo invoca import_invitation / arm_invitation_token / open_invitation (0003).
// origen (ideas): src/infra/adapters/postgres/invitation.adapter.ts@9345b78 (forma del adaptador); sin SQL de transición propio.
import type { InvitationState } from "../../domain/types.ts";
import type { InvitationRepo } from "../../ports/invitation.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

/** `uow` = pool de la app (consent_app); `mailerUow` = pool del mailer (consent_mailer), el único con EXECUTE de arm_invitation_token. */
export function createPgInvitationRepo(uow: UnitOfWork, mailerUow: UnitOfWork): InvitationRepo {
  return {
    import: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, $2, $3, $4)", [
            input.studentRef,
            input.studentFirstName,
            input.guardianEmail,
            input.batchRef,
          ]);
          const row = r.rows[0];
          if (!row) throw new Error("import_invitation no devolvió fila.");
          return { invitationRef: row.invitation_ref, created: row.created };
        }),
      ),

    armToken: (input) =>
      translating(() =>
        mailerUow.withTransaction(async (tx) => {
          await tx.query("SELECT app.arm_invitation_token($1, $2, $3, $4, $5)", [input.invitationRef, input.tokenHash, input.expiresAt, input.consentVersion, input.reissueReason ?? null]);
        }),
      ),

    cancel: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          await tx.query("SELECT app.cancel_invitation($1, $2)", [input.invitationRef, input.reasonCode]);
        }),
      ),

    openByTokenHash: (tokenHash) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ invitation_ref: string; student_ref: string; consent_version: string; state: InvitationState }>("SELECT * FROM app.open_invitation($1)", [tokenHash]);
          const row = r.rows[0];
          return row ? { invitationRef: row.invitation_ref, studentRef: row.student_ref, consentVersion: row.consent_version, state: row.state } : null;
        }),
      ),
  };
}
