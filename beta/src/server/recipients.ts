// Gobierna: plan v2 H1-05. El destinatario del OTP no cruza los puertos (el correo no es un dato de dominio del puerto): se resuelve aquí con el mismo SELECT
// de app.invitation que ya usa el outbox (consent_app tiene SELECT). Nunca se loguea ni se devuelve al cliente.
import type { Queryable } from "../mail/recipient-policy.ts";

export interface RecipientLookup {
  /** Correo ligado a la invitación (scope DECISION). null = no existe. */
  forInvitation(invitationRef: string): Promise<string | null>;
  /** Correo ligado a la invitación que originó la decisión (scope REVOCATION|MANAGE). */
  forConsent(consentId: string): Promise<string | null>;
}

export function createPgRecipientLookup(db: Queryable): RecipientLookup {
  return {
    async forInvitation(invitationRef) {
      const r = await db.query<{ guardian_email: string }>("SELECT guardian_email FROM app.invitation WHERE invitation_ref = $1", [invitationRef]);
      return r.rows[0]?.guardian_email ?? null;
    },
    async forConsent(consentId) {
      const r = await db.query<{ guardian_email: string }>(
        "SELECT i.guardian_email FROM app.consent_decision d JOIN app.invitation i ON i.tenant_id = d.tenant_id AND i.invitation_ref = d.invitation_ref WHERE d.consent_id = $1",
        [consentId],
      );
      return r.rows[0]?.guardian_email ?? null;
    },
  };
}
