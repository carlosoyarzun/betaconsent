// Gobierna: plan v2 H1-05. El correo del apoderado no cruza los puertos. `RecipientLookup` (pool consent_app, SELECT por columnas de app.invitation) solo sirve para
// calcular el seudónimo del canal en verify (deriveDecisionMakerRef); el ENVÍO del OTP lee el correo con readGuardianEmail sobre el pool del mailer (SEC-CNS-024-V1).
// Nunca se loguea ni se devuelve al cliente.
import type { Queryable } from "../mail/recipient-policy.ts";

export interface RecipientLookup {
  /** Correo ligado a la invitación (scope DECISION). null = no existe. */
  forInvitation(invitationRef: string): Promise<string | null>;
}

export function createPgRecipientLookup(db: Queryable): RecipientLookup {
  return {
    async forInvitation(invitationRef) {
      const r = await db.query<{ guardian_email: string }>("SELECT guardian_email FROM app.invitation WHERE invitation_ref = $1", [invitationRef]);
      return r.rows[0]?.guardian_email ?? null;
    },
  };
}
