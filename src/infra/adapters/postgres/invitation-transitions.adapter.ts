// Gobierna: invitation.spec.yaml I9, ADR-010 rev. 5, db/migrations/0044_invitation_cancel_subject_mismatch_fn.sql; src/server/ports/
// invitation-transitions.port.ts. ADR-001 §11: solo este adaptador conoce el SQL de la funcion `case_state.cancel_invitation_subject_mismatch`.
// La llamada va en un SAVEPOINT (un rechazo de guard de la base deja la tx utilizable) y los SQLSTATE se traducen igual que en
// revocation-transitions.adapter.ts (RV001 -> ERR-CM-01, IV009 -> ERR-IV-09, RV409 -> LedgerSequenceConflictError). Sin SQL dinamico.

import type { InvitationTransitionsPort } from "../../../server/ports/invitation-transitions.port.ts";
import { mapTransitionError } from "./revocation-transitions.adapter.ts";
import type { TenantTx } from "./unit-of-work.ts";

export function createPgInvitationTransitions(tx: TenantTx): InvitationTransitionsPort {
  return {
    async cancelSubjectMismatch(input) {
      await tx.query("SAVEPOINT invitation_transition");
      try {
        const r = await tx.query<{ r: { sequence: number } }>(
          "SELECT case_state.cancel_invitation_subject_mismatch($1::text, $2::text, $3::integer) AS r",
          [input.invitationRef, input.decisionMakerRef, input.expectedSequence],
        );
        await tx.query("RELEASE SAVEPOINT invitation_transition");
        return { sequence: Number(r.rows[0]?.r.sequence) };
      } catch (error) {
        await tx.query("ROLLBACK TO SAVEPOINT invitation_transition");
        throw mapTransitionError(error);
      }
    },
  };
}
