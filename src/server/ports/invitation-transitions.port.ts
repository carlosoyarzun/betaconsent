// Gobierna: invitation.spec.yaml I9 (CancelInvitation, SUBJECT_MISMATCH_REPORTED), ADR-010 rev. 5 (LG-3/LG-5: app_rw ya no escribe
// Invitation:INVITATION_CANCELLED en el ledger), db/migrations/0044_invitation_cancel_subject_mismatch_fn.sql, ADR-001 §11.
// Puerto de la transicion I9 por funcion SECURITY DEFINER de la base (Postgres). Ausente en in-memory: el dominio usa la ruta legacy
// `invitationRepo.save` + `ledger.append` (mismos estado y evento). El tenant sale de la sesion de la base, nunca de un parametro.

export interface InvitationTransitionsPort {
  /** VERIFIED -> CANCELLED + INVITATION_CANCELLED en la misma tx; idempotente para el mismo DecisionMaker. Los rechazos de guard de la base se
   * traducen a DomainError (ERR-IV-09 / ERR-CM-01); un conflicto de secuencia a LedgerSequenceConflictError. */
  cancelSubjectMismatch(input: { readonly invitationRef: string; readonly decisionMakerRef: string; readonly expectedSequence: number }): Promise<{ readonly sequence: number }>;
}
