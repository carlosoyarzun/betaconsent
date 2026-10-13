// Gobierna: ADR-010 rev. 4 §4.2 (PR-5a), specs/state-machines/revocation.spec.yaml `dbEnforcement` (FN-RV-01..15, TRG-RV-01, INV-RV-12),
// specs/db-roles.spec.yaml (transition_owner, Q-18). ADR-001 §11: el dominio solo conoce este puerto.
//
// Puerto de escritura de las transiciones de la Revocation. Con un adaptador que lo implementa (Postgres: funciones SECURITY DEFINER
// de `case_state`, dueno transition_owner), la fila, el evento de ledger, el outbox y la proyeccion C6 de cada transicion los escribe LA
// FUNCION en la misma tx; el dominio solo decide (lee, valida, pasa `expectedSequence`) y llama. Sin este puerto (adaptador in-memory),
// el dominio escribe con `revocationRepo.save` + `ledger.append` como antes (rutas legacy documentadas en revocation.ts). Ambos caminos
// producen los mismos eventos y estados (tests de paridad TS<->SQL).
//
// `sequence` = ultima sequence del agregado Revocation tras la llamada (para encadenar el siguiente `expectedSequence`).
// Los errores de guard de la base llegan como DomainError (ERR-CM-01/06, ERR-RV-02/05/07/18/20) y el conflicto de secuencia como
// LedgerSequenceConflictError, igual que el ledger.

export interface TransitionResult {
  readonly sequence: number;
}

export interface RevocationTransitionsPort {
  /** FN-RV-01 R1. */
  request(input: { readonly revocationRef: string; readonly chainRef: string; readonly revokedDecisionRef: string }): Promise<TransitionResult>;
  /** FN-RV-02 R2 (authPath OTP). */
  verifyOtp(input: { readonly revocationRef: string; readonly verificationRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-03 R3 / R3r. */
  confirm(input: { readonly revocationRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-04 R1r + R2r (o R10): consume el token y verifica por enlace. `expectedSequence` solo aplica a una Revocation ya existente. */
  revokeWithRecoveryLink(input: {
    readonly recoveryRef: string;
    readonly newRevocationRef: string;
    readonly expectedSequence: number;
  }): Promise<TransitionResult & { readonly revocationRef: string }>;
  /** FN-RV-05 R8. */
  withdraw(input: { readonly revocationRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-06 (lado Revocation de RC3 / R12). `attach` = R12 (la fila no cambia, solo el evento). */
  expressRevocationIntentInCase(input: {
    readonly caseRef: string;
    readonly chainRef: string;
    readonly revokedDecisionRef: string;
    readonly initiatedVia: "DECISION_MAKER" | "SCHOOL_REPORT";
    readonly revocationRef: string;
    readonly attach: boolean;
    readonly expectedSequence: number;
  }): Promise<TransitionResult>;
  /** FN-RV-07 RH2 paso 1. */
  proposeCaseVerification(input: {
    readonly revocationRef: string;
    readonly caseRef: string;
    readonly proposalRef: string;
    readonly proposedByRef: string;
    readonly verificationScriptVersion: string;
  }): Promise<void>;
  /** FN-RV-08 RH2 paso 2. */
  approveCaseVerification(input: {
    readonly revocationRef: string;
    readonly caseRef: string;
    readonly proposalRef: string;
    readonly approverRef: string;
    readonly expectedSequence: number;
  }): Promise<TransitionResult>;
  /** FN-RV-09 RH2w. */
  withdrawCaseVerificationProposal(input: {
    readonly revocationRef: string;
    readonly caseRef: string;
    readonly proposalRef: string;
    readonly actorRef: string;
    readonly expectedSequence: number;
  }): Promise<TransitionResult>;
  /** FN-RV-10 RH3 paso 1. */
  recordCaseConfirmation(input: { readonly revocationRef: string; readonly caseRef: string; readonly recordedByRef: string }): Promise<void>;
  /** FN-RV-11 RH3 paso 2. */
  cosignCaseConfirmation(input: {
    readonly revocationRef: string;
    readonly caseRef: string;
    readonly cosignedByRef: string;
    readonly expectedSequence: number;
  }): Promise<TransitionResult>;
  /** FN-RV-12 R4 + C6. */
  apply(input: { readonly revocationRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-13 R5. */
  markDownstreamEmitted(input: { readonly revocationRef: string; readonly subscriptionRefs: readonly string[]; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-14 R6. */
  recordDownstreamAck(input: { readonly revocationRef: string; readonly ackRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
  /** FN-RV-15 R7. */
  recordErasureAttestation(input: { readonly revocationRef: string; readonly attestationRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
}
