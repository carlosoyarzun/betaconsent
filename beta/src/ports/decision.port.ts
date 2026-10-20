// Gobierna: plan v2 H1-04. Puerto de decisiones; record_decision de 0003.
import type { ConsentId, DecisionOutcome, DecisionState, InvitationRef, InvitationState, VerificationRef } from "../domain/types.ts";

export interface RecordDecisionInput {
  readonly invitationRef: InvitationRef;
  readonly verificationRef: VerificationRef;
  readonly outcome: DecisionOutcome;
  readonly consentVersion: string;
  /** SHA-256 hex del texto servido. */
  readonly consentTextHash: string;
  /** 8–200 caracteres; la base guarda solo su hash. */
  readonly idempotencyKey: string;
  /** Códigos de la lista cerrada (STUDY_PARTICIPATION, AUDIO_RECORDING, AUTOMATED_ANALYSIS, HUMAN_REVIEW), sin duplicados; otro valor => INVALID_PURPOSES. */
  readonly purposes?: readonly string[];
}

export interface DecisionPageState {
  readonly invitationState: InvitationState;
  readonly consentVersion: string | null;
  readonly decision: { readonly consentId: ConsentId; readonly state: DecisionState } | null;
}

export interface DecisionRepo {
  /** Misma clave => misma decisión (deduped = true). Otra clave sobre invitación decidida => ALREADY_DECIDED. Sin OTP verificado => VERIFICATION_REQUIRED. */
  record(input: RecordDecisionInput): Promise<{ readonly consentId: ConsentId; readonly state: DecisionState; readonly deduped: boolean }>;
  /** Estado para pintar la página, por handle = invitationRef. null = no existe. */
  getPageState(invitationRef: InvitationRef): Promise<DecisionPageState | null>;
}
