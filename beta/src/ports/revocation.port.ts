// Gobierna: plan v2 H1-04. Puerto de revocación; revoke_decision de 0003.
import type { ConsentId, DecisionState, RevocationRef, VerificationRef } from "../domain/types.ts";

export interface ManageState {
  readonly consentId: ConsentId;
  readonly state: DecisionState;
  /** Seudónimo del apoderado que decidió: el OTP de REVOCATION|MANAGE debe verificarse con el mismo valor. */
  readonly decisionMakerRef: string;
  readonly decidedAt: Date;
}

export interface RevocationRepo {
  /** Exige OTP REVOCATION|MANAGE verificado. Lanza VERIFICATION_REQUIRED, NOT_REVOCABLE_DECLINED, ALREADY_REVOKED, IDEMPOTENCY_KEY_REUSED, DECISION_NOT_FOUND. */
  revoke(input: { readonly consentId: ConsentId; readonly verificationRef: VerificationRef; readonly idempotencyKey: string }): Promise<{ readonly revocationRef: RevocationRef; readonly deduped: boolean }>;
  /** Estado para la página de gestión, por handle = consentId. null = no existe. */
  getManageState(consentId: ConsentId): Promise<ManageState | null>;
}
