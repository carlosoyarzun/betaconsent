// Gobierna: plan v2 H1-04. Puerto de revocación; revoke_decision de 0003.
import type { ConsentId, DecisionState, RevocationRef, VerificationRef } from "../domain/types.ts";

export interface ManageState {
  readonly consentId: ConsentId;
  readonly state: DecisionState;
  // decision_maker_ref NO se expone: consent_app no lo lee (SEC-CNS-024-V1). revoke_decision compara dentro de la base el seudónimo del OTP con el de la decisión.
  readonly decidedAt: Date;
  /** Invitación que originó la decisión (consent_app la lee): sirve para resolver el correo del OTP de gestión/revocación. */
  readonly invitationRef: string;
}

export interface RevocationRepo {
  /** Exige OTP REVOCATION|MANAGE verificado. Lanza VERIFICATION_REQUIRED, NOT_REVOCABLE_DECLINED, ALREADY_REVOKED, IDEMPOTENCY_KEY_REUSED, DECISION_NOT_FOUND. */
  revoke(input: { readonly consentId: ConsentId; readonly verificationRef: VerificationRef; readonly idempotencyKey: string }): Promise<{ readonly revocationRef: RevocationRef; readonly deduped: boolean }>;
  /** Estado para la página de gestión, por handle = consentId. null = no existe. */
  getManageState(consentId: ConsentId): Promise<ManageState | null>;
  /**
   * Resuelve el enlace de gestión por el HASH sha256 (hex) del token (open_manage_link de 0004). No consume. null = inválido, invalidado, vencido o decisión DECLINED.
   * state GRANTED = se puede gestionar; REVOKED = la UI muestra "ya revocado".
   */
  openManageLink(tokenHashHex: string): Promise<{ readonly consentId: ConsentId; readonly invitationRef: string; readonly state: "GRANTED" | "REVOKED" } | null>;
}
