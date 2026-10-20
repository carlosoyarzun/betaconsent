// Gobierna: plan v2 H1-04. Puerto de invitaciones; las transiciones viven en las funciones SQL de 0003 (import_invitation, arm_invitation_token, open_invitation).
import type { InvitationRef, InvitationState, StudentRef } from "../domain/types.ts";

export interface ImportInvitationInput {
  readonly studentRef: StudentRef;
  readonly studentFirstName: string;
  readonly guardianEmail: string;
  readonly batchRef: string;
}

export interface OpenedInvitation {
  readonly invitationRef: InvitationRef;
  readonly studentRef: StudentRef;
  readonly consentVersion: string;
  readonly state: InvitationState;
}

export interface InvitationRepo {
  /** Idempotente en CUALQUIER estado (F-SB-03): si el estudiante ya tiene invitación (viva, decidida o revocada) devuelve la existente (created = false), sin cambiar el correo. */
  import(input: ImportInvitationInput): Promise<{ readonly invitationRef: InvitationRef; readonly created: boolean }>;
  /**
   * READY>SENT o rotación SENT>SENT. Recibe el HASH del token (nunca el token). Se ejecuta con el pool del MAILER (consent_mailer), no con el de la app (SEC-CNS-024-V1).
   * Vigencia <= 7 días (P-10, tolerancia de 60 s). La rotación con token vigente exige `reissueReason` (^[A-Z][A-Z0-9_]{2,39}$; queda en el ledger como INVITATION_LINK_REISSUED).
   * Lanza TOKEN_EXPIRY_IN_PAST / TOKEN_EXPIRY_TOO_LONG / TOKEN_STILL_VALID / INVALID_REISSUE_REASON / INVITATION_NOT_ARMABLE / INVITATION_NOT_FOUND.
   */
  armToken(input: {
    readonly invitationRef: InvitationRef;
    readonly tokenHash: string;
    readonly expiresAt: Date;
    readonly consentVersion: string;
    readonly reissueReason?: string;
  }): Promise<void>;
  /** null = token inválido, vencido, consumido o invitación terminal (respuesta uniforme). No consume el token. */
  openByTokenHash(tokenHash: string): Promise<OpenedInvitation | null>;
}
