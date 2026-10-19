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
  /** Idempotente: reimportar al mismo estudiante con invitación viva devuelve la existente (created = false). */
  import(input: ImportInvitationInput): Promise<{ readonly invitationRef: InvitationRef; readonly created: boolean }>;
  /** READY>SENT o rotación SENT>SENT. Recibe el HASH del token (nunca el token). Lanza TOKEN_EXPIRY_IN_PAST / INVITATION_NOT_ARMABLE / INVITATION_NOT_FOUND. */
  armToken(input: { readonly invitationRef: InvitationRef; readonly tokenHash: string; readonly expiresAt: Date; readonly consentVersion: string }): Promise<void>;
  /** null = token inválido, vencido, consumido o invitación terminal (respuesta uniforme). No consume el token. */
  openByTokenHash(tokenHash: string): Promise<OpenedInvitation | null>;
}
