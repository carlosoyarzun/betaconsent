// Gobierna: specs/state-machines/invitation.spec.yaml I3 effects ("Encola la entrega por el
// adaptador de email de IT0 (sink/allowlist, DEC-BR-014 §4.2); ningún SMTP externo") y
// contracts/openapi POST /staff/invitations/{invitationRef}/send ("El token se entrega solo por
// el adaptador de email IT0"). Puerto (ADR-001 §11), mismo patrón que
// recovery-link-channel.port.ts / otp-channel.port.ts. El enlace en claro (con el token) vive
// SOLO en este mensaje: nunca en la respuesta HTTP, el ledger, eventos ni logs (INV-IV-03).

import type { InvitationDeliveryChannel } from "../modules/invitation/invitation-issuance-policy.config.ts";

export interface InvitationLinkMessage {
  readonly invitationRef: string;
  /** Ruta relativa de canje (`/i/<token>`); el token en claro solo existe en este mensaje. */
  readonly invitationPath: string;
  readonly deliveryChannel: InvitationDeliveryChannel;
  /** Canal esperado ligado a la invitación (RECIPIENT_CHANNEL); ausente si UNBOUND. Ref opaca. */
  readonly recipientChannelRef?: string;
}

export interface InvitationLinkChannelPort {
  send(message: InvitationLinkMessage): void;
}
