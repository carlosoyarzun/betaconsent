// Gobierna: src/server/ports/invitation-link-channel.port.ts. Sink en memoria IT0 (DEC-BR-014
// §4.2), mismo patrón que in-memory-recovery-link-channel-sink.adapter.ts: solo acumula los
// mensajes para que dev.ts (/__dev/invitation-sink, solo LOCAL) o un test los inspeccionen. Sin
// SMTP ni ninguna salida de red.

import { assertSyntheticRecipient } from "../../server/modules/common/synthetic-recipient.ts";
import type { InvitationLinkChannelPort, InvitationLinkMessage } from "../../server/ports/invitation-link-channel.port.ts";

export interface InMemoryInvitationLinkChannelSink extends InvitationLinkChannelPort {
  readonly sent: readonly InvitationLinkMessage[];
}

export function createInMemoryInvitationLinkChannelSink(): InMemoryInvitationLinkChannelSink {
  const sent: InvitationLinkMessage[] = [];
  return {
    async send(message) {
      // X3 (DEC-BR-014 §4): allowlist synthetic-only; el destinatario esperado (si existe) debe ser reservado u opaco.
      if (message.recipientChannelRef !== undefined) assertSyntheticRecipient(message.recipientChannelRef);
      sent.push(message);
    },
    sent,
  };
}
