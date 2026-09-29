// Gobierna: src/server/ports/invitation-link-channel.port.ts. Sink en memoria IT0 (DEC-BR-014
// §4.2), mismo patrón que in-memory-recovery-link-channel-sink.adapter.ts: solo acumula los
// mensajes para que dev.ts (/__dev/invitation-sink, solo LOCAL) o un test los inspeccionen. Sin
// SMTP ni ninguna salida de red.

import type { InvitationLinkChannelPort, InvitationLinkMessage } from "../../server/ports/invitation-link-channel.port.ts";

export interface InMemoryInvitationLinkChannelSink extends InvitationLinkChannelPort {
  readonly sent: readonly InvitationLinkMessage[];
}

export function createInMemoryInvitationLinkChannelSink(): InMemoryInvitationLinkChannelSink {
  const sent: InvitationLinkMessage[] = [];
  return {
    send(message) {
      sent.push(message);
    },
    sent,
  };
}
