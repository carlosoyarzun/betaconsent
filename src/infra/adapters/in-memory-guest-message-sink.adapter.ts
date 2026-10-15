// Gobierna: src/server/ports/guest-message-channel.port.ts. Sink en memoria IT0 (DEC-BR-014
// §4.2), mismo patrón que in-memory-recovery-link-channel-sink.adapter.ts: solo acumula los
// mensajes para que dev.ts (/__dev/message-sink, solo LOCAL) o un test los inspeccionen. Sin red.

import type { GuestMessage, GuestMessageChannelPort } from "../../server/ports/guest-message-channel.port.ts";

export interface InMemoryGuestMessageSink extends GuestMessageChannelPort {
  readonly sent: readonly GuestMessage[];
}

export function createInMemoryGuestMessageSink(): InMemoryGuestMessageSink {
  const sent: GuestMessage[] = [];
  return {
    async send(message) {
      sent.push(message);
    },
    sent,
  };
}
