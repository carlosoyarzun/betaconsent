// Gobierna: src/server/ports/recovery-link-channel.port.ts. Sink en memoria IT0 (DEC-BR-014
// §4.2), mismo patrón que in-memory-otp-channel-sink.adapter.ts: solo acumula los mensajes
// para que dev.ts (/__dev/recovery-sink, solo LOCAL) o un test los inspeccionen.

import type { RecoveryLinkChannelPort, RecoveryLinkMessage } from "../../server/ports/recovery-link-channel.port.ts";

export interface InMemoryRecoveryLinkChannelSink extends RecoveryLinkChannelPort {
  readonly sent: readonly RecoveryLinkMessage[];
}

export function createInMemoryRecoveryLinkChannelSink(): InMemoryRecoveryLinkChannelSink {
  const sent: RecoveryLinkMessage[] = [];
  return {
    send(message) {
      sent.push(message);
    },
    sent,
  };
}
