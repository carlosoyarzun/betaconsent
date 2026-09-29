// Gobierna: src/server/ports/otp-channel.port.ts. Sink en memoria IT0 (DEC-BR-014 §4.2):
// no hay SMTP ni ninguna salida de red; solo acumula los mensajes para que un test los
// inspeccione. El código en claro vive únicamente aquí, nunca en el ledger ni en logs.

import type { OtpChannelMessage, OtpChannelPort } from "../../server/ports/otp-channel.port.ts";

export interface InMemoryOtpChannelSink extends OtpChannelPort {
  readonly sent: readonly OtpChannelMessage[];
}

export function createInMemoryOtpChannelSink(): InMemoryOtpChannelSink {
  const sent: OtpChannelMessage[] = [];
  return {
    async send(message) {
      sent.push(message);
    },
    sent,
  };
}
