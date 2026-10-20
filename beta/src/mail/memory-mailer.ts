// Gobierna: plan v2 H1-06. Mailer en memoria para tests: renderiza igual que el adaptador real y guarda lo "enviado".

import type { Mailer, SendRequest, SendResult } from "./mailer.port.ts";
import { renderTemplate, type Rendered } from "./templates/index.ts";

export interface SentMail extends Rendered {
  readonly to: string;
  readonly template: SendRequest["template"];
}

export class MemoryMailer implements Mailer {
  readonly sent: SentMail[] = [];
  /** Si se define, send() lanza este error (simula caída del SMTP). */
  failWith: Error | undefined;
  /** Se invoca justo después de aceptar el mensaje y antes de devolver (para simular muerte del proceso). */
  afterAccept: (() => void) | undefined;
  private n = 0;

  private readonly publicOrigin: string;

  constructor(publicOrigin = "https://consent.example.invalid") {
    this.publicOrigin = publicOrigin;
  }

  async send(request: SendRequest): Promise<SendResult> {
    if (this.failWith !== undefined) throw this.failWith;
    const r = renderTemplate(request.template, request.params as never, this.publicOrigin);
    this.sent.push({ to: request.to, template: request.template, ...r });
    this.afterAccept?.();
    this.n += 1;
    return { providerMessageId: `<memory-${this.n}@test.invalid>` };
  }
}
