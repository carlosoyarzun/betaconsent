// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19), plan v2 H1-06.
// Puerto único de correo para los cuatro canales (invitación, OTP, mensajes al titular, recuperación).
// El dominio solo conoce este puerto; nodemailer vive únicamente en smtp-mailer.ts.

import type { TemplateName, TemplateParams } from "./templates/index.ts";

export type { TemplateName, TemplateParams };

export type SendRequest = {
  [T in TemplateName]: { readonly to: string; readonly template: T; readonly params: TemplateParams[T] };
}[TemplateName];

export interface SendResult {
  readonly providerMessageId?: string;
}

export interface Mailer {
  send(request: SendRequest): Promise<SendResult>;
}
