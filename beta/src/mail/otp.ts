// Gobierna: plan v2 H1-06. OTP síncrono: se envía directo, sin pasar por el outbox. El código no se persiste ni se registra:
// esta función no recibe logger ni toca la BD; si el envío falla, el error propagado NO incluye el código.

import type { Mailer } from "./mailer.port.ts";
import { isRecipientAllowed, type RecipientPolicy } from "./recipient-policy.ts";

export class OtpSuppressedError extends Error {
  constructor() {
    super("destinatario fuera de la allowlist (catálogo SYNTHETIC)");
    this.name = "OtpSuppressedError";
  }
}

export class OtpSendError extends Error {
  constructor() {
    super("no se pudo enviar el código por correo");
    this.name = "OtpSendError";
  }
}

export async function sendOtpNow(mailer: Mailer, to: string, code: string, opts: { policy?: RecipientPolicy; ttlMinutes?: number } = {}): Promise<{ providerMessageId?: string }> {
  if (opts.policy !== undefined && !isRecipientAllowed(to, opts.policy)) throw new OtpSuppressedError();
  try {
    return await mailer.send({ to, template: "otp", params: { code, ttlMinutes: opts.ttlMinutes ?? 10 } });
  } catch {
    // Se descarta la causa original a propósito: los errores SMTP pueden reflejar el cuerpo del mensaje.
    throw new OtpSendError();
  }
}
