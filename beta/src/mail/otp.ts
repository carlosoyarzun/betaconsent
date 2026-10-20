// Gobierna: plan v2 H1-06 + SEC-CNS-024-V1. OTP síncrono: se envía directo, sin pasar por el outbox. El código no se persiste ni se registra:
// sendOtpNow no recibe logger ni toca la BD; si el envío falla, el error propagado NO incluye el código.
// El código sale de OtpRepo.issue/resend (pool de consent_mailer) y el destinatario se lee con readGuardianEmail sobre ESE MISMO pool: el pool HTTP (consent_app) no ve el código.

import type { Queryable } from "./recipient-policy.ts";
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

/** Correo del apoderado de una invitación (SELECT por columnas de consent_mailer). `db` = pool del mailer. null = no existe. */
export async function readGuardianEmail(db: Queryable, invitationRef: string): Promise<string | null> {
  const { rows } = await db.query<{ guardian_email: string }>("SELECT guardian_email FROM app.invitation WHERE invitation_ref = $1", [invitationRef]);
  return rows[0]?.guardian_email ?? null;
}
