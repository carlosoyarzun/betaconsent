// Gobierna: plan v2 H1-06. Adaptador SMTP con nodemailer (único módulo que lo importa).
// TLS obligatorio: smtps:// o puerto 465 => secure:true; en otro caso requireTLS:true (STARTTLS exigido, sin degradar a texto plano).
// Nunca rejectUnauthorized:false: la verificación de certificado queda en el valor por defecto de Node.
// Excepción acotada para desarrollo: `allowPlaintextLoopback` permite SMTP sin TLS SOLO si el host es loopback
// (p. ej. Mailpit local); la ruta de producción (createSmtpMailer) lo activa únicamente con CNS_ENVIRONMENT=LOCAL.

import nodemailer from "nodemailer";
import type { Transporter, TransportOptions } from "nodemailer";

import type { Mailer, SendRequest, SendResult } from "./mailer.port.ts";
import { renderTemplate } from "./templates/index.ts";

export interface SmtpMailerOptions {
  readonly smtpUrl: string;
  readonly from: string;
  readonly publicOrigin: string;
  readonly allowPlaintextLoopback?: boolean;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function buildTransportOptions(opts: Pick<SmtpMailerOptions, "smtpUrl" | "allowPlaintextLoopback">): TransportOptions {
  const u = new URL(opts.smtpUrl);
  if (u.protocol !== "smtp:" && u.protocol !== "smtps:") throw new Error("CNS_SMTP_URL debe ser smtp:// o smtps://");
  const port = u.port === "" ? (u.protocol === "smtps:" ? 465 : 587) : Number(u.port);
  const secure = u.protocol === "smtps:" || port === 465;
  const base: TransportOptions = {
    host: u.hostname,
    port,
    secure,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    ...(u.username !== "" ? { auth: { user: decodeURIComponent(u.username), pass: decodeURIComponent(u.password) } } : {}),
  };
  if (secure) return { ...base, tls: { minVersion: "TLSv1.2" } };
  if (opts.allowPlaintextLoopback === true && LOOPBACK.has(u.hostname)) return { ...base, ignoreTLS: true };
  return { ...base, requireTLS: true, tls: { minVersion: "TLSv1.2" } };
}

export class SmtpMailer implements Mailer {
  private readonly transport: Transporter;
  private readonly opts: SmtpMailerOptions;

  constructor(opts: SmtpMailerOptions, transport?: Transporter) {
    this.opts = opts;
    this.transport = transport ?? nodemailer.createTransport(buildTransportOptions(opts));
  }

  async send(request: SendRequest): Promise<SendResult> {
    const r = renderTemplate(request.template, request.params as never, this.opts.publicOrigin);
    const info = await this.transport.sendMail({ from: this.opts.from, to: request.to, subject: r.subject, text: r.text, html: r.html });
    return info.messageId !== undefined ? { providerMessageId: info.messageId.slice(0, 255) } : {};
  }

  close(): void {
    this.transport.close();
  }
}

export function createSmtpMailer(config: { smtpUrl: string; smtpFrom: string; publicOrigin: string; environment: "LOCAL" | "REAL" }): SmtpMailer {
  return new SmtpMailer({ smtpUrl: config.smtpUrl, from: config.smtpFrom, publicOrigin: config.publicOrigin, allowPlaintextLoopback: config.environment === "LOCAL" });
}
