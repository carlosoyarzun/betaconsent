// Gobierna: UX-CNS-006 (e-mail de comprobante) y UX-CNS-006b (e-mail del enlace de gestión),
// Master Plan §21 Consent Receipt (docs/beta-consent-master-plan.md:723-741), decisiones de
// Carlos 2026-10-14: D-03 (dos mensajes al canal verificado: comprobante SIN enlace y mensaje
// aparte con el enlace), D-04 (campos del §21 + marca de agua IT0; "cómo revocar" y "cómo ejercer
// derechos" con marcador [LEGAL DECISION] visible), sin descarga del comprobante, el enlace de
// gestión nunca dentro del comprobante (api-payloads.schema.json DecisionRecorded).
//
// HTML de tablas con estilos inline con los valores resueltos de los tokens --lp-* (un e-mail no
// carga CSS externo ni fuentes: fuente de sistema), sin JS, sin imágenes remotas, sin enlaces en
// el comprobante. Todo dato interpolado pasa por escapeHtml. Datos sintéticos (example.invalid).
// Todo texto legal es marcador [LEGAL DECISION]; el copy no legal es [UX — borrador].

import type { GuestMessage } from "../../ports/guest-message-channel.port.ts";
import { escapeHtml } from "./guest-layout.ts";
import { purposeTitle } from "./guest-purposes.ts";

/** Valores resueltos de tokens del DS (tokens.css, tema claro): --lp-action-primary, --lp-text-*,
 * --lp-border-default, --lp-bg-subtle. */
const C = {
  primary: "#1A5CB8",
  text: "#1E293B",
  secondary: "#475569",
  border: "#E2E8F0",
  subtle: "#F1F5F9",
  warnBg: "#FEF3C7",
  warnText: "#92400E",
} as const;

const FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";

export const RECEIPT_SUBJECT = "Comprobante de tu decisión — Estudio Beta de LectorPro";
export const MANAGEMENT_LINK_SUBJECT = "Enlace para gestionar tu decisión — Estudio Beta de LectorPro";
export const RECEIPT_NO_LINK_NOTE =
  "Este mensaje no incluye el enlace para gestionar tu decisión: ese enlace se envía solo a este mismo correo, en un mensaje aparte.";
export const RECEIPT_WATERMARK = "Comprobante de prueba · marca de agua IT0 · datos sintéticos";
export const LEGAL_HOW_TO_REVOKE = "[LEGAL DECISION — cómo retirar tu consentimiento: copy pendiente de aprobación de Carlos]";
export const LEGAL_HOW_TO_EXERCISE_RIGHTS = "[LEGAL DECISION — cómo ejercer tus derechos: copy pendiente de aprobación de Carlos]";

export interface ReceiptPurposeLine {
  readonly purpose: string;
  readonly choice: "GRANT" | "DECLINE";
}

export interface ReceiptInput {
  readonly recipientChannelRef: string;
  readonly subjectLabel: string | undefined;
  readonly consentVersion: string;
  readonly privacyNoticeVersion: string;
  readonly purposes: readonly ReceiptPurposeLine[];
  readonly decidedAt: Date;
  readonly receiptRef: string;
  readonly state: "GRANTED" | "DECLINED";
}

function formatDateTime(d: Date): string {
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function choiceText(choice: "GRANT" | "DECLINE"): string {
  return choice === "GRANT" ? "✓ Acepto" : "✕ No acepto";
}

function wrap(title: string, inner: string): string {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title></head>
<body style="margin:0;padding:0;background:${C.subtle};${FONT}color:${C.text};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${C.subtle};"><tr><td align="center" style="padding:16px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#FFFFFF;border:1px solid ${C.border};border-radius:12px;">
<tr><td style="padding:16px 24px;border-bottom:1px solid ${C.border};${FONT}font-weight:bold;color:${C.text};">LectorPro · Estudio Beta</td></tr>
<tr><td style="padding:24px;${FONT}font-size:16px;line-height:1.5;color:${C.text};">${inner}</td></tr>
</table></td></tr></table></body></html>
`;
}

function row(label: string, value: string): string {
  return `<tr><td style="padding:8px 0;border-bottom:1px solid ${C.border};width:40%;color:${C.secondary};font-size:14px;vertical-align:top;">${escapeHtml(label)}</td><td style="padding:8px 0;border-bottom:1px solid ${C.border};font-size:14px;vertical-align:top;">${value}</td></tr>`;
}

function legalMarker(text: string): string {
  return `<p style="margin:8px 0;padding:8px 12px;border:1px dashed ${C.warnText};background:${C.warnBg};color:${C.warnText};font-size:12px;">${escapeHtml(text)}</p>`;
}

/** UX-CNS-006: comprobante (§21). Nunca contiene un enlace (ni de gestión ni de otro tipo). */
export function renderReceiptMessage(input: ReceiptInput): GuestMessage {
  const subjectLabel = input.subjectLabel ?? "No disponible";
  const rows = [
    row("Estudio", "Estudio Beta de LectorPro · Colegio Ejemplo"),
    row("Estudiante", escapeHtml(subjectLabel)),
    row("Versión del consentimiento", escapeHtml(input.consentVersion)),
    row("Versión del aviso de privacidad", escapeHtml(input.privacyNoticeVersion)),
    row("Fecha y hora", escapeHtml(formatDateTime(input.decidedAt))),
    row("Referencia del comprobante", escapeHtml(input.receiptRef)),
    row("Decisión registrada", input.state === "GRANTED" ? "Participación aceptada" : "Participación no aceptada"),
  ].join("");
  const purposeRows = input.purposes
    .map((p) => row(purposeTitle(p.purpose), escapeHtml(choiceText(p.choice))))
    .join("");
  const html = wrap(
    RECEIPT_SUBJECT,
    `<h1 style="margin:0 0 8px;font-size:22px;">Comprobante de tu decisión</h1>
<p style="margin:0 0 12px;display:inline-block;padding:4px 12px;border-radius:999px;background:${C.warnBg};color:${C.warnText};font-size:12px;font-weight:bold;">${escapeHtml(RECEIPT_WATERMARK)}</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:12px 0;">${rows}</table>
<h2 style="margin:16px 0 4px;font-size:18px;">Decisión por finalidad</h2>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${purposeRows}</table>
<h2 style="margin:16px 0 4px;font-size:18px;">Cómo retirar tu consentimiento</h2>
${legalMarker(LEGAL_HOW_TO_REVOKE)}
<h2 style="margin:16px 0 4px;font-size:18px;">Cómo ejercer tus derechos</h2>
${legalMarker(LEGAL_HOW_TO_EXERCISE_RIGHTS)}
<p style="margin:16px 0 0;font-size:14px;color:${C.secondary};">${escapeHtml(RECEIPT_NO_LINK_NOTE)}</p>`,
  );
  const text = [
    "Comprobante de tu decisión",
    RECEIPT_WATERMARK,
    "",
    "Estudio: Estudio Beta de LectorPro · Colegio Ejemplo",
    `Estudiante: ${subjectLabel}`,
    `Versión del consentimiento: ${input.consentVersion}`,
    `Versión del aviso de privacidad: ${input.privacyNoticeVersion}`,
    `Fecha y hora: ${formatDateTime(input.decidedAt)}`,
    `Referencia del comprobante: ${input.receiptRef}`,
    "",
    "Decisión por finalidad:",
    ...input.purposes.map((p) => `- ${purposeTitle(p.purpose)}: ${choiceText(p.choice)}`),
    "",
    "Cómo retirar tu consentimiento:",
    LEGAL_HOW_TO_REVOKE,
    "Cómo ejercer tus derechos:",
    LEGAL_HOW_TO_EXERCISE_RIGHTS,
    "",
    RECEIPT_NO_LINK_NOTE,
  ].join("\n");
  return { kind: "RECEIPT", recipientChannelRef: input.recipientChannelRef, subject: RECEIPT_SUBJECT, html, text };
}

export interface ManagementLinkInput {
  readonly recipientChannelRef: string;
  /** Ruta de un solo enlace (`/m/<token>`); el token solo existe en este mensaje. */
  readonly managementPath: string;
  /** Origen público del enlace (sintético en IT0, p. ej. https://consent.example.invalid). */
  readonly publicBaseUrl: string;
}

/** UX-CNS-006b: mensaje aparte con el enlace de gestión (solo a este canal; nunca en el comprobante). */
export function renderManagementLinkMessage(input: ManagementLinkInput): GuestMessage {
  const url = `${input.publicBaseUrl.replace(/\/+$/, "")}${input.managementPath}`;
  const html = wrap(
    MANAGEMENT_LINK_SUBJECT,
    `<h1 style="margin:0 0 12px;font-size:22px;">Gestiona tu decisión</h1>
<p style="margin:0 0 16px;">Con este enlace puedes revisar el estado de tu decisión y, si lo deseas, retirar tu consentimiento.</p>
<p style="margin:0 0 16px;"><a href="${escapeHtml(url)}" style="display:inline-block;padding:14px 24px;background:${C.primary};color:#FFFFFF;text-decoration:none;border-radius:8px;font-weight:bold;">Gestionar mi decisión</a></p>
<p style="margin:0 0 8px;font-size:14px;color:${C.secondary};">El enlace es personal: no lo compartas ni lo reenvíes.</p>
<p style="margin:0;font-size:12px;color:${C.secondary};">${escapeHtml(RECEIPT_WATERMARK)}</p>`,
  );
  const text = ["Gestiona tu decisión", "", `Gestionar mi decisión: ${url}`, "", "El enlace es personal: no lo compartas ni lo reenvíes."].join("\n");
  return { kind: "MANAGEMENT_LINK", recipientChannelRef: input.recipientChannelRef, subject: MANAGEMENT_LINK_SUBJECT, html, text };
}
