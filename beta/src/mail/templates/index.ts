// Gobierna: plan v2 H1-06. Seis plantillas (texto + HTML sencillo), copy BORRADOR.
// Reglas: sin RUT; asunto fijo sin nombre ni correo; solo el nombre de pila del estudiante en el cuerpo (nunca en el asunto);
// enlaces = CNS_PUBLIC_ORIGIN + ruta (el origen ya incluye https://; http solo para localhost en LOCAL);
// los recibos llevan chain_seq/event_hash opcionales (los rellena H2-05).

import { LEGAL_HOW_TO_EXERCISE_RIGHTS, LEGAL_HOW_TO_REVOKE, LEGAL_INVITATION_BODY, RECEIPT_NO_LINK_NOTE, RECEIPT_WATERMARK, STUDY_NAME, SUBJECTS } from "../guest-messages.ts";
import { purposeTitle } from "../guest-purposes.ts";
import { badge, button, escapeHtml, h1, h2, legalMarker, muted, otpBox, p, row, table, wrap } from "./layout.ts";

export type TemplateName = "invitation" | "otp" | "receipt_granted" | "receipt_declined" | "receipt_revoked" | "management_link";

export interface PurposeChoice {
  readonly purpose: string;
  readonly choice: "GRANT" | "DECLINE";
}

export interface ReceiptParams {
  /** Solo nombre de pila. */
  readonly studentFirstName: string;
  readonly consentVersion: string;
  /** ISO 8601 UTC. */
  readonly decidedAt: string;
  readonly receiptRef: string;
  readonly purposes: readonly PurposeChoice[];
  /** Opcionales: los rellena H2-05 cuando exista la cadena del ledger. */
  readonly chain_seq?: number;
  readonly event_hash?: string;
}

export interface LinkParams {
  readonly studentFirstName: string;
  /** Ruta que empieza por "/" (p. ej. "/i/<token>"); el origen se antepone al renderizar. */
  readonly linkPath: string;
}

export interface TemplateParams {
  invitation: LinkParams;
  otp: { readonly code: string; readonly ttlMinutes: number };
  receipt_granted: ReceiptParams;
  receipt_declined: ReceiptParams;
  receipt_revoked: ReceiptParams;
  management_link: LinkParams;
}

export interface Rendered {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

export const TEMPLATE_NAMES: readonly TemplateName[] = ["invitation", "otp", "receipt_granted", "receipt_declined", "receipt_revoked", "management_link"];

export function buildLink(publicOrigin: string, linkPath: string): string {
  const u = new URL(publicOrigin);
  const localHttp = u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  if (u.protocol !== "https:" && !localHttp) throw new Error("CNS_PUBLIC_ORIGIN debe ser https:// para armar enlaces");
  if (!/^\/[A-Za-z0-9._~\-\/]*$/.test(linkPath) || linkPath.includes("//")) throw new Error("linkPath inválido");
  return `${u.origin}${linkPath}`;
}

function receiptBody(kind: "receipt_granted" | "receipt_declined" | "receipt_revoked", r: ReceiptParams): Rendered {
  const heading = kind === "receipt_revoked" ? "Comprobante de retiro de consentimiento" : "Comprobante de tu decisión";
  const state = { receipt_granted: "Participación aceptada", receipt_declined: "Participación no aceptada", receipt_revoked: "Consentimiento retirado" }[kind];
  const choiceText = (c: PurposeChoice["choice"]): string => (kind === "receipt_revoked" ? "Retirado" : c === "GRANT" ? "✓ Acepto" : "✕ No acepto");
  const fields: [string, string][] = [
    ["Estudio", STUDY_NAME],
    ["Estudiante", r.studentFirstName],
    ["Versión del consentimiento", r.consentVersion],
    ["Fecha y hora", r.decidedAt],
    ["Referencia del comprobante", r.receiptRef],
    ["Resultado", state],
  ];
  if (r.chain_seq !== undefined) fields.push(["Secuencia en la cadena", String(r.chain_seq)]);
  if (r.event_hash !== undefined) fields.push(["Huella del evento", r.event_hash]);
  const html = wrap(
    SUBJECTS[kind],
    `${h1(heading)}${badge(RECEIPT_WATERMARK)}${table(fields.map(([k, v]) => row(k, escapeHtml(v))).join(""))}
${h2("Detalle por finalidad")}${table(r.purposes.map((x) => row(purposeTitle(x.purpose), escapeHtml(choiceText(x.choice)))).join(""))}
${h2("Cómo retirar tu consentimiento")}${legalMarker(LEGAL_HOW_TO_REVOKE)}
${h2("Cómo ejercer tus derechos")}${legalMarker(LEGAL_HOW_TO_EXERCISE_RIGHTS)}
${muted(RECEIPT_NO_LINK_NOTE)}`,
  );
  const text = [
    heading,
    RECEIPT_WATERMARK,
    "",
    ...fields.map(([k, v]) => `${k}: ${v}`),
    "",
    "Detalle por finalidad:",
    ...r.purposes.map((x) => `- ${purposeTitle(x.purpose)}: ${choiceText(x.choice)}`),
    "",
    "Cómo retirar tu consentimiento:",
    LEGAL_HOW_TO_REVOKE,
    "Cómo ejercer tus derechos:",
    LEGAL_HOW_TO_EXERCISE_RIGHTS,
    "",
    RECEIPT_NO_LINK_NOTE,
  ].join("\n");
  return { subject: SUBJECTS[kind], text, html };
}

export function renderTemplate<T extends TemplateName>(template: T, params: TemplateParams[T], publicOrigin: string): Rendered {
  switch (template) {
    case "invitation": {
      const a = params as TemplateParams["invitation"];
      const url = buildLink(publicOrigin, a.linkPath);
      const intro = `Se te invita a decidir sobre la participación de ${a.studentFirstName} en el ${STUDY_NAME}.`;
      return {
        subject: SUBJECTS.invitation,
        text: [`Invitación al ${STUDY_NAME}`, "BORRADOR", "", intro, LEGAL_INVITATION_BODY, "", `Ver la invitación: ${url}`, "", "El enlace es personal: no lo compartas ni lo reenvíes."].join("\n"),
        html: wrap(SUBJECTS.invitation, `${h1(`Invitación al ${STUDY_NAME}`)}${badge("BORRADOR")}${p(intro)}${legalMarker(LEGAL_INVITATION_BODY)}${button(url, "Ver la invitación")}${muted("El enlace es personal: no lo compartas ni lo reenvíes.")}`),
      };
    }
    case "otp": {
      const a = params as TemplateParams["otp"];
      const line = `Tu código de verificación es: ${a.code}`;
      const ttl = `Vence en ${a.ttlMinutes} minutos. No lo compartas con nadie.`;
      return {
        subject: SUBJECTS.otp,
        text: ["BORRADOR", line, ttl].join("\n"),
        html: wrap(SUBJECTS.otp, `${h1("Código de verificación")}${badge("BORRADOR")}${p("Usa este código para continuar:")}${otpBox(a.code)}${muted(ttl)}`),
      };
    }
    case "receipt_granted":
    case "receipt_declined":
    case "receipt_revoked":
      return receiptBody(template, params as ReceiptParams);
    case "management_link": {
      const a = params as TemplateParams["management_link"];
      const url = buildLink(publicOrigin, a.linkPath);
      const body = "Con este enlace puedes revisar el estado de tu decisión y, si lo deseas, retirar tu consentimiento.";
      return {
        subject: SUBJECTS.management_link,
        text: ["Gestiona tu decisión", "BORRADOR", "", body, "", `Gestionar mi decisión: ${url}`, "", "El enlace es personal: no lo compartas ni lo reenvíes."].join("\n"),
        html: wrap(SUBJECTS.management_link, `${h1("Gestiona tu decisión")}${badge("BORRADOR")}${p(body)}${button(url, "Gestionar mi decisión")}${muted("El enlace es personal: no lo compartas ni lo reenvíes.")}`),
      };
    }
    default: {
      const never: never = template;
      throw new Error(`plantilla desconocida: ${String(never)}`);
    }
  }
}
