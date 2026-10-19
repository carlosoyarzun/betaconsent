// origen: src/server/entrypoints/http/guest-messages.ts@9345b78 (wrap/row/legalMarker; paleta de tokens --lp-* resuelta)

const C = { primary: "#1A5CB8", text: "#1E293B", secondary: "#475569", border: "#E2E8F0", subtle: "#F1F5F9", warnBg: "#FEF3C7", warnText: "#92400E" } as const;
const FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export function wrap(title: string, inner: string): string {
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

export function row(label: string, valueHtml: string): string {
  const td = `padding:8px 0;border-bottom:1px solid ${C.border};font-size:14px;vertical-align:top;`;
  return `<tr><td style="${td}width:40%;color:${C.secondary};">${escapeHtml(label)}</td><td style="${td}">${valueHtml}</td></tr>`;
}

export function table(rows: string): string {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:12px 0;">${rows}</table>`;
}

export function legalMarker(text: string): string {
  return `<p style="margin:8px 0;padding:8px 12px;border:1px dashed ${C.warnText};background:${C.warnBg};color:${C.warnText};font-size:12px;">${escapeHtml(text)}</p>`;
}

export function badge(text: string): string {
  return `<p style="margin:0 0 12px;display:inline-block;padding:4px 12px;border-radius:999px;background:${C.warnBg};color:${C.warnText};font-size:12px;font-weight:bold;">${escapeHtml(text)}</p>`;
}

export function button(url: string, label: string): string {
  return `<p style="margin:0 0 16px;"><a href="${escapeHtml(url)}" style="display:inline-block;padding:14px 24px;background:${C.primary};color:#FFFFFF;text-decoration:none;border-radius:8px;font-weight:bold;">${escapeHtml(label)}</a></p>`;
}

export function muted(text: string): string {
  return `<p style="margin:0 0 8px;font-size:14px;color:${C.secondary};">${escapeHtml(text)}</p>`;
}

export function h1(text: string): string {
  return `<h1 style="margin:0 0 8px;font-size:22px;">${escapeHtml(text)}</h1>`;
}

export function h2(text: string): string {
  return `<h2 style="margin:16px 0 4px;font-size:18px;">${escapeHtml(text)}</h2>`;
}

export function p(text: string): string {
  return `<p style="margin:0 0 16px;">${escapeHtml(text)}</p>`;
}

export function otpBox(code: string): string {
  return `<p style="margin:0 0 16px;font-size:32px;letter-spacing:6px;font-weight:bold;font-family:monospace;">${escapeHtml(code)}</p>`;
}
