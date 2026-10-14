// Gobierna: UX-CNS-001/002/003/004 (flujo del invitado v2, handoff de diseño Stitch->DS, Carlos
// 2026-10-14, decisiones D-01 y D-05). Piezas de HTML compartidas por las pantallas del
// invitado: <head> estático (solo /assets/** locales: nada de CDN, fuentes ni imágenes remotas,
// F-STITCH-17), cabecera de marca, stepper "Paso n de 3" y cabecera de alerta con icono
// decorativo. Todo el copy es literal, sintético y [UX — borrador]; ninguna pieza redacta copy
// legal. CSP `default-src 'self'` (writeHtmlSecurityHeaders): sin <style> ni style="" inline.

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** <head> común: charset, viewport, título y las dos hojas locales (DS + app.css). */
export function guestHead(title: string): string {
  return `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">`;
}

/** Cabecera de marca (sin elementos de navegación). El badge "Prueba · IT0" es texto visible. */
export function guestHeader(): string {
  return `<header class="lp-guest-header">
    <div class="lp-guest-brand"><span class="lp-guest-logo" aria-hidden="true">LP</span><span>LectorPro · Estudio Beta</span></div>
    <span class="lp-badge lp-badge-warning"><span class="lp-guest-env-short">Prueba · IT0</span><span class="lp-guest-env-long">Entorno de prueba · IT0 · datos sintéticos</span></span>
  </header>`;
}

export type StepNumber = 1 | 2 | 3;

const STEP_LABELS: Readonly<Record<StepNumber, string>> = { 1: "Verificación", 2: "Revisa y decide", 3: "Registro" };

/** Stepper "Paso n de 3 · {etiqueta}": el texto es la información; las barras son aria-hidden. */
export function renderStepper(step: StepNumber): string {
  const bar = (i: number): string =>
    `<div class="lp-progress-bar"><div class="lp-progress-fill ${i <= step ? "lp-stepper-fill-full" : "lp-stepper-fill-none"}"></div></div>`;
  return `<div class="lp-stepper">
      <div class="lp-stepper-bars" aria-hidden="true">${bar(1)}${bar(2)}${bar(3)}</div>
      <p class="lp-stepper-label">Paso ${step} de 3 · ${STEP_LABELS[step]}</p>
    </div>`;
}

export type AlertIcon = "error" | "warning" | "success" | "info";

const ALERT_GLYPH: Readonly<Record<AlertIcon, string>> = { error: "!", warning: "!", success: "✓", info: "i" };

/** Cabecera de alerta: icono decorativo (aria-hidden) + título (el título es texto, no solo color). */
export function alertHead(icon: AlertIcon, title: string): string {
  return `<div class="lp-alert-head"><span class="lp-alert-icon" aria-hidden="true">${ALERT_GLYPH[icon]}</span><span>${escapeHtml(title)}</span></div>`;
}

/** Enlace de ayuda (misma posición relativa en todas las pantallas: fin del contenido, 3.2.6). */
export const GUEST_HELP_LINK = `<p class="lp-guest-help"><a href="mailto:ayuda@example.invalid" class="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a></p>`;
