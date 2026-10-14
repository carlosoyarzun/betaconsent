// Gobierna: CLAUDE.md (UX-CNS-001, /welcome) + flujo del invitado v2 (handoff Stitch->DS, Carlos
// 2026-10-14; D-01 DS con estructura de pantallas Stitch, D-05 objetivo táctil 48px). Renderiza el
// HTML de GET /welcome en el servidor. Todo el copy es [UX — borrador], sin cláusulas legales (no se
// pide aceptación en /welcome). Sin campos de teléfono/correo ni elección de canal: el código va solo
// al canal ligado a la invitación (GRD-OT-02, F-STITCH-01). No hay valores dinámicos interpolados
// (colegio/dominio son placeholders sintéticos fijos, IT0); si en el futuro se interpola algo
// dinámico, debe pasar por `escapeHtml`.
//
// INV-CM-08 (no transiciona): esta página nunca llama a un puerto de dominio ni muta estado;
// solo lee la sesión ya creada por GET /i/{token} (consent-flow.handler.ts) para decidir si
// renderiza la pantalla o el estado de error uniforme.

import { alertHead, escapeHtml, GUEST_HELP_LINK, guestHead, guestHeader } from "./guest-layout.ts";

/** Reexportada: la usan las páginas de staff (dev-staff-console-page.ts, staff-ui-pages.ts). */
export { escapeHtml };

const HEAD = guestHead("Bienvenida a la invitación");

const HOW_IT_WORKS = `<ol class="lp-howto">
          <li><strong>Verifica tu identidad</strong>Te enviaremos un código de verificación a la vía de contacto registrada.</li>
          <li><strong>Revisa la información</strong>Leerás en qué consiste el estudio y qué datos se tratarían.</li>
          <li><strong>Decide si participar</strong>La decisión es tuya. Podrás aceptar o no aceptar cada finalidad.</li>
        </ol>`;

/** GET /welcome con sesión válida (default state; loading/error-uniform/error-red los toggles
 * welcome.js en el cliente). Móvil: una columna; escritorio (>=1024px): dos columnas con la
 * acción en la columna lateral (el CTA de la columna principal se oculta por CSS). */
export function renderWelcomePage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
    <h1 id="welcome-h1">Bienvenida a la invitación</h1>
    <div class="lp-welcome-grid">
      <div>
        <section class="lp-card lp-card-default" aria-label="Detalle de la invitación">
          <p>Colegio Ejemplo te invita a participar en el Estudio Beta de LectorPro.</p>
          <p>LectorPro es una aplicación que apoya la lectura de tu hija o hijo. El colegio invita a las familias a sumarse a un estudio piloto.</p>
        </section>
        <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="how-h2">
          <h2 id="how-h2">Cómo funciona</h2>
          ${HOW_IT_WORKS}
        </section>
        <div class="lp-welcome-action-mobile">
          <button type="button" class="lp-btn lp-btn-primary lp-cta lp-welcome-cta lp-welcome-action" id="continue-btn" data-continue aria-disabled="false" aria-busy="false">Continuar</button>
        </div>
      </div>
      <aside class="lp-card lp-card-default lp-welcome-aside" aria-labelledby="ready-h2">
        <h2 id="ready-h2">¿Listo para comenzar?</h2>
        <p>A continuación te enviaremos un código de verificación. Después de confirmarlo, podrás revisar la información y decidir si participar.</p>
        <button type="button" class="lp-btn lp-btn-primary lp-cta lp-welcome-cta" id="continue-btn-aside" data-continue aria-disabled="false" aria-busy="false">Continuar</button>
      </aside>
    </div>
    ${GUEST_HELP_LINK}
    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform" hidden>
      ${alertHead("error", "No pudimos abrir esta invitación.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    <div role="alert" aria-live="polite" class="lp-alert-warning" id="error-network" hidden>
      ${alertHead("warning", "No pudimos conectar.")}
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-welcome-cta">Reintentar</button>
    </div>
  </main>
  <script src="/assets/welcome.js" defer></script>
</body>
</html>
`;
}

/**
 * Estado de error uniforme de la pantalla (sesión inexistente/expirada/de otro tenant): INV-CM-05,
 * no distingue la causa. Se sirve como el CUERPO de la propia pantalla /welcome (nunca un 404
 * "crudo" del framework) cuando GET /welcome no tiene una sesión LANDING válida.
 */
export function renderWelcomeUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
    <h1 id="welcome-h1">Bienvenida a la invitación</h1>
    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform">
      ${alertHead("error", "No pudimos abrir esta invitación.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    ${GUEST_HELP_LINK}
  </main>
</body>
</html>
`;
}
