// Gobierna: CLAUDE.md (UX-CNS-001, /welcome). Renderiza el HTML de GET /welcome en el
// servidor. Copy textual exacto del handoff (scratchpad welcome-handoff.md §3); todo es
// [UX], sin cláusulas legales (no se pide aceptación en /welcome). No hay valores dinámicos
// interpolados en el copy (dominio/colegio son placeholders sintéticos fijos, IT0), por eso no
// hace falta escapar nada más allá de lo que ya es HTML literal en este archivo; si en el
// futuro se interpola algo dinámico, debe pasar por `escapeHtml`.
//
// INV-CM-08 (no transiciona): esta página nunca llama a un puerto de dominio ni muta estado;
// solo lee la sesión ya creada por GET /i/{token} (consent-flow.handler.ts) para decidir si
// renderiza la pantalla o el estado de error uniforme.

/** Usar si alguna vez se interpola un valor dinámico en el HTML de esta pantalla (hoy no hace
 * falta: todo el copy es literal y sintético). */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const HEAD = `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bienvenida a la invitación · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">`;

/** GET /welcome con sesión válida (default state; loading/error-uniform/error-red los toggles
 * welcome.js en el cliente, ver handoff §2 y §5). */
export function renderWelcomePage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
    <h1 id="welcome-h1">Bienvenida a la invitación</h1>
    <section class="lp-card lp-card-default" aria-label="Detalle de la invitación">
      <p>Colegio Ejemplo te invita a participar en el Estudio Beta de LectorPro.</p>
      <p>LectorPro es una aplicación que apoya la lectura de tu hija o hijo. El colegio invita a las familias a sumarse a un estudio piloto.</p>
      <p>A continuación te enviaremos un código de verificación. Después de confirmarlo, podrás revisar la información y decidir si participar.</p>
    </section>
    <button type="button" class="lp-btn lp-btn-primary lp-welcome-cta" id="continue-btn" aria-disabled="false" aria-busy="false">Continuar</button>
    <a href="mailto:ayuda@example.invalid" class="lp-link lp-welcome-help">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a>
    <div role="alert" aria-live="assertive" id="error-uniform" hidden>
      <p>No pudimos abrir esta invitación.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    <div role="alert" aria-live="polite" id="error-network" hidden>
      <p>No pudimos conectar.</p>
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-welcome-cta">Reintentar</button>
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
<body>
  <main class="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
    <h1 id="welcome-h1">Bienvenida a la invitación</h1>
    <div role="alert" aria-live="assertive" id="error-uniform">
      <p>No pudimos abrir esta invitación.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    <a href="mailto:ayuda@example.invalid" class="lp-link lp-welcome-help">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a>
  </main>
</body>
</html>
`;
}
