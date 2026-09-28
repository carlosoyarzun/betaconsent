// Gobierna: UX-CNS-004 (handoff revocation-handoff.md §1/§3/§4/§8, frames 33:87
// recovery/confirmar, 33:96 recovery/en-curso R11 NOOP, 33:106 recovery/error-uniforme
// ERR-RV-05; reutiliza 33:54 comprobante), specs/state-machines/revocation.spec.yaml R1r, R2r,
// R3r, R10, R11 y contracts/openapi/consent-it0.openapi.yaml API-CNS-135 (POST
// /recovery/revoke). GET /recovery/confirm requiere sesión RECOVERY (creada por GET
// /r/{token}, INV-CM-08: nunca transiciona, solo renderiza el formulario); recovery.js orquesta
// el único POST /recovery/revoke y decide qué bloque mostrar según la respuesta (CONFIRMED,
// IN_PROGRESS, o la respuesta uniforme de ERR-RV-05), nunca el propio HTML servido aquí.
//
// Los marcadores [LEGAL DECISION] de esta pantalla son literales y VISIBLES como texto (mismo
// criterio que revocation-page.ts, Carlos 2026-09-28: nunca dentro de un comentario HTML): el
// de efecto sobre los datos ya recolectados al revocar (handoff §4, protocolo l.522) y el de
// alcance/irreversibilidad del retiro (handoff §8, protocolo l.423). Ninguno se redacta aquí
// (CLAUDE.md, copy legal de producción).

const HEAD = `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recuperar acceso · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">`;

/** GET /recovery/confirm con sesión RECOVERY vigente (33:87 recovery/confirmar). */
export function renderRecoveryConfirmPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-revocation-page" aria-labelledby="recovery-h1">
    <h1 id="recovery-h1">Confirmar retiro</h1>

    <div id="recovery-form">
      <section class="lp-card-default lp-revocation-section" aria-labelledby="recovery-confirm-h2">
        <h2 id="recovery-confirm-h2">Vas a retirar tu consentimiento</h2>
        <p>Vas a retirar tu consentimiento para el Estudio Beta de LectorPro.</p>
        <p class="lp-revocation-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
        <p class="lp-revocation-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]</p>
      </section>
      <button type="button" class="lp-btn lp-btn-danger lp-revocation-cta lp-verify-tap-target" id="confirm-recovery-btn" aria-disabled="false" aria-busy="false">Confirmar retiro total</button>
      <p><a href="mailto:ayuda@example.invalid" class="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a></p>
    </div>

    <div role="status" aria-live="polite" id="state-applied" hidden>
      <h2 id="applied-heading" tabindex="-1">Retiramos tu consentimiento</h2>
      <p id="applied-receipt"></p>
      <p class="lp-revocation-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
      <p>Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.</p>
    </div>

    <div role="status" aria-live="polite" id="state-in-progress" hidden>
      <h2 id="in-progress-heading" tabindex="-1">Este retiro ya está en curso</h2>
      <p>Ya confirmamos este retiro antes: no necesitas hacer nada más.</p>
    </div>

    <div role="alert" aria-live="polite" id="error-network" hidden>
      <p>No pudimos conectar.</p>
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-tap-target" id="retry-btn">Reintentar</button>
    </div>

    <div role="alert" aria-live="assertive" id="error-uniform" hidden>
      <p>No pudimos continuar con este retiro.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
  </main>
  <script src="/assets/recovery.js" defer></script>
</body>
</html>
`;
}

/** Estado de error uniforme de la propia pantalla (sesión RECOVERY inexistente: sin
 * recoveryTokenHash, p. ej. GET /recovery/confirm sin haber canjeado /r/{token} antes), mismo
 * patrón que renderRevocationUniformErrorPage/renderManageUniformErrorPage (INV-CM-05). 33:106
 * recovery/error-uniforme. */
export function renderRecoveryUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-revocation-page" aria-labelledby="recovery-h1">
    <h1 id="recovery-h1">Confirmar retiro</h1>
    <div role="alert" aria-live="assertive" id="error-uniform">
      <p>No pudimos continuar con este retiro.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
  </main>
</body>
</html>
`;
}
