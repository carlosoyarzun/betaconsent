// Gobierna: UX-CNS-004 (handoff revocation-handoff.md §2/§3, frames 33:45 confirmar-retiro,
// 33:54 comprobante, 33:64 retiro-cancelado, 33:73 error-uniforme, 33:79 error-red),
// specs/state-machines/revocation.spec.yaml R3 (ConfirmRevocation), R8
// (WithdrawRevocationRequest). GET /manage/revocation/confirm requiere sesión con
// revocationOtpVerified (V3 scope REVOCATION correcto, posterior a R1) y
// manageDecisionMakerRef; INV-CM-08 (GET nunca transiciona): esta página nunca llama a R2/R3
// directamente, solo renderiza el formulario; revocation.js orquesta POST
// /manage/revocation/verify (R2) al cargar y luego POST /manage/revocation/confirm (R3) o
// /manage/revocation/withdraw (R8) según la acción del usuario.
//
// Los marcadores [LEGAL DECISION] de esta pantalla son literales y VISIBLES como texto (Carlos,
// 2026-09-28; fix Carlos, revisión en navegador con dev.ts: no pueden ir dentro de un
// comentario HTML `<!-- -->`, porque el usuario nunca los vería): el de alcance/
// irreversibilidad del retiro (handoff §8, reemplaza la frase citada antes como [UX], protocolo
// l.423) y el de efecto sobre los datos ya recolectados al revocar (handoff §4, protocolo
// l.522, en confirmar-retiro y en el comprobante). Ninguno se redacta aquí (CLAUDE.md, copy
// legal de producción).

import { HELP_MAILTO, REVOCATION_APPLY_FAILED_COPY as APPLY_FAILED } from "./revocation-apply-failed-copy.ts";
import { alertHead, GUEST_HELP_LINK, guestHead, guestHeader } from "./guest-layout.ts";
import { RECEIPT_WATERMARK } from "./guest-messages.ts";

const HEAD = guestHead("Confirmar retiro");

export function renderRevocationConfirmPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-revocation-page" aria-labelledby="revocation-h1">
    <h1 id="revocation-h1">Confirmar retiro</h1>

    <div id="revocation-form">
      <section class="lp-card-default lp-revocation-section" aria-labelledby="confirm-h2">
        <h2 id="confirm-h2">Vas a retirar tu consentimiento</h2>
        <p>Vas a retirar tu consentimiento para el Estudio Beta de LectorPro.</p>
        <p class="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
        <p class="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]</p>
      </section>
      <div class="lp-actions-stack">
        <button type="button" class="lp-btn lp-btn-danger lp-cta lp-revocation-cta lp-verify-tap-target" id="confirm-revocation-btn" aria-disabled="false" aria-busy="false">Confirmar retiro total</button>
        <button type="button" class="lp-btn lp-btn-outline lp-cta lp-revocation-cta lp-verify-tap-target" id="withdraw-btn">Cancelar solicitud de retiro</button>
      </div>
      ${GUEST_HELP_LINK}
    </div>

    <div role="status" aria-live="polite" id="state-applied" hidden>
      <span class="lp-hero-icon" aria-hidden="true">✓</span>
      <h1 id="applied-heading" tabindex="-1">Retiramos tu consentimiento</h1>
      <p class="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
      <section class="lp-card lp-card-default" aria-labelledby="applied-receipt-h2">
        <h2 id="applied-receipt-h2">Comprobante</h2>
        <p class="lp-receipt-ref" id="applied-receipt"></p>
        <div class="lp-badge-row"><span class="lp-badge lp-badge-warning">${RECEIPT_WATERMARK}</span></div>
      </section>
      <p>Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.</p>
    </div>

    <div role="status" aria-live="polite" id="state-withdrawn" hidden>
      <h1 id="withdrawn-heading" tabindex="-1">Cancelamos tu solicitud de retiro</h1>
      <p>Tu consentimiento sigue vigente. Puedes volver a solicitar el retiro cuando quieras.</p>
    </div>

    <div role="alert" aria-live="polite" class="lp-alert-warning" id="error-network" hidden>
      ${alertHead("warning", "No pudimos conectar.")}
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="retry-btn">Reintentar</button>
    </div>

    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform" hidden>
      ${alertHead("error", "No pudimos continuar con este retiro.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>

    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-apply-failed" tabindex="-1" hidden>
      ${alertHead("error", APPLY_FAILED.title)}
      <p>${APPLY_FAILED.body}</p>
      <p id="apply-failed-code">${APPLY_FAILED.codeLabel}: ${APPLY_FAILED.code}</p>
      <a href="/manage" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="new-code-link">${APPLY_FAILED.primaryLabel}</a>
      <p><a href="${HELP_MAILTO}" class="lp-link" id="apply-failed-help">${APPLY_FAILED.helpLabel}</a></p>
    </div>
  </main>
  <script src="/assets/revocation.js" defer></script>
</body>
</html>
`;
}

/** Estado de error uniforme de la propia pantalla (sesión inexistente o sin R2 verificado):
 * mismo patrón que renderVerifyUniformErrorPage/renderDecisionUniformErrorPage (INV-CM-05). */
export function renderRevocationUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-revocation-page" aria-labelledby="revocation-h1">
    <h1 id="revocation-h1">Confirmar retiro</h1>
    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform">
      ${alertHead("error", "No pudimos continuar con este retiro.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    ${GUEST_HELP_LINK}
  </main>
</body>
</html>
`;
}
