// Gobierna: UX-CNS-004 (handoff revocation-handoff.md §2/§3, frames 33:2 manage/entrada y
// 33:21 manage/estado), contracts/openapi/consent-it0.openapi.yaml API-CNS-102 (GET
// /m/{token}), specs/state-machines/revocation.spec.yaml managementLink (CFG-RV-MANAGEMENT-
// LINK, GRD-RV-20: "sin estado ni finalidades visibles" antes de la verificación MANAGE).
//
// Una sola ruta GET /manage sirve dos contenidos según el estado de la sesión (INV-CM-08: un
// GET nunca transiciona, solo lee la sesión): sin manageDecisionMakerRef -> entrada (33:2, sin
// estado ni finalidades, CTA "Verificar mi identidad" -> V1 scope MANAGE -> /manage/verify);
// con manageDecisionMakerRef (post V3 MANAGE) -> estado (33:21, CTA "Retirar mi consentimiento"
// -> R1 -> V1 scope REVOCATION -> /manage/revocation/verify).
//
// Todo el copy narrativo es [UX — borrador], sintético, sin PII (mismo patrón que
// welcome-page.ts/decision-page.ts). La frase de alcance del retiro lleva el marcador
// [LEGAL DECISION] literal y VISIBLE como texto (Carlos, 2026-09-28, handoff §8; fix Carlos,
// revisión en navegador con dev.ts: no puede ir dentro de un comentario HTML `<!-- -->`, porque
// el usuario nunca lo vería): no se redacta aquí (CLAUDE.md, copy legal de producción).

import { alertHead, GUEST_HELP_LINK, guestHead, guestHeader } from "./guest-layout.ts";

const HEAD = guestHead("Tu consentimiento");

/** Alertas de red/uniforme compartidas por las pantallas de gestión (UX-CNS-004, kit v2). */
const NETWORK_ALERT = `<div role="alert" aria-live="polite" class="lp-alert-warning" id="error-network" hidden>
      ${alertHead("warning", "No pudimos conectar.")}
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="retry-btn">Reintentar</button>
    </div>`;
const UNIFORM_ALERT = `<div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform" hidden>
      ${alertHead("error", "No pudimos continuar.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>`;

/** GET /manage sin sesión MANAGE verificada (33:2 manage/entrada). */
export function renderManageEntryPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
    <h1 id="manage-h1">Tu consentimiento</h1>
    <section class="lp-card lp-card-default">
      <p>Antes de mostrarte cualquier información, necesitamos verificar tu identidad con un código.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="start-verify-btn" aria-disabled="false" aria-busy="false">Verificar mi identidad</button>
    </section>
    ${GUEST_HELP_LINK}

    ${NETWORK_ALERT}

    ${UNIFORM_ALERT}
  </main>
  <script src="/assets/manage.js" defer></script>
</body>
</html>
`;
}

/** GET /manage con sesión MANAGE verificada (33:21 manage/estado). */
export function renderManageStatusPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
    <h1 id="manage-h1">Tu consentimiento</h1>
    <section class="lp-card-default lp-manage-status" role="status" aria-live="polite">
      <p><span class="lp-badge lp-badge-success">Consentimiento otorgado</span></p>
      <p>Colegio Ejemplo — Estudio Beta de LectorPro.</p>
      <p>Finalidades otorgadas:</p>
      <ul class="lp-purpose-list">
        <li><span aria-hidden="true">✓ </span>Participar en el Estudio Beta</li>
        <li><span aria-hidden="true">✓ </span>Grabación de audio</li>
        <li><span aria-hidden="true">✓ </span>Análisis automatizado</li>
        <li><span aria-hidden="true">✓ </span>Revisión humana</li>
      </ul>
      <p>Puedes retirar tu consentimiento en cualquier momento.</p>
      <p class="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial), protocolo l.423]</p>
    </section>
    <div class="lp-actions-stack">
      <button type="button" class="lp-btn lp-btn-danger lp-cta lp-revocation-cta lp-verify-tap-target" id="start-revocation-btn" aria-disabled="false" aria-busy="false">Retirar mi consentimiento</button>
    </div>
    ${GUEST_HELP_LINK}

    ${NETWORK_ALERT}

    ${UNIFORM_ALERT}
  </main>
  <script src="/assets/manage.js" defer></script>
</body>
</html>
`;
}

/** GET /manage con sesión MANAGE verificada y la decisión ya REVOKED (C6, INV-5). Frame Figma
 * 73:2 manage/mobile/ya-retirado (aprobado por Carlos, 2026-09-28). Neutro: sin fecha de
 * retiro, sin colegio ni estudio (no recibe datos del dominio), sin CTA de retirar ni de volver
 * a consentir. "Contactar a soporte" es el mismo mailto de ayuda que 59:3 y NO abre un caso RC1.
 * El marcador [LEGAL DECISION] es el mismo literal que usa el comprobante de retiro. */
export function renderManageRevokedPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
    <h1 id="manage-h1">Tu consentimiento</h1>
    <section class="lp-card-default lp-manage-status" role="status" aria-live="polite" id="manage-revoked">
      <p><strong>Tu consentimiento ya fue retirado.</strong></p>
      <p>No necesitas hacer nada más. Ya no hay una acción de retiro pendiente en este enlace.</p>
      <p class="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
    </section>
    <div class="lp-actions-stack">
      <a href="mailto:ayuda@example.invalid" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="contact-support-btn">Contactar a soporte</a>
    </div>
    ${GUEST_HELP_LINK}
  </main>
</body>
</html>
`;
}

/** Estado de error uniforme (handle inexistente/rotado/usado/vencido, GRD-CM-01): mismo patrón
 * que renderVerifyUniformErrorPage/renderWelcomeUniformErrorPage (INV-CM-05). Frame 59:3
 * (Carlos, 2026-09-28): copy propio de esta pantalla, distinto del de /welcome (9:12). El botón
 * "Contactar a soporte" es un enlace con estilo de botón (opción b de Carlos) al mismo contacto
 * de ayuda que usa el resto del sitio; NO abre un caso RC1 (intake sin enlace diferido). */
export function renderManageUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
    <h1 id="manage-h1">Gestiona tu consentimiento</h1>
    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform">
      ${alertHead("error", "Este enlace ya no está disponible.")}
      <p>Puede que ya no sea válido. Esto no significa que se haya perdido tu posibilidad de gestionar tu consentimiento.</p>
    </div>
    <div class="lp-actions-stack">
      <a href="mailto:ayuda@example.invalid" class="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="contact-support-btn">Contactar a soporte</a>
    </div>
    ${GUEST_HELP_LINK}
  </main>
</body>
</html>
`;
}
