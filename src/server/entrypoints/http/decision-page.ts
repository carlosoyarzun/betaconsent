// Gobierna: UX-CNS-003 (handoff /decision; frames Figma 24:2/24:64 y estados 27:*; flujo del
// invitado v2, Stitch->DS, frames 106:*, 105:353..507, Carlos 2026-10-14), Carlos eligió la opción
// (b) de relationshipRef (lista de valores permitidos por configuración,
// decision-relationship.config.ts).
//
// GRD-CD-03/LD-06 (texto de consentimiento real, hashes): PENDING, marcador [LEGAL DECISION]
// literal; igual para el enunciado de autoridad (DEC-BR-003/EXT-A/LD-01) y las descripciones de
// finalidad. Ninguno se redacta aquí (CLAUDE.md: nunca se edita copy legal de producción; el
// texto real lo sirve el servidor, GRD-CD-03). Todo el copy narrativo restante es [UX — borrador],
// sintético, sin PII.
//
// Nada preseleccionado (ni "Sí, es correcto", ni autoridad, ni finalidades): chips con
// aria-checked="false", casilla sin `checked`, select con opción deshabilitada (F-STITCH-03).
// Acepto / No acepto con el mismo peso visual (F-STITCH-19).
//
// D-02: referencia sintética del estudiante ("Alumno de prueba N") solo lectura, la aporta el
// servidor (resolveSubjectLabel); sin ella la sección sigue siendo la confirmación genérica.
// D-06: "No es mi estudiante" -> POST /decision/subject-mismatch (API-CNS-128, I9) desde un
// botón explícito; nunca por el solo hecho de elegir la opción.
//
// decision.js orquesta la secuencia de POST /decision/steps + POST /decision/submit; esta
// página nunca llama un puerto de dominio (INV-CM-08): solo lee la sesión ya verificada por V3.
// El texto de consentimiento se renderiza directo en el HTML (mismo ServedConsentVersion que
// GRD-CD-03) sin emitir CONSENT_VERSION_VIEWED en el GET.

import { alertHead, escapeHtml, GUEST_HELP_LINK, guestHead, guestHeader, renderStepper } from "./guest-layout.ts";
import { PURPOSES, type PurposeCopy } from "./guest-purposes.ts";
import type { ServedConsentVersion } from "./served-consent-version.ts";

const HEAD = guestHead("Revisa y decide");

function renderPurposeSection(p: PurposeCopy, index: number): string {
  return `    <div class="lp-decision-purpose" data-purpose="${p.purpose}" id="purpose-${p.purpose}">
      <h3>${index + 1}. ${escapeHtml(p.title)}</h3>
      <p>${escapeHtml(p.description)}</p>
      <p class="lp-legal-note">[LEGAL DECISION — descripción de finalidad, borrador UX grounded en el protocolo; texto legal definitivo pendiente de aprobación de Carlos]</p>
      <div class="lp-decision-chip-pair lp-decision-group" role="radiogroup" aria-label="${escapeHtml(p.title)}" aria-describedby="err-${p.purpose}">
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" data-purpose-choice="${p.purpose}" data-choice="GRANT">Acepto</button>
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" data-purpose-choice="${p.purpose}" data-choice="DECLINE">No acepto</button>
      </div>
      <p class="lp-field-error" id="err-${p.purpose}" hidden><span aria-hidden="true">⚠ </span>Elige una opción.</p>
    </div>
`;
}

function registeredStateBlock(kind: "granted" | "declined"): string {
  const granted = kind === "granted";
  return `    <div role="status" aria-live="polite" id="state-${kind}" hidden>
      ${renderStepper(3)}
      <span class="lp-hero-icon" aria-hidden="true">${granted ? "✓" : "•"}</span>
      <h1 id="${kind}-heading" tabindex="-1">${granted ? "Listo, registramos tu decisión" : "Registramos tu decisión"}</h1>
      ${granted ? "<p>Colegio Ejemplo — Estudio Beta de LectorPro.</p>" : "<p>El estudiante no participará en el Estudio Beta.</p><p class=\"lp-legal-note\">[LEGAL DECISION — efecto de no aceptar una finalidad obligatoria (Q-13): copy pendiente de aprobación de Carlos]</p>"}
      <section class="lp-card lp-card-default" aria-labelledby="${kind}-receipt-h2">
        <h2 id="${kind}-receipt-h2">Comprobante</h2>
        <p class="lp-receipt-ref" id="${kind}-receipt"></p>
        <div class="lp-badge-row">
          <span class="lp-badge lp-badge-success">Registrado</span>
          <span class="lp-badge lp-badge-warning">Marca de agua IT0 · comprobante de prueba</span>
        </div>
      </section>
      <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="${kind}-next-h2">
        <h2 id="${kind}-next-h2">Qué pasa ahora</h2>
        <ul class="lp-next-steps">
          <li><strong>Comprobante</strong>Te enviaremos el comprobante de tu decisión a la vía de contacto ya verificada.</li>
${granted ? `          <li><strong>Gestionar o retirar tu decisión</strong>Te enviaremos aparte el enlace para gestionarla o retirarla, solo a esa vía de contacto. Nunca lo mostramos aquí.</li>
` : ""}          <li><strong>Puedes cerrar esta ventana</strong>No necesitas hacer nada más aquí.</li>
        </ul>
      </section>
    </div>
`;
}

/**
 * GET /decision con sesión verificada (post-V3, session.decisionMakerRef). `relationshipRefs`
 * viene de la MISMA config que valida el servidor (GRD-CD-04): nunca una lista inventada en el
 * HTML. `servedVersion` es el MISMO `ServedConsentVersion` que devuelve POST /decision/steps
 * CONSENT_VERSION_VIEWED (GRD-CD-03). `subjectLabel` (D-02) es la etiqueta sintética de solo
 * lectura "Alumno de prueba N" (ya validada por el borde contra SUBJECT_LABEL_PATTERN).
 */
export function renderDecisionPage(
  relationshipRefs: readonly string[],
  servedVersion: ServedConsentVersion,
  subjectLabel?: string,
): string {
  const relationshipOptions = relationshipRefs
    .map((ref) => `<option value="${escapeHtml(ref)}">${escapeHtml(ref)}</option>`)
    .join("\n          ");
  const subjectRef = subjectLabel
    ? `<p class="lp-decision-subject-ref" id="subject-ref">${escapeHtml(subjectLabel)} · Colegio Ejemplo</p>`
    : "";

  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
    <div id="decision-form">
    ${renderStepper(2)}
    <h1 id="decision-h1">Revisa y decide</h1>
    <p>Colegio Ejemplo — Estudio Beta de LectorPro. Estás revisando esta decisión para el estudiante.</p>

    <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="consent-text-h2">
      <h2 id="consent-text-h2">Texto del consentimiento</h2>
      <p class="lp-input-help" id="consent-version-help">Versión vigente del texto: ${escapeHtml(servedVersion.consentVersion)} · Aviso de privacidad: ${escapeHtml(servedVersion.privacyNoticeVersion)}</p>
      <div class="lp-decision-legal-box" id="consent-text-box">${escapeHtml(servedVersion.text)}</div>
    </section>

    <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="subject-h2">
      <h2 id="subject-h2">¿Es tu estudiante?</h2>
      ${subjectRef}
      <p>Confirma que estás decidiendo por el estudiante correcto antes de continuar.</p>
      <div class="lp-decision-chip-pair lp-decision-group" role="radiogroup" aria-labelledby="subject-h2" aria-describedby="err-subject" id="subject-radiogroup">
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" id="subject-yes" data-value="yes">Sí, es correcto</button>
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" id="subject-no" data-value="no">No es mi estudiante</button>
      </div>
      <p class="lp-field-error" id="err-subject" hidden><span aria-hidden="true">⚠ </span>Elige una opción.</p>
      <div role="alert" aria-live="assertive" class="lp-alert-warning" id="subject-mismatch-note" hidden>
        ${alertHead("warning", "No podemos continuar si no es tu estudiante.")}
        <p>Puedes avisarnos para que cancelemos esta invitación, o escribirnos a <a href="mailto:ayuda@example.invalid" class="lp-link">ayuda@example.invalid</a> para revisar tu caso.</p>
        <button type="button" class="lp-btn lp-btn-outline lp-cta" id="report-mismatch-btn" aria-disabled="false" aria-busy="false">Informar que no es mi estudiante</button>
      </div>
    </section>

    <div id="decision-rest">
    <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="authority-h2">
      <h2 id="authority-h2">Tu autoridad para decidir</h2>
      <div class="lp-form-group">
        <label class="lp-label" for="relationship-select">¿Cuál es tu relación con el estudiante?</label>
        <select class="lp-input lp-decision-relationship-select" id="relationship-select" aria-describedby="relationship-help err-relationship" aria-invalid="false">
          <option value="" selected disabled>Selecciona una opción</option>
          ${relationshipOptions}
        </select>
        <p class="lp-legal-note" id="relationship-help">[LEGAL DECISION — enum de relación pendiente de DEC-BR-003 / EXT-A / LD-01; opción (b) de Carlos: lista de valores por configuración]</p>
        <p class="lp-field-error" id="err-relationship" hidden><span aria-hidden="true">⚠ </span>Elige una opción.</p>
      </div>
      <label class="lp-decision-checkbox-row" for="authority-declared">
        <input type="checkbox" id="authority-declared" class="lp-decision-checkbox" aria-labelledby="authority-declared-label" aria-describedby="err-authority" />
        <span id="authority-declared-label">[LEGAL DECISION — enunciado de autoridad pendiente de DEC-BR-003 / EXT-A / LD-01] Declaro que tengo la autoridad para tomar esta decisión por el estudiante.</span>
      </label>
      <p class="lp-field-error" id="err-authority" hidden><span aria-hidden="true">⚠ </span>Marca la casilla para continuar.</p>
    </section>

    <section class="lp-card lp-card-default lp-decision-section" aria-labelledby="purposes-h2">
      <h2 id="purposes-h2">Finalidades</h2>
      <p class="lp-legal-note">[LEGAL DECISION — carácter obligatorio de las 4 finalidades y consecuencia de no aceptar alguna: copy pendiente de aprobación de Carlos]</p>
      <p>Las 4 finalidades son necesarias para participar en el Estudio Beta. Si no aceptas alguna, el estudiante no participará.</p>
      <p class="lp-legal-note">[LEGAL DECISION — las descripciones de cada finalidad son borrador UX; texto legal definitivo pendiente de aprobación de Carlos]</p>
${PURPOSES.map(renderPurposeSection).join("")}    </section>

    <div role="status" aria-live="polite" class="lp-alert-info" id="decline-notice" hidden>
      ${alertHead("info", "Elegiste no aceptar al menos una finalidad.")}
      <p>Al enviar, registraremos que el estudiante no participará en el Estudio Beta.</p>
      <p class="lp-legal-note">[LEGAL DECISION — efecto de no aceptar una finalidad (Q-13): copy pendiente de aprobación de Carlos]</p>
    </div>

    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-validation" tabindex="-1" hidden>
      ${alertHead("error", "Falta completar algo antes de enviar.")}
      <p id="error-validation-detail">Revisa las secciones marcadas y vuelve a intentarlo.</p>
      <ul class="lp-error-list" id="error-validation-list"></ul>
    </div>

    <div class="lp-decision-submit-row">
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-decision-cta" id="submit-btn" aria-disabled="true" aria-busy="false">Enviar decisión</button>
      <p role="status" aria-live="polite" id="submit-helper">Completa todas las secciones para continuar.</p>
    </div>
    </div>
    ${GUEST_HELP_LINK}
    </div>

    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-conflict" hidden>
      ${alertHead("error", "No pudimos registrar esta decisión.")}
      <p id="error-conflict-detail">Esta decisión ya no está disponible para cambios. Si crees que esto es un error, contáctanos.</p>
    </div>

    <div role="alert" aria-live="polite" class="lp-alert-warning" id="error-network" hidden>
      ${alertHead("warning", "No pudimos conectar.")}
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-cta lp-decision-cta" id="retry-btn">Reintentar</button>
    </div>

    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform" hidden>
      ${alertHead("error", "No pudimos continuar con esta decisión.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>

${registeredStateBlock("granted")}
${registeredStateBlock("declined")}
    <div role="status" aria-live="polite" id="state-mismatch" hidden>
      <span class="lp-hero-icon" aria-hidden="true">•</span>
      <h1 id="mismatch-heading" tabindex="-1">Registramos tu aviso</h1>
      <p>Cancelamos esta invitación.</p>
      <p>Indicaste que no es tu estudiante. No se registró ninguna decisión.</p>
      <p>Puedes cerrar esta ventana.</p>
    </div>
  </main>
  <script src="/assets/decision.js" defer></script>
</body>
</html>
`;
}

/**
 * Estado de error uniforme de la propia pantalla (sesión inexistente o sin verificar, V3
 * pendiente, o invitación cancelada): mismo patrón que renderVerifyUniformErrorPage/
 * renderWelcomeUniformErrorPage (INV-CM-05, no distingue la causa).
 */
export function renderDecisionUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-guest-body">
  ${guestHeader()}
  <main class="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
    <h1 id="decision-h1">Revisa y decide</h1>
    <div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform">
      ${alertHead("error", "No pudimos continuar con esta decisión.")}
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
    ${GUEST_HELP_LINK}
  </main>
</body>
</html>
`;
}
