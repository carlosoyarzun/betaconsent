// Gobierna: UX-CNS-003 (handoff /decision, scratchpad decision-handoff.md, ravena-ux
// 2026-09-27; frames Figma 24:2/24:64 default, 27:8/17/25/33/39/49/58/64 estados), Carlos
// aprobó los frames y eligió la opción (b) de relationshipRef (lista de valores permitidos por
// configuración, decision-relationship.config.ts). Reemplaza el placeholder mínimo anterior
// (renderDecisionPlaceholderPage, CLAUDE.md, Carlos 2026-09-27).
//
// GRD-CD-03/LD-06 (texto de consentimiento real, hashes): PENDING, marcador [LEGAL DECISION]
// literal (handoff §3.1); igual para el enunciado de autoridad (§3.2, DEC-BR-003/EXT-A/LD-01) y
// las descripciones de finalidad (§3.3). Ninguno de los tres se redacta aquí (CLAUDE.md: nunca
// se edita copy legal de producción, y este archivo no es ese lugar de todos modos: el texto
// real lo sirve el servidor vía POST /decision/steps CONSENT_VERSION_VIEWED, GRD-CD-03).
//
// Todo el copy narrativo restante es [UX — borrador], sintético, sin PII (mismo patrón que
// welcome-page.ts / verify-page.ts).
//
// decision.js orquesta la secuencia de POST /decision/steps + POST /decision/submit; esta
// página nunca llama un puerto de dominio (INV-CM-08 aplicado por analogía: solo lee la sesión
// ya verificada por V3 para decidir si renderiza la pantalla o el estado de error uniforme).
//
// x-scope-note (reportado a Carlos): "No es mi estudiante" no dispara POST
// /decision/subject-mismatch (API-CNS-128) en este slice — esa ruta no está implementada
// todavía (fuera de alcance de CA-116 /decision). El chip "No es mi estudiante" solo bloquea el
// envío y muestra el aviso de ayuda; no cancela la invitación (I9) del lado servidor. Pendiente
// para un slice siguiente.
//
// Fix (Carlos, revisión en navegador con dev.ts, 2026-09-2x): el texto de consentimiento
// quedaba en "cargando…" hasta que el usuario completaba el primer paso (efecto de la primera
// llamada a POST /decision/steps), es decir después de interactuar. GRD-CD-03
// (specs/state-machines/consent-decision.spec.yaml:286-291, "el servidor sirve el texto de la
// versión en vigor") no exige que ese servido ocurra por POST: aquí se renderiza el MISMO
// `ServedConsentVersion` (served-consent-version.ts) directamente en el HTML de GET /decision,
// sin llamar recordDecisionStep ni emitir CONSENT_VERSION_VIEWED (INV-CM-08, common.spec.yaml:
// un GET nunca transiciona). El evento de ledger sigue emitiéndose solo por el POST /decision/
// steps que decision.js dispara antes de enviar (C2 sigue registrado normalmente).

import type { ServedConsentVersion } from "./served-consent-version.ts";

const HEAD = `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Revisa y decide · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

interface PurposeCopy {
  readonly purpose: string;
  readonly title: string;
  readonly description: string;
}

// [UX — borrador] grounding en docs/LectorPro_Estudio_Beta_Protocolo_y_Metodologia_v1.0.md
// (handoff §3, cita por finalidad); redacción final de cada descripción sigue [LEGAL DECISION].
const PURPOSES: readonly PurposeCopy[] = [
  {
    purpose: "STUDY_PARTICIPATION",
    title: "Participar en el Estudio Beta",
    description: "Tu hija o hijo participaría en sesiones de lectura del Estudio Beta de LectorPro.",
  },
  {
    purpose: "AUDIO_RECORDING",
    title: "Grabación de audio",
    description: "Se grabaría el audio de las sesiones de lectura para poder analizarlas.",
  },
  {
    purpose: "AUTOMATED_ANALYSIS",
    title: "Análisis automatizado",
    description: "El audio se analizaría con un motor automatizado de lectura.",
  },
  {
    purpose: "HUMAN_REVIEW",
    title: "Revisión humana",
    description: "Una persona revisaría una muestra de los resultados para validar el análisis automatizado.",
  },
];

function renderPurposeSection(p: PurposeCopy): string {
  return `    <div class="lp-decision-purpose" data-purpose="${p.purpose}">
      <h3>${escapeHtml(p.title)}</h3>
      <p>[LEGAL DECISION — descripción de finalidad, borrador UX grounded en el protocolo; texto legal definitivo pendiente de aprobación de Carlos, handoff §3.3] ${escapeHtml(p.description)}</p>
      <div class="lp-decision-chip-pair" role="radiogroup" aria-label="${escapeHtml(p.title)}">
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" data-purpose-choice="${p.purpose}" data-choice="GRANT">Acepto</button>
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" data-purpose-choice="${p.purpose}" data-choice="DECLINE">No acepto</button>
      </div>
    </div>
`;
}

/**
 * GET /decision con sesión verificada (post-V3, session.decisionMakerRef). `relationshipRefs`
 * viene de la MISMA config que valida el servidor (GRD-CD-04, decision-relationship.config.ts,
 * opción b de Carlos): nunca una lista distinta inventada en el HTML. `servedVersion` es el
 * MISMO `ServedConsentVersion` (served-consent-version.ts) que devuelve POST /decision/steps
 * CONSENT_VERSION_VIEWED (GRD-CD-03): se renderiza ya resuelto, sin esperar esa llamada.
 */
export function renderDecisionPage(relationshipRefs: readonly string[], servedVersion: ServedConsentVersion): string {
  const relationshipOptions = relationshipRefs
    .map((ref) => `<option value="${escapeHtml(ref)}">${escapeHtml(ref)}</option>`)
    .join("\n        ");

  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
    <h1 id="decision-h1">Revisa y decide</h1>
    <p>Colegio Ejemplo — Estudio Beta de LectorPro. Estás revisando esta decisión para tu hija o hijo.</p>

    <div id="decision-form">
    <section class="lp-card-default lp-decision-section" aria-labelledby="consent-text-h2">
      <h2 id="consent-text-h2">Texto del consentimiento</h2>
      <p class="lp-input-help" id="consent-version-help">Versión vigente del texto: ${escapeHtml(servedVersion.consentVersion)} · Aviso de privacidad: ${escapeHtml(servedVersion.privacyNoticeVersion)}</p>
      <div class="lp-decision-legal-box" id="consent-text-box">${escapeHtml(servedVersion.text)}</div>
    </section>

    <section class="lp-card-default lp-decision-section" aria-labelledby="subject-h2">
      <h2 id="subject-h2">¿Es tu estudiante?</h2>
      <p>Confirma que estás decidiendo por el estudiante correcto antes de continuar.</p>
      <div class="lp-decision-chip-pair" role="radiogroup" aria-labelledby="subject-h2" id="subject-radiogroup">
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" id="subject-yes" data-value="yes">Sí, es correcto</button>
        <button type="button" class="lp-decision-chip" role="radio" aria-checked="false" id="subject-no" data-value="no">No es mi estudiante</button>
      </div>
      <div role="alert" aria-live="assertive" id="subject-mismatch-note" hidden>
        <p>No podemos continuar si no es tu estudiante. Escríbenos a <a href="mailto:ayuda@example.invalid" class="lp-link">ayuda@example.invalid</a> para revisar tu caso.</p>
      </div>
    </section>

    <section class="lp-card-default lp-decision-section" aria-labelledby="authority-h2">
      <h2 id="authority-h2">Tu autoridad para decidir</h2>
      <div class="lp-form-group">
        <label class="lp-label" for="relationship-select">¿Cuál es tu relación con el estudiante?</label>
        <select class="lp-input lp-decision-relationship-select" id="relationship-select" aria-describedby="relationship-help">
          <option value="" selected disabled>Selecciona una opción</option>
          ${relationshipOptions}
        </select>
        <p class="lp-input-help" id="relationship-help">[LEGAL DECISION — enum de relación pendiente de DEC-BR-003 / EXT-A / LD-01; opción (b) de Carlos: lista de valores por configuración]</p>
      </div>
      <label class="lp-decision-checkbox-row" for="authority-declared">
        <input type="checkbox" id="authority-declared" class="lp-decision-checkbox" />
        <span>[LEGAL DECISION — enunciado de autoridad pendiente de DEC-BR-003 / EXT-A / LD-01] Declaro que tengo la autoridad para tomar esta decisión por el estudiante.</span>
      </label>
    </section>

    <section class="lp-card-default lp-decision-section" aria-labelledby="purposes-h2">
      <h2 id="purposes-h2">Finalidades</h2>
      <p>Las 4 finalidades son necesarias para participar en el Estudio Beta. Si rechazas alguna, tu hija o hijo no participará.</p>
      <p class="lp-decision-legal-note">[LEGAL DECISION — las descripciones de cada finalidad son borrador UX; texto legal definitivo pendiente de aprobación de Carlos]</p>
${PURPOSES.map(renderPurposeSection).join("")}    </section>

    <button type="button" class="lp-btn lp-btn-primary lp-decision-cta" id="submit-btn" aria-disabled="true" aria-busy="false">Enviar decisión</button>
    <p role="status" aria-live="polite" id="submit-helper">Completa todas las secciones para continuar.</p>
    </div>
    <p>¿Necesitas ayuda? Escríbenos a <a href="mailto:ayuda@example.invalid" class="lp-link">ayuda@example.invalid</a></p>

    <div role="alert" aria-live="assertive" id="error-validation" hidden>
      <p>Falta completar algo antes de enviar.</p>
      <p id="error-validation-detail">Revisa las secciones marcadas y vuelve a intentarlo.</p>
    </div>

    <div role="alert" aria-live="assertive" id="error-conflict" hidden>
      <p>No pudimos registrar esta decisión.</p>
      <p id="error-conflict-detail">Esta decisión ya no está disponible para cambios. Si crees que esto es un error, contáctanos.</p>
    </div>

    <div role="alert" aria-live="polite" id="error-network" hidden>
      <p>No pudimos conectar.</p>
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-decision-cta" id="retry-btn">Reintentar</button>
    </div>

    <div role="alert" aria-live="assertive" id="error-uniform" hidden>
      <p>No pudimos continuar con esta decisión.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>

    <div role="status" aria-live="polite" id="state-granted" hidden>
      <h2 id="granted-heading" tabindex="-1">Listo, registramos tu decisión</h2>
      <p id="granted-receipt"></p>
      <p>Nunca te mostraremos aquí el enlace para gestionar esta decisión: lo enviamos solo a la vía de contacto ya verificada.</p>
    </div>

    <div role="status" aria-live="polite" id="state-declined" hidden>
      <h2 id="declined-heading" tabindex="-1">Registramos tu decisión</h2>
      <p id="declined-receipt"></p>
      <p>Tu hija o hijo no participará en el Estudio Beta.</p>
    </div>
  </main>
  <script src="/assets/decision.js" defer></script>
</body>
</html>
`;
}

/**
 * Estado de error uniforme de la propia pantalla (sesión inexistente o sin verificar, V3
 * pendiente): mismo patrón que renderVerifyUniformErrorPage/renderWelcomeUniformErrorPage
 * (INV-CM-05, no distingue la causa).
 */
export function renderDecisionUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
    <h1 id="decision-h1">Revisa y decide</h1>
    <div role="alert" aria-live="assertive" id="error-uniform">
      <p>No pudimos continuar con esta decisión.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
  </main>
</body>
</html>
`;
}
