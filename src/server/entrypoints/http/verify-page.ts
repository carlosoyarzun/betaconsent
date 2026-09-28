// Gobierna: UX-CNS-002 (handoff /verify, scratchpad verify-handoff.md), autorización de Carlos
// 2026-09-27 opción (a). specs/state-machines/otp-challenge.spec.yaml V2 (CODE_SENT ->
// CODE_SENT wrong_code), V2r (ResendOtp), V3 (CODE_SENT -> VERIFIED), V4 (-> LOCKED), V5 (->
// EXPIRED); contracts/openapi/consent-it0.openapi.yaml API-CNS-120/121/122;
// contracts/schemas/api-payloads.schema.json OtpVerified/OtpRejected;
// contracts/schemas/common.schema.json ErrorCode. Copy textual exacto del handoff §3, incluidos
// los placeholders "[N] caracteres" (P-01) y "[tiempo pendiente de aprobación]" (P-02): P-01,
// P-02 y P-06 no tienen valor aprobado en SEC-CNS-006 (ver otp-policy.config.ts), así que el
// copy nunca muestra una cifra concreta (INV-OT-01: verificar el canal no es aceptar el
// consentimiento; ningún copy legal en esta pantalla).
//
// Todo el copy es literal y sintético (sin datos reales de canal/colegio/menor), igual que
// welcome-page.ts: no hace falta escapeHtml aquí (nada se interpola dinámicamente).
//
// INV-CM-08 (no transiciona): esta página nunca llama a un puerto de dominio ni muta estado;
// solo lee la sesión ya creada por V1 (otp/request) para decidir si renderiza la pantalla o el
// estado de error uniforme. Las transiciones (submit/resend/request de nuevo código) las
// ejecuta verify.js contra los endpoints HTTP correspondientes.
//
// Fix (Carlos, probado en navegador con dev.ts): #resend-feedback es una región aria-live
// nueva, sin frame/handoff que la defina, para anunciar el resultado de POST /otp/resend
// (202/409) que antes no daba feedback. El texto que usa verify.js ("Te enviamos un nuevo
// código." / mensaje de límite alcanzado) es [UX — borrador], no viene del handoff §3/§6; sin
// cifra concreta (P-06 sin valor aprobado en SEC-CNS-006, igual que el resto del copy de esta
// pantalla). Reportar a ravena-ux para que lo incorpore al handoff/Figma si corresponde.

const HEAD = `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verifica el código · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">`;

export type VerifyScope = "DECISION" | "MANAGE" | "REVOCATION";

/** verify.js redirige aquí tras un V3 correcto, según el scope de la sesión (data-verify-scope). */
const NEXT_ROUTE_BY_SCOPE: Readonly<Record<VerifyScope, string>> = {
  DECISION: "/decision",
  MANAGE: "/manage",
  REVOCATION: "/manage/revocation/confirm",
};

/**
 * Bloque de estado bloqueado (OTP_LOCKED), scope DECISION (Carlos, 2026-09-27): "Solicitar
 * nuevo código". Nunca se muestra en scope REVOCATION/MANAGE (ver renderRightsLockedBlock).
 */
function renderDecisionLockedBlock(): string {
  return `    <div role="alert" aria-live="assertive" id="state-locked" hidden>
      <p>Bloqueamos este código por varios intentos incorrectos.</p>
      <p>Por seguridad, no podemos usarlo de nuevo. Solicita un código nuevo para continuar.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-tap-target" id="request-new-code-btn-locked">Solicitar nuevo código</button>
    </div>
`;
}

/**
 * Bloque de estado bloqueado para scope REVOCATION/MANAGE (33:11, handoff §2/§6): INV-OT-06 —
 * ningún límite de la clase RIGHTS elimina la vía de revocación; NUNCA dice "denegado" ni
 * ofrece "solicitar nuevo código" (V6r/V6c). Las dos vías reales: enviar enlace de recuperación
 * (POST /manage/recovery-link, RV0 fuente BEARER) o abrir un caso con soporte humano (POST
 * /rights-case/open, RC1 fuente BEARER); ambas usan el handle MANAGE_ENTRY, no requieren la
 * sesión MANAGE verificada.
 */
function renderRightsLockedBlock(): string {
  return `    <div role="alert" aria-live="assertive" id="state-locked-rights" tabindex="-1" hidden>
      <p>Bloqueamos este código por varios intentos incorrectos.</p>
      <p>Nunca pierdes la posibilidad de retirar tu consentimiento: elige una opción.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-tap-target" id="send-recovery-link-btn">Enviar enlace de recuperación</button>
      <button type="button" class="lp-btn lp-btn-secondary lp-verify-tap-target" id="open-human-case-btn">Abrir caso con soporte humano</button>
      <div aria-live="polite" role="status" id="rights-locked-feedback" hidden></div>
    </div>
`;
}

/**
 * GET /verify (scope DECISION), /manage/verify (scope MANAGE) y /manage/revocation/verify
 * (scope REVOCATION) con sesión válida (verificationRef ya emitido por V1 del scope
 * correspondiente). Estado por defecto; los demás estados (enviando/incorrecto/expirado/
 * bloqueado/error-red/error-uniforme-inline) los activa verify.js según la respuesta de POST
 * /otp/submit, /otp/resend y /otp/request (handoff §6, tabla estado -> código de error ->
 * texto), parametrizado por `data-verify-scope` (UX-CNS-004 §3, reutiliza esta página y
 * verify.js para las tres variantes en vez de triplicar el HTML/JS).
 */
export function renderVerifyPage(scope: VerifyScope = "DECISION"): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body data-verify-scope="${scope}" data-verify-next="${NEXT_ROUTE_BY_SCOPE[scope]}">
  <main class="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
    <h1 id="verify-h1">Verifica el código</h1>
    <div id="verify-form">
      <p>Enviamos un código a la vía de contacto registrada para continuar. No lo compartas con nadie.</p>
      <div class="lp-form-group" id="verify-form-group">
        <label class="lp-label" for="code-input">Código de verificación</label>
        <input
          class="lp-input lp-verify-code-input"
          id="code-input"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="Ingresa el código"
          aria-describedby="code-help code-error"
          aria-invalid="false"
        />
        <p class="lp-input-help" id="code-help">Ingresa el código de [N] caracteres que enviamos (P-01, valor pendiente de aprobación). El código deja de funcionar después de [tiempo pendiente de aprobación] (P-02).</p>
        <div class="lp-input-error-msg" id="code-error" role="alert" aria-live="assertive" hidden>
          El código ingresado no es correcto. Revísalo e inténtalo nuevamente.
        </div>
      </div>
      <div class="lp-verify-resend">
        <span>¿No recibiste el código?</span> <button type="button" class="lp-link lp-verify-tap-target" id="resend-btn">Reenviar código</button>
      </div>
      <div aria-live="polite" role="status" id="resend-feedback" hidden></div>
      <p>Puedes solicitarlo un número limitado de veces (P-06, valor pendiente de aprobación).</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-cta" id="verify-btn" aria-disabled="false" aria-busy="false">Verificar</button>
    </div>
    <p><a href="mailto:ayuda@example.invalid" class="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a></p>

    <div role="alert" aria-live="assertive" id="state-expired" hidden>
      <p>Este código ya no es válido.</p>
      <p>Puede haber expirado o haberse usado antes. Solicita uno nuevo para continuar.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-tap-target" id="request-new-code-btn-expired">Solicitar nuevo código</button>
    </div>

${scope === "DECISION" ? renderDecisionLockedBlock() : renderRightsLockedBlock()}
    <div role="alert" aria-live="polite" id="error-network" hidden>
      <p>No pudimos conectar.</p>
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" class="lp-btn lp-btn-primary lp-verify-tap-target" id="retry-btn">Reintentar</button>
    </div>

    <div role="alert" aria-live="assertive" id="error-uniform" hidden>
      <p>No pudimos continuar con esta verificación.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
  </main>
  <script src="/assets/verify.js" defer></script>
</body>
</html>
`;
}

/**
 * Estado de error uniforme de la propia pantalla (sesión inexistente, sin verificationRef, o
 * expirada): INV-CM-05, no distingue la causa. Se sirve como el CUERPO de /verify (nunca un 404
 * "crudo" del framework) cuando GET /verify no tiene una sesión con un challenge OTP ya
 * solicitado (V1 previo).
 */
export function renderVerifyUniformErrorPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
  <main class="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
    <h1 id="verify-h1">Verifica el código</h1>
    <div role="alert" aria-live="assertive" id="error-uniform">
      <p>No pudimos continuar con esta verificación.</p>
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </div>
  </main>
</body>
</html>
`;
}
