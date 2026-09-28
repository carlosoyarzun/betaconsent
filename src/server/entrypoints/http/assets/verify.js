// JS mínimo de /verify, sin librerías, servido como estático (UX-CNS-002 handoff, Carlos
// 2026-09-27). Mismo patrón CSRF double-submit que welcome.js (GRD-CM-10): la cookie
// __Host-cns-csrf (sin HttpOnly, fijada por GET /verify vía csrf.ts) se copia al header
// x-csrf-token; el servidor solo compara igualdad byte a byte (guards.ts).
//
// "Solicitar nuevo código" (estados expirado/bloqueado, SOLO scope DECISION) llama POST
// /otp/request: la spec (specs/state-machines/otp-challenge.spec.yaml V1, GRD-OT-08
// single_active_challenge_bound_to_handle) hace que un V1 repetido desde el mismo handle/sesión
// reemplace el challenge existente (LOCKED/EXPIRED no cuentan como "activo") con uno nuevo
// (CODE_SENT, attempts=0), sujeto a presupuesto (V6/V6a); no crea una invitación ni un endpoint
// distinto.
//
// Fix (Carlos, probado en navegador con dev.ts): "Reenviar código" no daba feedback en 202 y
// dejaba visible el error previo ("El código ingresado no es correcto…"). Ahora, en 202, limpia
// el error del campo (aria-invalid, code-error) y anuncia un mensaje neutro por #resend-feedback
// (aria-live=polite); en 409 OTP_RESEND_LIMIT muestra un mensaje de límite alcanzado, sin cifra
// (P-06 sin valor aprobado en SEC-CNS-006). Copy [UX — borrador], sin frame/handoff que lo fije.
//
// CA-116 (revocación IT0, UX-CNS-004): esta misma página/script sirve también scope MANAGE
// (/manage/verify) y REVOCATION (/manage/revocation/verify), vía `data-verify-scope` en <body>
// (verify-page.ts). Tras un V3 correcto redirige a `data-verify-next` (scope-dependiente) en
// vez del "/decision" fijo. En estado bloqueado (OTP_LOCKED) con scope MANAGE/REVOCATION,
// INV-OT-06 exige NUNCA ofrecer "solicitar nuevo código": en su lugar se muestra
// #state-locked-rights con dos POST reales del contrato (RV0 fuente BEARER y RC1 fuente
// BEARER), nunca "denegado".
(function () {
  "use strict";

  var CSRF_COOKIE_NAME = "__Host-cns-csrf";
  var CSRF_HEADER_NAME = "x-csrf-token";

  function readCookie(name) {
    var parts = document.cookie ? document.cookie.split(";") : [];
    for (var i = 0; i < parts.length; i += 1) {
      var part = parts[i].trim();
      var eq = part.indexOf("=");
      if (eq === -1) continue;
      if (part.slice(0, eq) === name) {
        return decodeURIComponent(part.slice(eq + 1));
      }
    }
    return null;
  }

  function postJson(path, body) {
    var csrf = readCookie(CSRF_COOKIE_NAME);
    var headers = { "content-type": "application/json" };
    if (csrf) headers[CSRF_HEADER_NAME] = csrf;
    return fetch(path, { method: "POST", headers: headers, body: JSON.stringify(body || {}), credentials: "same-origin" });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var scope = document.body.getAttribute("data-verify-scope") || "DECISION";
    var nextRoute = document.body.getAttribute("data-verify-next") || "/decision";
    var isRights = scope === "MANAGE" || scope === "REVOCATION";

    var verifyBtn = document.getElementById("verify-btn");
    var codeInput = document.getElementById("code-input");
    var codeError = document.getElementById("code-error");
    var resendBtn = document.getElementById("resend-btn");
    var requestNewCodeExpired = document.getElementById("request-new-code-btn-expired");
    var requestNewCodeLocked = document.getElementById("request-new-code-btn-locked");
    var stateExpired = document.getElementById("state-expired");
    var stateLocked = document.getElementById("state-locked");
    var stateLockedRights = document.getElementById("state-locked-rights");
    var sendRecoveryLinkBtn = document.getElementById("send-recovery-link-btn");
    var openHumanCaseBtn = document.getElementById("open-human-case-btn");
    var rightsLockedFeedback = document.getElementById("rights-locked-feedback");
    var errorNetwork = document.getElementById("error-network");
    var errorUniform = document.getElementById("error-uniform");
    var retryBtn = document.getElementById("retry-btn");
    var resendFeedback = document.getElementById("resend-feedback");
    if (!verifyBtn || !codeInput) return;

    var busy = false;
    var verifyLabel = verifyBtn.textContent;
    var lastAction = null; // reintentado por el botón "Reintentar" (error de red)

    function hideStates() {
      if (codeError) codeError.hidden = true;
      if (stateExpired) stateExpired.hidden = true;
      if (stateLocked) stateLocked.hidden = true;
      if (stateLockedRights) stateLockedRights.hidden = true;
      if (errorNetwork) errorNetwork.hidden = true;
      if (errorUniform) errorUniform.hidden = true;
      if (resendFeedback) {
        resendFeedback.hidden = true;
        resendFeedback.textContent = "";
      }
      codeInput.setAttribute("aria-invalid", "false");
    }

    function showResendFeedback(message) {
      hideStates();
      if (resendFeedback) {
        resendFeedback.textContent = message;
        resendFeedback.hidden = false;
      }
    }

    function setBusy(isBusy) {
      busy = isBusy;
      verifyBtn.setAttribute("aria-disabled", isBusy ? "true" : "false");
      verifyBtn.setAttribute("aria-busy", isBusy ? "true" : "false");
      verifyBtn.textContent = isBusy ? "Verificando…" : verifyLabel;
    }

    function showCodeRejected() {
      hideStates();
      codeInput.setAttribute("aria-invalid", "true");
      if (codeError) codeError.hidden = false;
    }

    function showExpired() {
      hideStates();
      if (stateExpired) stateExpired.hidden = false;
    }

    function showLocked() {
      hideStates();
      // INV-OT-06: scope MANAGE/REVOCATION nunca ofrece "solicitar nuevo código"; siempre
      // RECOVERY (RV0) y caso humano (RC1), nunca "denegado".
      if (isRights) {
        if (stateLockedRights) stateLockedRights.hidden = false;
      } else if (stateLocked) {
        stateLocked.hidden = false;
      }
    }

    function showNetworkError() {
      hideStates();
      if (errorNetwork) errorNetwork.hidden = false;
    }

    function showUniformError() {
      hideStates();
      if (errorUniform) errorUniform.hidden = false;
    }

    function handleOtpRejected(code) {
      if (code === "OTP_LOCKED") {
        showLocked();
      } else if (code === "OTP_EXPIRED_OR_CONSUMED") {
        showExpired();
      } else {
        // OTP_CODE_REJECTED por defecto: no revela intentos restantes (V2, ERR-OT-02).
        showCodeRejected();
      }
    }

    function submitCode() {
      if (busy) return;
      lastAction = submitCode;
      hideStates();
      setBusy(true);
      postJson("/otp/submit", { code: codeInput.value })
        .then(function (res) {
          setBusy(false);
          if (res.status === 200) {
            window.location.assign(nextRoute);
            return null;
          }
          if (res.status === 404) {
            showUniformError();
            return null;
          }
          return res.json().catch(function () {
            return {};
          });
        })
        .then(function (body) {
          if (body && typeof body.code === "string") handleOtpRejected(body.code);
        })
        .catch(function () {
          setBusy(false);
          showNetworkError();
        });
    }

    function requestNewCode() {
      if (busy) return;
      lastAction = requestNewCode;
      hideStates();
      setBusy(true);
      postJson("/otp/request")
        .then(function (res) {
          setBusy(false);
          if (res.status === 404) {
            showUniformError();
            return;
          }
          // 202 UniformAccepted: nuevo challenge emitido (V1, GRD-OT-08); el usuario ingresa
          // el código nuevo en el mismo campo.
          codeInput.value = "";
          codeInput.focus();
        })
        .catch(function () {
          setBusy(false);
          showNetworkError();
        });
    }

    function resendCode() {
      if (busy) return;
      // V2r (POST /otp/resend): reemplaza el código sin reiniciar attempts ni presupuesto
      // (GRD-OT-06). 202: limpia el error previo del campo y anuncia un mensaje neutro por
      // #resend-feedback (fix Carlos, probado en navegador). 409 OTP_RESEND_LIMIT: mensaje de
      // límite alcanzado, sin cifra (P-06 sin valor aprobado). 404: sesión inválida (error
      // uniforme).
      postJson("/otp/resend")
        .then(function (res) {
          if (res.status === 202) {
            showResendFeedback("Te enviamos un nuevo código.");
            return;
          }
          if (res.status === 409) {
            showResendFeedback("Alcanzaste el límite de reenvíos disponible por ahora.");
            return;
          }
          if (res.status === 404) {
            showUniformError();
          }
        })
        .catch(function () {
          showNetworkError();
        });
    }

    function sendRecoveryLink() {
      // RV0 fuente BEARER (POST /manage/recovery-link, API-CNS-134): sin canal en el body
      // (GRD-RV-17); respuesta uniforme, nunca revela si el envío ocurrió.
      postJson("/manage/recovery-link")
        .then(function (res) {
          if (rightsLockedFeedback) {
            rightsLockedFeedback.hidden = false;
            rightsLockedFeedback.textContent =
              res.status === 202 ? "Si corresponde, enviamos un enlace a tu vía de contacto registrada." : "";
          }
        })
        .catch(function () {
          if (rightsLockedFeedback) {
            rightsLockedFeedback.hidden = false;
            rightsLockedFeedback.textContent = "No pudimos conectar. Inténtalo nuevamente.";
          }
        });
    }

    function openHumanCase() {
      // RC1 fuente BEARER (POST /rights-case/open): "en revisión", nunca "denegado".
      postJson("/rights-case/open")
        .then(function (res) {
          if (rightsLockedFeedback) {
            rightsLockedFeedback.hidden = false;
            rightsLockedFeedback.textContent = res.status === 200 ? "Abrimos un caso; te contactaremos." : "";
          }
        })
        .catch(function () {
          if (rightsLockedFeedback) {
            rightsLockedFeedback.hidden = false;
            rightsLockedFeedback.textContent = "No pudimos conectar. Inténtalo nuevamente.";
          }
        });
    }

    verifyBtn.addEventListener("click", submitCode);
    if (resendBtn) resendBtn.addEventListener("click", resendCode);
    if (requestNewCodeExpired) requestNewCodeExpired.addEventListener("click", requestNewCode);
    if (requestNewCodeLocked) requestNewCodeLocked.addEventListener("click", requestNewCode);
    if (sendRecoveryLinkBtn) sendRecoveryLinkBtn.addEventListener("click", sendRecoveryLink);
    if (openHumanCaseBtn) openHumanCaseBtn.addEventListener("click", openHumanCase);
    if (retryBtn) {
      retryBtn.addEventListener("click", function () {
        if (lastAction) lastAction();
      });
    }
  });
})();
