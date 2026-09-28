// JS mínimo de /verify, sin librerías, servido como estático (UX-CNS-002 handoff, Carlos
// 2026-09-27). Mismo patrón CSRF double-submit que welcome.js (GRD-CM-10): la cookie
// __Host-cns-csrf (sin HttpOnly, fijada por GET /verify vía csrf.ts) se copia al header
// x-csrf-token; el servidor solo compara igualdad byte a byte (guards.ts).
//
// "Solicitar nuevo código" (estados expirado/bloqueado) llama POST /otp/request: la spec
// (specs/state-machines/otp-challenge.spec.yaml V1, GRD-OT-08 single_active_challenge_
// bound_to_handle) hace que un V1 repetido desde el mismo handle/sesión reemplace el
// challenge existente (LOCKED/EXPIRED no cuentan como "activo") con uno nuevo (CODE_SENT,
// attempts=0), sujeto a presupuesto (V6/V6a); no crea una invitación ni un endpoint distinto.
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
    var verifyBtn = document.getElementById("verify-btn");
    var codeInput = document.getElementById("code-input");
    var codeError = document.getElementById("code-error");
    var resendBtn = document.getElementById("resend-btn");
    var requestNewCodeExpired = document.getElementById("request-new-code-btn-expired");
    var requestNewCodeLocked = document.getElementById("request-new-code-btn-locked");
    var stateExpired = document.getElementById("state-expired");
    var stateLocked = document.getElementById("state-locked");
    var errorNetwork = document.getElementById("error-network");
    var errorUniform = document.getElementById("error-uniform");
    var retryBtn = document.getElementById("retry-btn");
    if (!verifyBtn || !codeInput) return;

    var busy = false;
    var verifyLabel = verifyBtn.textContent;
    var lastAction = null; // reintentado por el botón "Reintentar" (error de red)

    function hideStates() {
      if (codeError) codeError.hidden = true;
      if (stateExpired) stateExpired.hidden = true;
      if (stateLocked) stateLocked.hidden = true;
      if (errorNetwork) errorNetwork.hidden = true;
      if (errorUniform) errorUniform.hidden = true;
      codeInput.setAttribute("aria-invalid", "false");
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
      if (stateLocked) stateLocked.hidden = false;
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
            window.location.assign("/decision");
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
      // (GRD-OT-06). Sin estado dedicado en el handoff para 409 OTP_RESEND_LIMIT: la nota de
      // límite ya visible en la pantalla no distingue intentos restantes (P-06 sin valor
      // aprobado); un 404 sí es la sesión inválida.
      postJson("/otp/resend").then(function (res) {
        if (res.status === 404) showUniformError();
      }).catch(function () {
        showNetworkError();
      });
    }

    verifyBtn.addEventListener("click", submitCode);
    if (resendBtn) resendBtn.addEventListener("click", resendCode);
    if (requestNewCodeExpired) requestNewCodeExpired.addEventListener("click", requestNewCode);
    if (requestNewCodeLocked) requestNewCodeLocked.addEventListener("click", requestNewCode);
    if (retryBtn) {
      retryBtn.addEventListener("click", function () {
        if (lastAction) lastAction();
      });
    }
  });
})();
