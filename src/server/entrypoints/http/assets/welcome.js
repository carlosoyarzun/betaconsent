// JS mínimo de /welcome, sin librerías, servido como estático (CLAUDE.md UX-CNS-001).
// CSRF double-submit (GRD-CM-10): el servidor fija la cookie __Host-cns-csrf SIN HttpOnly
// (csrf.ts) precisamente para que este script la lea de document.cookie y la copie al header
// x-csrf-token; el servidor solo compara igualdad byte a byte (guards.ts), nunca confía en la
// cookie por sí sola.
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

  function postJson(path) {
    var csrf = readCookie(CSRF_COOKIE_NAME);
    var headers = { "content-type": "application/json" };
    if (csrf) headers[CSRF_HEADER_NAME] = csrf;
    return fetch(path, { method: "POST", headers: headers, body: "{}", credentials: "same-origin" });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var continueBtn = document.getElementById("continue-btn");
    var errorUniform = document.getElementById("error-uniform");
    var errorNetwork = document.getElementById("error-network");
    var retryBtn = errorNetwork ? errorNetwork.querySelector("button") : null;
    if (!continueBtn) return;

    var busy = false;
    var continueLabel = continueBtn.textContent;

    function hideErrors() {
      if (errorUniform) errorUniform.hidden = true;
      if (errorNetwork) errorNetwork.hidden = true;
    }

    function setBusy(isBusy) {
      busy = isBusy;
      continueBtn.setAttribute("aria-disabled", isBusy ? "true" : "false");
      continueBtn.setAttribute("aria-busy", isBusy ? "true" : "false");
      continueBtn.textContent = isBusy ? "Abriendo invitación…" : continueLabel;
    }

    function showUniformError() {
      hideErrors();
      if (errorUniform) errorUniform.hidden = false;
    }

    function showNetworkError() {
      hideErrors();
      if (errorNetwork) errorNetwork.hidden = false;
    }

    function startFlow() {
      if (busy) return;
      hideErrors();
      setBusy(true);
      postJson("/invitation/open")
        .then(function (openRes) {
          if (!openRes.ok) {
            setBusy(false);
            showUniformError();
            return null;
          }
          return postJson("/otp/request");
        })
        .then(function (otpRes) {
          if (otpRes === null) return;
          setBusy(false);
          if (!otpRes.ok) {
            showUniformError();
            return;
          }
          // No hay pantalla de OTP todavía (placeholder /verify, CLAUDE.md).
          window.location.assign("/verify");
        })
        .catch(function () {
          setBusy(false);
          showNetworkError();
        });
    }

    continueBtn.addEventListener("click", startFlow);
    if (retryBtn) retryBtn.addEventListener("click", startFlow);
  });
})();
