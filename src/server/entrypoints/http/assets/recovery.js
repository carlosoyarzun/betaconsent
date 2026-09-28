// JS de /recovery/confirm (UX-CNS-004, CA-116 PR 2), sin librerías, servido como estático.
// Mismo patrón CSRF double-submit que welcome.js/verify.js/decision.js/manage.js/revocation.js
// (GRD-CM-10).
//
// Un solo botón dispara el único POST /recovery/revoke (R1r+R2r+R3r, o R10+R3r, o R11 NOOP,
// según decida el servidor): la respuesta decide qué bloque mostrar, nunca este script.
// CONFIRMED -> comprobante (reemplaza el formulario y recibe el foco, mismo patrón que
// manage.js/decision.js). IN_PROGRESS (R11) -> "en curso" (33:96). Cualquier 202/404 (ERR-RV-05
// uniforme, o sesión inexistente) -> error uniforme (33:106).
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
    return fetch(path, { method: "POST", headers: headers, body: JSON.stringify(body), credentials: "same-origin" });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("recovery-form");
    var confirmBtn = document.getElementById("confirm-recovery-btn");
    var stateApplied = document.getElementById("state-applied");
    var stateInProgress = document.getElementById("state-in-progress");
    var errorNetwork = document.getElementById("error-network");
    var errorUniform = document.getElementById("error-uniform");
    var retryBtn = document.getElementById("retry-btn");
    if (!form || !confirmBtn) return;

    var busy = false;

    function hideStates() {
      if (errorNetwork) errorNetwork.hidden = true;
      if (errorUniform) errorUniform.hidden = true;
    }

    function showNetworkError() {
      hideStates();
      if (errorNetwork) errorNetwork.hidden = false;
    }

    function showUniformError() {
      hideStates();
      if (errorUniform) errorUniform.hidden = false;
    }

    // Frame 33:54/33:87 (comprobante): la confirmación reemplaza el formulario y recibe el foco.
    function showApplied(revocationRef) {
      hideStates();
      form.hidden = true;
      var el = document.getElementById("applied-receipt");
      if (el) el.textContent = "Comprobante: " + revocationRef;
      if (stateApplied) {
        stateApplied.hidden = false;
        var heading = document.getElementById("applied-heading");
        if (heading) heading.focus();
      }
    }

    // Frame 33:96 (en-curso, R11 NOOP): mismo patrón de reemplazo+foco.
    function showInProgress() {
      hideStates();
      form.hidden = true;
      if (stateInProgress) {
        stateInProgress.hidden = false;
        var heading = document.getElementById("in-progress-heading");
        if (heading) heading.focus();
      }
    }

    function setBusy(isBusy) {
      confirmBtn.setAttribute("aria-disabled", isBusy ? "true" : "false");
      confirmBtn.setAttribute("aria-busy", isBusy ? "true" : "false");
      if (isBusy) {
        confirmBtn.dataset.label = confirmBtn.textContent;
        confirmBtn.textContent = "Confirmando…";
      } else if (confirmBtn.dataset.label) {
        confirmBtn.textContent = confirmBtn.dataset.label;
      }
    }

    function confirmRecovery() {
      if (busy) return;
      busy = true;
      hideStates();
      setBusy(true);
      postJson("/recovery/revoke", { confirmTotalWithdrawal: true })
        .then(function (res) {
          busy = false;
          setBusy(false);
          if (res.status === 404 || res.status === 202) {
            showUniformError();
            return null;
          }
          return res.json().catch(function () {
            return {};
          });
        })
        .then(function (body) {
          if (!body) return;
          if (body.state === "CONFIRMED" && typeof body.revocationRef === "string") {
            showApplied(body.revocationRef);
          } else if (body.result === "IN_PROGRESS") {
            showInProgress();
          } else {
            showUniformError();
          }
        })
        .catch(function () {
          busy = false;
          setBusy(false);
          showNetworkError();
        });
    }

    confirmBtn.addEventListener("click", confirmRecovery);
    if (retryBtn) retryBtn.addEventListener("click", confirmRecovery);
  });
})();
