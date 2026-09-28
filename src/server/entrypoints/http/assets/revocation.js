// JS de /manage/revocation/confirm (UX-CNS-004, CA-116), sin librerías, servido como
// estático. Mismo patrón CSRF double-submit que welcome.js/verify.js/decision.js (GRD-CM-10).
//
// Al cargar, ejecuta R2 (POST /manage/revocation/verify): idempotente si ya está VERIFIED
// (revocation.ts verifyRevocationOtp). "Confirmar retiro total" ejecuta R3 (POST
// /manage/revocation/confirm), que en el mismo request aplica R4 (revocation.ts
// confirmRevocation): la confirmación/comprobante REEMPLAZA el formulario y recibe el foco
// (mismo patrón que decision.js GRANTED/DECLINED, frames 27:49/27:58). "Cancelar solicitud de
// retiro" ejecuta R8 (POST /manage/revocation/withdraw), mismo patrón de reemplazo+foco
// (33:64 retiro-cancelado).
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
    var form = document.getElementById("revocation-form");
    var confirmBtn = document.getElementById("confirm-revocation-btn");
    var withdrawBtn = document.getElementById("withdraw-btn");
    var stateApplied = document.getElementById("state-applied");
    var stateWithdrawn = document.getElementById("state-withdrawn");
    var errorNetwork = document.getElementById("error-network");
    var errorUniform = document.getElementById("error-uniform");
    var retryBtn = document.getElementById("retry-btn");
    if (!form || !confirmBtn) return;

    var busy = false;
    var lastAction = null;

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

    // Frame 33:54 (comprobante): la confirmación reemplaza el formulario y recibe el foco.
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

    // Frame 33:64 (retiro-cancelado): mismo patrón de reemplazo+foco.
    function showWithdrawn() {
      hideStates();
      form.hidden = true;
      if (stateWithdrawn) {
        stateWithdrawn.hidden = false;
        var heading = document.getElementById("withdrawn-heading");
        if (heading) heading.focus();
      }
    }

    function setBusy(btn, isBusy, busyLabel) {
      if (!btn) return;
      btn.setAttribute("aria-disabled", isBusy ? "true" : "false");
      btn.setAttribute("aria-busy", isBusy ? "true" : "false");
      if (isBusy) {
        btn.dataset.label = btn.textContent;
        btn.textContent = busyLabel;
      } else if (btn.dataset.label) {
        btn.textContent = btn.dataset.label;
      }
    }

    function confirmRevocation() {
      if (busy) return;
      lastAction = confirmRevocation;
      busy = true;
      hideStates();
      setBusy(confirmBtn, true, "Confirmando…");
      postJson("/manage/revocation/confirm")
        .then(function (res) {
          busy = false;
          setBusy(confirmBtn, false);
          if (res.status === 404) {
            showUniformError();
            return null;
          }
          return res.json().catch(function () {
            return {};
          });
        })
        .then(function (body) {
          if (body && typeof body.revocationRef === "string") showApplied(body.revocationRef);
        })
        .catch(function () {
          busy = false;
          setBusy(confirmBtn, false);
          showNetworkError();
        });
    }

    function withdrawRevocation() {
      if (busy) return;
      lastAction = withdrawRevocation;
      busy = true;
      hideStates();
      setBusy(withdrawBtn, true, "Cancelando…");
      postJson("/manage/revocation/withdraw")
        .then(function (res) {
          busy = false;
          setBusy(withdrawBtn, false);
          if (res.status === 404) {
            showUniformError();
            return;
          }
          showWithdrawn();
        })
        .catch(function () {
          busy = false;
          setBusy(withdrawBtn, false);
          showNetworkError();
        });
    }

    // R2 (verificación de la solicitud), disparado al cargar: idempotente si ya VERIFIED.
    postJson("/manage/revocation/verify").catch(function () {
      showNetworkError();
    });

    confirmBtn.addEventListener("click", confirmRevocation);
    if (withdrawBtn) withdrawBtn.addEventListener("click", withdrawRevocation);
    if (retryBtn) {
      retryBtn.addEventListener("click", function () {
        if (lastAction) lastAction();
      });
    }
  });
})();
