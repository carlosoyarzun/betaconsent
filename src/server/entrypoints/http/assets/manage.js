// JS mínimo de /manage (UX-CNS-004, CA-116), sin librerías, servido como estático. Mismo
// patrón CSRF double-submit que welcome.js/verify.js/decision.js (GRD-CM-10).
//
// Dos botones mutuamente excluyentes según el render server-side de manage-page.ts:
// #start-verify-btn (entrada, 33:2): POST /otp/request (scope MANAGE, resuelto en servidor
// desde la sesión) -> GET /manage/verify. #start-revocation-btn (estado, 33:21): POST
// /manage/revocation (R1) -> POST /otp/request (scope REVOCATION, ya resuelto porque la sesión
// ahora tiene revocationRef) -> GET /manage/revocation/verify.
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
    var startVerifyBtn = document.getElementById("start-verify-btn");
    var startRevocationBtn = document.getElementById("start-revocation-btn");
    var errorUniform = document.getElementById("error-uniform");
    var errorNetwork = document.getElementById("error-network");
    var retryBtn = errorNetwork ? errorNetwork.querySelector("button") : null;

    function hideErrors() {
      if (errorUniform) errorUniform.hidden = true;
      if (errorNetwork) errorNetwork.hidden = true;
    }

    function showUniformError() {
      hideErrors();
      if (errorUniform) errorUniform.hidden = false;
    }

    function showNetworkError() {
      hideErrors();
      if (errorNetwork) errorNetwork.hidden = false;
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

    var busy = false;

    function startVerify() {
      if (busy || !startVerifyBtn) return;
      busy = true;
      hideErrors();
      setBusy(startVerifyBtn, true, "Enviando código…");
      postJson("/otp/request")
        .then(function (res) {
          busy = false;
          setBusy(startVerifyBtn, false);
          if (!res.ok) {
            showUniformError();
            return;
          }
          window.location.assign("/manage/verify");
        })
        .catch(function () {
          busy = false;
          setBusy(startVerifyBtn, false);
          showNetworkError();
        });
    }

    function startRevocation() {
      if (busy || !startRevocationBtn) return;
      busy = true;
      hideErrors();
      setBusy(startRevocationBtn, true, "Solicitando retiro…");
      postJson("/manage/revocation")
        .then(function (res) {
          if (!res.ok) return null;
          return postJson("/otp/request");
        })
        .then(function (otpRes) {
          busy = false;
          setBusy(startRevocationBtn, false);
          if (otpRes === null || !otpRes.ok) {
            showUniformError();
            return;
          }
          window.location.assign("/manage/revocation/verify");
        })
        .catch(function () {
          busy = false;
          setBusy(startRevocationBtn, false);
          showNetworkError();
        });
    }

    if (startVerifyBtn) startVerifyBtn.addEventListener("click", startVerify);
    if (startRevocationBtn) startRevocationBtn.addEventListener("click", startRevocation);
    if (retryBtn) {
      retryBtn.addEventListener("click", function () {
        if (startVerifyBtn) startVerify();
        else startRevocation();
      });
    }
  });
})();
