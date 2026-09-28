// JS mínimo de /decision, sin librerías, servido como estático (UX-CNS-003, handoff
// decision-handoff.md). Mismo patrón CSRF double-submit que welcome.js/verify.js (GRD-CM-10).
//
// Orquesta C2 (POST /decision/steps, un POST por paso) + C3/C5 (POST /decision/submit) al hacer
// clic en "Enviar decisión": CONTEXT_INFORMATION_VIEWED, CONSENT_VERSION_VIEWED,
// DECISION_MAKER_AUTHORITY_DECLARED, SUBJECT_CONFIRMED (solo si el usuario confirmó "Sí, es
// correcto") y por último /decision/submit con las 4 finalidades. decisionMakerRef y consentId
// siempre los deriva/guarda el servidor en la sesión (D5); este script nunca los envía.
//
// x-scope-note (handoff, reportado a Carlos): "No es mi estudiante" NO llama
// POST /decision/subject-mismatch (API-CNS-128, fuera de alcance de este slice); solo bloquea el
// envío y muestra el aviso de ayuda (#subject-mismatch-note).
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
    var submitBtn = document.getElementById("submit-btn");
    var submitHelper = document.getElementById("submit-helper");
    if (!submitBtn) return;

    var subjectYesBtn = document.getElementById("subject-yes");
    var subjectNoBtn = document.getElementById("subject-no");
    var subjectMismatchNote = document.getElementById("subject-mismatch-note");
    var relationshipSelect = document.getElementById("relationship-select");
    var authorityCheckbox = document.getElementById("authority-declared");
    var purposeChips = Array.prototype.slice.call(document.querySelectorAll("[data-purpose-choice]"));
    var consentVersionHelp = document.getElementById("consent-version-help");
    var consentTextBox = document.getElementById("consent-text-box");

    var errorValidation = document.getElementById("error-validation");
    var errorConflict = document.getElementById("error-conflict");
    var errorNetwork = document.getElementById("error-network");
    var errorUniform = document.getElementById("error-uniform");
    var stateGranted = document.getElementById("state-granted");
    var stateDeclined = document.getElementById("state-declined");
    var decisionForm = document.getElementById("decision-form");
    var retryBtn = document.getElementById("retry-btn");

    var subjectChoice = null; // "yes" | "no"
    var busy = false;
    var submitLabel = submitBtn.textContent;

    function hideStates() {
      if (errorValidation) errorValidation.hidden = true;
      if (errorConflict) errorConflict.hidden = true;
      if (errorNetwork) errorNetwork.hidden = true;
      if (errorUniform) errorUniform.hidden = true;
      if (stateGranted) stateGranted.hidden = true;
      if (stateDeclined) stateDeclined.hidden = true;
    }

    function setBusy(isBusy) {
      busy = isBusy;
      submitBtn.setAttribute("aria-busy", isBusy ? "true" : "false");
      submitBtn.textContent = isBusy ? "Enviando…" : submitLabel;
      if (isBusy) submitBtn.setAttribute("aria-disabled", "true");
      else evaluateFormComplete();
    }

    function purposeChoice(purpose) {
      var checked = purposeChips.filter(function (btn) {
        return btn.getAttribute("data-purpose-choice") === purpose && btn.getAttribute("aria-checked") === "true";
      })[0];
      return checked ? checked.getAttribute("data-choice") : null;
    }

    function allPurposes() {
      var purposes = [];
      purposeChips.forEach(function (btn) {
        var p = btn.getAttribute("data-purpose-choice");
        if (purposes.indexOf(p) === -1) purposes.push(p);
      });
      return purposes;
    }

    function purposesComplete() {
      return allPurposes().every(function (p) {
        return purposeChoice(p) !== null;
      });
    }

    function evaluateFormComplete() {
      if (busy) return;
      var complete =
        subjectChoice === "yes" &&
        authorityCheckbox &&
        authorityCheckbox.checked &&
        relationshipSelect &&
        relationshipSelect.value !== "" &&
        purposesComplete();
      submitBtn.setAttribute("aria-disabled", complete ? "false" : "true");
      if (submitHelper) {
        submitHelper.textContent =
          subjectChoice === "no"
            ? "No podemos continuar: indicaste que no es tu estudiante."
            : complete
              ? "Todo listo para enviar."
              : "Completa todas las secciones para continuar.";
      }
    }

    function selectSubject(value) {
      subjectChoice = value;
      if (subjectYesBtn) subjectYesBtn.setAttribute("aria-checked", value === "yes" ? "true" : "false");
      if (subjectNoBtn) subjectNoBtn.setAttribute("aria-checked", value === "no" ? "true" : "false");
      if (subjectMismatchNote) subjectMismatchNote.hidden = value !== "no";
      evaluateFormComplete();
    }

    function selectPurpose(purpose, choice) {
      purposeChips.forEach(function (btn) {
        if (btn.getAttribute("data-purpose-choice") === purpose) {
          btn.setAttribute("aria-checked", btn.getAttribute("data-choice") === choice ? "true" : "false");
        }
      });
      evaluateFormComplete();
    }

    function showValidationError(detailText) {
      hideStates();
      var detail = document.getElementById("error-validation-detail");
      if (detail && detailText) detail.textContent = detailText;
      if (errorValidation) errorValidation.hidden = false;
    }

    function showConflictError() {
      hideStates();
      if (errorConflict) errorConflict.hidden = false;
    }

    function showNetworkError() {
      hideStates();
      if (errorNetwork) errorNetwork.hidden = false;
    }

    function showUniformError() {
      hideStates();
      if (errorUniform) errorUniform.hidden = false;
    }

    // Frames 27:49 (GRANTED) / 27:58 (DECLINED): la confirmación REEMPLAZA el formulario, no
    // queda debajo. Se oculta #decision-form (todas las secciones + CTA + helper) y el foco se
    // mueve al encabezado de la confirmación (tabindex=-1, mismo patrón que un heading enfocable
    // tras una navegación por JS sin recarga de página).
    function showGranted(receiptRef) {
      hideStates();
      if (decisionForm) decisionForm.hidden = true;
      var el = document.getElementById("granted-receipt");
      if (el) el.textContent = "Comprobante: " + receiptRef;
      if (stateGranted) {
        stateGranted.hidden = false;
        var heading = document.getElementById("granted-heading");
        if (heading) heading.focus();
      }
    }

    function showDeclined(receiptRef) {
      hideStates();
      if (decisionForm) decisionForm.hidden = true;
      var el = document.getElementById("declined-receipt");
      if (el) el.textContent = "Comprobante: " + receiptRef;
      if (stateDeclined) {
        stateDeclined.hidden = false;
        var heading = document.getElementById("declined-heading");
        if (heading) heading.focus();
      }
    }

    // Rechazo determinado por status HTTP + code del Problem (contracts/common.schema.json).
    // Devuelve null si la respuesta fue manejada (error mostrado); si no hubo error, resuelve el
    // body ya parseado (o {} si no aplica) para que el caller siga la secuencia.
    function handleStepOrSubmitResponse(res) {
      if (res.status === 404) {
        showUniformError();
        return null;
      }
      if (res.status === 409) {
        showConflictError();
        return null;
      }
      if (res.status === 422) {
        return res.json().catch(function () {
          return {};
        }).then(function (body) {
          showValidationError(body && body.code ? "Código: " + body.code : undefined);
          return null;
        });
      }
      return res.json().catch(function () {
        return {};
      });
    }

    function submitDecision() {
      if (busy) return;
      if (submitBtn.getAttribute("aria-disabled") === "true") return;
      hideStates();
      setBusy(true);

      postJson("/decision/steps", { stepKind: "CONTEXT_INFORMATION_VIEWED" })
        .then(function (res) {
          return handleStepOrSubmitResponse(res);
        })
        .then(function (body) {
          if (body === null) return null;
          return postJson("/decision/steps", { stepKind: "CONSENT_VERSION_VIEWED" }).then(handleStepOrSubmitResponse);
        })
        .then(function (body) {
          if (body === null) return null;
          if (body && body.servedVersion) {
            if (consentTextBox) consentTextBox.textContent = body.servedVersion.text;
            if (consentVersionHelp) {
              consentVersionHelp.textContent =
                "Versión vigente del texto: " +
                body.servedVersion.consentVersion +
                " · Aviso de privacidad: " +
                body.servedVersion.privacyNoticeVersion;
            }
          }
          return postJson("/decision/steps", {
            stepKind: "DECISION_MAKER_AUTHORITY_DECLARED",
            relationshipRef: relationshipSelect ? relationshipSelect.value : "",
            authorityDeclared: true,
          }).then(handleStepOrSubmitResponse);
        })
        .then(function (body) {
          if (body === null) return null;
          return postJson("/decision/steps", { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true }).then(
            handleStepOrSubmitResponse,
          );
        })
        .then(function (body) {
          if (body === null) return null;
          var purposes = allPurposes().map(function (purpose) {
            return { purpose: purpose, choice: purposeChoice(purpose) };
          });
          return postJson("/decision/submit", { purposes: purposes }).then(handleStepOrSubmitResponse);
        })
        .then(function (body) {
          setBusy(false);
          if (body === null || !body) return;
          if (body.state === "GRANTED") {
            showGranted(body.receiptRef);
          } else if (body.state === "DECLINED") {
            showDeclined(body.receiptRef);
          }
        })
        .catch(function () {
          setBusy(false);
          showNetworkError();
        });
    }

    if (subjectYesBtn) subjectYesBtn.addEventListener("click", function () { selectSubject("yes"); });
    if (subjectNoBtn) subjectNoBtn.addEventListener("click", function () { selectSubject("no"); });
    if (authorityCheckbox) authorityCheckbox.addEventListener("change", evaluateFormComplete);
    if (relationshipSelect) relationshipSelect.addEventListener("change", evaluateFormComplete);
    purposeChips.forEach(function (btn) {
      btn.addEventListener("click", function () {
        selectPurpose(btn.getAttribute("data-purpose-choice"), btn.getAttribute("data-choice"));
      });
    });
    submitBtn.addEventListener("click", submitDecision);
    if (retryBtn) retryBtn.addEventListener("click", submitDecision);

    evaluateFormComplete();
  });
})();
