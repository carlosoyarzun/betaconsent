// Gobierna: UX-CNS-004, CA-127; frame Figma 73:2 manage/mobile/ya-retirado (aprobado por Carlos,
// 2026-09-28). TEST-CNS-705.

import test from "node:test";
import assert from "node:assert/strict";

import { renderManageRevokedPage } from "../../../src/server/entrypoints/http/manage-page.ts";

test("TEST-CNS-705: renderManageRevokedPage muestra el copy aprobado 73:2, sin Retirar/GRANTED/marcador UX y con mailto de ayuda", () => {
  const html = renderManageRevokedPage();
  assert.match(html, /<h1 id="manage-h1">Tu consentimiento<\/h1>/);
  assert.match(html, /role="status" aria-live="polite"/);
  assert.match(html, /<strong>Tu consentimiento ya fue retirado\.<\/strong>/);
  assert.match(html, /No necesitas hacer nada más\. Ya no hay una acción de retiro pendiente en este enlace\./);
  assert.match(html, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: [^\]]*protocolo l\.522\]/);
  assert.match(html, /<a href="mailto:ayuda@example\.invalid" class="lp-btn lp-btn-primary lp-verify-tap-target" id="contact-support-btn">Contactar a soporte<\/a>/);
  assert.match(html, /¿Necesitas ayuda\? Escríbenos a ayuda@example\.invalid/);
  assert.doesNotMatch(html, /Retirar/);
  assert.doesNotMatch(html, /GRANTED/);
  assert.doesNotMatch(html, /\[UX/);
  assert.doesNotMatch(html, /<button/);
  assert.doesNotMatch(html, /volver a consentir/i);
});
