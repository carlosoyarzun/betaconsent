// Gobierna: UX-CNS-006 / UX-CNS-006b, Master Plan §21 Consent Receipt (docs/beta-consent-master-plan.md:723-741),
// decisiones de Carlos 2026-10-14 D-03/D-04: el comprobante lleva los campos del §21 + marca de agua IT0 + marcadores
// [LEGAL DECISION] en "cómo revocar" y "cómo ejercer derechos", NUNCA un enlace (menos aún el de gestión) ni descarga;
// el mensaje de gestión es aparte. TEST-CNS-1408, TEST-CNS-1409.

import test from "node:test";
import assert from "node:assert/strict";

import { renderManagementLinkMessage, renderReceiptMessage } from "../../../src/server/entrypoints/http/guest-messages.ts";

const BASE = {
  recipientChannelRef: "test+unit@example.invalid",
  subjectLabel: "Alumno de prueba 3",
  consentVersion: "v1-dev",
  privacyNoticeVersion: "p1-dev",
  decidedAt: new Date("2026-10-14T15:30:00.000Z"),
  receiptRef: "5f1c3b0e-8a7d-4a39-9d5e-0b1f6a2c4d11",
} as const;

test("TEST-CNS-1408: el comprobante contiene los campos del §21 (estudio, estudiante, versiones, finalidades y decisión, fecha/hora, referencia, cómo revocar, derechos), marca de agua IT0 y marcadores [LEGAL DECISION], sin enlaces ni descarga", () => {
  const purposes = [
    { purpose: "STUDY_PARTICIPATION", choice: "GRANT" as const },
    { purpose: "AUDIO_RECORDING", choice: "DECLINE" as const },
  ];
  const msg = renderReceiptMessage({ ...BASE, purposes, state: "DECLINED" });
  assert.equal(msg.kind, "RECEIPT");
  assert.equal(msg.subject, "Comprobante de tu decisión — Estudio Beta de LectorPro");
  for (const body of [msg.html, msg.text]) {
    assert.match(body, /Estudio Beta de LectorPro/);
    assert.match(body, /Alumno de prueba 3/);
    assert.match(body, /v1-dev/);
    assert.match(body, /p1-dev/);
    assert.match(body, /2026-10-14 15:30:00 UTC/);
    assert.match(body, /5f1c3b0e-8a7d-4a39-9d5e-0b1f6a2c4d11/);
    assert.match(body, /✓ Acepto/);
    assert.match(body, /✕ No acepto/);
    assert.match(body, /Participar en el Estudio Beta/);
    assert.match(body, /Grabación de audio/);
    assert.match(body, /marca de agua IT0/);
    assert.match(body, /\[LEGAL DECISION — cómo retirar tu consentimiento/);
    assert.match(body, /\[LEGAL DECISION — cómo ejercer tus derechos/);
    assert.match(body, /no incluye el enlace para gestionar tu decisión/);
    assert.doesNotMatch(body, /https?:\/\/|href=|\/m\/|Descargar|\.pdf|firma|SHA-256/i);
  }
  assert.doesNotMatch(msg.html, /<script|<img|<link|url\(/i);
  assert.doesNotMatch(msg.html, /RUT|\d{1,2}\.\d{3}\.\d{3}-[\dkK]/);
});

test("TEST-CNS-1409: el mensaje del enlace de gestión es aparte, lleva solo el enlace sintético y la advertencia de no compartirlo, y escapa lo interpolado", () => {
  const msg = renderManagementLinkMessage({
    recipientChannelRef: "test+unit@example.invalid",
    managementPath: "/m/abcDEF_-0123456789abcdefghij",
    publicBaseUrl: "https://consent.example.invalid/",
  });
  assert.equal(msg.kind, "MANAGEMENT_LINK");
  assert.equal(msg.subject, "Enlace para gestionar tu decisión — Estudio Beta de LectorPro");
  assert.match(msg.html, /href="https:\/\/consent\.example\.invalid\/m\/abcDEF_-0123456789abcdefghij"/);
  assert.match(msg.html, /Gestionar mi decisión/);
  assert.match(msg.html, /no lo compartas ni lo reenvíes/);
  assert.doesNotMatch(msg.html, /Comprobante de tu decisión|Referencia del comprobante/);

  const hostile = renderManagementLinkMessage({
    recipientChannelRef: "test+unit@example.invalid",
    managementPath: '/m/"><script>x</script>',
    publicBaseUrl: "https://consent.example.invalid",
  });
  assert.doesNotMatch(hostile.html, /<script>x<\/script>/);
});
