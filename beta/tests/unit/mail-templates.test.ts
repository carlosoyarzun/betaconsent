// Gobierna: plan v2 H1-06. Snapshots de plantillas y reglas de contenido (sin PII en asunto, sin RUT en cuerpo).
import assert from "node:assert/strict";
import { test } from "node:test";

import { SUBJECTS } from "../../src/mail/guest-messages.ts";
import { buildLink, renderTemplate, TEMPLATE_NAMES, type TemplateName, type TemplateParams } from "../../src/mail/templates/index.ts";

const ORIGIN = "https://consent.example.invalid";
const receipt = {
  studentFirstName: "Valentina",
  consentVersion: "v1-borrador",
  decidedAt: "2026-10-19T15:00:00Z",
  receiptRef: "rcpt-0001",
  purposes: [
    { purpose: "STUDY_PARTICIPATION", choice: "GRANT" },
    { purpose: "AUDIO_RECORDING", choice: "DECLINE" },
  ],
} as const;
const FIXTURES: { [T in TemplateName]: TemplateParams[T] } = {
  invitation: { studentFirstName: "Valentina", linkPath: "/i/tok_ABC-123" },
  otp: { code: "493817", ttlMinutes: 10 },
  receipt_granted: receipt,
  receipt_declined: receipt,
  receipt_revoked: { ...receipt, chain_seq: 7, event_hash: "ab".repeat(32) },
  management_link: { studentFirstName: "Valentina", linkPath: "/m/tok_XYZ-789" },
};

for (const name of TEMPLATE_NAMES) {
  test(`snapshot de la plantilla ${name}`, (t) => {
    const r = renderTemplate(name, FIXTURES[name] as never, ORIGIN);
    t.assert.snapshot(r);
  });

  test(`${name}: asunto sin PII, sin RUT, marcada BORRADOR`, () => {
    const r = renderTemplate(name, FIXTURES[name] as never, ORIGIN);
    assert.equal(r.subject, SUBJECTS[name]);
    assert.ok(r.subject.includes("BORRADOR"));
    assert.ok(!/valentina/i.test(r.subject) && !r.subject.includes("@"), "asunto con nombre o correo");
    assert.ok(!/\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b/.test(r.text + r.html), "parece un RUT");
    assert.ok(r.text.includes("BORRADOR") || r.text.includes("[LEGAL DECISION"), "falta marca BORRADOR");
  });
}

test("solo el nombre de pila aparece en el cuerpo y los enlaces usan el origen público", () => {
  const inv = renderTemplate("invitation", FIXTURES.invitation, ORIGIN);
  assert.ok(inv.text.includes("Valentina"));
  assert.ok(inv.text.includes("https://consent.example.invalid/i/tok_ABC-123"));
  assert.ok(inv.html.includes('href="https://consent.example.invalid/i/tok_ABC-123"'));
  const rec = renderTemplate("receipt_granted", FIXTURES.receipt_granted, ORIGIN);
  assert.ok(!/https?:\/\//.test(rec.text + rec.html), "el recibo no lleva enlaces");
});

test("recibos: chain_seq y event_hash son opcionales", () => {
  const without = renderTemplate("receipt_granted", receipt, ORIGIN);
  const withChain = renderTemplate("receipt_revoked", FIXTURES.receipt_revoked, ORIGIN);
  assert.ok(!without.text.includes("Secuencia en la cadena"));
  assert.ok(withChain.text.includes("Secuencia en la cadena: 7") && withChain.text.includes("ab".repeat(32)));
});

test("escapa HTML en datos interpolados", () => {
  const r = renderTemplate("invitation", { studentFirstName: "<b>X</b>", linkPath: "/i/a" }, ORIGIN);
  assert.ok(!r.html.includes("<b>X</b>"));
});

test("buildLink: https obligatorio salvo localhost; rutas inválidas se rechazan", () => {
  assert.equal(buildLink("https://a.example.invalid", "/m/x"), "https://a.example.invalid/m/x");
  assert.equal(buildLink("http://localhost:3000", "/m/x"), "http://localhost:3000/m/x");
  assert.throws(() => buildLink("http://consent.example.invalid", "/m/x"));
  assert.throws(() => buildLink(ORIGIN, "//evil.invalid"));
  assert.throws(() => buildLink(ORIGIN, "/m/x?y=1"));
});
