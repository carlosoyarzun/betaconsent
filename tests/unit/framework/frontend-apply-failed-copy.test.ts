// Gobierna: F-PR6-25 (copy interino ERR-RV-21/22, no legal), ADR-001 F1 (fase C y retiro del SSR, AD-1 cerrada), DEC-BR-022 (trabajo aparte).
// TEST-CNS-1933: con el SSR retirado, la ÚNICA fuente del copy de "retiro no completado" es
// frontend/src/components/c/apply-failed-copy.ts (antes se comparaba contra src/server/entrypoints/http/revocation-apply-failed-copy.ts,
// eliminado). Este test fija el contrato del copy interino: marcado INTERINO/NO LEGAL, códigos de presentación ERR-RV-21/22 y que
// ningún texto afirme registro, recepción ni proceso (no hay acuse; DEC-BR-006 / REQ-CNS-033). Cambiarlo exige tocar este test (human gate).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { HELP_MAILTO, RECOVERY_APPLY_FAILED_COPY, REVOCATION_APPLY_FAILED_COPY } from "../../../frontend/src/components/c/apply-failed-copy.ts";

const FILE = new URL("../../../frontend/src/components/c/apply-failed-copy.ts", import.meta.url);
const NO_ACK = /registrad|recibid|en proceso|en curso|te avisaremos|revocad|cancelad|denegad/i;

test("TEST-CNS-1933: el copy ERR-RV-21/22 (única fuente: frontend/src/components/c/apply-failed-copy.ts) es el interino aprobado, marcado no legal y sin afirmar registro ni proceso", () => {
  const src = readFileSync(FILE, "utf8");
  assert.match(src, /INTERINO y NO LEGAL/);
  assert.match(src, /F-PR6-25/);
  assert.match(src, /REQ-CNS-033/);
  assert.equal(HELP_MAILTO, "mailto:ayuda@example.invalid");

  assert.deepEqual(REVOCATION_APPLY_FAILED_COPY, {
    title: "No pudimos completar tu retiro",
    body: "Ocurrió un problema interno y tu retiro no se completó. Tu autorización sigue vigente. El código que usaste puede haber expirado: pide uno nuevo e inténtalo otra vez. Si el problema continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
    code: "ERR-RV-21",
    codeLabel: "Código",
    primaryLabel: "Empezar de nuevo",
    helpLabel: "Escribir al equipo del estudio",
  });
  assert.deepEqual(RECOVERY_APPLY_FAILED_COPY, {
    title: "No pudimos completar tu retiro ahora",
    body: "Tu enlace sigue siendo válido, pero ocurrió un problema interno y el retiro no se completó. Tu autorización sigue vigente. Vuelve a intentarlo desde este mismo enlace en unos minutos. Si continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
    code: "ERR-RV-22",
    codeLabel: "Código",
    primaryLabel: "Volver a intentar",
    helpLabel: "Escribir al equipo del estudio",
  });
  for (const copy of [REVOCATION_APPLY_FAILED_COPY, RECOVERY_APPLY_FAILED_COPY]) {
    for (const text of [copy.title, copy.body]) assert.doesNotMatch(text, NO_ACK);
  }
  // Pantalla B: el enlace sigue vigente, así que el aviso no puede decir que el código "expiró" ni que "no sea válido".
  assert.match(RECOVERY_APPLY_FAILED_COPY.body, /Tu enlace sigue siendo válido/);
  assert.doesNotMatch(RECOVERY_APPLY_FAILED_COPY.body, /haber expirado|no sea válido/);
});
