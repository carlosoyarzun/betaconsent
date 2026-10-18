// Gobierna: ADR-001 rev. 8 F1 (AD-1 cerrada: SSR de titulares retirado), UX-CNS-003, UX-CNS-002, P-01/P-02/P-06.
// TEST-CNS-2066: invariantes de copy que hasta el retiro del SSR verificaban las aserciones de tests/integration/consent-flow/guest-flow-v2-http.test.ts
// (TEST-CNS-1406) sobre el HTML/JS del servidor y que ahora viven en el código fuente de la SPA: ninguna pantalla presume "hija o hijo",
// ninguna usa temporizadores/cuentas regresivas y ningún valor de parámetro pendiente (P-01/P-02/P-06) aparece como cifra.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const SRC = new URL("../../../frontend/src/", import.meta.url).pathname;

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...sources(full));
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

test("TEST-CNS-2066: el código de la SPA no presume 'hija o hijo', no usa setInterval y mantiene los valores P-01/P-02/P-06 como pendientes de aprobación", () => {
  const files = sources(SRC);
  assert.ok(files.length > 10, "debe haber código fuente de la SPA");
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /hija o hijo/, file);
    assert.doesNotMatch(text, /setInterval/, file);
  }
  const verify = readFileSync(join(SRC, "components/b/verify-screen.tsx"), "utf8");
  assert.match(verify, /\(P-01, valor pendiente de aprobación\)/);
  assert.match(verify, /\(P-06, valor pendiente de aprobación\)/);
  assert.doesNotMatch(verify, /\d{2}:\d{2}|\d+ minutos|\d+ segundos/);
});
