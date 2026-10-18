// Gobierna: F-PR6-25 (copy interino ERR-RV-21/22, no legal), ADR-001 F1 (fase C), DEC-BR-022 (trabajo aparte).
// TEST-CNS-1933: la réplica del copy de "retiro no completado" en frontend/ es literalmente igual a la del servidor
// (src/server/entrypoints/http/revocation-apply-failed-copy.ts); si uno cambia sin el otro, falla. Frontend no importa src/.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { HELP_MAILTO, RECOVERY_APPLY_FAILED_COPY, REVOCATION_APPLY_FAILED_COPY } from "../../../src/server/entrypoints/http/revocation-apply-failed-copy.ts";

test("TEST-CNS-1933: el copy ERR-RV-21/22 de frontend/src/components/c/apply-failed-copy.ts es idéntico al del servidor", async () => {
  const file = new URL("../../../frontend/src/components/c/apply-failed-copy.ts", import.meta.url);
  const text = readFileSync(file, "utf8");
  assert.ok(text.includes(`HELP_MAILTO = ${JSON.stringify(HELP_MAILTO)}`));
  for (const [name, copy] of [["REVOCATION_APPLY_FAILED_COPY", REVOCATION_APPLY_FAILED_COPY], ["RECOVERY_APPLY_FAILED_COPY", RECOVERY_APPLY_FAILED_COPY]] as const) {
    const block = text.slice(text.indexOf(`export const ${name}`));
    for (const [key, value] of Object.entries(copy)) {
      assert.ok(block.includes(`${key}: ${JSON.stringify(value)},`), `${name}.${key}`);
    }
  }
});
