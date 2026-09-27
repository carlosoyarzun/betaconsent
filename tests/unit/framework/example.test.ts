// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03).
//
// Ejemplo mínimo de la capa "unit", fuera de src/ (CA-118 es previo a todo código de
// dominio; ver DEC-BR-014 §2 y R9-4 C3). Prueba una función trivial declarada en el
// propio archivo, solo para que tests/unit tenga al menos un caso ejecutable y demostrar
// la convención de nombres ("TEST-CNS-900 ...") que traceability/test-matrix.csv
// registra. Se retira cuando exista el primer test unitario real de dominio.

import test from "node:test";
import assert from "node:assert/strict";

function dedupe<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

test("TEST-CNS-900 dedupe: quita duplicados preservando el primer orden", () => {
  assert.deepEqual(dedupe([1, 2, 2, 3, 1]), [1, 2, 3]);
});

test("TEST-CNS-900 dedupe: lista vacía devuelve lista vacía", () => {
  assert.deepEqual(dedupe([]), []);
});
