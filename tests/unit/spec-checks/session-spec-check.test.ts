// Gobierna: JIRA CA-140, specs/session.spec.yaml, specs/test-framework.spec.yaml (capa unit). Prueba
// tools/spec-checks/session-spec-checker.ts: PASS sobre el estado real del repo y mutaciones negativas en memoria.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSessionSpec, parseMatrix } from "../../../tools/spec-checks/session-spec-checker.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SPEC = readFileSync(resolve(ROOT, "specs", "session.spec.yaml"), "utf-8");
const MATRIX = parseMatrix(readFileSync(resolve(ROOT, "traceability", "test-matrix.csv"), "utf-8"));
const exists = (p: string): boolean => existsSync(resolve(ROOT, p));

test("TEST-CNS-1187 session-spec-check: specs/session.spec.yaml parsea, sus testIds existen en la matriz con archivo real y todo guard/invariante tiene tests o nota", () => {
  assert.deepEqual(checkSessionSpec(SPEC, MATRIX, exists), []);
});

test("TEST-CNS-1187 session-spec-check: detecta testId inexistente, guard sin tests ni nota, guard duplicado y archivo inexistente", () => {
  const withBadTest = SPEC.replace("TEST-CNS-1140, TEST-CNS-1160]", "TEST-CNS-1140, TEST-CNS-9999]");
  assert.ok(checkSessionSpec(withBadTest, MATRIX, exists).some((e) => e.includes("TEST-CNS-9999")));
  const noTests = SPEC.replace(/(id: GRD-SE-02[\s\S]*?testIds: )\[[^\]]*\]/, "$1[]");
  assert.ok(checkSessionSpec(noTests, MATRIX, exists).some((e) => e.includes("GRD-SE-02") && e.includes("sin tests")));
  const dup = SPEC.replace("id: GRD-SE-03", "id: GRD-SE-02");
  assert.ok(checkSessionSpec(dup, MATRIX, exists).some((e) => e.includes("duplicado")));
  assert.ok(checkSessionSpec(SPEC, MATRIX, () => false).some((e) => e.includes("archivo inexistente")));
  assert.ok(checkSessionSpec("specId: otra", MATRIX, exists).some((e) => e.includes("specId")));
  const absolute = parseMatrix("TEST-CNS-1140,unit,/etc/passwd,\"x\",\"g\",ACTIVE");
  assert.ok(checkSessionSpec(SPEC, absolute, () => true).some((e) => e.includes("ruta no permitida")));
  const dotdot = parseMatrix("TEST-CNS-1140,unit,tests/../../fuera.test.ts,\"x\",\"g\",ACTIVE");
  assert.ok(checkSessionSpec(SPEC, dotdot, () => true).some((e) => e.includes("ruta no permitida")));
});
