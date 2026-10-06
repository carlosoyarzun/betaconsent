// Gobierna: DEC-BR-014 rev. 8 §3 X8, specs/test-framework.spec.yaml (capa unit). Prueba
// tools/spec-checks/traceability-checker.ts: PASS sobre el estado real del repo y mutaciones negativas en memoria.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkTraceability, parseCsv, type TraceabilityInputs } from "../../../tools/spec-checks/traceability-checker.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...p: string[]): string => readFileSync(resolve(ROOT, ...p), "utf-8");
const SPECS = [
  ...readdirSync(resolve(ROOT, "specs", "state-machines")).filter((f) => f.endsWith(".yaml")).map((f) => read("specs", "state-machines", f)),
  read("specs", "session.spec.yaml"),
];
const REAL: TraceabilityInputs = {
  testMatrix: read("traceability", "test-matrix.csv"),
  smMatrix: read("traceability", "state-machine-matrix.csv"),
  smGuards: read("traceability", "state-machine-transition-guards.csv"),
  reqMatrix: read("traceability", "requirements-trace-matrix.csv"),
  exceptions: read("traceability", "x8-exceptions.csv"),
  specTexts: SPECS,
  fileExists: (p) => existsSync(resolve(ROOT, p)),
};

test("TEST-CNS-1220 traceability-check: las matrices de maquinas, la matriz REQ->test y las excepciones X8 son coherentes con test-matrix.csv", () => {
  assert.deepEqual(checkTraceability(REAL), []);
});

test("TEST-CNS-1221 traceability-check: detecta TEST-CNS inexistente, ruta absoluta o con .., archivo inexistente y UNCOVERED sin motivo", () => {
  const bogus = REAL.smMatrix.replace(/TEST-CNS-\d+/, "TEST-CNS-9999");
  assert.ok(checkTraceability({ ...REAL, smMatrix: bogus }).some((e) => e.includes("TEST-CNS-9999") && e.includes("no existe")));
  const abs = REAL.testMatrix.replace(/(\nTEST-CNS-900,unit,)[^,]*/, "$1/etc/passwd");
  assert.ok(checkTraceability({ ...REAL, testMatrix: abs }).some((e) => e.includes("ruta no permitida")));
  const dd = REAL.testMatrix.replace(/(\nTEST-CNS-900,unit,)[^,]*/, "$1tests/../../fuera.test.ts");
  assert.ok(checkTraceability({ ...REAL, testMatrix: dd }).some((e) => e.includes("ruta no permitida")));
  assert.ok(checkTraceability({ ...REAL, fileExists: () => false }).some((e) => e.includes("archivo inexistente")));
  const noReason = parseCsv(REAL.smGuards);
  assert.ok(noReason.some((r) => r.test_id === "UNCOVERED"), "el estado real debe tener filas UNCOVERED");
  const mutated = REAL.smGuards.replace(/(UNCOVERED,)[^\n]+/, "$1");
  assert.ok(checkTraceability({ ...REAL, smGuards: mutated }).some((e) => e.includes("UNCOVERED sin uncovered_reason")));
  const planned = REAL.smMatrix.replace(/TEST-CNS-\d+/, "TEST-CNS-467");
  assert.ok(checkTraceability({ ...REAL, smMatrix: planned }).some((e) => e.includes("PLANNED")));
});

test("TEST-CNS-1222 traceability-check: detecta filas e IDs duplicados inconsistentes en test-matrix.csv", () => {
  const row = "TEST-CNS-900,unit,tests/unit/framework/example.test.ts,\"dedupe: quita duplicados preservando el primer orden\",SPEC-CNS-TEST-FRAMEWORK,ACTIVE\n";
  assert.ok(checkTraceability({ ...REAL, testMatrix: REAL.testMatrix + row }).some((e) => e.includes("fila duplicada")));
  const otherLayer = "TEST-CNS-900,contract,tests/unit/framework/example.test.ts,\"otro\",SPEC-CNS-TEST-FRAMEWORK,ACTIVE\n";
  assert.ok(checkTraceability({ ...REAL, testMatrix: REAL.testMatrix + otherLayer }).some((e) => e.includes("capas distintas")));
  const otherStatus = "TEST-CNS-900,unit,tests/unit/framework/otro.test.ts,\"otro\",SPEC-CNS-TEST-FRAMEWORK,PLANNED\n";
  assert.ok(checkTraceability({ ...REAL, testMatrix: REAL.testMatrix + otherStatus }).some((e) => e.includes("estados inconsistentes")));
});

test("TEST-CNS-1223 traceability-check: todo hueco GRD/INV/ERR/API/REQ/RULE debe estar en x8-exceptions.csv y no puede haber excepciones obsoletas", () => {
  const lines = REAL.exceptions.split("\n");
  const without = [lines[0]!, ...lines.slice(2)].join("\n");
  assert.ok(checkTraceability({ ...REAL, exceptions: without }).some((e) => e.includes("hueco sin test y sin excepcion")));
  const stale = REAL.exceptions + "GRD-CM-05,GRD,specs/x.yaml,\"obsoleta\",,\n";
  assert.ok(checkTraceability({ ...REAL, exceptions: stale }).some((e) => e.includes("GRD-CM-05") && e.includes("ya tiene test")));
  const noReason = REAL.exceptions.replace(/^(ERR-CD-03,ERR,[^,]+,)"?[^\n]*$/m, "$1,,");
  assert.ok(checkTraceability({ ...REAL, exceptions: noReason }).length > 0);
  assert.equal(parseCsv('a,b\n"x,1","y ""q"""\n')[0]!.b, 'y "q"');
});
