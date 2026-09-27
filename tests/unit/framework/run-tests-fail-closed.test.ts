// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03),
// SEC-CNS-011 P1-02 (revisión de seguridad pre-PR CA-118: capa vacía verde en CI).
//
// Test negativo: corre tools/testing/run-tests.ts contra un directorio vacío (sin
// archivos *.test.ts) en un subproceso. En CI (CI="true") espera exit != 0
// (fail-closed); fuera de CI espera exit 0 (aviso, no bloquea desarrollo local).

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const RUN_TESTS_SCRIPT = join(REPO_ROOT, "tools", "testing", "run-tests.ts");

function runAgainstEmptyDir(env: Record<string, string | undefined>): ReturnType<typeof spawnSync> {
  const emptyDir = mkdtempSync(join(tmpdir(), "run-tests-fail-closed-"));
  // Quitar NODE_TEST_CONTEXT (que Node propaga a los subprocesos de su propio test
  // runner) para que run-tests.ts, y si llegara a invocar `node --test`, corra como una
  // corrida independiente y no como una "recursiva" que se omite sin ejecutar nada.
  const cleanEnv: Record<string, string | undefined> = { ...env };
  delete cleanEnv.NODE_TEST_CONTEXT;
  try {
    return spawnSync(process.execPath, [RUN_TESTS_SCRIPT, "unit", emptyDir], {
      cwd: REPO_ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
  } finally {
    rmSync(emptyDir, { recursive: true, force: true });
  }
}

test("TEST-CNS-904 run-tests fail-closed: capa vacía en CI termina con exit code distinto de 0", () => {
  const env: Record<string, string | undefined> = { ...process.env, CI: "true" };
  const result = runAgainstEmptyDir(env);
  assert.notEqual(result.status, 0, `esperaba exit != 0; stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});

test("TEST-CNS-904 run-tests fail-closed: capa vacía fuera de CI sigue en éxito (no rompe npm run ci en un clon limpio)", () => {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.CI;
  delete env.GITHUB_ACTIONS;
  const result = runAgainstEmptyDir(env);
  assert.equal(result.status, 0, `esperaba exit 0; stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});
