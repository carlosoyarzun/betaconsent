// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03),
// SEC-CNS-011 P1-01 (revisión de seguridad pre-PR CA-118: skip vacuo en CI).
//
// Test negativo: corre tests/integration/postgres-smoke.test.ts en un subproceso con
// CI="true" y sin TEST_DATABASE_URL, y espera que el proceso hijo salga con código
// distinto de 0 (falla, no skip vacuo). También verifica el camino simétrico: fuera de
// CI, sin la variable, el subproceso sigue saliendo con código 0 (skip), para no romper
// `npm run ci` en un clon limpio sin Docker.
//
// No es un test de infraestructura real (no requiere Postgres): solo verifica el
// comportamiento fail-closed del propio archivo de test, por eso vive en la capa "unit".

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const SMOKE_TEST_FILE = join(REPO_ROOT, "tests", "integration", "postgres-smoke.test.ts");

test("TEST-CNS-903 postgres-smoke fail-closed: sin TEST_DATABASE_URL en CI el test falla (no se omite)", () => {
  const env: Record<string, string | undefined> = { ...process.env, CI: "true" };
  delete env.TEST_DATABASE_URL;
  // Node propaga NODE_TEST_CONTEXT a los subprocesos que arranca su propio test
  // runner; si el subproceso hijo lo hereda, `--test` detecta una "corrida
  // recursiva" y se omite sin ejecutar nada (falso negativo de este test negativo).
  // Se quita para que el hijo corra `--test` de forma independiente y real.
  delete env.NODE_TEST_CONTEXT;

  const result = spawnSync(process.execPath, ["--test", SMOKE_TEST_FILE], {
    cwd: REPO_ROOT,
    env,
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0, `esperaba exit != 0; stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});

test("TEST-CNS-903 postgres-smoke fail-closed: sin TEST_DATABASE_URL fuera de CI el test se omite (exit 0)", () => {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.CI;
  delete env.GITHUB_ACTIONS;
  delete env.TEST_DATABASE_URL;
  delete env.NODE_TEST_CONTEXT;

  const result = spawnSync(process.execPath, ["--test", SMOKE_TEST_FILE], {
    cwd: REPO_ROOT,
    env,
    encoding: "utf8",
  });

  assert.equal(result.status, 0, `esperaba exit 0 (skip); stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});
