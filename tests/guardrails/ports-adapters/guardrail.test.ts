// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-01..P1-08).
// Tests del guardrail Ports & Adapters contra fixtures y contra el repo real.

import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { runGuardrail } from "../../../tools/guardrails/ports-adapters/guardrail.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "fixtures");
const REPO_ROOT = join(HERE, "..", "..", "..");

function fixture(name: string): string {
  return join(FIXTURES, name);
}

interface Case {
  fixture: string;
  expectFail: boolean;
  expectedKinds?: string[];
}

const cases: Case[] = [
  { fixture: "static-import-deny-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "export-from-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "dynamic-import-literal-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "require-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "create-require-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "subpath-violation", expectFail: true, expectedKinds: ["DENY_LIST_OUTSIDE_ADAPTERS"] },
  { fixture: "adapter-import-allowed", expectFail: false },
  { fixture: "layer-violation-modules-import-infra", expectFail: true, expectedKinds: ["LAYER_BOUNDARY"] },
  { fixture: "layer-violation-platform-import-infra", expectFail: true, expectedKinds: ["LAYER_BOUNDARY"] },
  { fixture: "layer-violation-ports-import-infra", expectFail: true, expectedKinds: ["LAYER_BOUNDARY"] },
  { fixture: "layer-violation-client-import-server", expectFail: true, expectedKinds: ["LAYER_BOUNDARY"] },
  { fixture: "layer-violation-client-import-infra", expectFail: true, expectedKinds: ["LAYER_BOUNDARY"] },
  { fixture: "manifest-sdk-without-adapter", expectFail: true, expectedKinds: ["MANIFEST_SDK_WITHOUT_ADAPTER"] },
  { fixture: "clean-repo", expectFail: false },
  { fixture: "entrypoint-import-infra-allowed", expectFail: false },
  { fixture: "manifest-npm-alias-sdk", expectFail: true, expectedKinds: ["MANIFEST_NPM_ALIAS_SDK"] },
  { fixture: "manifest-nonregistry-dependency", expectFail: true, expectedKinds: ["MANIFEST_NONREGISTRY_DEPENDENCY"] },
  { fixture: "manifest-forbidden-sdk", expectFail: true, expectedKinds: ["MANIFEST_FORBIDDEN_SDK"] },
  { fixture: "forbidden-mode-in-adapters", expectFail: true, expectedKinds: ["DENY_LIST_FORBIDDEN"] },
  {
    fixture: "manifest-forbidden-sdk-transitive",
    expectFail: true,
    expectedKinds: ["MANIFEST_FORBIDDEN_SDK_TRANSITIVE"],
  },
  {
    fixture: "config-alias-not-supported-tsconfig",
    expectFail: true,
    expectedKinds: ["CONFIG_ALIAS_NOT_SUPPORTED"],
  },
  {
    fixture: "config-alias-not-supported-package-imports",
    expectFail: true,
    expectedKinds: ["CONFIG_ALIAS_NOT_SUPPORTED"],
  },
  // SEC-CNS-010 re-verificación (corpus 2, R-01..R-03): una fixture por caso.
  { fixture: "r01-element-access-module", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  { fixture: "r01-indirect-eval", expectFail: true, expectedKinds: ["FORBIDDEN_EVAL_OR_FUNCTION"] },
  { fixture: "r01-constructor-access", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  { fixture: "r01-getbuiltin-destructure", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  { fixture: "r01-destructure-createrequire", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  {
    fixture: "r01-worker-eval",
    expectFail: true,
    expectedKinds: ["FORBIDDEN_DANGEROUS_MODULE_IMPORT", "FORBIDDEN_EVAL_OR_FUNCTION"],
  },
  { fixture: "r01-load-cjs", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  { fixture: "r01-reflect-apply-construct", expectFail: true, expectedKinds: ["FORBIDDEN_EVAL_OR_FUNCTION"] },
  { fixture: "r01-binding-dlopen", expectFail: true, expectedKinds: ["FORBIDDEN_DANGEROUS_REFERENCE"] },
  { fixture: "r02-relative-outside-src", expectFail: true, expectedKinds: ["UNRESOLVED_SPECIFIER"] },
  { fixture: "r02-relative-into-nodemodules", expectFail: true, expectedKinds: ["UNRESOLVED_SPECIFIER"] },
  { fixture: "r03-tsconfig-jsonc-paths", expectFail: true, expectedKinds: ["CONFIG_ALIAS_NOT_SUPPORTED"] },
];

for (const c of cases) {
  test(`fixture ${c.fixture} ${c.expectFail ? "falla" : "pasa"}`, () => {
    const { violations } = runGuardrail(fixture(c.fixture));
    if (c.expectFail) {
      assert.ok(violations.length > 0, `se esperaban violaciones en ${c.fixture}`);
      const kinds = new Set(violations.map((v) => v.kind));
      for (const expectedKind of c.expectedKinds ?? []) {
        assert.ok(
          kinds.has(expectedKind as never),
          `se esperaba una violación de tipo ${expectedKind} en ${c.fixture}, se obtuvo: ${[...kinds].join(", ")}`,
        );
      }
    } else {
      assert.deepEqual(violations, [], `no se esperaban violaciones en ${c.fixture}, se obtuvo: ${JSON.stringify(violations)}`);
    }
  });
}

test("subpath-violation reporta el especificador con subpath, no solo el nombre de paquete", () => {
  const { violations } = runGuardrail(fixture("subpath-violation"));
  const hit = violations.find((v) => v.kind === "DENY_LIST_OUTSIDE_ADAPTERS");
  assert.ok(hit);
  assert.equal(hit?.specifier, "aws-sdk/clients/s3");
});

test("create-require-violation detecta module.createRequire(...)(...)", () => {
  const { violations } = runGuardrail(fixture("create-require-violation"));
  const hit = violations.find((v) => v.kind === "DENY_LIST_OUTSIDE_ADAPTERS");
  assert.ok(hit);
  assert.equal(hit?.specifier, "aws-sdk/clients/s3");
});

test("el guardrail sobre el repo real (src/ vacío) pasa sin violaciones", () => {
  const { violations } = runGuardrail(REPO_ROOT);
  assert.deepEqual(violations, []);
});

test("el CLI (check.ts) sobre el repo real termina con código 0", () => {
  const cliPath = join(REPO_ROOT, "tools", "guardrails", "ports-adapters", "check.ts");
  const output = execFileSync(process.execPath, [cliPath, REPO_ROOT], { encoding: "utf-8" });
  assert.match(output, /OK/);
});

test("el CLI (check.ts) sobre un fixture con violaciones termina con código distinto de 0", () => {
  const cliPath = join(REPO_ROOT, "tools", "guardrails", "ports-adapters", "check.ts");
  assert.throws(() => {
    execFileSync(process.execPath, [cliPath, fixture("static-import-deny-violation")], { encoding: "utf-8" });
  });
});

// SEC-CNS-010 (lampone-security, hallazgo P1-01..P1-08): corpus de evasión con 28 técnicas
// distintas para saltarse el guardrail (require dinámico, aliasing, globals, eval,
// symlinks, directorios prohibidos, alias no relativos, etc.). Cada punto de evasión debe
// producir al menos una violación: fail-closed total.
const EVASION_CORPUS_ROOT = "evasion-corpus-sec-cns-010";
const EVASION_POINTS = [
  "src/server/modules/e01-alias.ts",
  "src/server/modules/e02-call.ts",
  "src/server/modules/e03-template.ts",
  "src/server/modules/e04-concat.ts",
  "src/server/modules/e05-mainmodule.ts",
  "src/server/modules/e06-globalthis.ts",
  "src/server/modules/e07-eval.ts",
  "src/server/modules/e08-metaresolve.ts",
  "src/server/modules/e09-createrequire-alias.ts",
  "src/server/modules/e10-createrequire-named.ts",
  "src/server/modules/e11-js.js",
  "src/server/modules/e12-mjs.mjs",
  "src/server/modules/e13-cjs.cjs",
  "src/server/modules/e14-jsx.jsx",
  "src/server/modules/e15-mts.mts",
  "src/server/modules/e16-importtype.ts",
  "src/server/modules/e17-mixedcase.ts",
  "src/server/modules/e18-declare.ts",
  "src/server/modules/e19-bare-infra.ts",
  "src/server/modules/e20-reexport-local-pkg.ts",
  "src/server/modules/e21-url.ts",
  "src/server/modules/e22-process-dlopen.ts",
  "src/server/modules/e23-symlink.ts",
  "src/server/modules/e24-symdir",
  "src/server/modules/e25-vue.vue",
  "src/server/modules/e26-json.d.ts",
  "src/server/modules/dist/x.ts",
  "src/server/modules/node_modules/@aws-sdk/client-s3/index.js",
  "src/server/modules/node_modules",
  "src/server/platform/p.ts", // "../../infra/adapters/s.ts" (la 2ª línea, "../../infra-evil/x.ts", es un control: no debe fallar por sí sola)
];

test("corpus de evasión SEC-CNS-010: todos los puntos de evasión fallan cerrado", () => {
  const { violations } = runGuardrail(fixture(EVASION_CORPUS_ROOT));
  const filesWithViolations = new Set(violations.map((v) => v.file).filter((f): f is string => f !== undefined));
  const missed = EVASION_POINTS.filter((p) => !filesWithViolations.has(p));
  assert.deepEqual(missed, [], `puntos de evasión sin violación detectada: ${missed.join(", ")}`);
  assert.equal(missed.length, 0);
  // Reporte legible: cuántos de los N puntos de evasión conocidos fallan cerrado.
  console.log(
    `[corpus SEC-CNS-010] ${EVASION_POINTS.length - missed.length}/${EVASION_POINTS.length} puntos de evasión fallan cerrado (${violations.length} violaciones totales).`,
  );
});

test("corpus de evasión SEC-CNS-010: el CLI termina con código distinto de 0", () => {
  const cliPath = join(REPO_ROOT, "tools", "guardrails", "ports-adapters", "check.ts");
  assert.throws(() => {
    execFileSync(process.execPath, [cliPath, fixture(EVASION_CORPUS_ROOT)], { encoding: "utf-8" });
  });
});

// SEC-CNS-010 re-verificación (2026-09-26): corpus 2 con los 12 casos que la primera
// corrección de P1-01..P1-08 no cubría (R-01: referencia sin llamada, acceso computado,
// eval indirecto, .constructor, destructuring, Reflect, worker eval, _load/binding/dlopen;
// R-02: relativo que escapa de src/ o entra a node_modules; R-03: tsconfig JSONC con
// "extends"). Los 12 deben fallar cerrado.
const EVASION2_CORPUS_ROOT = "evasion2-corpus-sec-cns-010";
const EVASION2_POINTS = [
  "tsconfig.json",
  "src/server/modules/f01-elem.ts",
  "src/server/modules/f02-indirect-eval.ts",
  "src/server/modules/f03-ctor.ts",
  "src/server/modules/f04-getbuiltin.ts",
  "src/server/modules/f05-destructure.ts",
  "src/server/modules/f06-relative-nodemodules.ts",
  "src/server/modules/f07-relative-outside-src.ts",
  "src/server/modules/f08-worker.ts",
  "src/server/modules/f09-load.cjs",
  "src/server/modules/f10-reflect.ts",
  "src/server/modules/f11-binding.ts",
];

test("corpus de evasión 2 SEC-CNS-010 (re-verificación): los 12 casos fallan cerrado", () => {
  const { violations } = runGuardrail(fixture(EVASION2_CORPUS_ROOT));
  const filesWithViolations = new Set(violations.map((v) => v.file).filter((f): f is string => f !== undefined));
  const missed = EVASION2_POINTS.filter((p) => !filesWithViolations.has(p));
  assert.deepEqual(missed, [], `puntos de evasión (corpus 2) sin violación detectada: ${missed.join(", ")}`);
  console.log(
    `[corpus 2 SEC-CNS-010] ${EVASION2_POINTS.length - missed.length}/${EVASION2_POINTS.length} puntos de evasión fallan cerrado (${violations.length} violaciones totales).`,
  );
});

test("corpus de evasión 2 SEC-CNS-010: el CLI termina con código distinto de 0", () => {
  const cliPath = join(REPO_ROOT, "tools", "guardrails", "ports-adapters", "check.ts");
  assert.throws(() => {
    execFileSync(process.execPath, [cliPath, fixture(EVASION2_CORPUS_ROOT)], { encoding: "utf-8" });
  });
});
