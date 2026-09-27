// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK, dependencyAllowlist),
// ADR-001 §5, JIRA CA-118 (H03), SEC-CNS-011 P2-01 (revisión de seguridad pre-PR
// CA-118: optional/peer/bundle deps y overrides fuera del alcance del checker;
// validación de versión exacta y owner humano en el propio allowlist).
//
// Fixtures en memoria contra la lógica pura de tools/guardrails/dependency-allowlist.ts
// (no toca el package.json/lockfile/allowlist reales del repo).

import test from "node:test";
import assert from "node:assert/strict";
import {
  runDependencyAllowlistCheck,
  validateAllowlistEntries,
  type Allowlist,
  type Lockfile,
  type PackageJson,
} from "../../../tools/guardrails/dependency-allowlist.ts";

const VALID_ALLOWLIST: Allowlist = {
  entries: [{ name: "left-pad", version: "1.2.3", owner: "carlosoyarzun" }],
};

function baseLockfile(deps: Record<string, string>): Lockfile {
  return { packages: { "": { dependencies: deps } } };
}

test("TEST-CNS-905 dependency-allowlist: caso válido (dependencies + lockfile sincronizados) no produce violaciones", () => {
  const packageJson: PackageJson = { dependencies: { "left-pad": "1.2.3" } };
  const violations = runDependencyAllowlistCheck({
    packageJson,
    lockfile: baseLockfile({ "left-pad": "1.2.3" }),
    allowlist: VALID_ALLOWLIST,
  });
  assert.deepEqual(violations, []);
});

test("TEST-CNS-905 dependency-allowlist: optionalDependencies fuera del allowlist falla", () => {
  const packageJson: PackageJson = { optionalDependencies: { "not-allowed": "9.9.9" } };
  const violations = runDependencyAllowlistCheck({
    packageJson,
    lockfile: baseLockfile({}),
    allowlist: VALID_ALLOWLIST,
  });
  assert.ok(violations.some((v) => v.includes("not-allowed@9.9.9")));
});

test("TEST-CNS-905 dependency-allowlist: peerDependencies fuera del allowlist falla", () => {
  const packageJson: PackageJson = { peerDependencies: { "not-allowed": "9.9.9" } };
  const violations = runDependencyAllowlistCheck({
    packageJson,
    lockfile: baseLockfile({}),
    allowlist: VALID_ALLOWLIST,
  });
  assert.ok(violations.some((v) => v.includes("not-allowed@9.9.9")));
});

test("TEST-CNS-905 dependency-allowlist: bundleDependencies presente falla explícitamente (evasión)", () => {
  const packageJson: PackageJson = { dependencies: { "left-pad": "1.2.3" }, bundleDependencies: ["left-pad"] };
  const violations = runDependencyAllowlistCheck({
    packageJson,
    lockfile: baseLockfile({ "left-pad": "1.2.3" }),
    allowlist: VALID_ALLOWLIST,
  });
  assert.ok(violations.some((v) => v.includes("bundleDependencies")));
});

test("TEST-CNS-905 dependency-allowlist: overrides presente falla explícitamente (evasión)", () => {
  const packageJson: PackageJson = {
    dependencies: { "left-pad": "1.2.3" },
    overrides: { "left-pad": "0.0.1" },
  };
  const violations = runDependencyAllowlistCheck({
    packageJson,
    lockfile: baseLockfile({ "left-pad": "1.2.3" }),
    allowlist: VALID_ALLOWLIST,
  });
  assert.ok(violations.some((v) => v.includes("overrides")));
});

test("TEST-CNS-905 dependency-allowlist entryValidation: versión con rango (no exacta) falla", () => {
  const violations = validateAllowlistEntries({ entries: [{ name: "left-pad", version: "^1.2.3", owner: "carlosoyarzun" }] });
  assert.ok(violations.some((v) => v.includes("no es una versión exacta")));
});

test("TEST-CNS-905 dependency-allowlist entryValidation: owner vacío falla", () => {
  const violations = validateAllowlistEntries({ entries: [{ name: "left-pad", version: "1.2.3", owner: "" }] });
  assert.ok(violations.some((v) => v.includes('no tiene "owner"')));
});

test("TEST-CNS-905 dependency-allowlist entryValidation: owner ausente falla", () => {
  const violations = validateAllowlistEntries({ entries: [{ name: "left-pad", version: "1.2.3" }] });
  assert.ok(violations.some((v) => v.includes('no tiene "owner"')));
});

test("TEST-CNS-905 dependency-allowlist entryValidation: owner que es un agente IA falla", () => {
  const violations = validateAllowlistEntries({ entries: [{ name: "left-pad", version: "1.2.3", owner: "lampone-dev" }] });
  assert.ok(violations.some((v) => v.includes("es un agente IA")));
});

test("TEST-CNS-905 dependency-allowlist entryValidation: owner humano válido no produce violaciones", () => {
  const violations = validateAllowlistEntries(VALID_ALLOWLIST);
  assert.deepEqual(violations, []);
});
