// Gobierna: ADR-001 §11, CA-136 (H21).
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
