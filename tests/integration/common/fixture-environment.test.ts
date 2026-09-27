// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-13 (fixture_actor_environment), R14-F.
// TEST-CNS-466.

import test from "node:test";
import assert from "node:assert/strict";

import { assertFixtureEnvironment } from "../../../src/server/modules/common/guards.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";

test("TEST-CNS-466: actorType FIXTURE aceptado en environment LOCAL (CI corre como LOCAL, OPEN-CM-07)", () => {
  assert.doesNotThrow(() => assertFixtureEnvironment("FIXTURE", "LOCAL"));
});

test("TEST-CNS-466: actorType FIXTURE rechazado con ERR-CM-10 en DEV, STAGING y PRODUCTION", () => {
  const rejectedEnvironments: Environment[] = ["DEV", "STAGING", "PRODUCTION"];
  for (const environment of rejectedEnvironments) {
    assert.throws(
      () => assertFixtureEnvironment("FIXTURE", environment),
      (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-10",
      `debía rechazar FIXTURE en ${environment}`,
    );
  }
});

test("TEST-CNS-466: actorType distinto de FIXTURE no está sujeto a este guard en ningún environment", () => {
  assert.doesNotThrow(() => assertFixtureEnvironment("HUMAN", "PRODUCTION"));
  assert.doesNotThrow(() => assertFixtureEnvironment("SYSTEM_GUARD", "STAGING"));
});
