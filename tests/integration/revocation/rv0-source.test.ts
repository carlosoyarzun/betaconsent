// Gobierna: specs/state-machines/revocation.spec.yaml RV0 (guardsBySource), SEC-CNS-013
// N-4c-01, common.spec.yaml GRD-CM-15 (source_from_execution_identity). TEST-CNS-471.

import test from "node:test";
import assert from "node:assert/strict";

import { triggerCaseContactNotice } from "../../../src/server/modules/revocation/rv0-trigger.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import type { ExecutionContext } from "../../../src/server/modules/common/types.ts";

test("TEST-CNS-471: RV0 trigger=CASE_CONTACT desde un POST web (fuente BEARER simulando SYSTEM) se rechaza sin envío ni evento", () => {
  const webPostCtx: ExecutionContext = { source: "BEARER", environment: "LOCAL" };

  assert.throws(
    () => triggerCaseContactNotice(webPostCtx, "CASE_CONTACT"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-10",
  );
});

test("TEST-CNS-471: RV0 trigger=CASE_CONTACT desde la fuente SYSTEM (dentro de la tx de RC2) se acepta", () => {
  const systemCtx: ExecutionContext = { source: "SYSTEM", environment: "LOCAL" };

  const result = triggerCaseContactNotice(systemCtx, "CASE_CONTACT");

  assert.equal(result.sent, true);
});
