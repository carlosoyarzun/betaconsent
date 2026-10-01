// Gobierna: decisión de Carlos 2026-10-01 (TTL de handles /i y /m = 10 min), CA-128, API-CNS-102. TEST-CNS-968.
import test from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_MANAGE_HANDLE_TTL_MS, loadManageHandlePolicyConfig } from "../../../src/server/modules/revocation/manage-handle-policy.config.ts";

test("TEST-CNS-968: el TTL del handle /m por defecto es 10 min; override explícito y env prevalecen", () => {
  delete process.env.CNS_MANAGE_HANDLE_TTL_MS;
  assert.equal(DEFAULT_MANAGE_HANDLE_TTL_MS, 600_000);
  assert.equal(loadManageHandlePolicyConfig().ttlMs, 600_000);
  assert.equal(loadManageHandlePolicyConfig({ ttlMs: 5_000 }).ttlMs, 5_000);
  process.env.CNS_MANAGE_HANDLE_TTL_MS = "7000";
  try {
    assert.equal(loadManageHandlePolicyConfig().ttlMs, 7_000);
  } finally {
    delete process.env.CNS_MANAGE_HANDLE_TTL_MS;
  }
});
