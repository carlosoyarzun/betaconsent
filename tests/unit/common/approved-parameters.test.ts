// Gobierna: CA-128, decisiones de Carlos 2026-10-01: P-33 = 24 h, P-10 = 7 dias, TTL handles /i y /m = 10 min
// aplican en cualquier entorno; deliveryChannel (EXT-B) sigue fail-closed. TEST-CNS-932.

import test from "node:test";
import assert from "node:assert/strict";

import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationHandlePolicyConfig } from "../../../src/server/modules/invitation/invitation-handle-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { LOCAL_ONLY_DEV_MANAGE_HANDLE_POLICY } from "../../../src/server/entrypoints/dev-local-config.ts";

test("TEST-CNS-932 parametros aprobados (Carlos, 2026-10-01): P-33 24 h, P-10 7 dias, handle /i y /m 10 min sin override; deliveryChannel sigue fail-closed", () => {
  const saved = { i: process.env.CNS_INVITATION_HANDLE_TTL_MS, p: process.env.CNS_IDEMPOTENCY_TTL_MS };
  delete process.env.CNS_INVITATION_HANDLE_TTL_MS;
  delete process.env.CNS_IDEMPOTENCY_TTL_MS;
  try {
    assert.deepEqual(loadIdempotencyPolicyConfig(), { ttlMs: 24 * 60 * 60_000 });
    assert.deepEqual(loadInvitationHandlePolicyConfig(), { ttlMs: 10 * 60_000 });
    assert.equal(LOCAL_ONLY_DEV_MANAGE_HANDLE_POLICY.ttlMs, 10 * 60_000);
    const policy = loadInvitationIssuancePolicyConfig({ deliveryChannel: "CONSENT_APP_EMAIL" });
    assert.equal(policy.expiresInMs, 7 * 24 * 60 * 60_000);
    assert.throws(() => loadInvitationIssuancePolicyConfig({}), /deliveryChannel/);
  } finally {
    if (saved.i !== undefined) process.env.CNS_INVITATION_HANDLE_TTL_MS = saved.i;
    if (saved.p !== undefined) process.env.CNS_IDEMPOTENCY_TTL_MS = saved.p;
  }
});
