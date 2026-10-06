// Gobierna: CA-138. Registra la suite de contrato de StaffSessionStorePort contra el adaptador in-memory (TEST-CNS-1141, 1142).
// El registro contra Postgres vive en tests/integration/postgres/staff-session.test.ts.

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { runStaffSessionStoreContract } from "./staff-session-store.contract.ts";

runStaffSessionStoreContract((name, body) => {
  test(name, () => body(createInMemoryStaffSessionStore()));
});

test("TEST-CNS-1153 StaffSessionStore in-memory: solo avanza la ultima actividad pasada la granularidad (60 s) y la inactividad sigue correcta", async () => {
  const store = createInMemoryStaffSessionStore();
  const T = "00000000-0000-4000-8000-000000001153";
  const t0 = Date.now();
  await store.create({ tenantId: T, sidHash: "a".repeat(64), principalRef: "staff-synthetic-01", role: "TENANT_ADMIN", issuedAtMs: t0, expiresAtMs: t0 + 8 * 3_600_000 });
  const v = (nowMs: number) => store.validateAndTouch({ tenantId: T, sidHash: "a".repeat(64), principalRef: "staff-synthetic-01", role: "TENANT_ADMIN", nowMs, idleTimeoutMs: 30 * 60_000 });
  assert.equal(await v(t0 + 10_000), true);
  assert.equal(store.rows()[0]!.lastSeenAtMs, t0);
  assert.equal(await v(t0 + 61_000), true);
  assert.equal(store.rows()[0]!.lastSeenAtMs, t0 + 61_000);
  assert.equal(await v(t0 + 61_000 + 30 * 60_000 + 1), false);
});
