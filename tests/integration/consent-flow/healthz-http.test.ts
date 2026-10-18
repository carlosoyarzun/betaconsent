// Gobierna: despliegue manual en modo sintetico (PR-F, orden de Carlos 2026-10-18; ADR-003 rev. 7 host propio). GET /healthz del proceso web:
// liveness sin tocar la base, sin cookies ni estado y sin datos; solo GET. Mismo contrato que GET /healthz del proceso platform.

import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY, TEST_GUEST_CHANNEL } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-consent.test.localhost";

async function withServer(fn: (base: string) => Promise<void>): Promise<void> {
  const server = createConsentFlowHttpServer({
    guestMessageChannel: TEST_GUEST_CHANNEL,
    config: { allowedOrigin: ORIGIN },
    ports: createDefaultConsentFlowPorts({ codeLength: 6, maxAttempts: 3, ttlMs: 60_000 }, { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] }, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET),
    environment: "LOCAL",
    sessionSecret: TEST_SESSION_SECRET,
    staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
  } as never);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("TEST-CNS-2062: GET /healthz responde 200 JSON {status:ok} sin cookies, sin cache y sin datos", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/healthz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("set-cookie"), null);
    assert.deepEqual(await res.json(), { status: "ok", process: "web" });
  });
});

test("TEST-CNS-2063: /healthz solo admite GET (POST no responde 200)", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/healthz`, { method: "POST", headers: { origin: ORIGIN } });
    assert.notEqual(res.status, 200);
  });
});
