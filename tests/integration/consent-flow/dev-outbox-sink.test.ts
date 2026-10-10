// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-13, CA-127. GET /__dev/outbox-sink
// (consent-flow-server.ts) es una ruta de desarrollo (no está en OpenAPI): solo existe con
// environment=LOCAL; en cualquier otro valor (incluido "no declarado") es 404. Solo expone
// refs opacas y enums. TEST-CNS-696.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

async function startServer(environment: "LOCAL" | "DEV" | "STAGING" | "PRODUCTION" | undefined): Promise<{ baseUrl: string; close(): Promise<void> }> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const server: Server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports, environment });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

test("TEST-CNS-696: GET /__dev/outbox-sink existe (200, {enqueued: []}) en LOCAL y no existe (404) en DEV/STAGING/PRODUCTION ni sin declarar", async () => {
  const local = await startServer("LOCAL");
  try {
    const res = await fetch(`${local.baseUrl}/__dev/outbox-sink`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { enqueued: unknown[] };
    assert.deepEqual(body, { enqueued: [] });
  } finally {
    await local.close();
  }

  for (const environment of ["DEV", "STAGING", "PRODUCTION", undefined] as const) {
    const harness = await startServer(environment);
    try {
      const res = await fetch(`${harness.baseUrl}/__dev/outbox-sink`);
      assert.equal(res.status, 404, `environment=${environment ?? "(sin declarar)"} debe dar 404`);
    } finally {
      await harness.close();
    }
  }
});

test("TEST-CNS-881: storeMode=postgres sin devOutboxSink responde 404 (nunca TypeError del Proxy); con el lector responde sus sobres", async () => {
  for (const [sink, expected] of [[undefined, 404], [async () => [], 200]] as const) {
    const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
    const server: Server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
      config: { allowedOrigin: ALLOWED_ORIGIN },
      ports,
      environment: "LOCAL",
      storeMode: "postgres",
      caseSessions: createInMemoryCaseSessionStore(), // CA-139: storeMode=postgres exige el registro de sesiones CASE
      ...(sink ? { devOutboxSink: sink } : {}),
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    try {
      const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/__dev/outbox-sink`);
      assert.equal(res.status, expected);
    } finally {
      await new Promise((r) => server.close(() => r(undefined)));
    }
  }
});
