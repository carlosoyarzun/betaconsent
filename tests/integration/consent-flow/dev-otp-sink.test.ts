// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-13 (fixture_actor_environment,
// aplicado aquí al sink de depuración de dev.ts, no a actorType FIXTURE). GET /__dev/otp-sink
// (src/server/entrypoints/http/consent-flow-server.ts) es una ruta de desarrollo, no una ruta
// del contrato (contracts/openapi/consent-it0.openapi.yaml no la lista): solo puede existir
// con environment=LOCAL; en cualquier otro valor (incluido "no declarado") la ruta no existe.
// TEST-CNS-508 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintetico (GRD-CD-04, decision-relationship.config.ts): estos tests no ejercen
// pasos de decision, pero createDefaultConsentFlowPorts exige la config igual que otpPolicy.
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

async function startServer(environment: "LOCAL" | "DEV" | "STAGING" | "PRODUCTION" | undefined): Promise<{
  baseUrl: string;
  close(): Promise<void>;
}> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports, environment });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

test("TEST-CNS-508: GET /__dev/otp-sink existe (200) en environment=LOCAL y no existe (404) en DEV/STAGING/PRODUCTION ni sin declarar", async () => {
  const local = await startServer("LOCAL");
  try {
    const res = await fetch(`${local.baseUrl}/__dev/otp-sink`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { sent: unknown[] };
    assert.ok(Array.isArray(body.sent));
  } finally {
    await local.close();
  }

  for (const environment of ["DEV", "STAGING", "PRODUCTION", undefined] as const) {
    const harness = await startServer(environment);
    try {
      const res = await fetch(`${harness.baseUrl}/__dev/otp-sink`);
      assert.equal(res.status, 404, `environment=${environment ?? "(sin declarar)"} debe dar 404`);
    } finally {
      await harness.close();
    }
  }
});
