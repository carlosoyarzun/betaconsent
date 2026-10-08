// Gobierna: SEC-CNS-017 F1 (P1). Un throw dentro del callback async de createServer no debe matar
// el proceso ni filtrar message/detail de pg: 500 uniforme, proceso vivo. TEST-CNS-877.

import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

import { encodeSession } from "../../../src/server/entrypoints/http/consent-session.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_SECRET = Buffer.alloc(32, 7);
const OTP = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const REL = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

test("TEST-CNS-877: un throw con detail de pg responde 500 uniforme sin message/detail y el servidor sigue vivo", async () => {
  const real = createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const leaky = Object.assign(new Error("SECRETO_MESSAGE row (a@b.test)"), { code: "23505", detail: "Key (email)=(SECRETO_DETAIL) already exists" });
  let armed = false;
  const ports = new Proxy(real, {
    get(target, prop, receiver) {
      if (armed && (prop === "invitation" || prop === "decision" || prop === "otp")) throw leaky;
      return Reflect.get(target, prop, receiver);
    },
  });
  const logs: string[] = [];
  const origError = console.error;
  console.error = (...a: unknown[]) => void logs.push(a.join(" "));
  const server = createConsentFlowHttpServer({ staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: "http://consola-consent.test.localhost" }, ports, environment: "LOCAL", sessionSecret: SESSION_SECRET });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  armed = true;
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const bodies: string[] = [];
    for (const accept of ["application/json", "text/html"]) {
      const res = await fetch(`${base}/invitation/open`, { method: "POST", headers: { "content-type": "application/json", accept, origin: ORIGIN, cookie: `${CSRF_COOKIE_NAME}=csrf-token-abcdefgh; __Host-cns-session=${encodeSession(SESSION_SECRET, { tenantId: "t", invitationRef: "i" } as never)}`, [CSRF_HEADER_NAME]: "csrf-token-abcdefgh" }, body: "{}" });
      assert.equal(res.status, 500);
      bodies.push(await res.text());
    }
    for (const b of bodies) assert.doesNotMatch(b, /SECRETO|23505/);
    assert.match(bodies[0] ?? "", /"code":"INTERNAL_ERROR".*"status":500.*"correlationId"/);
    const after = await fetch(`${base}/__dev/outbox-sink`);
    assert.equal(after.status, 200, "el proceso sigue vivo");
    const joined = logs.join("\n");
    assert.doesNotMatch(joined, /SECRETO/);
    assert.match(joined, /name=Error code=23505/);
  } finally {
    console.error = origError;
    await new Promise((r) => server.close(() => r(undefined)));
  }
});
