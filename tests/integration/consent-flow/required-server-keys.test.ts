// Gobierna: INV-CM-09 / OPEN-CM-10, revision lampone-security P2-6 (continuacion): sessionSecret, otpSecret y
// staffRosterCursorKey obligatorios y explicitos; sin default aleatorio por proceso.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { encodeSession } from "../../../src/server/entrypoints/http/consent-session.ts";
import { loadOtpSecret, loadSessionSecret } from "../../../src/server/entrypoints/http/server-secrets.config.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const OTP = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const REL = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const ORIGIN = "http://consola-consent.test.localhost";
const TENANT_ID = "c4cd7d8a-9578-4558-843e-a79fdab94fba";
const COOKIE = "__Host-cns-session";

function ports(otpSecret: Buffer = TEST_OTP_SECRET) {
  return createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, otpSecret);
}
type Opts = Parameters<typeof createConsentFlowHttpServer>[0];
function make(over: Partial<NonNullable<Opts>> = {}): Server {
  return createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports: ports(),
    environment: "LOCAL",
    sessionSecret: TEST_SESSION_SECRET,
    staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    ...over,
  });
}
function leaks(e: Error, ...keys: Buffer[]): boolean {
  return keys.some((k) => e.message.includes(k.toString("hex")) || e.message.includes(k.toString("base64")) || e.message.includes(k.toString("utf8")));
}

test("TEST-CNS-1249: sin sessionSecret, otpSecret o staffRosterCursorKey el servidor no arranca y el error no contiene claves", () => {
  assert.throws(() => make({ sessionSecret: undefined }), (e: Error) => /sessionSecret es obligatoria \(CNS_SESSION_SECRET\)/.test(e.message) && !leaks(e, TEST_SESSION_SECRET));
  assert.throws(() => make({ staffRosterCursorKey: undefined }), (e: Error) => /staffRosterCursorKey es obligatoria \(CNS_STAFF_ROSTER_CURSOR_SECRET\)/.test(e.message) && !leaks(e, TEST_STAFF_ROSTER_CURSOR_KEY));
  assert.throws(() => createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, undefined as unknown as Buffer), (e: Error) => /otpSecret es obligatoria \(CNS_OTP_SECRET\)/.test(e.message));
  // Sin `ports`: el otpSecret faltante tambien aborta el arranque.
  assert.throws(
    () => createConsentFlowHttpServer({ config: { allowedOrigin: ORIGIN }, otpPolicy: OTP, relationshipConfig: REL, chainRefKey: TEST_CHAIN_REF_KEY, decisionMakerRefKey: TEST_DECISION_MAKER_REF_KEY, environment: "LOCAL", sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY }),
    (e: Error) => /otpSecret es obligatoria/.test(e.message) && !leaks(e, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY),
  );
  // Material demasiado corto: tambien aborta, sin volcarlo.
  const short = Buffer.from("corta-pero-secreta");
  assert.throws(() => make({ sessionSecret: short }), (e: Error) => /al menos 32 bytes/.test(e.message) && !leaks(e, short));
  assert.throws(() => ports(short), (e: Error) => /al menos 32 bytes/.test(e.message) && !leaks(e, short));
});

test("TEST-CNS-1250: con claves explicitas arranca; una clave por proposito (no se reutiliza sesion para OTP ni cursor)", () => {
  assert.ok(make());
  assert.throws(() => make({ ports: ports(TEST_SESSION_SECRET) }), (e: Error) => /claves distintas/.test(e.message) && !leaks(e, TEST_SESSION_SECRET));
  assert.throws(() => make({ staffRosterCursorKey: TEST_SESSION_SECRET }), /claves distintas/);
  assert.throws(() => make({ ports: ports(TEST_STAFF_ROSTER_CURSOR_KEY) }), /claves distintas/);
});

async function listen(server: Server): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise((r) => server.close(() => r())) }));
  });
}

test("TEST-CNS-1251: dos servidores con la misma clave de sesion aceptan la misma cookie; con claves distintas no", async () => {
  const cookie = `${COOKIE}=${encodeSession(TEST_SESSION_SECRET, { tenantId: TENANT_ID, verificationRef: "11111111-1111-4111-8111-111111111111" })}`;
  const a = await listen(make());
  const b = await listen(make({ ports: ports() }));
  const c = await listen(make({ sessionSecret: Buffer.alloc(32, 1), ports: ports() }));
  try {
    assert.equal((await fetch(`${a.baseUrl}/verify`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${b.baseUrl}/verify`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${c.baseUrl}/verify`, { headers: { cookie } })).status, 404);
  } finally {
    await Promise.all([a.close(), b.close(), c.close()]);
  }
});

test("TEST-CNS-1252: loaders CNS_SESSION_SECRET / CNS_OTP_SECRET: obligatorios fuera de LOCAL, base64 estricto >= 32 bytes, sin volcar valores", () => {
  const good = Buffer.alloc(32, 3).toString("base64");
  for (const env of ["DEV", "STAGING", "PRODUCTION", ""]) {
    assert.throws(() => loadSessionSecret({}, env, () => Buffer.alloc(32)), /CNS_SESSION_SECRET es obligatorio fuera de LOCAL/);
    assert.throws(() => loadOtpSecret({ CNS_OTP_SECRET: "" }, env, () => Buffer.alloc(32)), /CNS_OTP_SECRET es obligatorio fuera de LOCAL/);
  }
  assert.deepEqual(loadSessionSecret({ CNS_SESSION_SECRET: good }, "PRODUCTION", () => Buffer.alloc(32)), Buffer.alloc(32, 3));
  assert.deepEqual(loadOtpSecret({ CNS_OTP_SECRET: good }, "LOCAL", () => Buffer.alloc(32)), Buffer.alloc(32, 3));
  // LOCAL sin variable: el fallback lo aporta el caller (explicito en dev.ts), no el modulo.
  assert.deepEqual(loadSessionSecret({}, "LOCAL", () => Buffer.alloc(32, 4)), Buffer.alloc(32, 4));
  const bad = ["!!!no-base64!!!", Buffer.alloc(16, 1).toString("base64"), `${good}\u0000x`];
  for (const raw of bad) {
    assert.throws(() => loadSessionSecret({ CNS_SESSION_SECRET: raw }, "PRODUCTION", () => Buffer.alloc(32)), (e: Error) => /base64 valido de al menos 32 bytes/.test(e.message) && !e.message.includes(raw));
  }
});
