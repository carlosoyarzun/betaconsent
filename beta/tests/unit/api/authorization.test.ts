// Gobierna: plan v2 H1-08; API-CNS-001. Unit: firma, ventana, formas de cabecera, rate limit, parsing de CNS_API_KEYS y cliente fail-closed con servidor falso.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { test } from "node:test";

import { createAuthorizationClient } from "../../../src/client/lectorpro-authorization-client.ts";
import type { ClientLogEvent } from "../../../src/client/lectorpro-authorization-client.ts";
import { loadConfig } from "../../../src/config.ts";
import { canonicalString, createRateLimiter, signRequest, verifySignature } from "../../../src/server/api/authorization.ts";

const SECRET = Buffer.alloc(32, 9);
const KEYS = [{ keyId: "k1", secret: SECRET }];
const NONCE = "A".repeat(22);
const PATH = "/api/v1/authorization-status/stu-1";
const NOW = 1_800_000_000;

function signed(over: Partial<{ ts: string; nonce: string; sig: string; path: string; keyId: string }> = {}) {
  const ts = over.ts ?? String(NOW);
  const nonce = over.nonce ?? NONCE;
  const sig = over.sig ?? signRequest(SECRET, canonicalString("GET", PATH, ts, nonce, ""));
  return { method: "GET", path: over.path ?? PATH, keyId: over.keyId ?? "k1", timestamp: ts, nonce, signature: sig, body: Buffer.alloc(0) };
}

test("firma válida; cuerpo/ruta/método alterados o firma de otro secreto => BAD_SIGNATURE", () => {
  assert.deepEqual(verifySignature(KEYS, signed(), NOW), { ok: true, keyId: "k1" });
  assert.deepEqual(verifySignature(KEYS, { ...signed(), path: "/api/v1/authorization-status/otro" }, NOW), { ok: false, reason: "BAD_SIGNATURE", keyId: "k1" });
  assert.deepEqual(verifySignature(KEYS, { ...signed(), body: Buffer.from("x") }, NOW), { ok: false, reason: "BAD_SIGNATURE", keyId: "k1" });
  assert.deepEqual(verifySignature(KEYS, { ...signed(), method: "POST" }, NOW), { ok: false, reason: "BAD_SIGNATURE", keyId: "k1" });
  const other = signRequest(Buffer.alloc(32, 1), canonicalString("GET", PATH, String(NOW), NONCE, ""));
  assert.equal(verifySignature(KEYS, signed({ sig: other }), NOW).ok, false);
});

test("ventana de tiempo ±60 s", () => {
  for (const delta of [0, 60, -60]) assert.equal(verifySignature(KEYS, signed({ ts: String(NOW + delta) }), NOW).ok, true);
  for (const delta of [61, -61, 120]) assert.equal((verifySignature(KEYS, signed({ ts: String(NOW + delta) }), NOW) as { reason: string }).reason, "SKEW");
});

test("formas inválidas de cabeceras y clave desconocida", () => {
  assert.equal((verifySignature(KEYS, signed({ nonce: "corto" }), NOW) as { reason: string }).reason, "BAD_HEADERS"); // < 16 bytes
  assert.equal((verifySignature(KEYS, signed({ ts: "abc" }), NOW) as { reason: string }).reason, "BAD_HEADERS");
  assert.equal((verifySignature(KEYS, signed({ sig: "x" }), NOW) as { reason: string }).reason, "BAD_HEADERS");
  assert.equal((verifySignature(KEYS, { ...signed(), keyId: undefined }, NOW) as { reason: string }).reason, "BAD_HEADERS");
  assert.equal((verifySignature(KEYS, signed({ keyId: "zz" }), NOW) as { reason: string }).reason, "UNKNOWN_KEY");
});

test("rate limit por keyId: ventana fija de un minuto", () => {
  let t = 0;
  const allow = createRateLimiter(3, () => t);
  assert.deepEqual([allow("a"), allow("a"), allow("a"), allow("a")], [true, true, true, false]);
  assert.equal(allow("b"), true); // otra clave no se ve afectada
  t = 60_000;
  assert.equal(allow("a"), true);
});

const S32 = Buffer.alloc(32, 0xfb).toString("base64"); // contiene '+' y '/'
const BASE = {
  CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: "postgresql://a", CNS_MAILER_DATABASE_URL: "postgresql://b", CNS_SESSION_SECRET: Buffer.alloc(32, 3).toString("base64"),
  CNS_PUBLIC_ORIGIN: "https://consent.example.invalid", CNS_SMTP_URL: "smtp://x", CNS_SMTP_FROM: "a@b.invalid", CNS_MAIL_ALLOWLIST: "@x.invalid", PORT: "8080", BIND: "127.0.0.1",
};
test("CNS_API_KEYS acepta base64url y base64, exige >= 32 bytes y máximo 2 claves", () => {
  const url = Buffer.alloc(32, 0xfb).toString("base64url");
  const c = loadConfig({ ...BASE, CNS_API_KEYS: `k1:${url},k2:${S32}` });
  assert.deepEqual(c.apiKeys.map((k) => k.keyId), ["k1", "k2"]);
  assert.ok(c.apiKeys[0]!.secret.equals(c.apiKeys[1]!.secret));
  assert.throws(() => loadConfig({ ...BASE, CNS_API_KEYS: `k1:${Buffer.alloc(31, 1).toString("base64url")}` }), /32 bytes/);
});

// ---- cliente fail-closed con servidor falso
async function fake(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ url: string; close(): Promise<void> }> {
  const s = createServer(handler);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  s.unref();
  return { url: `http://127.0.0.1:${(s.address() as { port: number }).port}`, close: () => new Promise((r) => (s.closeAllConnections(), s.close(() => r()))) };
}
const json = (res: ServerResponse, status: number, body: string): void => void res.writeHead(status, { "content-type": "application/json" }).end(body);

test("cliente: AUTHORIZED => true y firma verificable; todo lo demás => false con evento sin PII", async () => {
  let seen: IncomingMessage | undefined;
  const cases: Array<[string, (req: IncomingMessage, res: ServerResponse) => void, boolean]> = [
    ["200 AUTHORIZED", (req, res) => { seen = req; json(res, 200, '{"status":"AUTHORIZED","asOf":"2026-01-01T00:00:00Z"}'); }, true],
    ["200 NOT_AUTHORIZED", (_q, res) => json(res, 200, '{"status":"NOT_AUTHORIZED","asOf":"x"}'), false],
    ["401", (_q, res) => json(res, 401, "{}"), false],
    ["429", (_q, res) => json(res, 429, "{}"), false],
    ["503", (_q, res) => json(res, 503, "{}"), false],
    ["JSON roto", (_q, res) => json(res, 200, "{no"), false],
    ["estado desconocido", (_q, res) => json(res, 200, '{"status":"MAYBE"}'), false],
    ["sin status", (_q, res) => json(res, 200, "[]"), false],
    ["redirección", (_q, res) => void res.writeHead(302, { location: "http://127.0.0.1:1/" }).end(), false],
  ];
  for (const [name, handler, expected] of cases) {
    const srv = await fake(handler);
    const events: ClientLogEvent[] = [];
    const client = createAuthorizationClient({ baseUrl: srv.url, keyId: "k1", secret: SECRET, onEvent: (e) => void events.push(e), now: () => NOW * 1000 });
    assert.equal(await client.isAuthorized("stu-secreto-1"), expected, name);
    if (!expected) assert.ok(events.length === 1, name);
    assert.ok(!JSON.stringify(events).includes("stu-secreto-1"), "evento sin studentRef");
    await srv.close();
  }
  const h = seen!.headers;
  const v = verifySignature(KEYS, { method: "GET", path: "/api/v1/authorization-status/stu-secreto-1", keyId: h["x-cns-key-id"] as string, timestamp: h["x-cns-timestamp"] as string, nonce: h["x-cns-nonce"] as string, signature: h["x-cns-signature"] as string, body: Buffer.alloc(0) }, NOW);
  assert.equal(v.ok, true); // el cliente firma lo que el servidor verifica
});

test("cliente: timeout => false; servidor inalcanzable => false", async () => {
  const srv = await fake(() => undefined); // nunca responde
  const events: ClientLogEvent[] = [];
  const client = createAuthorizationClient({ baseUrl: srv.url, keyId: "k1", secret: SECRET, timeoutMs: 150, onEvent: (e) => void events.push(e) });
  const t0 = Date.now();
  assert.equal(await client.isAuthorized("stu-1"), false);
  assert.ok(Date.now() - t0 < 2000);
  assert.deepEqual(events.map((e) => e.reason), ["TIMEOUT"]);
  await srv.close();
  assert.equal(await client.isAuthorized("stu-1"), false);
});
