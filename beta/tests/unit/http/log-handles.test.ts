// Gobierna: plan v2 H1-05. Logger sin PII, normalización de rutas, codecs firmados y token de gestión.
import assert from "node:assert/strict";
import { test } from "node:test";

import { createCodecs, hashLinkToken, signManageToken, verifyManageToken } from "../../../src/server/handles.ts";
import { createJsonLogger, normalizeRoute } from "../../../src/server/log.ts";

test("normalizeRoute oculta tokens, assets y rutas desconocidas", () => {
  assert.equal(normalizeRoute("/i/SECRETO123"), "/i/:token");
  assert.equal(normalizeRoute("/m/m1.con-x.1.mac"), "/m/:token");
  assert.equal(normalizeRoute("/r/abc"), "/r/:token");
  assert.equal(normalizeRoute("/assets/app-1234.js"), "/assets/:file");
  assert.equal(normalizeRoute("/otp/submit"), "/otp/submit");
  assert.equal(normalizeRoute("/cualquier/cosa/pii@x.cl"), "/other");
});

test("el logger emite una línea JSON por llamada", () => {
  const lines: string[] = [];
  createJsonLogger((l) => lines.push(l), () => new Date("2026-10-19T00:00:00Z")).info("request", { method: "GET", status: 200 });
  assert.deepEqual(JSON.parse(lines[0]!), { ts: "2026-10-19T00:00:00.000Z", level: "info", msg: "request", method: "GET", status: 200 });
});

test("codecs: firma inválida, otra clave y vencimiento => null", () => {
  const c = createCodecs(Buffer.alloc(48, 1));
  const other = createCodecs(Buffer.alloc(48, 2));
  const now = Math.floor(Date.now() / 1000);
  const h = c.invitation.encode({ h: hashLinkToken("t"), exp: now + 60 });
  assert.ok(c.invitation.decode(h));
  assert.equal(other.invitation.decode(h), null);
  assert.equal(c.invitation.decode(h.slice(0, -2) + "xx"), null);
  assert.equal(c.invitation.decode(c.invitation.encode({ h: hashLinkToken("t"), exp: now - 1 })), null);
  // las claves por uso son independientes: un handle de invitación no vale como sesión
  assert.equal(c.session.decode(h), null);
});

test("token de gestión: válido, manipulado y vencido", () => {
  const s = Buffer.alloc(48, 9);
  const now = Math.floor(Date.now() / 1000);
  const t = signManageToken(s, "con-123e4567-e89b", now + 60);
  assert.equal(verifyManageToken(s, t), "con-123e4567-e89b");
  assert.equal(verifyManageToken(s, t + "x"), null);
  assert.equal(verifyManageToken(Buffer.alloc(48, 8), t), null);
  assert.equal(verifyManageToken(s, signManageToken(s, "con-123e4567-e89b", now - 1)), null);
  assert.equal(verifyManageToken(s, "basura"), null);
});
