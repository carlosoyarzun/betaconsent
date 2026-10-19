// Gobierna: plan v2 H1-05. Cierre ordenado: la petición en vuelo termina, las nuevas conexiones se rechazan, y el cierre respeta el tope.
import assert from "node:assert/strict";
import { test } from "node:test";

import { startHttpServer, effectiveProtocol } from "../../../src/server/http-server.ts";
import { createJsonLogger } from "../../../src/server/log.ts";

const logger = createJsonLogger(() => undefined);

test("close(): espera la petición en vuelo y luego rechaza conexiones nuevas", async () => {
  const app = {
    async handle(_req: unknown, res: import("node:http").ServerResponse) {
      await new Promise((r) => setTimeout(r, 400));
      res.writeHead(200, { "content-length": "2" });
      res.end("ok");
    },
  };
  const running = await startHttpServer({ app, bind: "127.0.0.1", port: 0, logger, requireSecure: false });
  const url = `http://127.0.0.1:${running.port}/slow`;
  const inflight = fetch(url).then((r) => r.text());
  await new Promise((r) => setTimeout(r, 100));
  const t0 = Date.now();
  const closing = running.close(5000);
  assert.equal(await inflight, "ok", "la petición en vuelo se completa");
  await closing;
  assert.ok(Date.now() - t0 < 4000);
  await assert.rejects(fetch(url));
});

test("close(): corta lo que no termina dentro del tope", async () => {
  const app = { async handle() { await new Promise((r) => setTimeout(r, 10_000)); } };
  const running = await startHttpServer({ app, bind: "127.0.0.1", port: 0, logger, requireSecure: false });
  const pending = fetch(`http://127.0.0.1:${running.port}/x`).catch(() => "cortada");
  await new Promise((r) => setTimeout(r, 100));
  const t0 = Date.now();
  await running.close(300);
  assert.ok(Date.now() - t0 < 3000);
  assert.equal(await pending, "cortada");
});

test("X-Forwarded-Proto solo se respeta desde loopback", () => {
  const mk = (addr: string, xf?: string) => ({ socket: { remoteAddress: addr }, headers: xf ? { "x-forwarded-proto": xf } : {} }) as never;
  assert.equal(effectiveProtocol(mk("127.0.0.1", "https")), "https");
  assert.equal(effectiveProtocol(mk("::1", "https")), "https");
  assert.equal(effectiveProtocol(mk("10.0.0.5", "https")), "http");
  assert.equal(effectiveProtocol(mk("127.0.0.1")), "http");
});
