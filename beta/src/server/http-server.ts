// Gobierna: plan v2 H1-05. Servidor node:http con timeouts, límite de cuerpo (en app.ts), proxy de confianza solo desde loopback y cierre ordenado.
import { createServer } from "node:http";
import type { IncomingMessage, Server } from "node:http";

import type { App } from "./app.ts";
import type { Logger } from "./log.ts";

export interface HttpServerOptions {
  readonly app: App;
  readonly bind: string;
  readonly port: number;
  readonly logger: Logger;
  readonly requireSecure: boolean;
}

export interface RunningServer {
  readonly server: Server;
  readonly port: number;
  /** Deja de aceptar, espera las peticiones en vuelo (<= graceMs) y cierra el resto. */
  close(graceMs?: number): Promise<void>;
}

const isLoopback = (a: string | undefined): boolean => a === "127.0.0.1" || a === "::1" || a === "::ffff:127.0.0.1";

/** Esquema efectivo: X-Forwarded-Proto solo se respeta si la conexión viene de loopback (proxy de confianza local). */
export function effectiveProtocol(req: IncomingMessage): "http" | "https" {
  if ((req.socket as { encrypted?: boolean }).encrypted) return "https";
  const xf = req.headers["x-forwarded-proto"];
  return isLoopback(req.socket.remoteAddress) && (Array.isArray(xf) ? xf[0] : xf) === "https" ? "https" : "http";
}

export function startHttpServer(opts: HttpServerOptions): Promise<RunningServer> {
  let inflight = 0;
  const server = createServer((req, res) => {
    inflight += 1;
    res.on("close", () => {
      inflight -= 1;
    });
    // REAL exige TLS delante (proxy en loopback con X-Forwarded-Proto: https); /healthz queda exento.
    if (opts.requireSecure && effectiveProtocol(req) !== "https" && !(req.url ?? "").startsWith("/healthz")) {
      res.writeHead(421, { "cache-control": "no-store" });
      res.end();
      return;
    }
    void opts.app.handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, opts.bind, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : opts.port;
      resolve({
        server,
        port,
        close(graceMs = 10_000) {
          return new Promise<void>((done) => {
            const timer = setTimeout(() => {
              server.closeAllConnections();
            }, graceMs);
            server.close(() => {
              clearTimeout(timer);
              done();
            });
            server.closeIdleConnections();
            const poll = setInterval(() => {
              if (inflight === 0) server.closeIdleConnections();
            }, 50);
            poll.unref();
          });
        },
      });
    });
  });
}
