// Gobierna: ADR-010 rev. 4 §4.1 (proceso platform = platform_rw, sin egress), §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; ... pools por rol"), INV-DBR-02; plan PR-6 sub-PR 6a:
// platform "por ahora minimo, sin rutas de login" (login/step-up/sesiones llegan en 6b/6c).
//
// Proceso platform (ENTRYPOINT, ADR-001 §11): un pool UNICO del rol platform_rw con chequeos de arranque (expectedRole = platform_rw, sin privilegios de tabla de platform, EXECUTE solo
// PLATFORM_RUNTIME_EXECUTE) y un servidor HTTP en 127.0.0.1 con UNA ruta: GET /healthz (sin datos). Todo lo demas responde 404 uniforme. No tiene egress (el canje OIDC es del verifier).

import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import type { ProcessPool } from "../../../infra/adapters/postgres/runtime-process.ts";

export interface PlatformProcess {
  readonly server: Server;
  readonly pool: ProcessPool;
  readonly port: number;
  stop(): Promise<void>;
}

export interface StartPlatformProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** 0 = puerto efimero (tests). Por defecto CNS_PLATFORM_PORT o 8788. */
  readonly port?: number;
}

export function platformRequestHandler(): Parameters<typeof createServer>[1] {
  return (req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (req.method === "GET" && path === "/healthz") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ status: "ok", process: "platform" }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ error: "not_found" }));
  };
}

/** Arranque fail-closed: environment (enum cerrado) -> pool de platform_rw con chequeos de arranque -> escuchar. Si algo falla, no se escucha. */
export async function startPlatformProcess(options: StartPlatformProcessOptions = {}): Promise<PlatformProcess> {
  const env = options.env ?? process.env;
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const pool = await openProcessPool({ process: "platform", environment, env, max: 4 });
  const server = createServer(platformRequestHandler());
  const requested = options.port ?? Number(env.CNS_PLATFORM_PORT ?? 8788);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(requested, "127.0.0.1", () => resolve());
    });
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    pool,
    port,
    stop: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await pool.end();
    },
  };
}
