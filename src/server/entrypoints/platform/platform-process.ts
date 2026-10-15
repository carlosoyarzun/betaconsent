// Gobierna: ADR-010 rev. 4 §4.1 (proceso platform = platform_rw, sin egress), §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; ... pools por rol"), INV-DBR-02; plan PR-6 sub-PR 6a:
// platform "por ahora minimo, sin rutas de login" (login/step-up/sesiones llegan en 6b/6c).
//
// Proceso platform (ENTRYPOINT, ADR-001 §11): un pool UNICO del rol platform_rw con chequeos de arranque (expectedRole = platform_rw, sin privilegios de tabla de platform, EXECUTE solo
// PLATFORM_RUNTIME_EXECUTE) y un servidor HTTP en 127.0.0.1 con UNA ruta: GET /healthz (sin datos). Todo lo demas responde 404 uniforme. No tiene egress (el canje OIDC es del verifier).

import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createPgOidcAuthorization } from "../../../infra/adapters/postgres/oidc-exchange.adapter.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import type { OidcAuthorizationPort } from "../../ports/oidc-exchange.port.ts";
import { handleAuthRoute } from "./auth-routes.ts";
import { loadPlatformSettings } from "./platform-settings.ts";
import type { PlatformSettings } from "./platform-settings.ts";
import { createSlidingLimiter } from "./rate-limit.ts";
import type { SlidingLimiter } from "./rate-limit.ts";
import type { ProcessPool } from "../../../infra/adapters/postgres/runtime-process.ts";

export interface PlatformProcess {
  readonly server: Server;
  readonly pool: ProcessPool;
  readonly port: number;
  readonly settings: PlatformSettings;
  /** P-50 (30/min por operador): limitador listo; se cablea a las rutas autenticadas en PR-6c (no hay sesiones aun). */
  readonly operatorLimiter: SlidingLimiter;
  stop(): Promise<void>;
}

export interface StartPlatformProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** 0 = puerto efimero (tests). Por defecto CNS_PLATFORM_PORT o 8788. */
  readonly port?: number;
}

export interface PlatformHandlerDeps {
  readonly authorization: OidcAuthorizationPort;
  readonly settings: PlatformSettings;
  readonly now?: () => number;
}

export function platformRequestHandler(deps?: PlatformHandlerDeps): Parameters<typeof createServer>[1] {
  const p49 = deps === undefined ? undefined : createSlidingLimiter({ max: deps.settings.p49.max, windowMs: deps.settings.p49.windowSeconds * 1000, ...(deps.now === undefined ? {} : { now: deps.now }) });
  return (req, res) => {
    if (deps !== undefined && p49 !== undefined && (req.url ?? "").startsWith("/platform/")) {
      void handleAuthRoute(req, res, {
        authorization: deps.authorization,
        ...(deps.settings.idp === undefined ? {} : { idp: deps.settings.idp }),
        p49,
        p49WindowSeconds: deps.settings.p49.windowSeconds,
        ipv4Prefix: deps.settings.p49.ipv4Prefix,
        allowedCidrs: deps.settings.allowedCidrs,
        maxAwaiting: deps.settings.maxAwaiting,
        flowTtlSeconds: 600,
      }).then((handled) => {
        if (!handled && !res.headersSent) {
          res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "not_found" }));
        }
      });
      return;
    }
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
  // Configuracion ANTES de abrir el pool: fuera de LOCAL, P-49..P-51/P-53, bind y allowlist son obligatorios (G-6); sin ellos no arranca.
  const settings = loadPlatformSettings(env, environment);
  const pool = await openProcessPool({ process: "platform", environment, env, max: 4 });
  const server = createServer(platformRequestHandler({ authorization: createPgOidcAuthorization(pool), settings }));
  const requested = options.port ?? Number(env.CNS_PLATFORM_PORT ?? 8788);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(requested, settings.bindAddress, () => resolve());
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
    settings,
    operatorLimiter: createSlidingLimiter({ max: settings.p50.max, windowMs: settings.p50.windowSeconds * 1000 }),
    stop: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await pool.end();
    },
  };
}
