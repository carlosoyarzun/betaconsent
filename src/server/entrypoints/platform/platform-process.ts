// Gobierna: ADR-010 rev. 4 §4.1 (proceso platform = platform_rw, sin egress), §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; ... pools por rol"), INV-DBR-02; plan PR-6 sub-PR 6a:
// platform "por ahora minimo, sin rutas de login" (login/step-up/sesiones llegan en 6b/6c).
//
// Proceso platform (ENTRYPOINT, ADR-001 §11): un pool UNICO del rol platform_rw con chequeos de arranque (expectedRole = platform_rw, sin privilegios de tabla de platform, EXECUTE solo
// PLATFORM_RUNTIME_EXECUTE) y un servidor HTTP con GET /healthz (sin datos), las rutas de login (GET /platform/auth/*, PR-6b) y las de sesion (POST /platform/sessions/*, /platform/logout,
// /platform/case-session/logout; PR-6c, ADR-010 rev. 5 §5.2). Todo lo demas responde 404 uniforme. No tiene egress (el canje OIDC es del verifier). `/platform/*` se sirve SOLO aqui.

import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createPgOidcAuthorization } from "../../../infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPgPlatformSessionStore } from "../../../infra/adapters/postgres/platform-session.adapter.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import type { OidcAuthorizationPort } from "../../ports/oidc-exchange.port.ts";
import type { PlatformSessionPort } from "../../ports/platform-session.port.ts";
import { handleAuthRoute } from "./auth-routes.ts";
import { handleSessionRoute } from "./session-routes.ts";
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
  /** P-50 (30/min por operador): el MISMO limitador que usan las rutas autenticadas (login CASE, sesiones CASE, logout), por principal de la sesion validada. */
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
  readonly sessions: PlatformSessionPort;
  readonly settings: PlatformSettings;
  readonly now?: () => number;
  /** P-50 compartido (el proceso lo expone en `operatorLimiter`); por defecto se crea uno desde `settings.p50`. */
  readonly p50?: SlidingLimiter;
}

export function platformRequestHandler(deps?: PlatformHandlerDeps): Parameters<typeof createServer>[1] {
  const p49 = deps === undefined ? undefined : createSlidingLimiter({ max: deps.settings.p49.max, windowMs: deps.settings.p49.windowSeconds * 1000, ...(deps.now === undefined ? {} : { now: deps.now }) });
  const p50 = deps === undefined ? undefined : (deps.p50 ?? createSlidingLimiter({ max: deps.settings.p50.max, windowMs: deps.settings.p50.windowSeconds * 1000, ...(deps.now === undefined ? {} : { now: deps.now }) }));
  return (req, res) => {
    if (deps !== undefined && p49 !== undefined && p50 !== undefined && (req.url ?? "").startsWith("/platform/")) {
      // Promise.resolve().then(...): tambien una excepcion SINCRONA al armar las dependencias cae en el .catch (no tumba el proceso).
      void Promise.resolve().then(async () => (await handleAuthRoute(req, res, {
        authorization: deps.authorization,
        sessions: deps.sessions,
        ...(deps.settings.idp === undefined ? {} : { idp: deps.settings.idp }),
        p49,
        p49WindowSeconds: deps.settings.p49.windowSeconds,
        ipv4Prefix: deps.settings.p49.ipv4Prefix,
        allowedCidrs: deps.settings.allowedCidrs,
        maxAwaiting: deps.settings.maxAwaiting,
        flowTtlSeconds: 600,
        p50,
        p50WindowSeconds: deps.settings.p50.windowSeconds,
      })) || (await handleSessionRoute(req, res, {
        authorization: deps.authorization,
        sessions: deps.sessions,
        lifetime: deps.settings.session,
        allowedCidrs: deps.settings.allowedCidrs,
        p49,
        p49WindowSeconds: deps.settings.p49.windowSeconds,
        ipv4Prefix: deps.settings.p49.ipv4Prefix,
        publicOrigin: deps.settings.publicOrigin,
        p50,
        p50WindowSeconds: deps.settings.p50.windowSeconds,
      }))).then((handled) => {
        if (!handled && !res.headersSent) {
          res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "not_found" }));
        }
      }).catch(() => {
        // Una excepcion inesperada del handler NO tumba el proceso (unhandledRejection): 404 uniforme, sin detalle; si ya se enviaron headers, se corta la respuesta.
        if (!res.headersSent) {
          res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "not_found" }));
        } else {
          res.destroy();
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
  const operatorLimiter = createSlidingLimiter({ max: settings.p50.max, windowMs: settings.p50.windowSeconds * 1000 });
  const server = createServer(platformRequestHandler({ authorization: createPgOidcAuthorization(pool), sessions: createPgPlatformSessionStore(pool), settings, p50: operatorLimiter }));
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
    operatorLimiter,
    stop: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await pool.end();
    },
  };
}
