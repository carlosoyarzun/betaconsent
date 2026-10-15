// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7 (apertura de sesiones PLATFORM y CASE), §5.3, §5.4 (P-50), §10 fila PR-6c; G-8 (exchangeRef solo en cookie
// `__Host-` Strict), seguridad rev. c puntos 5 y 6; revision de seguridad de 6b: F-PR6-38 (borrar las cookies state y exchange al abrir sesion); contracts/openapi/consent-platform.openapi.yaml
// (openPlatformSession, openCaseSession, platformLogout, caseSessionLogout).
//
// Rutas POST del proceso platform (platform_rw, sin egress). Reglas comunes:
//  - Solo origen permitido (allowlist CIDR de defensa en profundidad) y SOLO MISMO ORIGEN: `Origin` debe ser exactamente el origen publico de la plataforma; un `Sec-Fetch-Site` presente y distinto de
//    same-origin tambien se rechaza. Cualquier otra cosa = 404 uniforme, ANTES de tocar la base.
//  - El `exchangeRef` y el `state` salen SOLO de las cookies `__Host-` (G-8); la asercion se consume en la base en la misma tx que crea la sesion. El principal sale de la asercion/sesion, nunca de la request.
//  - Cookie de sesion: `__Host-`, Secure, HttpOnly, SameSite=Strict, con el sid que genero la base. Al abrir una sesion se BORRAN las cookies de state y de exchange (F-PR6-38) y se rota (la sesion
//    previa del navegador se revoca en la base). El logout revoca en el servidor y borra las cookies.
//  - P-50: las rutas autenticadas cuentan por el principal de la sesion VALIDADA en la base (30/min); al excederse, 429 uniforme y un evento por ventana (sin IP).
//  - Cualquier fallo, incluido un error de base: 404 uniforme (sin motivo).

import type { IncomingMessage, ServerResponse } from "node:http";
import { PlatformDeniedError } from "../../ports/oidc-exchange.port.ts";
import type { PlatformSessionPort, SessionLifetime } from "../../ports/platform-session.port.ts";
import { CASE_REF_RE, OIDC_EXCHANGE_COOKIE, OIDC_STATE_COOKIE } from "./auth-routes.ts";
import { CASE_SESSION_COOKIE, cookie, expireCookie, json, notFound, p50Allows, parseCookies, PLATFORM_SESSION_COOKIE, tooManyRequests } from "./http-util.ts";
import type { OperatorLimitDeps } from "./http-util.ts";
import type { Cidr, SlidingLimiter } from "./rate-limit.ts";
import { ipInCidrs, truncateIp } from "./rate-limit.ts";

export const SESSION_ROUTES = {
  openPlatform: "/platform/sessions/platform",
  openCase: "/platform/sessions/case",
  platformLogout: "/platform/logout",
  caseLogout: "/platform/case-session/logout",
} as const;

export interface SessionRoutesDeps extends OperatorLimitDeps {
  readonly sessions: PlatformSessionPort;
  readonly lifetime: SessionLifetime;
  readonly allowedCidrs: readonly Cidr[];
  /** P-49 (por IP truncada, en memoria): se aplica a la apertura de sesion PLATFORM y a los logout (mismo limitador que login/callback). */
  readonly p49: SlidingLimiter;
  readonly p49WindowSeconds: number;
  readonly ipv4Prefix: number;
  /** Origen publico de la plataforma (esquema + host + puerto). Ausente = login no configurado: todas las rutas responden 404. */
  readonly publicOrigin: string | undefined;
}

const MAX_BODY_BYTES = 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SID_RE = /^[0-9a-f]{64}$/;

async function readJsonBody(req: IncomingMessage): Promise<unknown | null> {
  const type = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") return null;
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    return null;
  }
}

/** Devuelve true si la ruta fue atendida. El resto cae al 404 del proceso. */
export async function handleSessionRoute(req: IncomingMessage, res: ServerResponse, deps: SessionRoutesDeps): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://platform.invalid");
  const path = url.pathname;
  const known = Object.values(SESSION_ROUTES) as string[];
  if (!known.includes(path)) return false;
  if (req.method !== "POST" || url.search !== "") return notFound(res), true;
  const remote = req.socket.remoteAddress ?? "";
  if (deps.allowedCidrs.length > 0 && !ipInCidrs(remote, deps.allowedCidrs)) return notFound(res), true;
  // Mismo origen (seguridad rev. c, §5.2 paso 5): sin Origin exacto no hay efecto.
  if (deps.publicOrigin === undefined || req.headers.origin !== deps.publicOrigin) return notFound(res), true;
  const site = req.headers["sec-fetch-site"];
  if (site !== undefined && site !== "same-origin") return notFound(res), true;

  // P-49 (seguridad PR-6c): intentos de autenticacion por IP truncada en memoria; solo la apertura de sesion PLATFORM y los logout (la sesion CASE ya exige una sesion PLATFORM validada: P-50).
  if (path !== SESSION_ROUTES.openCase) {
    const d = deps.p49.hit(truncateIp(remote, deps.ipv4Prefix));
    if (!d.allowed) {
      if (d.firstDenial) void deps.authorization.recordLimitEvent({ limitKind: "P-49", windowSeconds: deps.p49WindowSeconds }).catch(() => {});
      return notFound(res), true;
    }
  }
  const cookies = parseCookies(req.headers.cookie);
  const clearFlow = [expireCookie(OIDC_STATE_COOKIE, "Lax"), expireCookie(OIDC_EXCHANGE_COOKIE, "Strict")];
  const sidOf = (name: string): string | undefined => {
    const v = cookies.get(name);
    return v !== undefined && SID_RE.test(v) ? v : undefined;
  };
  try {
    if (path === SESSION_ROUTES.openPlatform) {
      const exchangeRef = cookies.get(OIDC_EXCHANGE_COOKIE);
      const state = cookies.get(OIDC_STATE_COOKIE);
      if (exchangeRef === undefined || state === undefined || !UUID_RE.test(exchangeRef)) return notFound(res), true;
      const sid = await deps.sessions.openPlatformSession({ exchangeRef, state, lifetime: deps.lifetime, previousSid: sidOf(PLATFORM_SESSION_COOKIE) ?? null });
      if (sid === null) return notFound(res), true;
      // F-PR6-38: se borran state y exchange; la sesion nueva rota la previa; una sesion CASE previa del navegador cae (la base revoco las hijas) y su cookie tambien.
      json(res, 200, { status: "platform_session_open" }, [cookie(PLATFORM_SESSION_COOKIE, sid, "Strict", deps.lifetime.absoluteSeconds), ...clearFlow, expireCookie(CASE_SESSION_COOKIE, "Strict")]);
      return true;
    }

    if (path === SESSION_ROUTES.openCase) {
      const platformSid = sidOf(PLATFORM_SESSION_COOKIE);
      if (platformSid === undefined) return notFound(res), true;
      const session = await deps.sessions.validate({ sid: platformSid, kind: "PLATFORM" });
      if (session === null) return notFound(res), true;
      if (!p50Allows(deps, session.principalRef)) return tooManyRequests(res), true;
      const exchangeRef = cookies.get(OIDC_EXCHANGE_COOKIE);
      const state = cookies.get(OIDC_STATE_COOKIE);
      const body = await readJsonBody(req);
      const caseRef = typeof body === "object" && body !== null ? (body as Record<string, unknown>).caseRef : undefined;
      if (exchangeRef === undefined || state === undefined || !UUID_RE.test(exchangeRef) || typeof caseRef !== "string" || !CASE_REF_RE.test(caseRef)) return notFound(res), true;
      const sid = await deps.sessions.openCaseSession({
        exchangeRef, state, caseRef, platformSid, lifetime: deps.lifetime, previousCaseSid: sidOf(CASE_SESSION_COOKIE) ?? null,
      });
      if (sid === null) return notFound(res), true;
      json(res, 200, { status: "case_session_open" }, [cookie(CASE_SESSION_COOKIE, sid, "Strict", deps.lifetime.absoluteSeconds), ...clearFlow]);
      return true;
    }

    // Logout (platform o case): revoca en el servidor aunque la sesion ya haya vencido; P-50 solo si la sesion valida (principal confiable).
    const kind = path === SESSION_ROUTES.platformLogout ? "PLATFORM" : "CASE";
    const sid = sidOf(kind === "PLATFORM" ? PLATFORM_SESSION_COOKIE : CASE_SESSION_COOKIE);
    if (sid === undefined) return notFound(res), true;
    const session = await deps.sessions.validate({ sid, kind });
    if (session !== null && !p50Allows(deps, session.principalRef)) return tooManyRequests(res), true;
    await deps.sessions.revoke({ sid, kind });
    json(res, 200, { status: "logged_out" }, kind === "PLATFORM"
      ? [expireCookie(PLATFORM_SESSION_COOKIE, "Strict"), expireCookie(CASE_SESSION_COOKIE, "Strict")]
      : [expireCookie(CASE_SESSION_COOKIE, "Strict")]);
    return true;
  } catch (error) {
    if (error instanceof PlatformDeniedError) return notFound(res), true;
    return notFound(res), true; // fallo cerrado, sin detalle
  }
}
