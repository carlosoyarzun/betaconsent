// Gobierna: ADR-010 rev. 5 §5.2 pasos 1-2 (login PLATFORM sin principal previo, state, PKCE, max_age=0 + prompt=login, 303 sin code ni ref, no-referrer), G-5 (reautenticacion), G-6 (P-49),
// G-8 (exchangeRef SOLO en cookie `__Host-` Strict; nunca en URL, cuerpo ni headers), F-PR6-18/31; contracts/openapi/consent-platform.openapi.yaml (platformAuthLogin/Callback/ExchangeStatus).
// Rutas del proceso platform (platform_rw, sin egress: el 302 es una redireccion del navegador). Respuestas de error: 404 uniforme (sin motivo). Nombres de cookie ilustrativos (P-26 pendiente).
// PR-6c (§5.2 paso 6, F-PR6-36): `kind=CASE` exige una sesion PLATFORM vigente (cookie `__Host-cns-platform`, validada EN LA BASE con validate_session) y `caseRef` (UUIDv4); la base toma el principal de la
// sesion (no de la request) y guarda solo sha256(caseRef) como target_ref_hash. P-50 (30/min por operador) se aplica a esta ruta autenticada. Las sesiones (open_*_session, logout) estan en session-routes.ts.

import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { OidcAuthorizationPort } from "../../ports/oidc-exchange.port.ts";
import { PlatformDeniedError } from "../../ports/oidc-exchange.port.ts";
import type { PlatformSessionPort } from "../../ports/platform-session.port.ts";
import { COMMON, constantTimeEqual, cookie, notFound, p50Allows, parseCookies, PLATFORM_SESSION_COOKIE, tooManyRequests } from "./http-util.ts";
import type { OperatorLimitDeps } from "./http-util.ts";
import type { Cidr, SlidingLimiter } from "./rate-limit.ts";
import { ipInCidrs, truncateIp } from "./rate-limit.ts";

export const OIDC_STATE_COOKIE = "__Host-cns-oidc";
export const OIDC_EXCHANGE_COOKIE = "__Host-cns-oidc-ex";
/** Ruta de aterrizaje del 303 del callback: sin code ni ref (P2(b)). */
export const AUTH_CONTINUE_PATH = "/platform/auth/continue";

export interface IdpRedirectConfig {
  readonly authorizationEndpoint: string;
  readonly clientId: string;
  readonly redirectUri: string;
}

/** case_ref = UUIDv4 opaco (mismo formato que la base, 0024/0052). */
export const CASE_REF_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface AuthRoutesDeps extends OperatorLimitDeps {
  readonly authorization: OidcAuthorizationPort;
  /** Valida la sesion PLATFORM de `kind=CASE` EN LA BASE (no se confia en la cookie ni en un principal declarado). */
  readonly sessions: PlatformSessionPort;
  /** Ausente = login no configurado: las rutas de login responden 404 (IdP real apagado hasta IT0b). */
  readonly idp?: IdpRedirectConfig;
  /** P-49 por IP truncada, en memoria. */
  readonly p49: SlidingLimiter;
  readonly p49WindowSeconds: number;
  readonly ipv4Prefix: number;
  readonly allowedCidrs: readonly Cidr[];
  /** P-53 (null = sin tope; solo LOCAL). */
  readonly maxAwaiting: number | null;
  readonly flowTtlSeconds: number;
}

/** URL de autorizacion del IdP (G-5: max_age=0 + prompt=login en TODO flujo, login y step-up). `nonce` es el del navegador (login) o el nonce de step-up emitido por la base. */
export function idpAuthorizationUrl(idp: IdpRedirectConfig, flow: { readonly state: string; readonly nonce: string; readonly verifier: string }): URL {
  const target = new URL(idp.authorizationEndpoint);
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: idp.clientId,
    redirect_uri: idp.redirectUri,
    scope: "openid",
    state: flow.state,
    nonce: flow.nonce,
    code_challenge: createHash("sha256").update(flow.verifier, "utf8").digest("base64url"),
    code_challenge_method: "S256",
    max_age: "0",
    prompt: "login",
  })) target.searchParams.set(k, v);
  return target;
}

const b64u = (n: number): string => randomBytes(n).toString("base64url");
const sha256Hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/** Devuelve true si la ruta fue atendida. El resto cae al 404 del proceso. */
export async function handleAuthRoute(req: IncomingMessage, res: ServerResponse, deps: AuthRoutesDeps): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://platform.invalid");
  const path = url.pathname;
  if (req.method !== "GET" || !path.startsWith("/platform/auth/")) return false;
  const remote = req.socket.remoteAddress ?? "";
  // Allowlist de origen (defensa en profundidad; la restriccion de red real es del host): fuera de ella, 404 uniforme.
  if (deps.allowedCidrs.length > 0 && !ipInCidrs(remote, deps.allowedCidrs)) {
    notFound(res);
    return true;
  }

  if (path === AUTH_CONTINUE_PATH) {
    res.writeHead(200, { ...COMMON, "content-type": "application/json" });
    res.end(JSON.stringify({ status: "login_in_progress" })); // marcador: la UI y open_platform_session llegan en 6c
    return true;
  }

  const isLogin = path === "/platform/auth/login";
  const isCallback = path === "/platform/auth/callback";
  const isStatus = path === "/platform/auth/exchange";
  if (!isLogin && !isCallback && !isStatus) {
    notFound(res);
    return true;
  }

  // /login solo por navegacion de nivel superior del propio sitio (o tecleada): Sec-Fetch-Site in {same-origin, none} y Sec-Fetch-Mode = navigate. Un origen ajeno (CSRF de login, <img>, fetch cruzado)
  // o un cliente sin esos headers recibe 404 uniforme, ANTES de tocar P-49 o la base.
  if (isLogin) {
    const site = req.headers["sec-fetch-site"];
    const mode = req.headers["sec-fetch-mode"];
    if ((site !== "same-origin" && site !== "none") || mode !== "navigate") {
      notFound(res);
      return true;
    }
  }

  // P-49: solo login y callback (intentos de autenticacion), por IP truncada en memoria.
  if (isLogin || isCallback) {
    const decision = deps.p49.hit(truncateIp(remote, deps.ipv4Prefix));
    if (!decision.allowed) {
      if (decision.firstDenial) void deps.authorization.recordLimitEvent({ limitKind: "P-49", windowSeconds: deps.p49WindowSeconds }).catch(() => {});
      notFound(res);
      return true;
    }
  }

  try {
    if (isLogin) {
      const kindParam = url.searchParams.get("kind");
      if (deps.idp === undefined || (kindParam !== "PLATFORM" && kindParam !== "CASE")) return notFound(res), true;
      let caseLogin: { readonly sessionSid: string; readonly targetRefHash: string } | undefined;
      if (kindParam === "CASE") {
        // §5.2 paso 6: sesion PLATFORM vigente (validada por la base) y caseRef destino. Sin ellas, 404 uniforme (sin tocar oidc_exchange).
        const caseRef = url.searchParams.get("caseRef") ?? "";
        const platformSid = parseCookies(req.headers.cookie).get(PLATFORM_SESSION_COOKIE);
        if (!CASE_REF_RE.test(caseRef) || platformSid === undefined) return notFound(res), true;
        const session = await deps.sessions.validate({ sid: platformSid, kind: "PLATFORM" });
        if (session === null) return notFound(res), true;
        // P-50: solicitud autenticada del operador (principal de la sesion validada).
        if (!p50Allows(deps, session.principalRef)) return tooManyRequests(res), true;
        caseLogin = { sessionSid: platformSid, targetRefHash: sha256Hex(caseRef) };
      }
      const state = b64u(24);
      const nonce = b64u(24);
      const verifier = b64u(48);
      await deps.authorization.begin({
        kind: caseLogin === undefined ? "LOGIN_PLATFORM" : "LOGIN_CASE",
        state,
        bindingHex: sha256Hex(nonce),
        pkceVerifier: verifier,
        ttlSeconds: deps.flowTtlSeconds,
        maxAwaiting: deps.maxAwaiting,
        ...(caseLogin === undefined ? {} : { sessionSid: caseLogin.sessionSid, targetRefHash: caseLogin.targetRefHash }),
      });
      const target = idpAuthorizationUrl(deps.idp, { state, nonce, verifier });
      res.writeHead(302, { ...COMMON, location: target.toString(), "set-cookie": cookie(OIDC_STATE_COOKIE, state, "Lax", deps.flowTtlSeconds) });
      res.end();
      return true;
    }

    const cookies = parseCookies(req.headers.cookie);
    if (isCallback) {
      const state = url.searchParams.get("state") ?? "";
      const code = url.searchParams.get("code") ?? "";
      const own = cookies.get(OIDC_STATE_COOKIE);
      if (own === undefined || state === "" || code === "" || !constantTimeEqual(own, state)) return notFound(res), true;
      const ref = await deps.authorization.complete({ state, code });
      if (ref === null) return notFound(res), true;
      // 303 a una URL SIN code ni ref; el exchangeRef solo viaja en la cookie Strict (G-8).
      res.writeHead(303, { ...COMMON, location: AUTH_CONTINUE_PATH, "set-cookie": cookie(OIDC_EXCHANGE_COOKIE, ref, "Strict", deps.flowTtlSeconds) });
      res.end();
      return true;
    }

    // isStatus: el ref SOLO se acepta de la cookie Strict (nunca de query, cuerpo ni headers) y se verifica contra state en la base.
    const ref = cookies.get(OIDC_EXCHANGE_COOKIE);
    const state = cookies.get(OIDC_STATE_COOKIE);
    if (ref === undefined || state === undefined || url.search !== "") return notFound(res), true;
    const status = await deps.authorization.status({ exchangeRef: ref, state });
    if (status === null) return notFound(res), true;
    res.writeHead(200, { ...COMMON, "content-type": "application/json" });
    res.end(JSON.stringify({ status }));
    return true;
  } catch (error) {
    if (error instanceof PlatformDeniedError) return notFound(res), true;
    return notFound(res), true; // fallo cerrado, sin detalle
  }
}
