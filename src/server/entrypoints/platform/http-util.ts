// Gobierna: ADR-010 rev. 5 §5.2 (cookies `__Host-`, 404 uniforme, no-referrer), G-8, seguridad rev. c punto 5; contracts/openapi/consent-platform.openapi.yaml (securitySchemes). Utilidades HTTP
// compartidas por las rutas del proceso platform (auth-routes.ts y session-routes.ts). Sin estado; nada se registra (ni cookies, ni sids, ni IP).

import { randomUUID, timingSafeEqual } from "node:crypto";
import type { ServerResponse } from "node:http";
import { isServiceUnavailableError } from "../../../infra/adapters/postgres/transient-error.ts";
import { PlatformUnavailableError } from "../../ports/oidc-exchange.port.ts";
import type { OidcAuthorizationPort } from "../../ports/oidc-exchange.port.ts";
import type { SlidingLimiter } from "./rate-limit.ts";

/** Cookies de sesion (nombres del contrato consent-platform.openapi.yaml, ilustrativos hasta P-26). `__Host-`, Secure, HttpOnly, SameSite=Strict. El valor es el sid opaco generado por la base. */
export const PLATFORM_SESSION_COOKIE = "__Host-cns-platform";
export const CASE_SESSION_COOKIE = "__Host-cns-case";

export const COMMON = { "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" } as const;

export type SameSite = "Lax" | "Strict";

export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    if (!out.has(name)) out.set(name, part.slice(i + 1).trim());
  }
  return out;
}

/** Cookie `__Host-` (Secure, HttpOnly, Path=/, sin Domain). */
export function cookie(name: string, value: string, sameSite: SameSite, maxAgeSeconds: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAgeSeconds}`;
}

/** Borra una cookie `__Host-` en el navegador (mismos atributos que al fijarla, Max-Age=0 y valor vacio). */
export function expireCookie(name: string, sameSite: SameSite): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=0`;
}

export function constantTimeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

export function notFound(res: ServerResponse): void {
  res.writeHead(404, { ...COMMON, "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
}

/** ADR-010 PR-7a (F-PR7-10, T-10): el borde responde 503 uniforme (mismo cuerpo para cualquier ruta o recurso, con correlationId opaco) ante la indisponibilidad de la base; nunca 404 (no es "no existe"). */
export function serviceUnavailable(res: ServerResponse): void {
  res.writeHead(503, { ...COMMON, "content-type": "application/json" });
  res.end(JSON.stringify({ code: "SERVICE_UNAVAILABLE", status: 503, correlationId: randomUUID() }));
}

/** true = el error es indisponibilidad de infraestructura (PlatformUnavailableError o SQLSTATE/socket de indisponibilidad): el llamador responde `serviceUnavailable`. */
export function isUnavailable(error: unknown): boolean {
  return error instanceof PlatformUnavailableError || isServiceUnavailableError(error);
}

/** Rechazo temporal de un limite autenticado (P-50): sin revelar cual limite. */
export function tooManyRequests(res: ServerResponse): void {
  res.writeHead(429, { ...COMMON, "content-type": "application/json", "retry-after": "60" });
  res.end(JSON.stringify({ error: "rate_limited" }));
}

export function json(res: ServerResponse, status: number, body: unknown, setCookies: readonly string[] = []): void {
  res.writeHead(status, { ...COMMON, "content-type": "application/json", ...(setCookies.length === 0 ? {} : { "set-cookie": [...setCookies] }) });
  res.end(JSON.stringify(body));
}

/** P-50 (G-6): solicitudes autenticadas por operador en memoria (ventana deslizante). Sin IP; al excederse, un solo evento por principal y ventana (platform.record_limit_event). */
export interface OperatorLimitDeps {
  readonly p50: SlidingLimiter;
  readonly p50WindowSeconds: number;
  readonly authorization: Pick<OidcAuthorizationPort, "recordLimitEvent">;
}

/** true = permitida. La clave es el principal de la sesion VALIDADA en la base, nunca un valor de la request. */
export function p50Allows(deps: OperatorLimitDeps, principalRef: string): boolean {
  const decision = deps.p50.hit(principalRef);
  if (decision.allowed) return true;
  if (decision.firstDenial) void deps.authorization.recordLimitEvent({ limitKind: "P-50", windowSeconds: deps.p50WindowSeconds, principalRef }).catch(() => {});
  return false;
}
