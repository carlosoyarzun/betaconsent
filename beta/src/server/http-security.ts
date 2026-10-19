// Gobierna: plan v2 H1-05; DEC "Reconstrucción mínima" (2026-10-19).
// origen: src/server/entrypoints/http/html-security.ts@9345b78 (CSP única, nosniff) y csrf.ts@9345b78 (cookie CSRF double-submit: __Host-, Secure, SameSite=Lax,
// legible por JS porque la SPA la copia a x-csrf-token). Se agregan Referrer-Policy y Cache-Control: no-store, y los nombres de cookie de beta.

import { randomBytes, timingSafeEqual } from "node:crypto";

export const HTML_CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
export const HTML_X_CONTENT_TYPE_OPTIONS = "nosniff";

export const CSRF_COOKIE = "__Host-cns-csrf";
export const CSRF_HEADER = "x-csrf-token";
export const SESSION_COOKIE = "__Host-cns-session";
export const INVITATION_HANDLE_COOKIE = "__Host-cns-i-handle";
export const MANAGE_HANDLE_COOKIE = "__Host-cns-m-handle";

/** Cabeceras de toda respuesta con handle/sesión (HTML, JSON y 303). */
export function securityHeaders(): Record<string, string> {
  return {
    "content-security-policy": HTML_CONTENT_SECURITY_POLICY,
    "x-content-type-options": HTML_X_CONTENT_TYPE_OPTIONS,
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
  };
}

export function generateCsrfToken(): string {
  return randomBytes(24).toString("base64url");
}

export function serializeCsrfCookie(token: string): string {
  return `${CSRF_COOKIE}=${token}; Path=/; Secure; SameSite=Lax`;
}

/** Cookie HttpOnly con prefijo __Host- (Secure, Path=/, sin Domain). */
export function serializeHttpOnlyCookie(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export function serializeClearCookie(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/** Igualdad en tiempo constante de dos cadenas (cookie vs cabecera CSRF). */
export function safeEqual(a: string | undefined, b: string | undefined): boolean {
  if (a === undefined || b === undefined || a === "" || b === "") return false;
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}
