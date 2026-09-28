// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-10 (csrf_and_origin), CLAUDE.md
// (UX-CNS-001, Carlos 2026-09-27: /welcome hace el double-submit CSRF en el navegador).
//
// El double-submit exige que el valor de la cookie CSRF sea legible por el JS de la página
// (para copiarlo al header `x-csrf-token`, ver assets/welcome.js); por eso esta cookie NO
// lleva HttpOnly, a diferencia de la cookie de sesión (consent-session.ts, siempre HttpOnly).
// Sigue siendo `__Host-` (Secure, Path=/, sin Domain). SameSite=Lax (SEC-CNS-014 FINDING
// P1-02, Carlos 2026-09-28 opción b): el JS que lee esta cookie corre en una página servida
// tras la navegación GET de nivel superior que sigue a un 303 de canje (GET /r/, /i/, /m/),
// que puede llegar desde fuera del origen de la app; con Strict el navegador la omitía en esa
// primera navegación. Lax sigue sin enviarla en un POST cross-site: un sitio de terceros no
// puede leerla (no HttpOnly la protege de lectura, GRD-CM-10 la protege de uso) ni hacer que el
// navegador la incluya en un POST ajeno.

import { randomBytes } from "node:crypto";

/** Token opaco, sin relación con ningún identificador de dominio (no hace falta firmarlo: el
 * guard de csrf_and_origin (guards.ts) solo compara igualdad byte a byte cookie==header). */
export function generateCsrfToken(): string {
  return randomBytes(24).toString("base64url");
}

/** Serializa el Set-Cookie del token CSRF. `__Host-` exige Secure + Path=/ + sin Domain
 * (RFC 6265bis); SameSite=Lax (SEC-CNS-014 P1-02, ver nota de cabecera de este archivo). */
export function serializeCsrfCookie(csrfCookieName: string, token: string): string {
  return `${csrfCookieName}=${token}; Path=/; Secure; SameSite=Lax`;
}
