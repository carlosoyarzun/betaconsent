// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-10 (csrf_and_origin), CLAUDE.md
// (UX-CNS-001, Carlos 2026-09-27: /welcome hace el double-submit CSRF en el navegador).
//
// El double-submit exige que el valor de la cookie CSRF sea legible por el JS de la página
// (para copiarlo al header `x-csrf-token`, ver assets/welcome.js); por eso esta cookie NO
// lleva HttpOnly, a diferencia de la cookie de sesión (consent-session.ts, siempre HttpOnly).
// Sigue siendo `__Host-` (Secure, Path=/, sin Domain) y SameSite=Strict: un sitio de terceros
// no puede leerla ni hacer que el navegador la envíe en un POST cross-site.

import { randomBytes } from "node:crypto";

/** Token opaco, sin relación con ningún identificador de dominio (no hace falta firmarlo: el
 * guard de csrf_and_origin (guards.ts) solo compara igualdad byte a byte cookie==header). */
export function generateCsrfToken(): string {
  return randomBytes(24).toString("base64url");
}

/** Serializa el Set-Cookie del token CSRF. `__Host-` exige Secure + Path=/ + sin Domain
 * (RFC 6265bis); SameSite=Strict porque solo se envía en navegación de primera parte. */
export function serializeCsrfCookie(csrfCookieName: string, token: string): string {
  return `${csrfCookieName}=${token}; Path=/; Secure; SameSite=Strict`;
}
