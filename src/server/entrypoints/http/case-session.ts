// Gobierna: contracts/openapi/consent-it0.openapi.yaml securitySchemes.caseSession
// (__Host-cns-case, "Sesión CASE del RIGHTS_OPERATOR ligada a un caseRef"; x-pending: "P-26
// (nombre de cookie)", "APR-IDP"). CA-128 (API-CNS-138). Decisión de Carlos, 2026-09-28, opción
// (ii): IT0 no tiene IdP real (APR-IDP PENDING — Carlos / studio); esta sesión la emite
// únicamente el endpoint de desarrollo /__dev/staff-login (case-confirmation.handler.ts,
// LOCAL-only, mismo guard GRD-CM-13 que /__dev/otp-sink), nunca un IdP de terceros.
//
// Mismo patrón que recovery-handle.ts: cookie opaca `<base64url(json)>.<hmac>` firmada con
// HMAC-SHA256 usando una clave HKDF propia derivada de `sessionSecret` con un `info` distinto
// de cualquier otra cookie de este repo (consent-session.ts, recovery-handle.ts), para que
// comprometer una firma nunca comprometa las demás. El payload SOLO lleva refs opacas
// sintéticas (p. ej. "staff-synthetic-01"): cero PII (nunca email, nombre ni sub del IdP).
//
// LEGAL DECISION LD-03 (revocation.spec.yaml): quién tiene autoridad legal para registrar la
// confirmación de RH3 NO se resuelve aquí ni en ningún archivo de este repo; esta sesión solo
// modela el piso técnico (rol RIGHTS_OPERATOR vs. APPROVER) que GRD-CM-07/GRD-RC-15 exigen.

import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import type { StaffRole } from "../../ports/staff-identity.port.ts";

const CASE_SESSION_HKDF_INFO = "CNS-CASE-SESSION-v1";

export interface CaseSessionPayload {
  readonly tenantId: string;
  readonly caseRef: string;
  /** Ref opaca sintética del principal de plataforma; nunca PII (P-26 pendiente de nombre exacto
   * de cookie/cabecera, no de este campo). */
  readonly principalRef: string;
  readonly role: StaffRole;
}

/** Clave propia de la sesión CASE, nunca la de consent-session.ts ni la de recovery-handle.ts. */
export function deriveCaseSessionKey(sessionSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sessionSecret, Buffer.alloc(0), CASE_SESSION_HKDF_INFO, 32));
}

function sign(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
}

export function encodeCaseSession(key: Buffer, payload: CaseSessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/**
 * Verifica y decodifica la sesión CASE. Cualquier fallo (formato, firma, JSON, campos
 * inválidos) devuelve `null`; el llamador SIEMPRE lo trata como "sin sesión CASE" (404
 * uniforme, GRD-CM-01), nunca como un error distinguible (mismo criterio que decodeSession y
 * decodeRecoveryHandle).
 */
export function decodeCaseSession(key: Buffer, cookieValue: string | undefined): CaseSessionPayload | null {
  if (!cookieValue) return null;
  const dot = cookieValue.indexOf(".");
  if (dot === -1) return null;
  const body = cookieValue.slice(0, dot);
  const mac = cookieValue.slice(dot + 1);
  if (!timingSafeEqualStrings(mac, sign(key, body))) return null;
  try {
    const json = Buffer.from(body, "base64url").toString("utf8");
    const parsed = JSON.parse(json) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    if (typeof record.tenantId !== "string" || record.tenantId.length === 0) return null;
    if (typeof record.caseRef !== "string" || record.caseRef.length === 0) return null;
    if (typeof record.principalRef !== "string" || record.principalRef.length === 0) return null;
    if (record.role !== "RIGHTS_OPERATOR" && record.role !== "APPROVER") return null;
    return { tenantId: record.tenantId, caseRef: record.caseRef, principalRef: record.principalRef, role: record.role };
  } catch {
    return null;
  }
}

/** `Set-Cookie` de `__Host-cns-case`: HttpOnly (nunca legible por JS, mismo criterio que la
 * cookie de sesión de consent-session.ts), Secure + Path=/ (prefijo `__Host-`), SameSite=Lax
 * (mismo criterio P1-02 que el resto de las cookies de sesión de este repo). */
export function serializeCaseSessionCookie(cookieName: string, value: string): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
