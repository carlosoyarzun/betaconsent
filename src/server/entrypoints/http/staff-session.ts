// Gobierna: contracts/openapi/consent-it0.openapi.yaml securitySchemes.staffSession
// (__Host-cns-staff, "Sesión de consola STAFF con membership TENANT vigente (GRD-CM-01/02/07)";
// x-pending: "P-26 (nombre de cookie)", "LD-03"). CA-125. Decisión de Carlos, 2026-09-28,
// opción (ii): sin IdP real (APR-IDP PENDING); esta sesión la emite únicamente el endpoint de
// desarrollo /__dev/staff-login (LOCAL-only, GRD-CM-13), a partir del roster sintético de
// StaffIdentityPort. Mismo patrón que case-session.ts, con clave HKDF propia (info distinto de
// consent-session, recovery-handle, link-handle y case-session): comprometer una firma nunca
// compromete las demás. El payload SOLO lleva refs opacas sintéticas; cero PII.
//
// LEGAL DECISION LD-03 (quién opera RC0 y con qué base) y APR-IDP no se resuelven aquí.

import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

import type { StaffRole } from "../../ports/staff-identity.port.ts";

const STAFF_SESSION_HKDF_INFO = "CNS-STAFF-SESSION-v1";
const KNOWN_ROLES: readonly StaffRole[] = ["TENANT_ADMIN", "RIGHTS_OPERATOR", "APPROVER"];

export interface StaffSessionPayload {
  /** tenant_id de la membership, fijado por el servidor al emitir la sesión (GRD-CM-01). */
  readonly tenantId: string;
  /** Ref opaca sintética del principal; nunca PII. */
  readonly principalRef: string;
  readonly role: StaffRole;
}

export function deriveStaffSessionKey(sessionSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sessionSecret, Buffer.alloc(0), STAFF_SESSION_HKDF_INFO, 32));
}

function sign(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
}

export function encodeStaffSession(key: Buffer, payload: StaffSessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/** Cualquier fallo (formato, firma, JSON, campos) devuelve null: "sin sesión STAFF" (404
 * uniforme, GRD-CM-01), nunca un error distinguible. */
export function decodeStaffSession(key: Buffer, cookieValue: string | undefined): StaffSessionPayload | null {
  if (!cookieValue) return null;
  const dot = cookieValue.indexOf(".");
  if (dot === -1) return null;
  const body = cookieValue.slice(0, dot);
  const mac = cookieValue.slice(dot + 1);
  if (!timingSafeEqualStrings(mac, sign(key, body))) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    if (typeof record.tenantId !== "string" || record.tenantId.length === 0) return null;
    if (typeof record.principalRef !== "string" || record.principalRef.length === 0) return null;
    if (typeof record.role !== "string" || !KNOWN_ROLES.includes(record.role as StaffRole)) return null;
    return { tenantId: record.tenantId, principalRef: record.principalRef, role: record.role as StaffRole };
  } catch {
    return null;
  }
}

/** `Set-Cookie` de `__Host-cns-staff`: HttpOnly, Secure, Path=/, SameSite=Lax (mismo criterio que
 * las demás cookies de sesión de este repo). */
export function serializeStaffSessionCookie(cookieName: string, value: string): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
