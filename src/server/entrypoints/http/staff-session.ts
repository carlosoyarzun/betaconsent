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

// CA-138 (Carlos, 2026-10-05; SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3): la cookie ya NO es un HMAC sin vida. Lleva `sid`
// (aleatorio, 256 bits), `iat` y `exp` (absoluta); el servidor guarda además un registro por sid (StaffSessionStorePort) que
// permite REVOCAR (logout) y expirar por INACTIVIDAD. El token CSRF, el cursor de API-CNS-116 y la cookie flash se ligan al
// sid. Los valores de vida estan aprobados (approved-parameters.ts, Carlos 2026-10-05).

import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

import { APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS, APPROVED_STAFF_SESSION_PURGE_RETENTION_MS } from "../../modules/common/approved-parameters.ts";
import type { StaffRole } from "../../ports/staff-identity.port.ts";
import type { StaffSessionStorePort } from "../../ports/staff-session-store.port.ts";

export const STAFF_SESSION_HKDF_INFO = "CNS-STAFF-SESSION-v1";
export const STAFF_CSRF_HKDF_INFO = "CNS-STAFF-CSRF-v1";
const KNOWN_ROLES: readonly StaffRole[] = ["TENANT_ADMIN", "RIGHTS_OPERATOR", "APPROVER"];
/** sid: 32 bytes aleatorios (256 bits >= 128) en base64url (43 caracteres). */
const SID_BYTES = 32;
const SID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface StaffSessionPayload {
  /** Identificador de sesion aleatorio (256 bits). Solo la cookie lo lleva en claro; el servidor guarda su hash. */
  readonly sid: string;
  /** tenant_id de la membership, fijado por el servidor al emitir la sesión (GRD-CM-01). */
  readonly tenantId: string;
  /** Ref opaca sintética del principal; nunca PII. */
  readonly principalRef: string;
  readonly role: StaffRole;
  /** Emision y expiracion ABSOLUTA (ms epoch, reloj del servidor). */
  readonly iat: number;
  readonly exp: number;
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

export function newStaffSid(): string {
  return randomBytes(SID_BYTES).toString("base64url");
}

/** sha256 hex del sid: es lo unico que el registro del servidor persiste. */
export function hashStaffSid(sid: string): string {
  return createHash("sha256").update(sid, "utf8").digest("hex");
}

/** Token CSRF de la consola STAFF LIGADO al sid: HMAC(clave HKDF propia, sid). El double-submit sigue comparando cookie==campo,
 * y ademas el servidor exige que el valor sea el de ESTA sesion (un token de otra sesion no sirve aunque la cookie y el campo coincidan). */
export function staffCsrfTokenFor(staffSessionKey: Buffer, sid: string): string {
  const csrfKey = Buffer.from(hkdfSync("sha256", staffSessionKey, Buffer.alloc(0), STAFF_CSRF_HKDF_INFO, 32));
  return createHmac("sha256", csrfKey).update(sid, "utf8").digest("base64url");
}

export function staffCsrfMatchesSession(staffSessionKey: Buffer, sid: string, token: string | undefined): boolean {
  return token !== undefined && timingSafeEqualStrings(token, staffCsrfTokenFor(staffSessionKey, sid));
}

export function encodeStaffSession(key: Buffer, payload: StaffSessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/**
 * Verifica formato, firma y campos. Con `nowMs` tambien exige `iat <= nowMs < exp` (expiracion absoluta); sin `nowMs` solo valida la firma
 * (para revocar en el logout una cookie ya vencida). Cualquier fallo devuelve null: "sin sesión STAFF" (404 uniforme, GRD-CM-01),
 * nunca un error distinguible. NO consulta el registro del servidor: eso lo hace authenticateStaffSession.
 */
export function decodeStaffSession(key: Buffer, cookieValue: string | undefined, nowMs?: number): StaffSessionPayload | null {
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
    if (typeof record.sid !== "string" || !SID_PATTERN.test(record.sid)) return null;
    if (typeof record.tenantId !== "string" || record.tenantId.length === 0) return null;
    if (typeof record.principalRef !== "string" || record.principalRef.length === 0) return null;
    if (typeof record.role !== "string" || !KNOWN_ROLES.includes(record.role as StaffRole)) return null;
    if (typeof record.iat !== "number" || !Number.isFinite(record.iat) || typeof record.exp !== "number" || !Number.isFinite(record.exp)) return null;
    if (record.exp <= record.iat) return null;
    if (nowMs !== undefined && (record.iat > nowMs || record.exp <= nowMs)) return null;
    return { sid: record.sid, tenantId: record.tenantId, principalRef: record.principalRef, role: record.role as StaffRole, iat: record.iat, exp: record.exp };
  } catch {
    return null;
  }
}

/** `Set-Cookie` de `__Host-cns-staff`: HttpOnly, Secure, Path=/, SameSite=Lax (mismo criterio que las demás cookies de sesión de
 * este repo). `maxAgeSec` (opcional) acota la cookie del navegador a la vida absoluta de la sesión. */
export function serializeStaffSessionCookie(cookieName: string, value: string, maxAgeSec?: number): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax${maxAgeSec !== undefined ? `; Max-Age=${maxAgeSec}` : ""}`;
}

export interface IssuedStaffSession {
  readonly sid: string;
  /** Valor de la cookie `__Host-cns-staff`. */
  readonly cookieValue: string;
  /** Token CSRF ligado a este sid (valor de la cookie CSRF STAFF y del campo/cabecera double-submit). */
  readonly csrfToken: string;
  readonly maxAgeSec: number;
}

/**
 * Emite una sesion STAFF NUEVA: sid aleatorio fresco (anti fixation: nunca se reutiliza un sid previo), registro en servidor,
 * limpieza oportunista de sesiones YA expiradas del tenant (best-effort: un fallo de limpieza no impide el login) y cookie firmada.
 * Es el unico camino de emision (dev-login LOCAL y tests): sin privilegios extra. Si `previousCookie` trae una sesion valida de
 * firma, su sid se REVOCA en servidor (rotacion).
 */
export async function issueStaffSession(
  deps: { readonly sessions: StaffSessionStorePort; readonly staffSessionKey: Buffer; readonly nowMs?: () => number; readonly absoluteTtlMs?: number },
  principal: { readonly tenantId: string; readonly principalRef: string; readonly role: StaffRole },
  previousCookie?: string,
): Promise<IssuedStaffSession> {
  const now = (deps.nowMs ?? Date.now)();
  const ttl = deps.absoluteTtlMs ?? APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS;
  const previous = decodeStaffSession(deps.staffSessionKey, previousCookie);
  if (previous !== null) await deps.sessions.revoke(previous.tenantId, hashStaffSid(previous.sid), now, "ROTATION");
  const sid = newStaffSid();
  const payload: StaffSessionPayload = { sid, tenantId: principal.tenantId, principalRef: principal.principalRef, role: principal.role, iat: now, exp: now + ttl };
  await deps.sessions.create({ tenantId: payload.tenantId, sidHash: hashStaffSid(sid), principalRef: payload.principalRef, role: payload.role, issuedAtMs: payload.iat, expiresAtMs: payload.exp });
  await deps.sessions.purgeExpired(payload.tenantId, now, APPROVED_STAFF_SESSION_PURGE_RETENTION_MS).catch((error: unknown) => {
    // P2-6: solo nombre/codigo del error (nunca sid, hash, refs ni el mensaje de la base).
    const code = (error as { code?: unknown } | null)?.code;
    console.error(`staff_session_purge_failed name=${error instanceof Error ? error.name : "unknown"}${typeof code === "string" ? ` code=${code}` : ""}`);
    return 0;
  });
  return { sid, cookieValue: encodeStaffSession(deps.staffSessionKey, payload), csrfToken: staffCsrfTokenFor(deps.staffSessionKey, sid), maxAgeSec: Math.floor(ttl / 1000) };
}

/** Logout: revoca en servidor el sid de la cookie (si la firma es valida, aunque ya haya vencido). Idempotente; sin cookie valida no hace nada. */
export async function revokeStaffSessionCookie(
  deps: { readonly sessions: StaffSessionStorePort; readonly staffSessionKey: Buffer; readonly nowMs?: () => number },
  cookieValue: string | undefined,
): Promise<StaffSessionPayload | null> {
  const session = decodeStaffSession(deps.staffSessionKey, cookieValue);
  if (session === null) return null;
  await deps.sessions.revoke(session.tenantId, hashStaffSid(session.sid), (deps.nowMs ?? Date.now)(), "USER_LOGOUT");
  return session;
}
