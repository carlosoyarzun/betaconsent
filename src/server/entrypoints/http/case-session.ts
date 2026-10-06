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

// CA-139 (Carlos, 2026-10-06; P1-1 de la revision de seguridad de CA-138): la cookie ya NO es un HMAC sin vida. Lleva `sid` (aleatorio, 256
// bits), `iat` y `exp` (absoluta); el servidor guarda ademas un registro por sid (CaseSessionStorePort) que permite REVOCAR (logout) y expirar
// por INACTIVIDAD, y el token CSRF queda ligado al sid. Se conserva la ligadura al `caseRef`. Mismo mecanismo que staff-session.ts. Los valores
// de vida estan aprobados (approved-parameters.ts, Carlos 2026-10-06).

import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

import { APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS, APPROVED_CASE_SESSION_PURGE_RETENTION_MS } from "../../modules/common/approved-parameters.ts";
import type { CaseSessionStorePort } from "../../ports/case-session-store.port.ts";
import type { CaseStaffRole } from "../../ports/staff-identity.port.ts";

const CASE_SESSION_HKDF_INFO = "CNS-CASE-SESSION-v1";
const CASE_CSRF_HKDF_INFO = "CNS-CASE-CSRF-v1";
/** sid: 32 bytes aleatorios (256 bits >= 128) en base64url (43 caracteres). */
const SID_BYTES = 32;
const SID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface CaseSessionPayload {
  /** Identificador de sesion aleatorio (256 bits). Solo la cookie lo lleva en claro; el servidor guarda su hash. */
  readonly sid: string;
  readonly tenantId: string;
  readonly caseRef: string;
  /** Ref opaca sintética del principal de plataforma; nunca PII (P-26 pendiente de nombre exacto
   * de cookie/cabecera, no de este campo). */
  readonly principalRef: string;
  readonly role: CaseStaffRole;
  /** Emision y expiracion ABSOLUTA (ms epoch, reloj del servidor). */
  readonly iat: number;
  readonly exp: number;
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

export function newCaseSid(): string {
  return randomBytes(SID_BYTES).toString("base64url");
}

/** sha256 hex del sid: es lo unico que el registro del servidor persiste. */
export function hashCaseSid(sid: string): string {
  return createHash("sha256").update(sid, "utf8").digest("hex");
}

/** Token CSRF de la consola CASE LIGADO al sid: HMAC(clave HKDF propia, sid). El double-submit sigue comparando cookie==cabecera y ademas
 * el servidor exige que el valor sea el de ESTA sesion (un token de otra sesion no sirve aunque cookie y cabecera coincidan). */
export function caseCsrfTokenFor(caseSessionKey: Buffer, sid: string): string {
  const csrfKey = Buffer.from(hkdfSync("sha256", caseSessionKey, Buffer.alloc(0), CASE_CSRF_HKDF_INFO, 32));
  return createHmac("sha256", csrfKey).update(sid, "utf8").digest("base64url");
}

export function caseCsrfMatchesSession(caseSessionKey: Buffer, sid: string, token: string | undefined): boolean {
  return token !== undefined && timingSafeEqualStrings(token, caseCsrfTokenFor(caseSessionKey, sid));
}

export function encodeCaseSession(key: Buffer, payload: CaseSessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/**
 * Verifica formato, firma y campos. Con `nowMs` tambien exige `iat <= nowMs < exp` (expiracion absoluta); sin `nowMs` solo valida la firma
 * (para revocar en el logout una cookie ya vencida). Cualquier fallo devuelve `null`; el llamador SIEMPRE lo trata como "sin sesión CASE"
 * (404 uniforme, GRD-CM-01), nunca como un error distinguible. NO consulta el registro del servidor (eso lo hace authenticateCaseSession).
 */
export function decodeCaseSession(key: Buffer, cookieValue: string | undefined, nowMs?: number): CaseSessionPayload | null {
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
    if (typeof record.sid !== "string" || !SID_PATTERN.test(record.sid)) return null;
    if (typeof record.tenantId !== "string" || record.tenantId.length === 0) return null;
    if (typeof record.caseRef !== "string" || record.caseRef.length === 0) return null;
    if (typeof record.principalRef !== "string" || record.principalRef.length === 0) return null;
    if (record.role !== "RIGHTS_OPERATOR" && record.role !== "APPROVER") return null;
    if (typeof record.iat !== "number" || !Number.isFinite(record.iat) || typeof record.exp !== "number" || !Number.isFinite(record.exp)) return null;
    if (record.exp <= record.iat) return null;
    if (nowMs !== undefined && (record.iat > nowMs || record.exp <= nowMs)) return null;
    return { sid: record.sid, tenantId: record.tenantId, caseRef: record.caseRef, principalRef: record.principalRef, role: record.role, iat: record.iat, exp: record.exp };
  } catch {
    return null;
  }
}

/** `Set-Cookie` de `__Host-cns-case`: HttpOnly (nunca legible por JS, mismo criterio que la
 * cookie de sesión de consent-session.ts), Secure + Path=/ (prefijo `__Host-`), SameSite=Lax
 * (mismo criterio P1-02 que el resto de las cookies de sesión de este repo). `maxAgeSec` acota la cookie del navegador a la vida absoluta. */
export function serializeCaseSessionCookie(cookieName: string, value: string, maxAgeSec?: number): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax${maxAgeSec !== undefined ? `; Max-Age=${maxAgeSec}` : ""}`;
}

export interface IssuedCaseSession {
  readonly sid: string;
  readonly cookieValue: string;
  /** Token CSRF ligado a este sid (valor de la cookie CSRF CASE y de la cabecera double-submit). */
  readonly csrfToken: string;
  readonly maxAgeSec: number;
}

/**
 * Emite una sesion CASE NUEVA: sid aleatorio fresco (anti fixation), registro en servidor, limpieza oportunista de sesiones YA expiradas
 * del tenant (best-effort: un fallo de limpieza no impide el login; solo se registra name/code) y cookie firmada. Si `previousCookie` trae
 * una sesion valida de firma, su sid se REVOCA en servidor (rotacion). Camino unico de emision (dev-login LOCAL y tests).
 */
export async function issueCaseSession(
  deps: { readonly sessions: CaseSessionStorePort; readonly caseSessionKey: Buffer; readonly nowMs?: () => number; readonly absoluteTtlMs?: number },
  principal: { readonly tenantId: string; readonly caseRef: string; readonly principalRef: string; readonly role: CaseStaffRole },
  previousCookie?: string,
): Promise<IssuedCaseSession> {
  const now = (deps.nowMs ?? Date.now)();
  const ttl = deps.absoluteTtlMs ?? APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS;
  const previous = decodeCaseSession(deps.caseSessionKey, previousCookie);
  if (previous !== null) await deps.sessions.revoke(previous.tenantId, hashCaseSid(previous.sid), now);
  const sid = newCaseSid();
  const payload: CaseSessionPayload = { sid, tenantId: principal.tenantId, caseRef: principal.caseRef, principalRef: principal.principalRef, role: principal.role, iat: now, exp: now + ttl };
  await deps.sessions.create({ tenantId: payload.tenantId, sidHash: hashCaseSid(sid), caseRef: payload.caseRef, principalRef: payload.principalRef, role: payload.role, issuedAtMs: payload.iat, expiresAtMs: payload.exp });
  await deps.sessions.purgeExpired(payload.tenantId, now, APPROVED_CASE_SESSION_PURGE_RETENTION_MS).catch((error: unknown) => {
    // Solo nombre/codigo del error (nunca sid, hash, refs ni el mensaje de la base).
    const code = (error as { code?: unknown } | null)?.code;
    console.error(`case_session_purge_failed name=${error instanceof Error ? error.name : "unknown"}${typeof code === "string" ? ` code=${code}` : ""}`);
    return 0;
  });
  return { sid, cookieValue: encodeCaseSession(deps.caseSessionKey, payload), csrfToken: caseCsrfTokenFor(deps.caseSessionKey, sid), maxAgeSec: Math.floor(ttl / 1000) };
}

/** Logout: revoca en servidor el sid de la cookie (si la firma es valida, aunque ya haya vencido). Idempotente; sin cookie valida no hace nada. */
export async function revokeCaseSessionCookie(
  deps: { readonly sessions: CaseSessionStorePort; readonly caseSessionKey: Buffer; readonly nowMs?: () => number },
  cookieValue: string | undefined,
): Promise<CaseSessionPayload | null> {
  const session = decodeCaseSession(deps.caseSessionKey, cookieValue);
  if (session === null) return null;
  await deps.sessions.revoke(session.tenantId, hashCaseSid(session.sid), (deps.nowMs ?? Date.now)());
  return session;
}
