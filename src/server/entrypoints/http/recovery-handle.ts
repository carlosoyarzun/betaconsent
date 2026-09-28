// Gobierna: SEC-CNS-014 (APROBADO CON CAMBIOS, FINDINGS P2-01, P2-02, P2-03), ADR-006 §6.2
// (P-18), contracts/openapi/consent-it0.openapi.yaml securitySchemes.recoveryHandle. GET
// /r/{token} (API-CNS-103) ya no lee la BD (INV-CM-08 reforzado): solo hashea el token y fija
// la cookie `__Host-cns-recovery` con este payload firmado de largo fijo, para que la respuesta
// 303 sea idéntica sin importar la validez del token. GET /recovery/confirm y POST
// /recovery/revoke son los únicos lectores; MANAGE y DECISION nunca aceptan esta cookie (nunca
// se decodifica desde ConsentSessionPayload, consent-session.ts).
//
// P2-02: clave HKDF-SHA256 propia, derivada de `sessionSecret` con un `info` distinto del de
// consent-session.ts, para que comprometer una firma no comprometa la otra. Una segunda clave
// derivada (info distinto) liga el token CSRF de /recovery/confirm al hash del portador
// (P2, fijación de cookie): recalculado en cada POST /recovery/revoke contra la cookie
// `__Host-cns-recovery` ACTUAL, así que si esta cookie cambia entre el render y el POST, el
// CSRF deja de coincidir y el POST se rechaza (GRD-CM-10 adicional, específico de recovery).

import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

const RECOVERY_HANDLE_HKDF_INFO = "CNS-RECOVERY-HANDLE-v1";
const RECOVERY_CSRF_HKDF_INFO = "CNS-RECOVERY-CSRF-v1";
const RECOVERY_TYPE = "RECOVERY" as const;
const TOKEN_HASH_PATTERN = /^[0-9a-f]{64}$/;

export interface RecoveryHandlePayload {
  readonly typ: "RECOVERY";
  /** sha256 hex del token en claro (64 chars fijos, P2-01: largo fijo del payload). */
  readonly h: string;
  /** epoch segundos (10 dígitos hasta el año 2286); el servidor valida contra Date.now(). */
  readonly exp: number;
}

/** P2-02: clave propia del handle RECOVERY, nunca la de consent-session.ts. */
export function deriveRecoveryHandleKey(sessionSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sessionSecret, Buffer.alloc(0), RECOVERY_HANDLE_HKDF_INFO, 32));
}

/** P2 (fijación de cookie): clave propia del CSRF ligado al hash del portador, distinta de la
 * clave del handle y de la de consent-session.ts. */
export function deriveRecoveryCsrfKey(sessionSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sessionSecret, Buffer.alloc(0), RECOVERY_CSRF_HKDF_INFO, 32));
}

function sign(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
}

/** Fija el payload `{typ:"RECOVERY", h, exp}` (P2-01: largo fijo, sin variantes de forma). */
export function encodeRecoveryHandle(key: Buffer, tokenHash: string, expiresAtEpochSeconds: number): string {
  const payload: RecoveryHandlePayload = { typ: RECOVERY_TYPE, h: tokenHash, exp: expiresAtEpochSeconds };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/**
 * Verifica y decodifica el handle RECOVERY. Cualquier fallo (formato, firma, JSON, typ
 * incorrecto, exp vencido) devuelve `null`; el llamador SIEMPRE lo trata como "no hay handle"
 * (mismo criterio que decodeSession, consent-session.ts), nunca como un error distinguible.
 */
export function decodeRecoveryHandle(key: Buffer, cookieValue: string | undefined): RecoveryHandlePayload | null {
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
    if (record.typ !== RECOVERY_TYPE) return null;
    if (typeof record.h !== "string" || !TOKEN_HASH_PATTERN.test(record.h)) return null;
    if (typeof record.exp !== "number" || !Number.isInteger(record.exp)) return null;
    if (record.exp <= Math.floor(Date.now() / 1000)) return null; // P-18 vencido.
    return { typ: RECOVERY_TYPE, h: record.h, exp: record.exp };
  } catch {
    return null;
  }
}

/** `Set-Cookie` de `__Host-cns-recovery`: SameSite=Lax (SEC-CNS-014 P1-02, mismo criterio que
 * consent-session.ts/csrf.ts), HttpOnly (nunca legible por JS, a diferencia de la cookie
 * CSRF), Secure + Path=/ (prefijo `__Host-`). */
export function serializeRecoveryHandleCookie(cookieName: string, value: string, maxAgeSeconds: number): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

// ---------------------------------------------------------------------------
// CSRF ligado al hash del portador (P2, fijación de cookie de recuperación).
// ---------------------------------------------------------------------------

/** Token CSRF de 33:87 ligado a `tokenHash` mediante HMAC(k, tokenHash‖0x00‖nonce): el nonce
 * es público (va en el propio token), la ligazón depende solo de la clave derivada. */
export function generateRecoveryCsrfToken(key: Buffer, tokenHash: string): string {
  const nonce = randomBytes(16).toString("base64url");
  const mac = sign(key, `${tokenHash}\u0000${nonce}`);
  return `${nonce}.${mac}`;
}

/** POST /recovery/revoke recalcula contra la cookie `__Host-cns-recovery` ACTUAL (tokenHash del
 * handle vigente en ESTE request, no el de cuando se emitió el token CSRF): si la cookie de
 * recuperación cambió entre el render de 33:87 y este POST (fijación), la recomputación no
 * coincide y el POST se rechaza, aunque el double-submit cookie==header (csrf.ts, GRD-CM-10)
 * por sí solo hubiera pasado. */
export function verifyRecoveryCsrfToken(key: Buffer, tokenHash: string, csrfToken: string | undefined): boolean {
  if (!csrfToken) return false;
  const dot = csrfToken.indexOf(".");
  if (dot === -1) return false;
  const nonce = csrfToken.slice(0, dot);
  const mac = csrfToken.slice(dot + 1);
  const expected = sign(key, `${tokenHash}\u0000${nonce}`);
  return timingSafeEqualStrings(mac, expected);
}
