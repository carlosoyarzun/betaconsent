// Gobierna: SEC-CNS-014 (mismo patrón P2-01/P2-02/P2-04 de recovery-handle.ts), ahora aplicado
// a GET /i/{token} (API-CNS-101) y GET /m/{token} (API-CNS-102) por decisión de Carlos
// (2026-09-28, opción a): ambos GET responden SIEMPRE el mismo 303 sin leer la BD; la página
// siguiente (/welcome, /manage) resuelve en solo lectura si el handle es elegible, con la misma
// página de error 404 byte-idéntica para cualquier causa (inexistente, vencido, usado, de otro
// tenant). Generaliza el codec de recovery-handle.ts para los dos `typ` nuevos
// (INVITATION_LANDING, MANAGE_ENTRY): cada uno usa su propia clave HKDF (info distinto de
// recovery-handle.ts y de consent-session.ts) y su propia cookie `__Host-` (config.ts), para que
// comprometer una nunca comprometa las otras.
//
// GET /i/{token} y GET /m/{token} (consent-flow.handler.ts handleRedeemInvitationLink,
// revocation-flow.handler.ts handleRedeemManagementLink) usan `hashLinkToken` SIN leer ningún
// port: el hash es puro, así que el 303 es idéntico sea o no válido el token (INV-CM-08
// reforzado, mismo criterio que GET /r/{token}).

import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export type LinkHandleType = "INVITATION_LANDING" | "MANAGE_ENTRY";

const TOKEN_HASH_PATTERN = /^[0-9a-f]{64}$/;

/** SEC-CNS-014 FINDING P2-04 (mismo criterio que RECOVERY_TOKEN_HASH_MAX_INPUT_LENGTH,
 * revocation-flow.handler.ts): tope de largo antes de hashear, para acotar el costo de una
 * entrada adversarial larguísima sin cambiar jamás el resultado observable. */
const LINK_TOKEN_HASH_MAX_INPUT_LENGTH = 512;

export interface LinkHandlePayload {
  readonly typ: LinkHandleType;
  /** sha256 hex del token en claro (64 chars fijos, P2-01: largo fijo del payload). */
  readonly h: string;
  /** epoch segundos; el servidor valida contra Date.now(). */
  readonly exp: number;
}

/** sha256 hex del token en claro, con el mismo tope de largo que hashRecoveryToken. */
export function hashLinkToken(token: string): string {
  const bounded = token.length > LINK_TOKEN_HASH_MAX_INPUT_LENGTH ? token.slice(0, LINK_TOKEN_HASH_MAX_INPUT_LENGTH) : token;
  return createHash("sha256").update(bounded).digest("hex");
}

/** P2-02: clave propia por `typ` (INVITATION_LANDING o MANAGE_ENTRY), derivada con un `info`
 * HKDF distinto para cada una y distinto también del de recovery-handle.ts/consent-session.ts. */
export function deriveLinkHandleKey(sessionSecret: Buffer, hkdfInfo: string): Buffer {
  return Buffer.from(hkdfSync("sha256", sessionSecret, Buffer.alloc(0), hkdfInfo, 32));
}

function sign(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
}

/** Fija el payload `{typ, h, exp}` (P2-01: largo fijo, sin variantes de forma). */
export function encodeLinkHandle(key: Buffer, typ: LinkHandleType, tokenHash: string, expiresAtEpochSeconds: number): string {
  const payload: LinkHandlePayload = { typ, h: tokenHash, exp: expiresAtEpochSeconds };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(key, body)}`;
}

/**
 * Verifica y decodifica el handle. Cualquier fallo (formato, firma, JSON, `typ` incorrecto,
 * exp vencido) devuelve `null`; el llamador SIEMPRE lo trata como "no hay handle" (mismo
 * criterio que decodeSession/decodeRecoveryHandle), nunca como un error distinguible.
 */
export function decodeLinkHandle(key: Buffer, typ: LinkHandleType, cookieValue: string | undefined): LinkHandlePayload | null {
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
    if (record.typ !== typ) return null;
    if (typeof record.h !== "string" || !TOKEN_HASH_PATTERN.test(record.h)) return null;
    if (typeof record.exp !== "number" || !Number.isInteger(record.exp)) return null;
    if (record.exp <= Math.floor(Date.now() / 1000)) return null;
    return { typ, h: record.h, exp: record.exp };
  } catch {
    return null;
  }
}

/** `Set-Cookie` propio: SameSite=Lax (mismo criterio que recovery-handle.ts/consent-session.ts,
 * SEC-CNS-014 P1-02), HttpOnly, Secure + Path=/ (prefijo `__Host-`). */
export function serializeLinkHandleCookie(cookieName: string, value: string, maxAgeSeconds: number): string {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}
