// Gobierna: plan v2 H1-05; DEC "Reconstrucción mínima" (2026-10-19).
// origen (ideas): src/server/entrypoints/http/link-handle.ts@9345b78 (handle firmado {payload}.{hmac}, clave HKDF propia por uso, fallo => null),
// consent-session.ts@9345b78 (sesión firmada, HMAC-SHA256 de node:crypto) y recovery-handle.ts@9345b78 (hash acotado del token).
// Se unifica en un codec genérico: invitación (handle con el HASH del token), gestión (handle con el token firmado, ver manage-token) y sesión del apoderado.
// Todo se firma con claves HKDF independientes derivadas de CNS_SESSION_SECRET; comprometer una cookie no compromete las otras.

import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export const HANDLE_TTL_SECONDS = 30 * 60;
export const SESSION_TTL_SECONDS = 60 * 60;
/** Tope de largo antes de hashear/guardar el token (acota el costo ante una entrada adversarial). */
const TOKEN_MAX_INPUT_LENGTH = 512;

function deriveKey(secret: Buffer, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), info, 32));
}

function mac(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

function eq(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

export interface Codec<T extends { readonly exp: number }> {
  encode(payload: T): string;
  /** null ante cualquier fallo (formato, firma, JSON, vencimiento): el llamador lo trata siempre como "no hay handle/sesión". */
  decode(value: string | undefined): T | null;
}

export function createCodec<T extends { readonly exp: number }>(secret: Buffer, info: string, valid: (x: unknown) => x is T): Codec<T> {
  const key = deriveKey(secret, info);
  return {
    encode(payload) {
      const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
      return `${body}.${mac(key, body)}`;
    },
    decode(value) {
      if (!value) return null;
      const dot = value.indexOf(".");
      if (dot === -1) return null;
      const body = value.slice(0, dot);
      if (!eq(value.slice(dot + 1), mac(key, body))) return null;
      try {
        const parsed: unknown = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
        if (!valid(parsed) || parsed.exp <= Math.floor(Date.now() / 1000)) return null;
        return parsed;
      } catch {
        return null;
      }
    },
  };
}

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

// --- Handle de invitación (GET /i/{token}): solo el hash del token ---
export interface InvitationHandle {
  readonly h: string;
  readonly exp: number;
}
export const isInvitationHandle = (x: unknown): x is InvitationHandle =>
  isRecord(x) && typeof x.h === "string" && /^[0-9a-f]{64}$/.test(x.h) && Number.isInteger(x.exp);

/** sha256 hex del token en claro, con tope de largo (mismo criterio que hashLinkToken del origen). */
export function hashLinkToken(token: string): string {
  return createHash("sha256").update(token.length > TOKEN_MAX_INPUT_LENGTH ? token.slice(0, TOKEN_MAX_INPUT_LENGTH) : token).digest("hex");
}

// --- Handle de gestión (GET /m/{token}): el token firmado viaja dentro de la cookie HttpOnly firmada ---
export interface ManageHandle {
  readonly t: string;
  readonly exp: number;
}
export const isManageHandle = (x: unknown): x is ManageHandle => isRecord(x) && typeof x.t === "string" && x.t.length <= TOKEN_MAX_INPUT_LENGTH && Number.isInteger(x.exp);

export function boundToken(token: string): string {
  return token.length > TOKEN_MAX_INPUT_LENGTH ? token.slice(0, TOKEN_MAX_INPUT_LENGTH) : token;
}

// --- Sesión del apoderado ---
export type OtpScopeInSession = "DECISION" | "MANAGE" | "REVOCATION";
export interface Session {
  /** D = flujo de decisión (invitación); M = flujo de gestión/revocación. */
  readonly k: "D" | "M";
  /** Prefijo del hash del handle que creó la sesión: si el handle cambia ("el último enlace abierto manda") la sesión deja de valer. */
  readonly hp: string;
  readonly exp: number;
  /** D: invitationRef. */
  readonly inv?: string;
  /** M: consentId. */
  readonly con?: string;
  /** OTP activo (verificationRef) y su scope. */
  readonly ver?: string;
  readonly sc?: OtpScopeInSession;
  /** true tras verify_otp VERIFIED sobre `ver`. */
  readonly vok?: boolean;
  /** D: pasos registrados y relación declarada. */
  readonly steps?: readonly string[];
  readonly rel?: string;
  /** M: el titular pidió explícitamente revocar (R1, solo en sesión). */
  readonly rq?: boolean;
}
export const isSession = (x: unknown): x is Session =>
  isRecord(x) && (x.k === "D" || x.k === "M") && typeof x.hp === "string" && x.hp.length === 16 && Number.isInteger(x.exp);

export function handlePrefix(handleKey: string): string {
  return createHash("sha256").update(handleKey).digest("hex").slice(0, 16);
}

export interface Codecs {
  readonly invitation: Codec<InvitationHandle>;
  readonly manage: Codec<ManageHandle>;
  readonly session: Codec<Session>;
}

export function createCodecs(sessionSecret: Buffer): Codecs {
  return {
    invitation: createCodec(sessionSecret, "consent-beta/handle/invitation/v1", isInvitationHandle),
    manage: createCodec(sessionSecret, "consent-beta/handle/manage/v1", isManageHandle),
    session: createCodec(sessionSecret, "consent-beta/session/v1", isSession),
  };
}

// --- Token de gestión sin estado (ver DESVIACIÓN en app.ts): m1.<consentId>.<exp>.<mac> ---
export const MANAGE_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const CONSENT_ID = /^con-[A-Za-z0-9-]{1,60}$/;

export function signManageToken(sessionSecret: Buffer, consentId: string, expiresAtEpochSeconds: number): string {
  if (!CONSENT_ID.test(consentId)) throw new Error("consentId inválido");
  const key = deriveKey(sessionSecret, "consent-beta/manage-token/v1");
  const body = `m1.${consentId}.${expiresAtEpochSeconds}`;
  return `${body}.${mac(key, body)}`;
}

/** consentId del token si la firma y el vencimiento valen; null en cualquier otro caso. */
export function verifyManageToken(sessionSecret: Buffer, token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "m1") return null;
  const [, consentId, expRaw, tag] = parts as [string, string, string, string];
  const key = deriveKey(sessionSecret, "consent-beta/manage-token/v1");
  if (!eq(tag, mac(key, `m1.${consentId}.${expRaw}`))) return null;
  const exp = Number(expRaw);
  if (!CONSENT_ID.test(consentId) || !Number.isInteger(exp) || exp <= Math.floor(Date.now() / 1000)) return null;
  return consentId;
}
