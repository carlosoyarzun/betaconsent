// Gobierna: API-CNS-116 (GET /staff/roster), diseno api-cns-116-staff-list-design.md rev. 2 §3 (cursor), SEC-CNS-018 rev. 2
// (R4, R6), REQ-CNS-036. Cursor opaco y autenticado del keyset (subject_ref, context_ref):
//
//   cursor = "c1." + base64url( nonce(12) || AES-256-GCM(ciphertext || tag(16)) )
//   clave  = HKDF-SHA256(secreto del servidor propio por entorno, info "CNS-STAFF-ROSTER-CURSOR-v1")
//   AAD    = JSON canonico (arreglo) ["CNS-STAFF-ROSTER-CURSOR-v1", tenantId, principalRef, role, sid, "GET /staff/roster"]
//            CA-138 (SEC-CNS-018 rev. 2 D-3): el sid de la sesion STAFF entra en el AAD, asi un cursor de otra sesion (aunque sea
//            del mismo principal) no descifra; cerrar sesion invalida los cursores de esa sesion.
//            (JSON.stringify de un arreglo de cadenas: sin ambiguedad por concatenacion)
//   plaintext = JSON {"s": lastSubjectRef, "x": lastContextRef, "t": iat(ms)}; TTL 15 min contra la hora del servidor.
//
// Cualquier fallo (prefijo/version desconocidos, formato, tag, AAD de otro tenant/principal/rol/ruta, expirado, JSON o
// refs invalidas tras descifrar) lanza RosterCursorInvalidError: el borde responde un 422 uniforme (ERR-CM-13
// LIST_QUERY_INVALID) sin eco. El cursor nunca se loguea (los logs de ruta omiten el query string). Secreto:
// CNS_STAFF_ROSTER_CURSOR_SECRET; en LOCAL sin el, constante LOCAL_ONLY; fuera de LOCAL no arranca sin el (patron
// CNS_CHAIN_REF_SECRET). No es la sesion: no rota con ella.

import { decodeStrictSecret } from "../secrets/strict-secret.ts";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

export const STAFF_ROSTER_CURSOR_HKDF_INFO = "CNS-STAFF-ROSTER-CURSOR-v1";
export const STAFF_ROSTER_CURSOR_PREFIX = "c1.";
export const STAFF_ROSTER_CURSOR_ROUTE = "GET /staff/roster";
/** TTL del cursor: 15 min (diseno §3). */
export const STAFF_ROSTER_CURSOR_TTL_MS = 15 * 60_000;

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** Espejo de common.schema.json (Ref UUIDv4 y ContextRef). */
const REF_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTEXT_REF_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;

export class RosterCursorInvalidError extends Error {
  constructor() {
    super("cursor invalido"); // sin causa ni valor: la causa no es distinguible para el cliente
    this.name = "RosterCursorInvalidError";
  }
}

export interface RosterCursorScope {
  readonly tenantId: string;
  readonly principalRef: string;
  readonly role: string;
  /** CA-138: sid de la sesion STAFF (en claro, solo en memoria; nunca se persiste ni se loguea). */
  readonly sid: string;
}

export interface RosterCursorPosition {
  readonly subjectRef: string;
  readonly contextRef: string;
}

export function deriveStaffRosterCursorKey(secret: Buffer): Buffer {
  if (secret.length < 32) throw new Error("cursor del roster: el secreto raiz debe tener al menos 32 bytes (fail-closed).");
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), STAFF_ROSTER_CURSOR_HKDF_INFO, 32));
}

/** `CNS_STAFF_ROSTER_CURSOR_SECRET` (base64, >=32 bytes). Fuera de LOCAL, sin el: aborta (fail-closed). En LOCAL sin el:
 * constante LOCAL_ONLY (datos sinteticos). */
export function loadStaffRosterCursorSecret(env: Readonly<Record<string, string | undefined>>, environment: string): Buffer {
  const raw = env.CNS_STAFF_ROSTER_CURSOR_SECRET;
  if (raw === undefined || raw === "") {
    if (environment !== "LOCAL") {
      throw new Error("CNS_STAFF_ROSTER_CURSOR_SECRET es obligatorio fuera de LOCAL (cursor de GET /staff/roster). Abortando (fail-closed).");
    }
    return Buffer.from("LOCAL_ONLY_DEV_STAFF_ROSTER_CURSOR_SECRET_SYNTHETIC_DATA_ONLY");
  }
  return decodeStrictSecret(raw, "CNS_STAFF_ROSTER_CURSOR_SECRET");
}

function aadOf(scope: RosterCursorScope): Buffer {
  return Buffer.from(JSON.stringify([STAFF_ROSTER_CURSOR_HKDF_INFO, scope.tenantId, scope.principalRef, scope.role, scope.sid, STAFF_ROSTER_CURSOR_ROUTE]), "utf8");
}

export function encodeRosterCursor(key: Buffer, scope: RosterCursorScope, position: RosterCursorPosition, nowMs: number = Date.now()): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aadOf(scope));
  const plaintext = Buffer.from(JSON.stringify({ s: position.subjectRef, x: position.contextRef, t: nowMs }), "utf8");
  const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return `${STAFF_ROSTER_CURSOR_PREFIX}${Buffer.concat([nonce, sealed]).toString("base64url")}`;
}

export function decodeRosterCursor(
  key: Buffer,
  scope: RosterCursorScope,
  cursor: string,
  nowMs: number = Date.now(),
): RosterCursorPosition {
  try {
    if (typeof cursor !== "string" || !cursor.startsWith(STAFF_ROSTER_CURSOR_PREFIX)) throw new RosterCursorInvalidError();
    const body = cursor.slice(STAFF_ROSTER_CURSOR_PREFIX.length);
    if (!/^[A-Za-z0-9_-]{40,400}$/.test(body)) throw new RosterCursorInvalidError();
    const raw = Buffer.from(body, "base64url");
    if (raw.length < NONCE_BYTES + TAG_BYTES + 1) throw new RosterCursorInvalidError();
    const nonce = raw.subarray(0, NONCE_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    const ciphertext = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aadOf(scope));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    const parsed = JSON.parse(plaintext) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new RosterCursorInvalidError();
    const o = parsed as Record<string, unknown>;
    if (Object.keys(o).sort().join(",") !== "s,t,x") throw new RosterCursorInvalidError();
    if (typeof o.s !== "string" || !REF_PATTERN.test(o.s)) throw new RosterCursorInvalidError(); // UUIDv4 tras descifrar
    if (typeof o.x !== "string" || !CONTEXT_REF_PATTERN.test(o.x)) throw new RosterCursorInvalidError();
    if (typeof o.t !== "number" || !Number.isFinite(o.t)) throw new RosterCursorInvalidError();
    const age = nowMs - o.t;
    if (age < 0 || age > STAFF_ROSTER_CURSOR_TTL_MS) throw new RosterCursorInvalidError();
    return { subjectRef: o.s, contextRef: o.x };
  } catch {
    // Todo fallo es el mismo error: tag, AAD, formato, version, expirado, JSON o refs.
    throw new RosterCursorInvalidError();
  }
}
