// Gobierna: ADR-010 rev. 4 §4.3.3 (verificacion del ID token en el verifier: firma, iss/aud/exp, nonce <-> binding, auth_time, acr/amr), §7 fila PR-4.
// Decisiones: ninguna libreria JWT (dependency-allowlist): solo node:crypto. Algoritmos permitidos por configuracion (lista cerrada EdDSA | ES256 | RS256); nunca
// `none` ni HS* (confusion de algoritmo). La clave se elige por `kid` del JWKS fijado y su `alg`/`kty`/`crv` deben coincidir con el header. El ID token crudo vive
// solo en memoria del llamador; de los claims solo salen los minimos (sub, auth_time, acr, amr). El claim email (u otro) se descarta sin persistir.
// Parametros del IdP (acr/amr exigidos, auth_time maximo = P-36) son configuracion: APR-IDP / P-36 siguen PENDING; el codigo no inventa valores.
// Cero PII: este archivo nunca registra el token ni sus claims.

import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";
import type { JsonWebKey, KeyObject } from "node:crypto";
import type { Jwk, Jwks } from "../../ports/idp-client.port.ts";

export type JwtAlg = "EdDSA" | "ES256" | "RS256";
const SUPPORTED_ALGS: ReadonlySet<string> = new Set(["EdDSA", "ES256", "RS256"]);
const MAX_TOKEN_BYTES = 8192;
const ACR_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const AMR_ITEM_RE = /^[A-Za-z0-9:._-]{1,64}$/;

/** Rechazo del ID token. Sin detalle del token: solo un codigo interno de diagnostico (no se persiste en la base; ahi va INVALID_CLAIMS). */
export class IdTokenRejected extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`id_token rechazado: ${reason}`);
    this.name = "IdTokenRejected";
    this.reason = reason;
  }
}

export interface IdTokenPolicy {
  issuer: string;
  audience: string;
  /** Algoritmos aceptados (lista cerrada del IdP fijado). */
  allowedAlgs: readonly JwtAlg[];
  /** Edad maxima de auth_time en segundos (P-36: PENDING; el llamador debe pasarla explicita). */
  maxAuthAgeSeconds: number;
  /** Si no es vacio, el `acr` debe estar en la lista (APR-IDP: PENDING). */
  requiredAcrAnyOf?: readonly string[];
  /** Tolerancia de reloj en segundos (default 30). */
  clockSkewSeconds?: number;
  /** Reloj inyectable (segundos desde epoch). */
  nowSeconds: number;
}

export interface VerifiedIdToken {
  sub: string;
  authTime: Date;
  acr: string | null;
  amr: readonly string[] | null;
  /** sha256 hex del token crudo. */
  assertionHash: string;
}

function b64urlDecode(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new IdTokenRejected("segmento base64url invalido");
  return Buffer.from(segment, "base64url");
}

function parseJsonObject(buf: Buffer): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(buf.toString("utf8"));
  } catch {
    throw new IdTokenRejected("json invalido");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new IdTokenRejected("json no es un objeto");
  return value as Record<string, unknown>;
}

function keyMatchesAlg(jwk: Jwk, alg: JwtAlg): boolean {
  if ("d" in jwk || "p" in jwk || "q" in jwk || "k" in jwk) return false; // un JWKS publico no lleva material privado ni simetrico
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (alg === "EdDSA") return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256";
  return jwk.kty === "RSA" && typeof jwk.n === "string" && Buffer.from(jwk.n, "base64url").length >= 256; // RSA >= 2048 bits
}

function selectKey(jwks: Jwks, kid: string | undefined, alg: JwtAlg): KeyObject {
  const candidates = jwks.keys.filter((k) => keyMatchesAlg(k, alg) && (kid === undefined ? jwks.keys.length === 1 : k.kid === kid));
  if (candidates.length !== 1) throw new IdTokenRejected("clave no encontrada o ambigua");
  try {
    return createPublicKey({ key: candidates[0] as unknown as JsonWebKey, format: "jwk" });
  } catch {
    throw new IdTokenRejected("clave invalida");
  }
}

function verifySignature(alg: JwtAlg, key: KeyObject, signingInput: Buffer, signature: Buffer): boolean {
  try {
    if (alg === "EdDSA") return cryptoVerify(null, signingInput, key, signature);
    if (alg === "ES256") return cryptoVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    return cryptoVerify("sha256", signingInput, key, signature);
  } catch {
    return false;
  }
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function safeEqualHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Verifica firma y claims. `nonceHashHex` es el sha256 hex del action nonce (platform.oidc_exchange.binding); el claim `nonce` se hashea y se compara en tiempo constante.
 * Lanza IdTokenRejected ante cualquier incumplimiento. No devuelve el email ni ningun otro claim.
 */
export function verifyIdToken(idToken: string, jwks: Jwks, nonceHashHex: string, policy: IdTokenPolicy): VerifiedIdToken {
  if (typeof idToken !== "string" || idToken.length === 0 || Buffer.byteLength(idToken, "utf8") > MAX_TOKEN_BYTES) throw new IdTokenRejected("tamano");
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new IdTokenRejected("estructura");
  const [h, p, s] = parts as [string, string, string];
  const header = parseJsonObject(b64urlDecode(h));
  const alg = header.alg;
  if (typeof alg !== "string" || !SUPPORTED_ALGS.has(alg) || !policy.allowedAlgs.includes(alg as JwtAlg)) throw new IdTokenRejected("alg no permitido");
  if (header.crit !== undefined || header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) throw new IdTokenRejected("header no admitido");
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const key = selectKey(jwks, kid, alg as JwtAlg);
  if (!verifySignature(alg as JwtAlg, key, Buffer.from(`${h}.${p}`, "utf8"), b64urlDecode(s))) throw new IdTokenRejected("firma");

  const claims = parseJsonObject(b64urlDecode(p));
  const skew = policy.clockSkewSeconds ?? 30;
  const now = policy.nowSeconds;
  if (claims.iss !== policy.issuer) throw new IdTokenRejected("iss");
  const aud = claims.aud;
  if (!(aud === policy.audience || (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === "string") && aud.includes(policy.audience)))) throw new IdTokenRejected("aud");
  if (Array.isArray(aud) && aud.length > 1 && claims.azp !== policy.audience) throw new IdTokenRejected("azp");
  const exp = claims.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp + skew <= now) throw new IdTokenRejected("exp");
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf - skew > now)) throw new IdTokenRejected("nbf");
  if (claims.iat !== undefined && (typeof claims.iat !== "number" || claims.iat - skew > now)) throw new IdTokenRejected("iat");
  const sub = claims.sub;
  if (typeof sub !== "string" || sub.length < 1 || sub.length > 255) throw new IdTokenRejected("sub");
  const nonce = claims.nonce;
  if (typeof nonce !== "string" || nonce.length < 1 || nonce.length > 512 || !/^[0-9a-f]{64}$/.test(nonceHashHex) || !safeEqualHex(sha256Hex(nonce), nonceHashHex)) throw new IdTokenRejected("nonce");
  const authTime = claims.auth_time;
  if (typeof authTime !== "number" || !Number.isFinite(authTime) || authTime - skew > now || now - authTime > policy.maxAuthAgeSeconds + skew) throw new IdTokenRejected("auth_time");

  let acr: string | null = null;
  if (claims.acr !== undefined) {
    if (typeof claims.acr !== "string" || !ACR_RE.test(claims.acr)) throw new IdTokenRejected("acr");
    acr = claims.acr;
  }
  if (policy.requiredAcrAnyOf !== undefined && policy.requiredAcrAnyOf.length > 0 && (acr === null || !policy.requiredAcrAnyOf.includes(acr))) throw new IdTokenRejected("acr no exigido");
  let amr: string[] | null = null;
  if (claims.amr !== undefined) {
    if (!Array.isArray(claims.amr) || claims.amr.length < 1 || claims.amr.length > 8 || !claims.amr.every((x) => typeof x === "string" && AMR_ITEM_RE.test(x))) throw new IdTokenRejected("amr");
    amr = claims.amr as string[];
  }
  return { sub, authTime: new Date(Math.round(authTime * 1000)), acr, amr, assertionHash: sha256Hex(idToken) };
}

/**
 * sub_hmac = HMAC-SHA256(K_sub, iss 0x1f sub) en hex (ADR-010 §4.4). K_sub viene del SecretStore (puerto pendiente, F-X8-09): aqui se inyecta, minimo 32 bytes.
 * El separador 0x1f evita colisiones entre (iss, sub) distintos. El sub en claro nunca se persiste.
 */
export function computeSubHmac(key: Buffer, issuer: string, sub: string): string {
  if (key.length < 32) throw new Error("K_sub debe tener al menos 32 bytes. Abortando (fail-closed).");
  return createHmac("sha256", key).update(`${issuer}\u001f${sub}`, "utf8").digest("hex");
}
