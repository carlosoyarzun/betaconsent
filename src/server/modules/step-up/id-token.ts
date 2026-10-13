// Gobierna: ADR-010 rev. 4 §4.3.3 (verificacion del ID token en el verifier: firma, iss/aud/exp, nonce <-> binding, auth_time, acr/amr), §7 fila PR-4.
// Decisiones: ninguna libreria JWT (dependency-allowlist): solo node:crypto. Algoritmos permitidos por configuracion (lista cerrada EdDSA | ES256 | RS256); nunca
// `none` ni HS* (confusion de algoritmo). La clave se elige por `kid` del JWKS fijado y su `alg`/`kty`/`crv` deben coincidir con el header. El ID token crudo vive
// solo en memoria del llamador; de los claims solo salen los minimos (sub, auth_time, acr, amr). El claim email (u otro) se descarta sin persistir.
// Parametros del IdP (acr/amr exigidos, auth_time maximo = P-36) son configuracion (acr obligatorio fuera de LOCAL; la frescura auth_time >= issued_at del nonce - skew la impone la base: record_assertion, migracion 0040): APR-IDP / P-36 siguen PENDING; el codigo no inventa valores aprobados.
// La POLITICA se valida antes de verificar y una politica invalida LANZA VerifierConfigError (aborta; nunca se convierte en REJECTED): NaN/Infinity/negativos
// en tolerancias harian fail-open (comparaciones con NaN son siempre falsas).
// Cero PII: este archivo nunca registra el token ni sus claims.

import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";
import type { JsonWebKey, KeyObject } from "node:crypto";
import type { Jwk, Jwks } from "../../ports/idp-client.port.ts";

export type JwtAlg = "EdDSA" | "ES256" | "RS256";
const SUPPORTED_ALGS: ReadonlySet<string> = new Set(["EdDSA", "ES256", "RS256"]);
const MAX_TOKEN_BYTES = 8192;
const ACR_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const AMR_ITEM_RE = /^[A-Za-z0-9:._-]{1,64}$/;
/** Orden del grupo de P-256; low-S exige s <= N/2 (la firma se acepta en una sola forma). */
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

/** Techo tecnico de max auth age (s). PLACEHOLDER: P-36 (frescura de reautenticacion) sigue PENDING de Carlos; no es un valor aprobado. */
export const MAX_AUTH_AGE_CAP_SECONDS = 3600;
export const MAX_CLOCK_SKEW_SECONDS = 120;
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;
/** Dominio del HMAC del sub (separacion de dominio): versionado. */
export const SUB_HMAC_DOMAIN = "consent-app/sub-hmac/v1\u001f";

/** Rechazo del ID token. Sin detalle del token: solo un codigo interno de diagnostico (no se persiste en la base; ahi va INVALID_CLAIMS). */
export class IdTokenRejected extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`id_token rechazado: ${reason}`);
    this.name = "IdTokenRejected";
    this.reason = reason;
  }
}

/** Configuracion/politica invalida: error de despliegue. NO es un rechazo de token; el llamador debe abortar. */
export class VerifierConfigError extends Error {
  constructor(detail: string) {
    super(`configuracion del verifier invalida: ${detail}. Abortando (fail-closed).`);
    this.name = "VerifierConfigError";
  }
}

export interface IdTokenPolicy {
  issuer: string;
  audience: string;
  /** Algoritmos aceptados (lista cerrada del IdP fijado; no vacia). */
  allowedAlgs: readonly JwtAlg[];
  /** Edad maxima de auth_time en segundos, entero 1..MAX_AUTH_AGE_CAP_SECONDS (P-36: PENDING; el llamador debe pasarla explicita). */
  maxAuthAgeSeconds: number;
  /**
   * Entorno del proceso ("LOCAL", "DEV", "STAGING", ...). Obligatorio y sin default (fail-closed). Decision de Carlos (2026-10-12, ADR-010 rev. 4, PR-4 #87):
   * MFA/acr obligatorio fuera de LOCAL, o sea `requiredAcrAnyOf` NO vacio si environment !== "LOCAL". En LOCAL (IdP sintetico) la lista puede ir vacia.
   */
  environment: string;
  /** Lista de `acr` aceptados: el `acr` del token debe estar en ella. Vacia solo en LOCAL; los valores dependen de APR-IDP (PENDING, el codigo no los inventa). */
  requiredAcrAnyOf?: readonly string[];
  /** Tolerancia de reloj en segundos, entero 0..120 (default 30). */
  clockSkewSeconds?: number;
  /** Reloj inyectable (segundos desde epoch, entero seguro). */
  nowSeconds: number;
}

function isIntIn(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

/** Valida la politica; lanza VerifierConfigError. Devuelve el skew efectivo. */
export function validateIdTokenPolicy(policy: IdTokenPolicy): number {
  if (typeof policy.issuer !== "string" || policy.issuer.length === 0) throw new VerifierConfigError("issuer vacio");
  if (typeof policy.audience !== "string" || policy.audience.length === 0) throw new VerifierConfigError("audience vacia");
  if (!Array.isArray(policy.allowedAlgs) || policy.allowedAlgs.length === 0 || !policy.allowedAlgs.every((a) => SUPPORTED_ALGS.has(a))) throw new VerifierConfigError("allowedAlgs vacio o con algoritmos no soportados");
  if (!isIntIn(policy.maxAuthAgeSeconds, 1, MAX_AUTH_AGE_CAP_SECONDS)) throw new VerifierConfigError(`maxAuthAgeSeconds debe ser un entero entre 1 y ${MAX_AUTH_AGE_CAP_SECONDS}`);
  const skew = policy.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  if (!isIntIn(skew, 0, MAX_CLOCK_SKEW_SECONDS)) throw new VerifierConfigError(`clockSkewSeconds debe ser un entero entre 0 y ${MAX_CLOCK_SKEW_SECONDS}`);
  if (!isIntIn(policy.nowSeconds, 0, Number.MAX_SAFE_INTEGER)) throw new VerifierConfigError("nowSeconds debe ser un entero seguro no negativo");
  if (policy.requiredAcrAnyOf !== undefined && (!Array.isArray(policy.requiredAcrAnyOf) || !policy.requiredAcrAnyOf.every((a) => typeof a === "string" && a.length > 0))) {
    throw new VerifierConfigError("requiredAcrAnyOf debe ser una lista de cadenas no vacias");
  }
  if (typeof policy.environment !== "string" || policy.environment.length === 0) throw new VerifierConfigError("environment vacio");
  if (policy.environment !== "LOCAL" && (policy.requiredAcrAnyOf === undefined || policy.requiredAcrAnyOf.length === 0)) {
    throw new VerifierConfigError("requiredAcrAnyOf no puede ser vacio fuera de LOCAL (MFA/acr obligatorio, decision de Carlos 2026-10-12)");
  }
  return skew;
}

/** base64url CANONICO: la decodificacion y recodificacion devuelven exactamente el segmento (sin bits sobrantes, relleno ni caracteres ajenos). */
function b64urlDecode(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new IdTokenRejected("segmento base64url invalido");
  const buf = Buffer.from(segment, "base64url");
  if (buf.toString("base64url") !== segment) throw new IdTokenRejected("segmento base64url no canonico");
  return buf;
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
  return jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string";
}

function selectKey(jwks: Jwks, kid: string | undefined, alg: JwtAlg): KeyObject {
  const candidates = jwks.keys.filter((k) => keyMatchesAlg(k, alg) && (kid === undefined ? jwks.keys.length === 1 : k.kid === kid));
  if (candidates.length !== 1) throw new IdTokenRejected("clave no encontrada o ambigua");
  let key: KeyObject;
  try {
    key = createPublicKey({ key: candidates[0] as unknown as JsonWebKey, format: "jwk" });
  } catch {
    throw new IdTokenRejected("clave invalida");
  }
  if (alg === "RS256") {
    const details = key.asymmetricKeyDetails;
    // RSA >= 2048 bits y exponente publico 65537 (rechaza e pequenos o raros).
    if (details?.modulusLength === undefined || details.modulusLength < 2048 || details.publicExponent !== 65537n) throw new IdTokenRejected("clave rsa debil");
  }
  return key;
}

function verifySignature(alg: JwtAlg, key: KeyObject, signingInput: Buffer, signature: Buffer): boolean {
  try {
    if (alg === "EdDSA") return signature.length === 64 && cryptoVerify(null, signingInput, key, signature);
    if (alg === "ES256") {
      // IEEE P1363 de 64 bytes (r||s) y low-S: una unica forma aceptada por firma (sin maleabilidad).
      if (signature.length !== 64) return false;
      const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
      if (s === 0n || s > P256_HALF_N) return false;
      return cryptoVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
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

export interface VerifiedIdToken {
  sub: string;
  authTime: Date;
  acr: string | null;
  amr: readonly string[] | null;
  /** sha256 hex del token crudo. */
  assertionHash: string;
}

/**
 * Verifica firma y claims. `nonceHashHex` es el sha256 hex del action nonce (platform.oidc_exchange.binding); el claim `nonce` se hashea y se compara en tiempo constante.
 * Lanza VerifierConfigError si la politica es invalida (antes de mirar el token) e IdTokenRejected ante cualquier incumplimiento del token.
 * No devuelve el email ni ningun otro claim.
 */
export function verifyIdToken(idToken: string, jwks: Jwks, nonceHashHex: string, policy: IdTokenPolicy): VerifiedIdToken {
  const skew = validateIdTokenPolicy(policy);
  if (typeof idToken !== "string" || idToken.length === 0 || Buffer.byteLength(idToken, "utf8") > MAX_TOKEN_BYTES) throw new IdTokenRejected("tamano");
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new IdTokenRejected("estructura");
  const [h, p, s] = parts as [string, string, string];
  const header = parseJsonObject(b64urlDecode(h));
  const payloadBytes = b64urlDecode(p);
  const signature = b64urlDecode(s);
  const alg = header.alg;
  if (typeof alg !== "string" || !SUPPORTED_ALGS.has(alg) || !policy.allowedAlgs.includes(alg as JwtAlg)) throw new IdTokenRejected("alg no permitido");
  if (header.crit !== undefined || header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) throw new IdTokenRejected("header no admitido");
  if (header.kid !== undefined && typeof header.kid !== "string") throw new IdTokenRejected("kid no es cadena");
  const kid = header.kid as string | undefined;
  const key = selectKey(jwks, kid, alg as JwtAlg);
  if (!verifySignature(alg as JwtAlg, key, Buffer.from(`${h}.${p}`, "utf8"), signature)) throw new IdTokenRejected("firma");

  const claims = parseJsonObject(payloadBytes);
  const now = policy.nowSeconds;
  if (claims.iss !== policy.issuer) throw new IdTokenRejected("iss");
  const aud = claims.aud;
  if (!(aud === policy.audience || (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === "string") && aud.includes(policy.audience)))) throw new IdTokenRejected("aud");
  if (claims.azp !== undefined && claims.azp !== policy.audience) throw new IdTokenRejected("azp");
  if (Array.isArray(aud) && aud.length > 1 && claims.azp !== policy.audience) throw new IdTokenRejected("azp");
  const exp = claims.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp + skew <= now) throw new IdTokenRejected("exp");
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf) || claims.nbf - skew > now)) throw new IdTokenRejected("nbf");
  if (typeof claims.iat !== "number" || !Number.isFinite(claims.iat) || claims.iat - skew > now) throw new IdTokenRejected("iat");
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
 * sub_hmac = HMAC-SHA256(K_sub, "consent-app/sub-hmac/v1" 0x1f iss 0x1f sub) en hex (ADR-010 §4.4; el prefijo versionado separa el dominio de esta clave de otros usos).
 * K_sub viene del SecretStore (puerto pendiente, F-X8-09): aqui se inyecta, minimo 32 bytes. El sub en claro nunca se persiste.
 */
export function computeSubHmac(key: Buffer, issuer: string, sub: string): string {
  if (key.length < 32) throw new VerifierConfigError("K_sub debe tener al menos 32 bytes");
  return createHmac("sha256", key).update(`${SUB_HMAC_DOMAIN}${issuer}\u001f${sub}`, "utf8").digest("hex");
}
