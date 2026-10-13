// Gobierna: ADR-010 rev. 4 §4.3.3 (verificacion del ID token en el verifier: firma, iss/aud/exp, nonce <-> binding, auth_time, acr/amr), §7 fila PR-4; F-A10-12 (sub_hmac).
// TEST-CNS-1369: verifyIdToken acepta un token valido del IdP sintetico y rechaza (con el MOTIVO esperado) firma/alg/iss/aud/azp/exp/iat/nonce/auth_time/acr/amr/kid,
//   base64url no canonico, firma DER o de longitud incorrecta y ES256 high-S; una politica invalida (NaN, Infinity, negativos, enormes, vacios) LANZA VerifierConfigError
//   y nunca acepta un token vencido (fail-closed); computeSubHmac con separacion de dominio.
// Sin Postgres. Solo sinteticos: el IdP es SyntheticIdpAdapter (par Ed25519 efimero, JWKS en memoria).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, createSign, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { computeSubHmac, IdTokenRejected, MAX_AUTH_AGE_CAP_SECONDS, verifyIdToken, VerifierConfigError } from "../../../src/server/modules/step-up/id-token.ts";
import type { IdTokenPolicy } from "../../../src/server/modules/step-up/id-token.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const NOW_MS = Date.UTC(2026, 9, 11, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);
const NONCE = "n".repeat(64);
const NONCE_HASH = createHash("sha256").update(NONCE, "utf8").digest("hex");
const policy = (over: Partial<IdTokenPolicy> = {}): IdTokenPolicy => ({ issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", nowSeconds: NOW_S, ...over });
const idp = (): SyntheticIdpAdapter => new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE, now: () => NOW_MS });

async function tokenFor(p: SyntheticIdpAdapter, auth: Partial<Parameters<SyntheticIdpAdapter["simulateAuthorization"]>[0]> = {}): Promise<string> {
  const { code, pkceVerifier } = p.simulateAuthorization({ sub: "sub-synthetic-1", nonce: NONCE, ...auth });
  return (await p.exchangeCode({ code, pkceVerifier })).idToken;
}

/** El rechazo debe ser un IdTokenRejected con ESE motivo (no basta con que falle). */
const rejects = (fn: () => unknown, reason: string, label = reason): void =>
  assert.throws(fn, (e) => e instanceof IdTokenRejected && e.reason.includes(reason), `${label} (motivo esperado: ${reason})`);
const configError = (fn: () => unknown, label: string): void => assert.throws(fn, (e) => e instanceof VerifierConfigError, label);
const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");

test("TEST-CNS-1369 id-token: un token valido del IdP sintetico se verifica y devuelve solo claims minimos (el email se descarta)", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const token = await tokenFor(p, { acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "alguien@example.invalid", authTime: NOW_S - 30 });
  const v = verifyIdToken(token, jwks, NONCE_HASH, policy());
  assert.equal(v.sub, "sub-synthetic-1");
  assert.equal(v.authTime.getTime(), (NOW_S - 30) * 1000);
  assert.equal(v.acr, "urn:synthetic:mfa");
  assert.deepEqual(v.amr, ["pwd", "otp"]);
  assert.equal(v.assertionHash, createHash("sha256").update(token, "utf8").digest("hex"));
  assert.ok(!JSON.stringify(v).includes("example.invalid"), "el email no sale del verificador");
  verifyIdToken(token, jwks, NONCE_HASH, policy({ requiredAcrAnyOf: ["urn:synthetic:mfa"] }));
  rejects(() => verifyIdToken(token, { keys: [] }, NONCE_HASH, policy()), "clave no encontrada");
  rejects(() => verifyIdToken(tokenWithoutAcr(p), jwks, NONCE_HASH, policy({ requiredAcrAnyOf: ["urn:synthetic:mfa"] })), "acr no exigido");
});

function tokenWithoutAcr(p: SyntheticIdpAdapter): string {
  return p.signRaw({ iss: ISSUER, aud: AUDIENCE, sub: "s", iat: NOW_S, exp: NOW_S + 300, nonce: NONCE, auth_time: NOW_S });
}

test("TEST-CNS-1369 id-token: rechazos de claims (iss, aud, azp, exp, iat, nonce, auth_time, acr, amr, sub) con su motivo", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const claims = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    iss: ISSUER, aud: AUDIENCE, sub: "sub-synthetic-1", iat: NOW_S, exp: NOW_S + 300, nonce: NONCE, auth_time: NOW_S - 10, ...over,
  });
  verifyIdToken(p.signRaw(claims()), jwks, NONCE_HASH, policy());

  const cases: Array<[string, Record<string, unknown>, string, Partial<IdTokenPolicy>?]> = [
    ["iss distinto", claims({ iss: "https://otro.invalid" }), "iss"],
    ["aud distinto", claims({ aud: "otra-app" }), "aud"],
    ["aud lista sin la audiencia", claims({ aud: ["x", "y"] }), "aud"],
    ["aud multiple sin azp", claims({ aud: [AUDIENCE, "y"] }), "azp"],
    ["azp distinto de la audiencia (aud simple)", claims({ azp: "otra-app" }), "azp"],
    ["azp distinto con aud multiple", claims({ aud: [AUDIENCE, "y"], azp: "y" }), "azp"],
    ["exp vencido (mas alla de la tolerancia)", claims({ exp: NOW_S - 31 }), "exp"],
    ["exp no numerico", claims({ exp: "manana" }), "exp"],
    ["nbf futuro", claims({ nbf: NOW_S + 3600 }), "nbf"],
    ["iat futuro", claims({ iat: NOW_S + 3600 }), "iat"],
    ["iat ausente", claims({ iat: undefined }), "iat"],
    ["iat no numerico", claims({ iat: "ayer" }), "iat"],
    ["sub ausente", claims({ sub: undefined }), "sub"],
    ["sub demasiado largo", claims({ sub: "s".repeat(256) }), "sub"],
    ["nonce distinto", claims({ nonce: "otro-nonce" }), "nonce"],
    ["nonce ausente", claims({ nonce: undefined }), "nonce"],
    ["auth_time ausente", claims({ auth_time: undefined }), "auth_time"],
    ["auth_time demasiado antiguo", claims({ auth_time: NOW_S - 3600 }), "auth_time"],
    ["auth_time futuro", claims({ auth_time: NOW_S + 3600 }), "auth_time"],
    ["acr con forma invalida", claims({ acr: "con espacios" }), "acr"],
    ["amr con elemento invalido", claims({ amr: ["pwd", "con espacios"] }), "amr"],
    ["amr demasiado larga", claims({ amr: Array.from({ length: 9 }, (_, i) => `m${i}`) }), "amr"],
    ["acr no exigido", claims({ acr: "urn:otro" }), "acr no exigido", { requiredAcrAnyOf: ["urn:synthetic:mfa"] }],
  ];
  for (const [label, c, reason, pol] of cases) rejects(() => verifyIdToken(p.signRaw(c), jwks, NONCE_HASH, policy(pol)), reason, label);
  verifyIdToken(p.signRaw(claims({ aud: [AUDIENCE, "y"], azp: AUDIENCE })), jwks, NONCE_HASH, policy());
  verifyIdToken(p.signRaw(claims({ azp: AUDIENCE })), jwks, NONCE_HASH, policy());
  rejects(() => verifyIdToken(p.signRaw(claims()), jwks, "no-hex", policy()), "nonce", "binding mal formado");
  rejects(() => verifyIdToken(p.signRaw(claims()), jwks, "0".repeat(64), policy()), "nonce", "binding distinto");
});

test("TEST-CNS-1369 id-token: firma, algoritmo, cabecera, kid y base64url canonico", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const kid = (jwks.keys[0] as { kid: string }).kid;
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: "s", iat: NOW_S, exp: NOW_S + 300, nonce: NONCE, auth_time: NOW_S - 10 };
  const ok = p.signRaw(claims);
  verifyIdToken(ok, jwks, NONCE_HASH, policy());
  const [h, pl, s] = ok.split(".") as [string, string, string];

  rejects(() => verifyIdToken(`${h}.${b64({ ...claims, sub: "otro" })}.${s}`, jwks, NONCE_HASH, policy()), "firma", "payload manipulado");
  rejects(() => verifyIdToken(`${h}.${pl}.${Buffer.from(randomBytes(64)).toString("base64url")}`, jwks, NONCE_HASH, policy()), "firma", "firma aleatoria");
  rejects(() => verifyIdToken(`${h}.${pl}.${Buffer.from(randomBytes(63)).toString("base64url")}`, jwks, NONCE_HASH, policy()), "firma", "EdDSA de longitud incorrecta");
  rejects(() => verifyIdToken(`${h}.${pl}.${Buffer.from(randomBytes(65)).toString("base64url")}`, jwks, NONCE_HASH, policy()), "firma", "EdDSA de 65 bytes");
  rejects(() => verifyIdToken(`${b64({ alg: "none", typ: "JWT" })}.${pl}.`, jwks, NONCE_HASH, policy()), "alg no permitido", "alg none");
  rejects(() => verifyIdToken(`${b64({ alg: "HS256", kid })}.${pl}.${Buffer.from("x").toString("base64url")}`, jwks, NONCE_HASH, policy()), "alg no permitido", "alg HS256");
  rejects(() => verifyIdToken(p.signRaw(claims, { kid: "otra-clave" }), jwks, NONCE_HASH, policy()), "clave no encontrada", "kid desconocido");
  for (const bad of [123, ["a"], { a: 1 }, null, true]) rejects(() => verifyIdToken(p.signRaw(claims, { kid: bad }), jwks, NONCE_HASH, policy()), "kid no es cadena", `kid ${JSON.stringify(bad)}`);
  for (const extra of [{ jku: "https://x.invalid/jwks" }, { jwk: { kty: "OKP" } }, { x5u: "https://x.invalid" }, { crit: ["b64"] }]) {
    rejects(() => verifyIdToken(p.signRaw(claims, extra), jwks, NONCE_HASH, policy()), "header no admitido", `header ${Object.keys(extra)[0]}`);
  }
  rejects(() => verifyIdToken(ok, jwks, NONCE_HASH, policy({ allowedAlgs: ["ES256"] })), "alg no permitido", "alg no permitido por configuracion");
  rejects(() => verifyIdToken("a.b", jwks, NONCE_HASH, policy()), "estructura");
  rejects(() => verifyIdToken("x".repeat(9000), jwks, NONCE_HASH, policy()), "tamano");
  rejects(() => verifyIdToken(ok, { keys: [{ ...(jwks.keys[0] as object), d: "AAAA" }] } as never, NONCE_HASH, policy()), "clave no encontrada", "JWKS con parametro privado");
  rejects(() => verifyIdToken(idp().signRaw(claims, { kid }), jwks, NONCE_HASH, policy()), "firma", "token firmado por otro IdP");

  // base64url no canonico: el ultimo caracter con bits sobrantes distintos decodifica igual pero NO es el mismo segmento.
  const lastChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const tweak = (seg: string): string | null => {
    for (const c of lastChars) if (c !== seg.at(-1) && Buffer.from(seg.slice(0, -1) + c, "base64url").equals(Buffer.from(seg, "base64url"))) return seg.slice(0, -1) + c;
    return null;
  };
  // Se usa un payload cuya longitud deja bits sobrantes; si el segmento es canonico completo, se alarga el sub para forzarlo.
  let payload = claims;
  let seg = b64(payload);
  for (let i = 0; i < 4 && seg.length % 4 === 0; i++) { payload = { ...payload, sub: `s${"x".repeat(i + 1)}` }; seg = b64(payload); }
  const signed = p.signRaw(payload);
  const [h2, p2, s2] = signed.split(".") as [string, string, string];
  assert.equal(seg, p2);
  verifyIdToken(signed, jwks, NONCE_HASH, policy());
  const tp = tweak(p2);
  const ts = tweak(s2);
  const th = tweak(h2);
  assert.ok(tp !== null && ts !== null, "payload y firma tienen variante no canonica");
  rejects(() => verifyIdToken(`${h2}.${tp}.${s2}`, jwks, NONCE_HASH, policy()), "no canonico", "payload no canonico");
  if (th !== null) rejects(() => verifyIdToken(`${th}.${p2}.${s2}`, jwks, NONCE_HASH, policy()), "no canonico", "header no canonico");
  rejects(() => verifyIdToken(`${h2}.${p2}.${ts}`, jwks, NONCE_HASH, policy()), "no canonico", "firma no canonica");
  rejects(() => verifyIdToken(`${h2}.${p2}=.${s2}`, jwks, NONCE_HASH, policy()), "base64url invalido", "relleno '='");
});

/** Normaliza a low-S (s <= n/2) como lo exige el verificador. */
function lowS(sig: Buffer): Buffer {
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
  if (s <= n >> 1n) return sig;
  return Buffer.concat([sig.subarray(0, 32), Buffer.from((n - s).toString(16).padStart(64, "0"), "hex")]);
}

test("TEST-CNS-1369 id-token: ES256 solo P1363 de 64 bytes y low-S (sin DER ni high-S); RS256 >= 2048 bits con e = 65537; kid ausente solo con una unica clave", () => {
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const ecJwk = { ...(ec.publicKey.export({ format: "jwk" }) as object), kty: "EC", crv: "P-256", kid: "ec1", alg: "ES256" } as never;
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: "s", iat: NOW_S, exp: NOW_S + 60, nonce: NONCE, auth_time: NOW_S };
  const mk = (alg: string, signer: (data: Buffer) => Buffer, kid?: string): string => {
    const h = b64({ alg, ...(kid === undefined ? {} : { kid }) });
    const pl = b64(claims);
    return `${h}.${pl}.${signer(Buffer.from(`${h}.${pl}`)).toString("base64url")}`;
  };
  const p1363 = (d: Buffer): Buffer => sign("sha256", d, { key: ec.privateKey, dsaEncoding: "ieee-p1363" });
  const pol = policy({ allowedAlgs: ["ES256"] });
  verifyIdToken(mk("ES256", (d) => lowS(p1363(d)), "ec1"), { keys: [ecJwk] }, NONCE_HASH, pol);
  verifyIdToken(mk("ES256", (d) => lowS(p1363(d))), { keys: [ecJwk] }, NONCE_HASH, pol);
  rejects(() => verifyIdToken(mk("ES256", (d) => lowS(p1363(d))), { keys: [ecJwk, { ...(ecJwk as object), kid: "ec2" } as never] }, NONCE_HASH, pol), "clave no encontrada", "sin kid y dos claves");
  // DER (70-72 bytes) y longitud incorrecta.
  rejects(() => verifyIdToken(mk("ES256", (d) => sign("sha256", d, ec.privateKey), "ec1"), { keys: [ecJwk] }, NONCE_HASH, pol), "firma", "ES256 en DER");
  rejects(() => verifyIdToken(mk("ES256", (d) => lowS(p1363(d)).subarray(0, 63), "ec1"), { keys: [ecJwk] }, NONCE_HASH, pol), "firma", "ES256 de 63 bytes");
  rejects(() => verifyIdToken(mk("ES256", (d) => Buffer.concat([lowS(p1363(d)), Buffer.from([0])]), "ec1"), { keys: [ecJwk] }, NONCE_HASH, pol), "firma", "ES256 de 65 bytes");
  // high-S: la firma es matematicamente valida pero maleable; se rechaza. Con varias firmas, alguna cae en la mitad alta.
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const high = (d: Buffer): Buffer => {
    const sig = lowS(p1363(d));
    const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
    return Buffer.concat([sig.subarray(0, 32), Buffer.from((n - s).toString(16).padStart(64, "0"), "hex")]);
  };
  rejects(() => verifyIdToken(mk("ES256", high, "ec1"), { keys: [ecJwk] }, NONCE_HASH, pol), "firma", "ES256 high-S");

  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaJwk = { ...(rsa.publicKey.export({ format: "jwk" }) as object), kty: "RSA", kid: "r1", alg: "RS256" } as never;
  const rpol = policy({ allowedAlgs: ["RS256"] });
  verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(rsa.privateKey), "r1"), { keys: [rsaJwk] }, NONCE_HASH, rpol);
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const weakJwk = { ...(weak.publicKey.export({ format: "jwk" }) as object), kty: "RSA", kid: "r1", alg: "RS256" } as never;
  rejects(() => verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(weak.privateKey), "r1"), { keys: [weakJwk] }, NONCE_HASH, rpol), "clave rsa debil", "RSA < 2048 bits");
  const e3 = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 3 });
  const e3Jwk = { ...(e3.publicKey.export({ format: "jwk" }) as object), kty: "RSA", kid: "r1", alg: "RS256" } as never;
  rejects(() => verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(e3.privateKey), "r1"), { keys: [e3Jwk] }, NONCE_HASH, rpol), "clave rsa debil", "RSA e = 3");
  rejects(() => verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(rsa.privateKey), "ec1"), { keys: [ecJwk] }, NONCE_HASH, rpol), "clave no encontrada", "kty no coincide con alg");
});

test("TEST-CNS-1369 id-token: una politica invalida (NaN, Infinity, negativo, enorme, vacio) LANZA VerifierConfigError y nunca acepta un token vencido (fail-closed)", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const expired = p.signRaw({ iss: ISSUER, aud: AUDIENCE, sub: "s", iat: NOW_S - 200_000, exp: NOW_S - 100_000, nonce: NONCE, auth_time: NOW_S - 100_000 });
  // Regresion P1: con skew = NaN las comparaciones eran siempre falsas y se aceptaba un token vencido hace 100.000 s.
  rejects(() => verifyIdToken(expired, jwks, NONCE_HASH, policy()), "exp", "sin config rota el vencido se rechaza");
  const valid = p.signRaw({ iss: ISSUER, aud: AUDIENCE, sub: "s", iat: NOW_S, exp: NOW_S + 300, nonce: NONCE, auth_time: NOW_S });
  const bad: Array<[string, Partial<IdTokenPolicy>]> = [
    ["skew NaN", { clockSkewSeconds: Number.NaN }], ["skew Infinity", { clockSkewSeconds: Number.POSITIVE_INFINITY }], ["skew -Infinity", { clockSkewSeconds: Number.NEGATIVE_INFINITY }],
    ["skew negativo", { clockSkewSeconds: -1 }], ["skew 121", { clockSkewSeconds: 121 }], ["skew enorme", { clockSkewSeconds: 1e9 }], ["skew fraccionario", { clockSkewSeconds: 1.5 }],
    ["skew no numerico", { clockSkewSeconds: "30" as never }],
    ["maxAuth NaN", { maxAuthAgeSeconds: Number.NaN }], ["maxAuth Infinity", { maxAuthAgeSeconds: Number.POSITIVE_INFINITY }], ["maxAuth 0", { maxAuthAgeSeconds: 0 }],
    ["maxAuth negativo", { maxAuthAgeSeconds: -5 }], ["maxAuth sobre el tope", { maxAuthAgeSeconds: MAX_AUTH_AGE_CAP_SECONDS + 1 }], ["maxAuth enorme", { maxAuthAgeSeconds: 1e12 }],
    ["maxAuth fraccionario", { maxAuthAgeSeconds: 10.5 }], ["maxAuth ausente", { maxAuthAgeSeconds: undefined as never }],
    ["allowedAlgs vacio", { allowedAlgs: [] }], ["allowedAlgs con none", { allowedAlgs: ["none" as never] }], ["allowedAlgs no es lista", { allowedAlgs: "EdDSA" as never }],
    ["issuer vacio", { issuer: "" }], ["audience vacia", { audience: "" }], ["issuer no cadena", { issuer: 7 as never }],
    ["nowSeconds NaN", { nowSeconds: Number.NaN }], ["nowSeconds Infinity", { nowSeconds: Number.POSITIVE_INFINITY }], ["nowSeconds negativo", { nowSeconds: -1 }],
    ["requiredAcrAnyOf con vacio", { requiredAcrAnyOf: [""] }],
  ];
  for (const [label, over] of bad) {
    configError(() => verifyIdToken(valid, jwks, NONCE_HASH, policy(over)), label);
    configError(() => verifyIdToken(expired, jwks, NONCE_HASH, policy(over)), `${label} (token vencido)`);
  }
  // Limites validos.
  verifyIdToken(valid, jwks, NONCE_HASH, policy({ clockSkewSeconds: 0 }));
  verifyIdToken(valid, jwks, NONCE_HASH, policy({ clockSkewSeconds: 120, maxAuthAgeSeconds: MAX_AUTH_AGE_CAP_SECONDS }));
});

test("TEST-CNS-1369 id-token: computeSubHmac es determinista, depende de la clave y del issuer, lleva separacion de dominio y exige K_sub >= 32 bytes", () => {
  const key = randomBytes(32);
  const h = computeSubHmac(key, ISSUER, "sub-1");
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, computeSubHmac(key, ISSUER, "sub-1"));
  assert.notEqual(h, computeSubHmac(key, ISSUER, "sub-2"));
  assert.notEqual(h, computeSubHmac(key, "https://otro.invalid", "sub-1"));
  assert.notEqual(h, computeSubHmac(randomBytes(32), ISSUER, "sub-1"));
  assert.ok(!h.includes("sub-1"));
  // El HMAC sin el prefijo de dominio NO coincide; con el prefijo versionado, si.
  assert.notEqual(h, createHmac("sha256", key).update(`${ISSUER}\u001fsub-1`, "utf8").digest("hex"));
  assert.equal(h, createHmac("sha256", key).update(`consent-app/sub-hmac/v1\u001f${ISSUER}\u001fsub-1`, "utf8").digest("hex"));
  configError(() => computeSubHmac(randomBytes(31), ISSUER, "sub-1"), "K_sub corta");
});
