// Gobierna: ADR-010 rev. 4 §4.3.3 (verificacion del ID token en el verifier: firma, iss/aud/exp, nonce <-> binding, auth_time, acr/amr), §7 fila PR-4; F-A10-12 (sub_hmac).
// TEST-CNS-1369: verifyIdToken acepta un token valido del IdP sintetico y rechaza firma/alg/iss/aud/exp/nonce/auth_time/acr/amr/kid invalidos; computeSubHmac.
// Sin Postgres. Solo sinteticos: el IdP es SyntheticIdpAdapter (par Ed25519 efimero, JWKS en memoria).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { computeSubHmac, IdTokenRejected, verifyIdToken } from "../../../src/server/modules/step-up/id-token.ts";
import type { IdTokenPolicy } from "../../../src/server/modules/step-up/id-token.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const NOW_MS = Date.UTC(2026, 9, 11, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);
const NONCE = "n".repeat(64);
const NONCE_HASH = createHash("sha256").update(NONCE, "utf8").digest("hex");
const policy = (over: Partial<IdTokenPolicy> = {}): IdTokenPolicy => ({ issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, nowSeconds: NOW_S, ...over });
const idp = (): SyntheticIdpAdapter => new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE, now: () => NOW_MS });

async function tokenFor(p: SyntheticIdpAdapter, auth: Partial<Parameters<SyntheticIdpAdapter["simulateAuthorization"]>[0]> = {}): Promise<string> {
  const { code, pkceVerifier } = p.simulateAuthorization({ sub: "sub-synthetic-1", nonce: NONCE, ...auth });
  return (await p.exchangeCode({ code, pkceVerifier })).idToken;
}

const rejects = (fn: () => unknown, label: string): void => assert.throws(fn, (e) => e instanceof IdTokenRejected, label);
const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");

test("TEST-CNS-1369 id-token: un token valido del IdP sintetico se verifica y devuelve solo claims minimos (el email se descarta)", async () => {
  const p = idp();
  const token = await tokenFor(p, { acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "alguien@example.invalid", authTime: NOW_S - 30 });
  const jwks = await p.getJwks();
  const v = verifyIdToken(token, jwks, NONCE_HASH, policy());
  assert.equal(v.sub, "sub-synthetic-1");
  assert.equal(v.authTime.getTime(), (NOW_S - 30) * 1000);
  assert.equal(v.acr, "urn:synthetic:mfa");
  assert.deepEqual(v.amr, ["pwd", "otp"]);
  assert.equal(v.assertionHash, createHash("sha256").update(token, "utf8").digest("hex"));
  assert.ok(!JSON.stringify(v).includes("example.invalid"), "el email no sale del verificador");
  // acr exigido: presente y en la lista pasa; ausente o distinto falla.
  verifyIdToken(token, jwks, NONCE_HASH, policy({ requiredAcrAnyOf: ["urn:synthetic:mfa"] }));
  rejects(() => verifyIdToken(token, { keys: [] }, NONCE_HASH, policy()), "JWKS sin claves");
  const noAcr = await tokenFor(p);
  rejects(() => verifyIdToken(noAcr, jwks, NONCE_HASH, policy({ requiredAcrAnyOf: ["urn:synthetic:mfa"] })), "acr ausente");
});

test("TEST-CNS-1369 id-token: rechazos de claims (iss, aud, exp, nonce, auth_time, acr, amr, sub) y de firma/alg/kid/header", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const claims = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    iss: ISSUER, aud: AUDIENCE, sub: "sub-synthetic-1", iat: NOW_S, exp: NOW_S + 300, nonce: NONCE, auth_time: NOW_S - 10, ...over,
  });
  const ok = p.signRaw(claims());
  verifyIdToken(ok, jwks, NONCE_HASH, policy());

  const cases: Array<[string, Record<string, unknown>, Partial<IdTokenPolicy>?]> = [
    ["iss distinto", claims({ iss: "https://otro.invalid" })],
    ["aud distinto", claims({ aud: "otra-app" })],
    ["aud lista sin la audiencia", claims({ aud: ["x", "y"] })],
    ["aud multiple sin azp", claims({ aud: [AUDIENCE, "y"] })],
    ["exp vencido (mas alla de la tolerancia)", claims({ exp: NOW_S - 31 })],
    ["exp no numerico", claims({ exp: "manana" })],
    ["nbf futuro", claims({ nbf: NOW_S + 3600 })],
    ["iat futuro", claims({ iat: NOW_S + 3600 })],
    ["sub ausente", claims({ sub: undefined })],
    ["sub demasiado largo", claims({ sub: "s".repeat(256) })],
    ["nonce distinto", claims({ nonce: "otro-nonce" })],
    ["nonce ausente", claims({ nonce: undefined })],
    ["auth_time ausente", claims({ auth_time: undefined })],
    ["auth_time demasiado antiguo", claims({ auth_time: NOW_S - 3600 })],
    ["auth_time futuro", claims({ auth_time: NOW_S + 3600 })],
    ["acr con forma invalida", claims({ acr: "con espacios" })],
    ["amr con elemento invalido", claims({ amr: ["pwd", "con espacios"] })],
    ["amr demasiado larga", claims({ amr: Array.from({ length: 9 }, (_, i) => `m${i}`) })],
    ["acr no exigido", claims({ acr: "urn:otro" }), { requiredAcrAnyOf: ["urn:synthetic:mfa"] }],
  ];
  for (const [label, c, pol] of cases) rejects(() => verifyIdToken(p.signRaw(c), jwks, NONCE_HASH, policy(pol)), label);
  // aud multiple con azp correcto si pasa.
  verifyIdToken(p.signRaw(claims({ aud: [AUDIENCE, "y"], azp: AUDIENCE })), jwks, NONCE_HASH, policy());
  // El binding debe ser un sha256 hex.
  rejects(() => verifyIdToken(ok, jwks, "no-hex", policy()), "binding mal formado");
  rejects(() => verifyIdToken(ok, jwks, "0".repeat(64), policy()), "binding distinto");

  // Firma, algoritmo y cabecera.
  const [h, pl, s] = ok.split(".") as [string, string, string];
  rejects(() => verifyIdToken(`${h}.${b64(claims({ sub: "otro" }))}.${s}`, jwks, NONCE_HASH, policy()), "payload manipulado con la firma original");
  rejects(() => verifyIdToken(`${h}.${pl}.${Buffer.from(randomBytes(64)).toString("base64url")}`, jwks, NONCE_HASH, policy()), "firma aleatoria");
  rejects(() => verifyIdToken(`${b64({ alg: "none", typ: "JWT" })}.${pl}.`, jwks, NONCE_HASH, policy()), "alg none");
  const kid = (jwks.keys[0] as { kid: string }).kid;
  rejects(() => verifyIdToken(`${b64({ alg: "HS256", kid })}.${pl}.${Buffer.from("x").toString("base64url")}`, jwks, NONCE_HASH, policy()), "alg HS256 (confusion de algoritmo)");
  rejects(() => verifyIdToken(p.signRaw(claims(), { kid: "otra-clave" }), jwks, NONCE_HASH, policy()), "kid desconocido");
  for (const extra of [{ jku: "https://x.invalid/jwks" }, { jwk: { kty: "OKP" } }, { x5u: "https://x.invalid" }, { crit: ["b64"] }]) {
    rejects(() => verifyIdToken(p.signRaw(claims(), extra), jwks, NONCE_HASH, policy()), `header ${Object.keys(extra)[0]}`);
  }
  rejects(() => verifyIdToken(ok, jwks, NONCE_HASH, policy({ allowedAlgs: ["ES256"] })), "alg no permitido por configuracion");
  rejects(() => verifyIdToken("a.b", jwks, NONCE_HASH, policy()), "estructura");
  rejects(() => verifyIdToken("x".repeat(9000), jwks, NONCE_HASH, policy()), "tamano");
  // Un JWKS con material privado no se acepta como clave de verificacion.
  const withPrivate = { keys: [{ ...(jwks.keys[0] as object), d: "AAAA" }] } as never;
  rejects(() => verifyIdToken(ok, withPrivate, NONCE_HASH, policy()), "JWKS con parametro privado");
  // Otro IdP (otra clave) con el mismo kid no valida.
  const other = idp();
  const forged = other.signRaw(claims(), { kid });
  rejects(() => verifyIdToken(forged, jwks, NONCE_HASH, policy()), "token firmado por otro IdP");
});

test("TEST-CNS-1369 id-token: ES256 (P1363) y RS256 con JWKS propios; el kid ausente solo vale con una unica clave", () => {
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const ecJwk = { ...(ec.publicKey.export({ format: "jwk" }) as object), kty: "EC", crv: "P-256", kid: "ec1", alg: "ES256" } as never;
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: "s", exp: NOW_S + 60, nonce: NONCE, auth_time: NOW_S };
  const mk = (alg: string, signer: (data: Buffer) => Buffer, kid?: string): string => {
    const h = b64({ alg, ...(kid === undefined ? {} : { kid }) });
    const pl = b64(claims);
    return `${h}.${pl}.${signer(Buffer.from(`${h}.${pl}`)).toString("base64url")}`;
  };
  const es = mk("ES256", (d) => sign("sha256", d, { key: ec.privateKey, dsaEncoding: "ieee-p1363" }), "ec1");
  verifyIdToken(es, { keys: [ecJwk] }, NONCE_HASH, policy({ allowedAlgs: ["ES256"] }));
  verifyIdToken(mk("ES256", (d) => sign("sha256", d, { key: ec.privateKey, dsaEncoding: "ieee-p1363" })), { keys: [ecJwk] }, NONCE_HASH, policy({ allowedAlgs: ["ES256"] }));
  rejects(() => verifyIdToken(mk("ES256", (d) => sign("sha256", d, { key: ec.privateKey, dsaEncoding: "ieee-p1363" })), { keys: [ecJwk, { ...(ecJwk as object), kid: "ec2" } as never] }, NONCE_HASH, policy({ allowedAlgs: ["ES256"] })), "sin kid y dos claves");

  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaJwk = { ...(rsa.publicKey.export({ format: "jwk" }) as object), kty: "RSA", kid: "r1", alg: "RS256" } as never;
  const rs = mk("RS256", (d) => createSign("sha256").update(d).sign(rsa.privateKey), "r1");
  verifyIdToken(rs, { keys: [rsaJwk] }, NONCE_HASH, policy({ allowedAlgs: ["RS256"] }));
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const weakJwk = { ...(weak.publicKey.export({ format: "jwk" }) as object), kty: "RSA", kid: "r1", alg: "RS256" } as never;
  rejects(() => verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(weak.privateKey), "r1"), { keys: [weakJwk] }, NONCE_HASH, policy({ allowedAlgs: ["RS256"] })), "RSA < 2048 bits");
  // Una clave EC no sirve para un token que declara RS256.
  rejects(() => verifyIdToken(mk("RS256", (d) => createSign("sha256").update(d).sign(rsa.privateKey), "ec1"), { keys: [ecJwk] }, NONCE_HASH, policy({ allowedAlgs: ["RS256"] })), "kty no coincide con alg");
});

test("TEST-CNS-1369 id-token: computeSubHmac es determinista, depende de la clave y del issuer, y exige K_sub >= 32 bytes", () => {
  const key = randomBytes(32);
  const h = computeSubHmac(key, ISSUER, "sub-1");
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, computeSubHmac(key, ISSUER, "sub-1"));
  assert.notEqual(h, computeSubHmac(key, ISSUER, "sub-2"));
  assert.notEqual(h, computeSubHmac(key, "https://otro.invalid", "sub-1"));
  assert.notEqual(h, computeSubHmac(randomBytes(32), ISSUER, "sub-1"));
  assert.ok(!h.includes("sub-1"));
  assert.throws(() => computeSubHmac(randomBytes(31), ISSUER, "sub-1"), /K_sub/);
});
