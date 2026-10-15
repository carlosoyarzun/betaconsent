// Gobierna: ADR-010 rev. 5 §10 fila PR-6b (adaptador de IdP real APAGADO), F-A10-24 (endpoints fijados, sin discovery ni jku), P-45/APR-IDP/TP-02 PENDING.
// TEST-CNS-1510: el factory se niega en LOCAL, sin egress aprobado y con configuracion insegura; con cliente HTTP inyectado FALSO (sin red) canjea con PKCE, cachea el JWKS por TTL, no hace discovery
//   y los errores no filtran secretos; el ID token de un IdP asi sigue pasando por verifyIdToken (rechaza jku/alg no permitido/kid desconocido).

import assert from "node:assert/strict";
import test from "node:test";
import { createOidcIdpAdapter, IdpConfigError } from "../../../src/infra/adapters/oidc-idp.adapter.ts";
import type { IdpHttpClient, OidcIdpConfig } from "../../../src/infra/adapters/oidc-idp.adapter.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { IdTokenRejected, verifyIdToken } from "../../../src/server/modules/step-up/id-token.ts";
import { createHash } from "node:crypto";

const ISSUER = "https://idp.example.invalid";
const base: OidcIdpConfig = {
  environment: "STAGING", egressApproved: true, issuer: ISSUER, tokenEndpoint: `${ISSUER}/token`, jwksUri: `${ISSUER}/jwks`,
  clientId: "consent-platform", redirectUri: "https://platform.example.invalid/platform/auth/callback", timeoutMs: 5000, jwksCacheTtlMs: 60_000,
};

class FakeHttp implements IdpHttpClient {
  calls: string[] = [];
  forms: Array<Record<string, string>> = [];
  tokenBody = JSON.stringify({ id_token: "token.crudo.firmado" });
  tokenStatus = 200;
  jwksBody = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "k1", x: "AAAA" }] });
  async postForm(url: string, form: Readonly<Record<string, string>>): Promise<{ status: number; body: string }> {
    this.calls.push(`POST ${url}`);
    this.forms.push({ ...form });
    return { status: this.tokenStatus, body: this.tokenBody };
  }
  async get(url: string): Promise<{ status: number; body: string }> {
    this.calls.push(`GET ${url}`);
    return { status: 200, body: this.jwksBody };
  }
}

test("TEST-CNS-1510 adaptador real del IdP (apagado): factory fail-closed; canje con PKCE contra endpoints fijados (cliente inyectado falso); JWKS con cache por TTL; sin discovery; errores sin secretos", async () => {
  const http = new FakeHttp();
  // Apagado: LOCAL, sin egress aprobado, environment fuera del enum, URL insegura, origen distinto, timeouts fuera de rango.
  const bad: Array<[string, Partial<OidcIdpConfig>]> = [
    ["LOCAL", { environment: "LOCAL" }], ["PRODUCTION", { environment: "PRODUCTION" }], ["sin egress", { egressApproved: false }],
    ["issuer http", { issuer: "http://idp.example.invalid" }], ["token otro origen", { tokenEndpoint: "https://otro.example.invalid/token" }],
    ["jwks otro origen", { jwksUri: "https://otro.example.invalid/jwks" }], ["credenciales en URL", { tokenEndpoint: `https://u:p@idp.example.invalid/token` }],
    ["fragmento", { jwksUri: `${ISSUER}/jwks#x` }], ["clientId vacio", { clientId: "" }], ["timeout 0", { timeoutMs: 0 }], ["timeout enorme", { timeoutMs: 120_000 }],
    ["cache 0", { jwksCacheTtlMs: 0 }], ["redirect http", { redirectUri: "http://platform.invalid/cb" }],
  ];
  for (const [label, over] of bad) assert.throws(() => createOidcIdpAdapter({ ...base, ...over }, http), IdpConfigError, label);
  assert.equal(http.calls.length, 0, "construir el adaptador no hace red");

  const idp = createOidcIdpAdapter(base, http);
  assert.equal(idp.synthetic, undefined, "un adaptador real no lleva la marca sintetica");
  // Canje: POST al token_endpoint FIJADO con code, code_verifier PKCE, client_id y redirect_uri; devuelve el id_token crudo.
  const out = await idp.exchangeCode({ code: "code-1", pkceVerifier: "v".repeat(64) });
  assert.equal(out.idToken, "token.crudo.firmado");
  assert.deepEqual(http.calls, [`POST ${ISSUER}/token`]);
  assert.deepEqual(http.forms[0], { grant_type: "authorization_code", code: "code-1", code_verifier: "v".repeat(64), client_id: "consent-platform", redirect_uri: base.redirectUri });
  // Errores uniformes y sin secretos.
  for (const [status, body] of [[400, "{}"], [200, "no-json"], [200, "{}"], [200, JSON.stringify({ id_token: "" })]] as const) {
    http.tokenStatus = status;
    http.tokenBody = body;
    await assert.rejects(() => idp.exchangeCode({ code: "SECRETO-CODE", pkceVerifier: "SECRETO-PKCE".padEnd(43, "x") }), (e: Error) => !/SECRETO/.test(e.message));
  }
  // JWKS: un GET al jwks_uri fijado, cacheado por TTL; nunca discovery (.well-known) ni jku.
  let t = 1_000_000;
  const cached = createOidcIdpAdapter({ ...base, now: () => t }, http);
  http.calls = [];
  await cached.getJwks();
  await cached.getJwks();
  assert.deepEqual(http.calls, [`GET ${ISSUER}/jwks`]);
  t += 60_001;
  await cached.getJwks();
  assert.equal(http.calls.length, 2, "vencido el TTL se vuelve a pedir");
  assert.ok(!http.calls.some((c) => c.includes(".well-known")));
  for (const body of ["no-json", "{}", JSON.stringify({ keys: [] }), JSON.stringify({ keys: [{ nokty: 1 }] })]) {
    http.jwksBody = body;
    await assert.rejects(() => createOidcIdpAdapter(base, http).getJwks());
  }

  // El token de un IdP asi pasa por verifyIdToken: jku, alg none y kid desconocido se rechazan.
  const syn = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: "aud" });
  const nonce = "n1";
  const nonceHash = createHash("sha256").update(nonce).digest("hex");
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, aud: "aud", sub: "s", iat: now, exp: now + 60, nonce, auth_time: now };
  const policy = { issuer: ISSUER, audience: "aud", allowedAlgs: ["EdDSA"] as const, maxAuthAgeSeconds: 300, environment: "LOCAL", nowSeconds: now };
  const jwks = await syn.getJwks();
  assert.equal(verifyIdToken(syn.signRaw(claims), jwks, nonceHash, policy).sub, "s");
  assert.throws(() => verifyIdToken(syn.signRaw(claims, { jku: "https://evil.invalid/jwks" }), jwks, nonceHash, policy), IdTokenRejected);
  assert.throws(() => verifyIdToken(syn.signRaw(claims, { alg: "none" }), jwks, nonceHash, policy), IdTokenRejected);
  assert.throws(() => verifyIdToken(syn.signRaw(claims, { kid: "desconocido" }), jwks, nonceHash, policy), IdTokenRejected);
});
