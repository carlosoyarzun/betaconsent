// Gobierna: ADR-010 rev. 5 PR-6b, revision de seguridad (APROBADO CON P2, 2026-10-15): /login solo por navegacion (Sec-Fetch), excepciones del handler sin tumbar el proceso, allowlist y prefijo P-49 sin
// defaults fuera de LOCAL, REDIRECT_URI https, tope de cuerpo del IdP, P-48 con fallos acr/auth_time (F-PR6-33).
// TEST-CNS-1511: verifier: un fallo de acr/auth_time con firma valida entrega el sub_hmac a la base (solo REJECTED/INVALID_CLAIMS, para contar P-48); un fallo previo a la firma/nonce no.
// TEST-CNS-1513: /login exige Sec-Fetch-Site in {same-origin, none} y Sec-Fetch-Mode=navigate (404 uniforme y sin tocar la base); una excepcion del handler responde 404 y el proceso sigue vivo.
// TEST-CNS-1514: platform-settings: prefijo P-49 obligatorio fuera de LOCAL; allowlist con /0 o prefijo < /8 rechazada; REDIRECT_URI solo https (http solo loopback en LOCAL). Adaptador IdP: cuerpo > 64 KiB rechazado.

import { DENY_ALL_SESSIONS } from "../../helpers/fake-platform-sessions.ts";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { rawFetch } from "../../helpers/raw-http.ts";
import { createOidcIdpAdapter, MAX_IDP_BODY_BYTES } from "../../../src/infra/adapters/oidc-idp.adapter.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { platformRequestHandler } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { loadPlatformSettings, PlatformConfigError } from "../../../src/server/entrypoints/platform/platform-settings.ts";
import { runVerifierCycle } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import { computeSubHmac } from "../../../src/server/modules/step-up/id-token.ts";
import type { AssertionRecord, BeginAuthorizationInput, ClaimedExchange, LoginAssertionRecord, OidcAuthorizationPort, OidcExchangeStorePort } from "../../../src/server/ports/oidc-exchange.port.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const K_SUB = randomBytes(32);
const NONCE = "nonce-hardening";
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

class Store implements OidcExchangeStorePort {
  logins: LoginAssertionRecord[] = [];
  private served = false;
  private readonly next: ClaimedExchange;
  constructor(next: ClaimedExchange) {
    this.next = next;
  }
  async claim(): Promise<ClaimedExchange | null> {
    if (this.served) return null;
    this.served = true;
    return this.next;
  }
  async recordAssertion(_r: AssertionRecord): Promise<boolean> { return false; }
  async recordLoginAssertion(r: LoginAssertionRecord): Promise<boolean> { this.logins.push(r); return false; }
}

test("TEST-CNS-1511 verifier: fallo de acr/auth_time CON firma valida entrega el sub_hmac a la base (REJECTED/INVALID_CLAIMS, para contar P-48); un fallo previo (nonce) no lleva identidad", async () => {
  const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
  const config: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "STAGING", requiredAcrAnyOf: ["urn:acr:mfa"], subHmacKey: K_SUB, subKeyVersion: 2, login: { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 300 } };
  const claimed = (auth: Parameters<SyntheticIdpAdapter["simulateAuthorization"]>[0]): ClaimedExchange => {
    const { code, pkceVerifier } = idp.simulateAuthorization(auth);
    return { exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", kind: "LOGIN_PLATFORM", nonceHash: sha(NONCE), principalRef: null, code, pkceVerifier };
  };
  const expected = { subHmac: computeSubHmac(K_SUB, ISSUER, "sub-hard"), keyVersion: 2 };
  // acr no exigido, acr ausente, auth_time viejo: todos con firma valida => identidad (el sub_hmac, no el sub).
  const now = Math.floor(Date.now() / 1000);
  for (const [label, auth] of [
    ["acr distinto", { sub: "sub-hard", nonce: NONCE, acr: "urn:acr:pwd" }],
    ["acr ausente", { sub: "sub-hard", nonce: NONCE }],
    ["auth_time viejo", { sub: "sub-hard", nonce: NONCE, acr: "urn:acr:mfa", authTime: now - 7200 }],
  ] as const) {
    const store = new Store(claimed(auth));
    assert.equal(await runVerifierCycle({ store, idp, config }), "REJECTED", label);
    assert.deepEqual(store.logins, [{ decision: "REJECTED", exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", reason: "INVALID_CLAIMS", identity: expected }], label);
    assert.ok(!JSON.stringify(store.logins).includes("sub-hard"), "nunca el sub en claro");
  }
  // Nonce ajeno (falla ANTES de confiar en el sub): sin identidad.
  const bad = new Store(claimed({ sub: "sub-hard", nonce: "otro", acr: "urn:acr:mfa" }));
  assert.equal(await runVerifierCycle({ store: bad, idp, config }), "REJECTED");
  assert.deepEqual(bad.logins, [{ decision: "REJECTED", exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", reason: "INVALID_CLAIMS" }]);
});

class Authz implements OidcAuthorizationPort {
  begins = 0;
  async begin(_i: BeginAuthorizationInput): Promise<string> { this.begins += 1; return "0f1e2d3c-4b5a-4968-8776-655443322110"; }
  async complete(): Promise<string | null> { return null; }
  async status(): Promise<null> { return null; }
  async recordLimitEvent(): Promise<void> {}
}
const IDP_ENV = { CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "c", CNS_PLATFORM_REDIRECT_URI: "http://127.0.0.1:8788/platform/auth/callback" };

test("TEST-CNS-1513 /login: Sec-Fetch-Site in {same-origin, none} y Sec-Fetch-Mode=navigate o 404 uniforme sin tocar la base; una excepcion del handler responde 404 y el proceso sigue vivo", async () => {
  const authz = new Authz();
  const server = createServer(platformRequestHandler({ authorization: authz, sessions: DENY_ALL_SESSIONS, settings: loadPlatformSettings(IDP_ENV, "LOCAL") }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const login = (headers: Record<string, string>): Promise<Awaited<ReturnType<typeof rawFetch>>> => rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers });
    assert.equal((await login({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate" })).status, 302);
    assert.equal((await login({ "sec-fetch-site": "none", "sec-fetch-mode": "navigate" })).status, 302);
    assert.equal(authz.begins, 2);
    for (const [label, h] of [
      ["cross-site", { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" }],
      ["same-site", { "sec-fetch-site": "same-site", "sec-fetch-mode": "navigate" }],
      ["no-cors", { "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors" }],
      ["cors (fetch)", { "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }],
      ["sin site", { "sec-fetch-mode": "navigate" }],
      ["sin mode", { "sec-fetch-site": "same-origin" }],
      ["sin headers", {}],
    ] as const) {
      const r = await login(h);
      assert.equal(r.status, 404, label);
      assert.deepEqual(await r.json(), { error: "not_found" }, label);
    }
    assert.equal(authz.begins, 2, "ningun rechazo toca la base");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }

  // Excepcion inesperada al armar las dependencias del handler: 404 uniforme, el proceso no cae y atiende la siguiente solicitud.
  const hostile = loadPlatformSettings(IDP_ENV, "LOCAL");
  let armed = true;
  const settings = new Proxy(hostile, { get(t, k, rcv) { if (armed && k === "allowedCidrs") throw new Error("boom"); return Reflect.get(t, k, rcv); } });
  const s2 = createServer(platformRequestHandler({ authorization: new Authz(), sessions: DENY_ALL_SESSIONS, settings }));
  await new Promise<void>((r) => s2.listen(0, "127.0.0.1", () => r()));
  const b2 = `http://127.0.0.1:${(s2.address() as AddressInfo).port}`;
  try {
    const r = await fetch(`${b2}/platform/auth/callback?code=c&state=s`);
    assert.equal(r.status, 404);
    assert.deepEqual(await r.json(), { error: "not_found" });
    armed = false;
    assert.equal((await fetch(`${b2}/healthz`)).status, 200, "el proceso sigue vivo");
  } finally {
    await new Promise<void>((r) => s2.close(() => r()));
  }
});

test("TEST-CNS-1514 settings: prefijo P-49 obligatorio fuera de LOCAL; allowlist /0 o < /8 rechazada; REDIRECT_URI https (http solo loopback en LOCAL); IdP: cuerpo > 64 KiB rechazado", async () => {
  const full: Record<string, string> = {
    CNS_PLATFORM_BIND_ADDRESS: "10.8.0.5", CNS_PLATFORM_ALLOWED_CIDRS: "10.8.0.0/16", CNS_PLATFORM_P53_MAX_AWAITING: "500", CNS_PLATFORM_SESSION_ABSOLUTE_SECONDS: "14400", CNS_PLATFORM_SESSION_IDLE_SECONDS: "900", CNS_PLATFORM_P49_IPV4_PREFIX: "32",
    CNS_PLATFORM_P49_MAX: "20", CNS_PLATFORM_P49_WINDOW_SECONDS: "900", CNS_PLATFORM_P50_MAX: "30", CNS_PLATFORM_P50_WINDOW_SECONDS: "60", CNS_PLATFORM_P51_MAX: "5", CNS_PLATFORM_P51_WINDOW_SECONDS: "600",
  };
  assert.equal(loadPlatformSettings(full, "STAGING").p49.ipv4Prefix, 32);
  const noPrefix = { ...full };
  delete noPrefix.CNS_PLATFORM_P49_IPV4_PREFIX;
  assert.throws(() => loadPlatformSettings(noPrefix, "STAGING"), PlatformConfigError, "sin default /24 fuera de LOCAL");
  assert.equal(loadPlatformSettings({}, "LOCAL").p49.ipv4Prefix, 24);
  for (const bad of ["0.0.0.0/0", "10.0.0.0/7", "::/0", "fc00::/7", "::/3"]) {
    assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_ALLOWED_CIDRS: bad }, "STAGING"), PlatformConfigError, bad);
    assert.throws(() => loadPlatformSettings({ CNS_PLATFORM_ALLOWED_CIDRS: bad }, "LOCAL"), PlatformConfigError, `LOCAL ${bad}`);
  }
  for (const ok of ["10.0.0.0/8", "fd00::/8", "10.8.0.0/16,192.168.0.0/16"]) assert.ok(loadPlatformSettings({ ...full, CNS_PLATFORM_ALLOWED_CIDRS: ok }, "STAGING"));
  // Fuera de LOCAL solo rangos privados: los publicos (y los que desbordan un rango privado) se rechazan; en LOCAL no aplica.
  for (const pub of ["8.0.0.0/8", "8.8.8.0/24", "2000::/8", "172.15.0.0/16", "172.32.0.0/16", "100.128.0.0/16", "11.0.0.0/8", "10.0.0.0/8,8.8.8.8/32"]) {
    assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_ALLOWED_CIDRS: pub }, "STAGING"), PlatformConfigError, `publico ${pub}`);
  }
  for (const priv of ["172.16.0.0/12", "172.20.1.0/24", "192.168.1.0/24", "100.64.0.0/10", "100.100.0.0/16", "fd12:3456::/32", "10.1.2.3/32"]) {
    assert.ok(loadPlatformSettings({ ...full, CNS_PLATFORM_ALLOWED_CIDRS: priv }, "STAGING"), `privado ${priv}`);
  }
  assert.ok(loadPlatformSettings({ CNS_PLATFORM_ALLOWED_CIDRS: "8.0.0.0/8" }, "LOCAL"), "LOCAL no aplica el filtro de rangos privados");
  const idp = { CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "https://idp.example.invalid/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "c" };
  assert.throws(() => loadPlatformSettings({ ...full, ...idp, CNS_PLATFORM_REDIRECT_URI: "http://platform.example.invalid/cb" }, "STAGING"), PlatformConfigError, "http fuera de LOCAL");
  assert.throws(() => loadPlatformSettings({ ...full, ...idp, CNS_PLATFORM_REDIRECT_URI: "http://127.0.0.1/cb" }, "STAGING"), PlatformConfigError, "loopback http fuera de LOCAL");
  assert.throws(() => loadPlatformSettings({ ...full, ...idp, CNS_PLATFORM_REDIRECT_URI: "https://u:p@platform.example.invalid/cb" }, "STAGING"), PlatformConfigError, "credenciales");
  assert.ok(loadPlatformSettings({ ...full, ...idp, CNS_PLATFORM_REDIRECT_URI: "https://platform.example.invalid/cb" }, "STAGING").idp);
  assert.ok(loadPlatformSettings({ ...idp, CNS_PLATFORM_AUTHORIZATION: "x", CNS_PLATFORM_REDIRECT_URI: "http://127.0.0.1:8788/cb" }, "LOCAL").idp);

  // Adaptador IdP: tope de 64 KiB en token y JWKS.
  const cfg = { environment: "STAGING", egressApproved: true, issuer: ISSUER.replace("synthetic", "real"), tokenEndpoint: "https://idp.real.invalid/token", jwksUri: "https://idp.real.invalid/jwks", clientId: "c", redirectUri: "https://p.example.invalid/cb", timeoutMs: 5000, jwksCacheTtlMs: 60_000 };
  const big = "x".repeat(MAX_IDP_BODY_BYTES + 1);
  const http = {
    postForm: async () => ({ status: 200, body: JSON.stringify({ id_token: big }) }),
    get: async () => ({ status: 200, body: JSON.stringify({ keys: [{ kty: "OKP", pad: big }] }) }),
  };
  const adapter = createOidcIdpAdapter(cfg, http);
  await assert.rejects(() => adapter.exchangeCode({ code: "c", pkceVerifier: "v".repeat(64) }), /demasiado grande/);
  await assert.rejects(() => adapter.getJwks(), /demasiado grande/);
  const small = createOidcIdpAdapter(cfg, { postForm: async () => ({ status: 200, body: JSON.stringify({ id_token: "t" }) }), get: http.get });
  assert.deepEqual(await small.exchangeCode({ code: "c", pkceVerifier: "v".repeat(64) }), { idToken: "t" });
});
