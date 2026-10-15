// Gobierna: ADR-010 rev. 5 §5.2 pasos 1-2, §5.4 (P-49, P-50), G-5 (max_age=0 + prompt=login), G-6 (limites, red), G-8 (exchangeRef solo en cookie __Host- Strict), F-PR6-15/31.
// TEST-CNS-1505: limitadores en memoria (ventana deslizante, un evento por clave, tope de claves fail-closed), truncado de IP y allowlist CIDR.
// TEST-CNS-1506: platform-settings: fuera de LOCAL P-49..P-51, P-53, bind y allowlist son obligatorios (sin defaults); LOCAL usa los valores iniciales aprobados.
// TEST-CNS-1507: rutas HTTP de login: 302 con max_age=0 y prompt=login, cookie state Lax, callback con comparacion de state, 303 sin code ni ref, ref solo en cookie Strict, 404 uniforme, P-49 y allowlist.
// TEST-CNS-1508: ciclo del verifier para LOGIN_*: entrega sub_hmac + key_version + limites a la base, nunca un principal; rechazos sin sub; limites de login obligatorios fuera de LOCAL.

import { DENY_ALL_SESSIONS } from "../../helpers/fake-platform-sessions.ts";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { rawFetch } from "../../helpers/raw-http.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { AUTH_CONTINUE_PATH, OIDC_EXCHANGE_COOKIE, OIDC_STATE_COOKIE } from "../../../src/server/entrypoints/platform/auth-routes.ts";
import { loadPlatformSettings, PlatformConfigError } from "../../../src/server/entrypoints/platform/platform-settings.ts";
import { platformRequestHandler } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { createSlidingLimiter, ipInCidrs, parseCidr, truncateIp } from "../../../src/server/entrypoints/platform/rate-limit.ts";
import { VerifierConfigError } from "../../../src/server/modules/step-up/id-token.ts";
import { runVerifierCycle, validateVerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import type { AssertionRecord, BeginAuthorizationInput, ClaimedExchange, ExchangeStatus, LoginAssertionRecord, OidcAuthorizationPort, OidcExchangeStorePort } from "../../../src/server/ports/oidc-exchange.port.ts";
import { PlatformDeniedError } from "../../../src/server/ports/oidc-exchange.port.ts";

// Sec-Fetch de una navegacion legitima al login (seguridad PR-6b): same-origin|none + navigate.
const NAV = { "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate" };
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

test("TEST-CNS-1505 limitadores en memoria: ventana deslizante, un solo evento por clave, tope de claves fail-closed; truncado de IP; allowlist CIDR (v4 y v6)", () => {
  let t = 1_000_000;
  const lim = createSlidingLimiter({ max: 3, windowMs: 1000, now: () => t });
  assert.deepEqual([lim.hit("a"), lim.hit("a"), lim.hit("a")].map((d) => d.allowed), [true, true, true]);
  assert.deepEqual(lim.hit("a"), { allowed: false, firstDenial: true });
  assert.deepEqual(lim.hit("a"), { allowed: false, firstDenial: false }, "un solo evento por clave y ventana");
  assert.equal(lim.hit("b").allowed, true, "otra clave no se afecta");
  t += 1001;
  assert.equal(lim.hit("a").allowed, true, "vencida la ventana vuelve a admitir");
  // Tope de claves: lleno y sin vencidas => deniega (fail-closed).
  const capped = createSlidingLimiter({ max: 5, windowMs: 60_000, now: () => t, maxKeys: 2 });
  assert.equal(capped.hit("k1").allowed && capped.hit("k2").allowed, true);
  assert.equal(capped.hit("k3").allowed, false);
  assert.throws(() => createSlidingLimiter({ max: 0, windowMs: 1 }));
  // Truncado: /24 agrupa vecinos; /32 los separa; v4-mapeado-en-v6 equivale a v4; v6 a /48.
  assert.equal(truncateIp("10.1.2.3"), truncateIp("10.1.2.200"));
  assert.notEqual(truncateIp("10.1.2.3"), truncateIp("10.1.3.3"));
  assert.notEqual(truncateIp("10.1.2.3", 32), truncateIp("10.1.2.4", 32));
  assert.equal(truncateIp("::ffff:10.1.2.3"), truncateIp("10.1.2.3"));
  assert.equal(truncateIp("2001:db8:1:1::1"), truncateIp("2001:db8:1:1:ffff::2"));
  assert.notEqual(truncateIp("2001:db8:1::1"), truncateIp("2001:db8:2::1"));
  assert.equal(truncateIp("no-ip"), "unknown");
  // Allowlist.
  const cidrs = ["10.8.0.0/16", "fd00::/8"].map(parseCidr);
  assert.equal(ipInCidrs("10.8.3.4", cidrs), true);
  assert.equal(ipInCidrs("::ffff:10.8.3.4", cidrs), true);
  assert.equal(ipInCidrs("10.9.0.1", cidrs), false);
  assert.equal(ipInCidrs("fd12::1", cidrs), true);
  assert.equal(ipInCidrs("2001:db8::1", cidrs), false);
  assert.equal(ipInCidrs("basura", cidrs), false);
  assert.throws(() => parseCidr("10.0.0.0/40"));
  assert.throws(() => parseCidr("host/8"));
});

test("TEST-CNS-1506 platform-settings: fuera de LOCAL no hay defaults (P-49..P-51, P-53, bind y allowlist obligatorios); LOCAL usa los valores iniciales aprobados; bind sin comodin; IdP todo o nada", () => {
  const local = loadPlatformSettings({}, "LOCAL");
  assert.equal(local.bindAddress, "127.0.0.1");
  assert.deepEqual([local.p49.max, local.p49.windowSeconds, local.p50.max, local.p50.windowSeconds, local.p51.max, local.p51.windowSeconds], [20, 900, 30, 60, 5, 600]);
  assert.equal(local.maxAwaiting, null);
  assert.equal(local.idp, undefined);
  const full = {
    CNS_PLATFORM_BIND_ADDRESS: "10.8.0.5", CNS_PLATFORM_ALLOWED_CIDRS: "10.8.0.0/16", CNS_PLATFORM_P53_MAX_AWAITING: "500",
    CNS_PLATFORM_P49_MAX: "20", CNS_PLATFORM_P49_WINDOW_SECONDS: "900", CNS_PLATFORM_P49_IPV4_PREFIX: "32", CNS_PLATFORM_P50_MAX: "30", CNS_PLATFORM_P50_WINDOW_SECONDS: "60", CNS_PLATFORM_P51_MAX: "5", CNS_PLATFORM_P51_WINDOW_SECONDS: "600",
  };
  const ok = loadPlatformSettings(full, "STAGING");
  assert.equal(ok.bindAddress, "10.8.0.5");
  assert.equal(ok.maxAwaiting, 500);
  for (const missing of Object.keys(full)) {
    const env: Record<string, string | undefined> = { ...full };
    delete env[missing];
    assert.throws(() => loadPlatformSettings(env, "STAGING"), PlatformConfigError, `falta ${missing}`);
  }
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_BIND_ADDRESS: "0.0.0.0" }, "STAGING"), PlatformConfigError);
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_BIND_ADDRESS: "::" }, "LOCAL"), PlatformConfigError);
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_ALLOWED_CIDRS: "no-cidr" }, "STAGING"), PlatformConfigError);
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_P49_MAX: "0" }, "STAGING"), PlatformConfigError);
  assert.throws(() => loadPlatformSettings({ CNS_PLATFORM_IDP_CLIENT_ID: "x" }, "LOCAL"), PlatformConfigError, "IdP parcial");
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://idp.example/auth", CNS_PLATFORM_IDP_CLIENT_ID: "c", CNS_PLATFORM_REDIRECT_URI: "https://p/cb" }, "STAGING"), PlatformConfigError, "http fuera de LOCAL");
  assert.ok(loadPlatformSettings({ CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/auth", CNS_PLATFORM_IDP_CLIENT_ID: "c", CNS_PLATFORM_REDIRECT_URI: "http://127.0.0.1:8788/platform/auth/callback" }, "LOCAL").idp);
});

class FakeAuthorization implements OidcAuthorizationPort {
  begins: BeginAuthorizationInput[] = [];
  limitEvents: Array<{ limitKind: string; windowSeconds: number; principalRef?: string | null }> = [];
  private readonly flows = new Map<string, { ref: string; used: boolean }>();
  deny = false;
  async begin(input: BeginAuthorizationInput): Promise<string> {
    if (this.deny) throw new PlatformDeniedError();
    this.begins.push(input);
    const ref = "0f1e2d3c-4b5a-4968-8776-655443322110";
    this.flows.set(input.state, { ref, used: false });
    return ref;
  }
  async complete(input: { state: string; code: string }): Promise<string | null> {
    const f = this.flows.get(input.state);
    if (f === undefined || f.used) return null;
    f.used = true;
    return f.ref;
  }
  async status(input: { exchangeRef: string; state: string }): Promise<ExchangeStatus | null> {
    const f = this.flows.get(input.state);
    return f !== undefined && f.ref === input.exchangeRef ? "PENDING" : null;
  }
  async recordLimitEvent(input: { limitKind: "P-49" | "P-50"; windowSeconds: number; principalRef?: string | null }): Promise<void> {
    this.limitEvents.push(input);
  }
}

async function withServer(env: Record<string, string>, fn: (base: string, auth: FakeAuthorization) => Promise<void>): Promise<void> {
  const auth = new FakeAuthorization();
  const settings = loadPlatformSettings(env, "LOCAL");
  const server = createServer(platformRequestHandler({ authorization: auth, sessions: DENY_ALL_SESSIONS, settings }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, auth);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}
const IDP = { CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "consent-platform", CNS_PLATFORM_REDIRECT_URI: "http://127.0.0.1:8788/platform/auth/callback" };
const cookieValue = (setCookie: string | null, name: string): string => new RegExp(`${name}=([^;]+)`).exec(setCookie ?? "")?.[1] ?? "";

test("TEST-CNS-1507 rutas de login: 302 al IdP con max_age=0, prompt=login, PKCE S256, state y nonce; callback compara state, 303 sin code ni ref, exchangeRef solo en cookie __Host- Strict; 404 uniforme; P-49; allowlist", async () => {
  await withServer({ ...IDP, CNS_PLATFORM_P49_MAX: "60", CNS_PLATFORM_P49_WINDOW_SECONDS: "900" }, async (base, auth) => {
    // Login PLATFORM: sin principal; 302 con los parametros del IdP.
    const r = await rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers: NAV });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("referrer-policy"), "no-referrer");
    assert.equal(r.headers.get("cache-control"), "no-store");
    const loc = new URL(r.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, "http://127.0.0.1:9000/authorize");
    const q = loc.searchParams;
    assert.equal(q.get("max_age"), "0");
    assert.equal(q.get("prompt"), "login");
    assert.equal(q.get("scope"), "openid");
    assert.equal(q.get("code_challenge_method"), "S256");
    assert.equal(q.get("response_type"), "code");
    const state = q.get("state")!;
    assert.ok(Buffer.from(state, "base64url").length >= 16, "state >= 128 bits");
    assert.ok(Buffer.from(q.get("nonce")!, "base64url").length >= 16, "nonce >= 128 bits");
    const begin = auth.begins[0]!;
    assert.equal(begin.kind, "LOGIN_PLATFORM");
    assert.equal(begin.principalRef ?? null, null);
    assert.equal(begin.bindingHex, sha(q.get("nonce")!), "binding = sha256(nonce)");
    assert.equal(q.get("code_challenge"), createHash("sha256").update(begin.pkceVerifier).digest("base64url"));
    const sc = r.headers.get("set-cookie")!;
    assert.match(sc, new RegExp(`^${OIDC_STATE_COOKIE}=${state}; Path=/; Secure; HttpOnly; SameSite=Lax`));
    assert.equal(begin.state, state);
    // kind=CASE sin sesion PLATFORM (PR-6c) y kind ajeno: 404.
    for (const k of ["CASE", "OTRO", ""]) assert.equal((await rawFetch(`${base}/platform/auth/login?kind=${k}`, { redirect: "manual", headers: NAV })).status, 404, k);

    // Callback: sin cookie, con cookie distinta o con state ajeno => 404 uniforme y no completa.
    const cb = (qs: string, cookie?: string): Promise<Response> => fetch(`${base}/platform/auth/callback?${qs}`, { redirect: "manual", headers: cookie === undefined ? {} : { cookie } });
    assert.equal((await cb(`code=c1&state=${state}`)).status, 404);
    assert.equal((await cb(`code=c1&state=${state}`, `${OIDC_STATE_COOKIE}=otro`)).status, 404);
    assert.equal((await cb(`code=c1&state=ajeno`, `${OIDC_STATE_COOKIE}=ajeno`)).status, 404);
    const ok = await cb(`code=c1&state=${state}`, `${OIDC_STATE_COOKIE}=${state}`);
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.get("location"), AUTH_CONTINUE_PATH, "303 a una URL SIN code ni ref");
    assert.ok(!(ok.headers.get("location") ?? "").includes("?"));
    assert.equal(ok.headers.get("referrer-policy"), "no-referrer");
    const ex = ok.headers.get("set-cookie")!;
    assert.match(ex, new RegExp(`^${OIDC_EXCHANGE_COOKIE}=0f1e2d3c-4b5a-4968-8776-655443322110; Path=/; Secure; HttpOnly; SameSite=Strict`));
    // state reusado: 404.
    assert.equal((await cb(`code=c2&state=${state}`, `${OIDC_STATE_COOKIE}=${state}`)).status, 404);

    // exchange status: solo con ambas cookies; el ref NUNCA se acepta por query, ni por header, ni por la ruta antigua.
    const ref = cookieValue(ex, OIDC_EXCHANGE_COOKIE);
    const both = `${OIDC_STATE_COOKIE}=${state}; ${OIDC_EXCHANGE_COOKIE}=${ref}`;
    const st = await fetch(`${base}/platform/auth/exchange`, { headers: { cookie: both } });
    assert.equal(st.status, 200);
    assert.deepEqual(await st.json(), { status: "PENDING" });
    assert.equal((await fetch(`${base}/platform/auth/exchange`, { headers: { cookie: `${OIDC_STATE_COOKIE}=${state}` } })).status, 404, "sin cookie del ref");
    assert.equal((await fetch(`${base}/platform/auth/exchange?exchangeRef=${ref}`, { headers: { cookie: `${OIDC_STATE_COOKIE}=${state}` } })).status, 404, "ref por query");
    assert.equal((await fetch(`${base}/platform/auth/exchange`, { headers: { cookie: `${OIDC_STATE_COOKIE}=${state}`, "x-exchange-ref": ref } })).status, 404, "ref por header");
    assert.equal((await fetch(`${base}/platform/auth/exchanges/${ref}`, { headers: { cookie: both } })).status, 404, "la ruta antigua con ref en la URL ya no existe");
    // Un DENY de la base en el login => 404 uniforme, sin motivo.
    auth.deny = true;
    const denied = await rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers: NAV });
    assert.equal(denied.status, 404);
    assert.deepEqual(await denied.json(), { error: "not_found" });
  });

  // P-49: 6 intentos (login/callback) por IP truncada; el 7.o => 404 y UN evento sin IP ni principal.
  await withServer({ ...IDP, CNS_PLATFORM_P49_MAX: "6", CNS_PLATFORM_P49_WINDOW_SECONDS: "900" }, async (base, auth) => {
    const codes: number[] = [];
    for (let i = 0; i < 9; i++) codes.push((await rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers: NAV })).status);
    assert.deepEqual(codes, [302, 302, 302, 302, 302, 302, 404, 404, 404]);
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(auth.limitEvents, [{ limitKind: "P-49", windowSeconds: 900 }], "un evento, sin IP ni principal");
  });

  // Allowlist: un origen fuera del CIDR recibe 404 uniforme y no toca la base.
  await withServer({ ...IDP, CNS_PLATFORM_ALLOWED_CIDRS: "10.99.0.0/16" }, async (base, auth) => {
    assert.equal((await rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers: NAV })).status, 404);
    assert.equal(auth.begins.length, 0);
  });
  // Sin IdP configurado (adaptador real apagado): el login no existe.
  await withServer({}, async (base) => {
    assert.equal((await rawFetch(`${base}/platform/auth/login?kind=PLATFORM`, { redirect: "manual", headers: NAV })).status, 404);
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
  });
});

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const K_SUB = randomBytes(32);
const NONCE = "nonce-login-sintetico";
const vconfig = (over: Partial<VerifierConfig> = {}): VerifierConfig => ({ issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", subHmacKey: K_SUB, ...over });

class LoginStore implements OidcExchangeStorePort {
  logins: LoginAssertionRecord[] = [];
  steps: AssertionRecord[] = [];
  private readonly next: ClaimedExchange;
  private served = false;
  constructor(next: ClaimedExchange) {
    this.next = next;
  }
  async claim(): Promise<ClaimedExchange | null> {
    if (this.served) return null;
    this.served = true;
    return this.next;
  }
  async recordAssertion(r: AssertionRecord): Promise<boolean> { this.steps.push(r); return false; }
  async recordLoginAssertion(r: LoginAssertionRecord): Promise<boolean> { this.logins.push(r); return r.decision === "ATTESTED"; }
}

test("TEST-CNS-1508 verifier LOGIN_*: entrega sub_hmac + key_version + limites (P-48/P-52) a la base y nunca recibe un principal; fallos => REJECTED sin sub; limites obligatorios fuera de LOCAL", async () => {
  const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
  const nonceHash = sha(NONCE);
  const claimed = (kind: "LOGIN_PLATFORM" | "LOGIN_CASE", auth: Parameters<SyntheticIdpAdapter["simulateAuthorization"]>[0]): ClaimedExchange => {
    const { code, pkceVerifier } = idp.simulateAuthorization(auth);
    return { exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", kind, nonceHash, principalRef: kind === "LOGIN_PLATFORM" ? null : "5b0c1d2e-3f40-4a51-8b62-73849a0b1c2d", code, pkceVerifier };
  };
  // LOGIN_PLATFORM (sin principal): ATTESTED; el registro lleva sub_hmac (HMAC, no el sub), key_version, authTime y los limites aprobados de LOCAL.
  const s1 = new LoginStore(claimed("LOGIN_PLATFORM", { sub: "sub-synthetic-login", nonce: NONCE, acr: "urn:synthetic:mfa", amr: ["pwd"], email: "persona@example.invalid" }));
  assert.equal(await runVerifierCycle({ store: s1, idp, config: vconfig({ subKeyVersion: 3 }) }), "ATTESTED");
  const rec = s1.logins[0]!;
  assert.equal(rec.decision, "ATTESTED");
  if (rec.decision === "ATTESTED") {
    assert.match(rec.subHmac, /^[0-9a-f]{64}$/);
    assert.notEqual(rec.subHmac, "sub-synthetic-login");
    assert.equal(rec.keyVersion, 3);
    assert.deepEqual(rec.limits, { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 300 });
  }
  assert.ok(!JSON.stringify(s1.logins).includes("persona@example.invalid"));
  assert.ok(!JSON.stringify(s1.logins).includes("principal"), "el registro de login no transporta ningun principal");
  assert.equal(s1.steps.length, 0, "un login no usa record_assertion");
  // Limites explicitos de la configuracion.
  const s2 = new LoginStore(claimed("LOGIN_CASE", { sub: "sub-synthetic-login", nonce: NONCE }));
  assert.equal(await runVerifierCycle({ store: s2, idp, config: vconfig({ login: { p48MaxFailures: 2, p48WindowSeconds: 120, p52AssertionSeconds: 60 } }) }), "ATTESTED");
  const r2 = s2.logins[0]!;
  assert.deepEqual(r2.decision === "ATTESTED" ? r2.limits : null, { p48MaxFailures: 2, p48WindowSeconds: 120, p52AssertionSeconds: 60 });
  // Token invalido (nonce ajeno): REJECTED INVALID_CLAIMS, sin sub ni claims; canje fallido: EXCHANGE_FAILED.
  const s3 = new LoginStore(claimed("LOGIN_PLATFORM", { sub: "sub-synthetic-login", nonce: "otro-nonce" }));
  assert.equal(await runVerifierCycle({ store: s3, idp, config: vconfig() }), "REJECTED");
  assert.deepEqual(s3.logins, [{ decision: "REJECTED", exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", reason: "INVALID_CLAIMS" }]);
  const bad = claimed("LOGIN_PLATFORM", { sub: "sub-synthetic-login", nonce: NONCE });
  const s4 = new LoginStore({ ...bad, pkceVerifier: "pkce-equivocado".padEnd(43, "q") });
  assert.equal(await runVerifierCycle({ store: s4, idp, config: vconfig() }), "REJECTED");
  assert.deepEqual(s4.logins.map((l) => (l.decision === "REJECTED" ? l.reason : "ATTESTED")), ["EXCHANGE_FAILED"]);
  // Fail-closed: fuera de LOCAL sin limites => VerifierConfigError (el proceso no arranca); fuera de rango tambien.
  const stag = { environment: "STAGING", requiredAcrAnyOf: ["urn:acr"] } as const;
  assert.throws(() => validateVerifierConfig(vconfig(stag), 1_800_000_000), VerifierConfigError);
  validateVerifierConfig(vconfig({ ...stag, login: { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 300 } }), 1_800_000_000);
  for (const login of [{ p48MaxFailures: 0, p48WindowSeconds: 900, p52AssertionSeconds: 300 }, { p48MaxFailures: 5, p48WindowSeconds: 30, p52AssertionSeconds: 300 }, { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 301 }, { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 0 }]) {
    assert.throws(() => validateVerifierConfig(vconfig({ login }), 1_800_000_000), VerifierConfigError);
  }
  assert.throws(() => validateVerifierConfig(vconfig({ subKeyVersion: 0 }), 1_800_000_000), VerifierConfigError);
});
