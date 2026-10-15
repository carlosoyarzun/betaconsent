// Gobierna: ADR-010 rev. 5 (enmienda rev. c) §5.2 pasos 5-7, §5.4 (P-50), §10 fila PR-6c; G-8; seguridad rev. c puntos 5 y 6; F-PR6-36 (LOGIN_CASE con sesion), F-PR6-38 (borrar cookies state/exchange).
// TEST-CNS-1557: POST /platform/sessions/platform: Origin exacto (mismo origen), cookies state+exchange, sesion en cookie __Host- Secure HttpOnly SameSite=Strict, borra state y exchange, rota la previa,
//   404 uniforme sin asercion, sin sid en el cuerpo.
// TEST-CNS-1558: login kind=CASE exige sesion PLATFORM validada por la base y caseRef UUIDv4; begin recibe sessionSid (no principal) y solo sha256(caseRef); POST /platform/sessions/case y logout.
// TEST-CNS-1559: P-50 cableado a las rutas autenticadas (por principal de la sesion validada; 429 uniforme; un evento por ventana); settings de sesion (obligatorias fuera de LOCAL).
// Sin base de datos (dobles en memoria de los puertos). Solo sinteticos.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { FakePlatformSessions } from "../../helpers/fake-platform-sessions.ts";
import { OIDC_EXCHANGE_COOKIE, OIDC_STATE_COOKIE } from "../../../src/server/entrypoints/platform/auth-routes.ts";
import { CASE_SESSION_COOKIE, PLATFORM_SESSION_COOKIE } from "../../../src/server/entrypoints/platform/http-util.ts";
import { platformRequestHandler } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { loadPlatformSettings, PlatformConfigError } from "../../../src/server/entrypoints/platform/platform-settings.ts";
import { PlatformDeniedError } from "../../../src/server/ports/oidc-exchange.port.ts";
import type { BeginAuthorizationInput, ExchangeStatus, OidcAuthorizationPort } from "../../../src/server/ports/oidc-exchange.port.ts";

const ORIGIN = "http://127.0.0.1:8788";
const ENV = { CNS_PLATFORM_P49_MAX: "1000", CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "consent-platform", CNS_PLATFORM_REDIRECT_URI: `${ORIGIN}/platform/auth/callback` };
const PRINCIPAL = "0f1e2d3c-4b5a-4968-8776-655443322110";
const OTHER = "1f1e2d3c-4b5a-4968-8776-655443322111";
const REF = "2f1e2d3c-4b5a-4968-8776-655443322112";
const CASE = "3f1e2d3c-4b5a-4968-8776-655443322113";
const STATE = "s".repeat(32);

class Authz implements OidcAuthorizationPort {
  begins: BeginAuthorizationInput[] = [];
  limitEvents: Array<{ limitKind: string; windowSeconds: number; principalRef?: string | null }> = [];
  async begin(input: BeginAuthorizationInput): Promise<string> {
    if (input.kind === "LOGIN_CASE" && (input.sessionSid ?? null) === null) throw new PlatformDeniedError();
    this.begins.push(input);
    return REF;
  }
  async complete(): Promise<string | null> { return null; }
  async status(): Promise<ExchangeStatus | null> { return null; }
  async recordLimitEvent(input: { limitKind: "P-49" | "P-50"; windowSeconds: number; principalRef?: string | null }): Promise<void> { this.limitEvents.push(input); }
}

interface Res { status: number; setCookie: string[]; body: string }
function send(base: string, method: string, path: string, headers: Record<string, string>, body?: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = request(`${base}${path}`, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, setCookie: (res.headers["set-cookie"] ?? []) as string[], body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

async function withServer(env: Record<string, string>, fn: (base: string, s: FakePlatformSessions, a: Authz) => Promise<void>): Promise<void> {
  const sessions = new FakePlatformSessions();
  const authz = new Authz();
  const server = createServer(platformRequestHandler({ authorization: authz, sessions, settings: loadPlatformSettings({ ...ENV, ...env }, "LOCAL") }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, sessions, authz);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}
const cookieHeader = (c: Record<string, string>): string => Object.entries(c).map(([k, v]) => `${k}=${v}`).join("; ");
const find = (cookies: string[], name: string): string => cookies.find((c) => c.startsWith(`${name}=`)) ?? "";
const NAV = { "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate" };

test("TEST-CNS-1557 POST /platform/sessions/platform: mismo origen, cookies state+exchange, sesion __Host- Strict, borra state y exchange, rota la previa; 404 uniforme", async () => {
  await withServer({}, async (base, sessions) => {
    sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL });
    const flow: Record<string, string> = { [OIDC_STATE_COOKIE]: STATE, [OIDC_EXCHANGE_COOKIE]: REF };
    const post = (headers: Record<string, string>, cookies = flow, path = "/platform/sessions/platform"): Promise<Res> =>
      send(base, "POST", path, { ...headers, cookie: cookieHeader(cookies) });
    // Sin Origin, con Origin ajeno, 'null' o Sec-Fetch-Site cruzado, GET, query: 404 y NO se llama a la base.
    for (const h of [{} as Record<string, string>, { origin: "https://evil.example" }, { origin: "null" }, { origin: ORIGIN, "sec-fetch-site": "cross-site" }]) assert.equal((await post(h)).status, 404, JSON.stringify(h));
    assert.equal((await send(base, "GET", "/platform/sessions/platform", { origin: ORIGIN, cookie: cookieHeader(flow) })).status, 404);
    assert.equal((await post({ origin: ORIGIN }, flow, "/platform/sessions/platform?exchangeRef=" + REF)).status, 404, "nada por query");
    assert.deepEqual(sessions.calls, []);
    // Sin cookies de flujo o con state ajeno: 404 (la base no consume).
    assert.equal((await post({ origin: ORIGIN }, { [OIDC_STATE_COOKIE]: STATE })).status, 404);
    assert.equal((await post({ origin: ORIGIN }, { ...flow, [OIDC_STATE_COOKIE]: "x".repeat(32) })).status, 404);
    assert.equal(sessions.assertions.size, 1, "la asercion sigue disponible");
    // Camino feliz.
    const ok = await post({ origin: ORIGIN });
    assert.equal(ok.status, 200);
    const sess = find(ok.setCookie, PLATFORM_SESSION_COOKIE);
    assert.match(sess, new RegExp(`^${PLATFORM_SESSION_COOKIE}=[0-9a-f]{64}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=14400$`));
    for (const [name, site] of [[OIDC_STATE_COOKIE, "Lax"], [OIDC_EXCHANGE_COOKIE, "Strict"], [CASE_SESSION_COOKIE, "Strict"]] as const) {
      assert.equal(find(ok.setCookie, name), `${name}=; Path=/; Secure; HttpOnly; SameSite=${site}; Max-Age=0`, `se borra ${name} (F-PR6-38)`);
    }
    assert.ok(!ok.body.includes(sess.split("=")[1]!.split(";")[0]!), "el sid no va en el cuerpo");
    // Un solo uso: repetir con las mismas cookies = 404.
    assert.equal((await post({ origin: ORIGIN })).status, 404);
    // Rotacion: con la cookie de sesion previa, la anterior se revoca.
    const first = sess.split("=")[1]!.split(";")[0]!;
    sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL });
    const rotated = await post({ origin: ORIGIN }, { ...flow, [PLATFORM_SESSION_COOKIE]: first });
    assert.equal(rotated.status, 200);
    assert.equal(sessions.rows.get(first)?.revoked, true);
    // Un fallo de base es 404 uniforme (sin detalle).
    sessions.failWith = new PlatformDeniedError();
    sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL });
    const failed = await post({ origin: ORIGIN });
    assert.deepEqual([failed.status, failed.body], [404, JSON.stringify({ error: "not_found" })]);
  });
  // Sin IdP configurado (sin origen publico) las rutas de sesion responden 404.
  const sessions = new FakePlatformSessions();
  const server = createServer(platformRequestHandler({ authorization: new Authz(), sessions, settings: loadPlatformSettings({}, "LOCAL") }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    assert.equal((await send(base, "POST", "/platform/sessions/platform", { origin: ORIGIN, cookie: cookieHeader({ [OIDC_STATE_COOKIE]: STATE, [OIDC_EXCHANGE_COOKIE]: REF }) })).status, 404);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("TEST-CNS-1558 login kind=CASE y sesion CASE: exige sesion PLATFORM validada y caseRef UUIDv4; begin recibe sessionSid y solo sha256(caseRef); logout revoca en servidor", async () => {
  await withServer({}, async (base, sessions, authz) => {
    const platformSid = (await (async () => { sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL }); return sessions.openPlatformSession({ exchangeRef: REF, state: STATE, lifetime: { absoluteSeconds: 60, idleSeconds: 60 } }); })())!;
    const login = (q: string, cookies: Record<string, string>): Promise<Res> => send(base, "GET", `/platform/auth/login?${q}`, { ...NAV, cookie: cookieHeader(cookies) });
    // Sin cookie de sesion, con sid desconocido o caseRef invalido: 404 y begin no se llama.
    assert.equal((await login(`kind=CASE&caseRef=${CASE}`, {})).status, 404);
    assert.equal((await login(`kind=CASE&caseRef=${CASE}`, { [PLATFORM_SESSION_COOKIE]: "a".repeat(64) })).status, 404);
    assert.equal((await login("kind=CASE&caseRef=no-es-uuid", { [PLATFORM_SESSION_COOKIE]: platformSid })).status, 404);
    assert.equal((await login(`kind=CASE`, { [PLATFORM_SESSION_COOKIE]: platformSid })).status, 404);
    assert.equal(authz.begins.length, 0);
    // Con sesion vigente: 302 al IdP con max_age=0 y prompt=login; begin LOGIN_CASE con sessionSid, sin principal, con el hash del caso.
    const r = await login(`kind=CASE&caseRef=${CASE}`, { [PLATFORM_SESSION_COOKIE]: platformSid });
    assert.equal(r.status, 302);
    const b = authz.begins[0]!;
    assert.equal(b.kind, "LOGIN_CASE");
    assert.equal(b.sessionSid, platformSid);
    assert.equal(b.principalRef ?? null, null);
    assert.match(b.targetRefHash ?? "", /^[0-9a-f]{64}$/);
    assert.ok(!JSON.stringify(b).includes(CASE), "el case_ref en claro no viaja a la base");

    // POST /platform/sessions/case.
    const flow: Record<string, string> = { [OIDC_STATE_COOKIE]: STATE, [OIDC_EXCHANGE_COOKIE]: REF };
    const body = JSON.stringify({ caseRef: CASE });
    const postCase = (cookies: Record<string, string>, b2 = body, headers: Record<string, string> = {}): Promise<Res> =>
      send(base, "POST", "/platform/sessions/case", { origin: ORIGIN, "content-type": "application/json", cookie: cookieHeader(cookies), ...headers }, b2);
    sessions.allow(REF, STATE, { kind: "LOGIN_CASE", principalRef: PRINCIPAL, targetCaseRef: CASE });
    assert.equal((await postCase({ ...flow })).status, 404, "sin sesion PLATFORM");
    assert.equal((await postCase({ ...flow, [PLATFORM_SESSION_COOKIE]: platformSid }, body, { "content-type": "text/plain" })).status, 404, "solo JSON");
    assert.equal((await postCase({ ...flow, [PLATFORM_SESSION_COOKIE]: platformSid }, JSON.stringify({ caseRef: "x" }))).status, 404);
    assert.equal((await postCase({ ...flow, [PLATFORM_SESSION_COOKIE]: platformSid })).status, 404, "sin grant");
    sessions.grants.add(`${PRINCIPAL}|${CASE}`);
    sessions.allow(REF, STATE, { kind: "LOGIN_CASE", principalRef: PRINCIPAL, targetCaseRef: CASE });
    const ok = await postCase({ ...flow, [PLATFORM_SESSION_COOKIE]: platformSid });
    assert.equal(ok.status, 200);
    const caseCookie = find(ok.setCookie, CASE_SESSION_COOKIE);
    assert.match(caseCookie, new RegExp(`^${CASE_SESSION_COOKIE}=[0-9a-f]{64}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=14400$`));
    assert.equal(find(ok.setCookie, OIDC_STATE_COOKIE), `${OIDC_STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    assert.equal(find(ok.setCookie, OIDC_EXCHANGE_COOKIE), `${OIDC_EXCHANGE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    const caseSid = caseCookie.split("=")[1]!.split(";")[0]!;

    // Logout de la sesion CASE: revoca en servidor y borra solo su cookie; Origin obligatorio.
    const out = (path: string, cookies: Record<string, string>, origin: string | null = ORIGIN): Promise<Res> => send(base, "POST", path, { ...(origin === null ? {} : { origin }), cookie: cookieHeader(cookies) });
    assert.equal((await out("/platform/case-session/logout", { [CASE_SESSION_COOKIE]: caseSid }, null)).status, 404);
    assert.equal(sessions.rows.get(caseSid)?.revoked, false);
    const lo = await out("/platform/case-session/logout", { [CASE_SESSION_COOKIE]: caseSid });
    assert.equal(lo.status, 200);
    assert.equal(sessions.rows.get(caseSid)?.revoked, true);
    assert.equal(find(lo.setCookie, CASE_SESSION_COOKIE), `${CASE_SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    // Logout PLATFORM: revoca la sesion y borra ambas cookies.
    const lp = await out("/platform/logout", { [PLATFORM_SESSION_COOKIE]: platformSid });
    assert.equal(lp.status, 200);
    assert.equal(sessions.rows.get(platformSid)?.revoked, true);
    assert.ok(find(lp.setCookie, PLATFORM_SESSION_COOKIE).includes("Max-Age=0") && find(lp.setCookie, CASE_SESSION_COOKIE).includes("Max-Age=0"));
    assert.equal((await out("/platform/logout", {})).status, 404, "sin cookie");
  });
});

test("TEST-CNS-1559 P-50 cableado a las rutas autenticadas: por principal de la sesion validada, 429 uniforme, un solo evento por ventana, sin IP; settings de sesion obligatorias fuera de LOCAL", async () => {
  await withServer({ CNS_PLATFORM_P50_MAX: "3", CNS_PLATFORM_P50_WINDOW_SECONDS: "60" }, async (base, sessions, authz) => {
    const mk = async (principal: string): Promise<string> => {
      const ref = randomUUID();
      sessions.allow(ref, STATE, { kind: "LOGIN_PLATFORM", principalRef: principal });
      return (await sessions.openPlatformSession({ exchangeRef: ref, state: STATE, lifetime: { absoluteSeconds: 60, idleSeconds: 60 } }))!;
    };
    const sidA = await mk(PRINCIPAL);
    const sidB = await mk(OTHER);
    const login = (sid: string): Promise<Res> => send(base, "GET", `/platform/auth/login?kind=CASE&caseRef=${CASE}`, { ...NAV, cookie: cookieHeader({ [PLATFORM_SESSION_COOKIE]: sid }) });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await login(sidA)).status);
    assert.deepEqual(statuses, [302, 302, 302, 429, 429, 429]);
    assert.equal((await login(sidB)).status, 302, "el limite es POR operador");
    assert.equal(authz.limitEvents.filter((e) => e.limitKind === "P-50").length, 1, "un solo evento por ventana");
    assert.deepEqual(authz.limitEvents[0], { limitKind: "P-50", windowSeconds: 60, principalRef: PRINCIPAL });
    const r = await login(sidA);
    assert.equal(r.body, JSON.stringify({ error: "rate_limited" }), "respuesta uniforme sin revelar el limite");
    // Un sid invalido nunca cuenta como operador (no hay principal confiable): 404.
    assert.equal((await login("b".repeat(64))).status, 404);
  });
  const full = {
    CNS_PLATFORM_BIND_ADDRESS: "10.8.0.5", CNS_PLATFORM_ALLOWED_CIDRS: "10.8.0.0/16", CNS_PLATFORM_P53_MAX_AWAITING: "500",
    CNS_PLATFORM_P49_MAX: "20", CNS_PLATFORM_P49_WINDOW_SECONDS: "900", CNS_PLATFORM_P49_IPV4_PREFIX: "32", CNS_PLATFORM_P50_MAX: "30", CNS_PLATFORM_P50_WINDOW_SECONDS: "60",
    CNS_PLATFORM_P51_MAX: "5", CNS_PLATFORM_P51_WINDOW_SECONDS: "600", CNS_PLATFORM_SESSION_ABSOLUTE_SECONDS: "14400", CNS_PLATFORM_SESSION_IDLE_SECONDS: "900",
  };
  assert.deepEqual(loadPlatformSettings(full, "STAGING").session, { absoluteSeconds: 14400, idleSeconds: 900 });
  for (const missing of ["CNS_PLATFORM_SESSION_ABSOLUTE_SECONDS", "CNS_PLATFORM_SESSION_IDLE_SECONDS"]) {
    const env: Record<string, string | undefined> = { ...full };
    delete env[missing];
    assert.throws(() => loadPlatformSettings(env, "STAGING"), PlatformConfigError, missing);
  }
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_SESSION_ABSOLUTE_SECONDS: "600", CNS_PLATFORM_SESSION_IDLE_SECONDS: "900" }, "STAGING"), PlatformConfigError, "idle <= absoluta");
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_SESSION_ABSOLUTE_SECONDS: "14401" }, "STAGING"), PlatformConfigError, "techo P-36/P-25 (4 h)");
  assert.throws(() => loadPlatformSettings({ ...full, CNS_PLATFORM_SESSION_IDLE_SECONDS: "901" }, "STAGING"), PlatformConfigError, "techo P-36/P-25 (15 min)");
  assert.deepEqual(loadPlatformSettings({}, "LOCAL").session, { absoluteSeconds: 14400, idleSeconds: 900 });
});

test("TEST-CNS-1564 P-49 por IP truncada aplica a POST /platform/sessions/platform y a los logout (404 uniforme, un evento sin IP); no a la sesion CASE (ya exige sesion validada)", async () => {
  await withServer({ CNS_PLATFORM_P49_MAX: "3", CNS_PLATFORM_P49_WINDOW_SECONDS: "900" }, async (base, sessions, authz) => {
    const flow = { [OIDC_STATE_COOKIE]: STATE, [OIDC_EXCHANGE_COOKIE]: REF };
    const post = (path: string): Promise<Res> => send(base, "POST", path, { origin: ORIGIN, cookie: cookieHeader(flow) });
    const statuses: number[] = [];
    for (const path of ["/platform/sessions/platform", "/platform/logout", "/platform/case-session/logout", "/platform/sessions/platform", "/platform/logout"]) statuses.push((await post(path)).status);
    assert.deepEqual(statuses, [404, 404, 404, 404, 404]);
    assert.equal(sessions.calls.filter((c) => c === "openPlatformSession").length, 1, "tras el limite la base no se toca");
    assert.deepEqual(authz.limitEvents, [{ limitKind: "P-49", windowSeconds: 900 }], "un solo evento, sin principal ni IP");
  });
});
