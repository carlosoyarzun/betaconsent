// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1, §5.4 (P-50, P-51), §6 (grants), §10 fila 6d; GRD-RC-10, GRD-RC-12; contracts/openapi/consent-platform.openapi.yaml.
// TEST-CNS-1659: POST /platform/step-up: mismo origen, sesion validada en la base, accion/destino validos, 303 al IdP con max_age=0 + prompt=login y nonce de la base, STEP_UP con sessionSid (nunca
//   principal), cookie state Lax; 404 uniforme sin tocar la base ante cualquier otra cosa.
// TEST-CNS-1660: POST .../grant-requests y .../approval: el principal y el tenant nunca salen de la request ni del cuerpo; validSeconds solo entero; DENY de la base = 404 uniforme; P-50 por operador.
// Sin base de datos (dobles en memoria de los puertos). Solo sinteticos.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { FakePlatformSessions } from "../../helpers/fake-platform-sessions.ts";
import { OIDC_STATE_COOKIE } from "../../../src/server/entrypoints/platform/auth-routes.ts";
import { PLATFORM_SESSION_COOKIE } from "../../../src/server/entrypoints/platform/http-util.ts";
import { platformRequestHandler } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { loadPlatformSettings } from "../../../src/server/entrypoints/platform/platform-settings.ts";
import type { BeginAuthorizationInput, ExchangeStatus, OidcAuthorizationPort } from "../../../src/server/ports/oidc-exchange.port.ts";
import type { CaseStepUpAction, PlatformGrantPort, StepUpLimit } from "../../../src/server/ports/platform-grant.port.ts";

const ORIGIN = "http://127.0.0.1:8788";
const ENV = { CNS_PLATFORM_P49_MAX: "1000", CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "consent-platform", CNS_PLATFORM_REDIRECT_URI: `${ORIGIN}/platform/auth/callback` };
const PRINCIPAL = "0f1e2d3c-4b5a-4968-8776-655443322110";
const REF = "2f1e2d3c-4b5a-4968-8776-655443322112";
const CASE = "3f1e2d3c-4b5a-4968-8776-655443322113";
const REQ = "4f1e2d3c-4b5a-4968-8776-655443322114";
const STATE = "s".repeat(32);
const NONCE = "n".repeat(64);
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

class Authz implements OidcAuthorizationPort {
  begins: BeginAuthorizationInput[] = [];
  async begin(input: BeginAuthorizationInput): Promise<string> { this.begins.push(input); return REF; }
  async complete(): Promise<string | null> { return null; }
  async status(): Promise<ExchangeStatus | null> { return null; }
  async recordLimitEvent(): Promise<void> { /* sin efecto */ }
}

class Grants implements PlatformGrantPort {
  calls: Array<{ op: string; input: Record<string, unknown> }> = [];
  nonce: string | null = NONCE;
  requestRef: string | null = REQ;
  grantRef: string | null = "5f1e2d3c-4b5a-4968-8776-655443322115";
  async issueStepUpNonce(input: { sid: string; action: CaseStepUpAction; targetRef: string; ttlSeconds: number }): Promise<string | null> { this.calls.push({ op: "issue", input }); return this.nonce; }
  async requestGrant(input: { sid: string; caseRef: string; limit: StepUpLimit }): Promise<string | null> { this.calls.push({ op: "request", input }); return this.requestRef; }
  async approveGrant(input: { sid: string; caseRef: string; requestRef: string; validSeconds: number | null; limit: StepUpLimit }): Promise<string | null> { this.calls.push({ op: "approve", input }); return this.grantRef; }
}

interface Res { status: number; setCookie: string[]; location: string | undefined; body: string }
function send(base: string, method: string, path: string, headers: Record<string, string>, body?: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = request(`${base}${path}`, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, setCookie: (res.headers["set-cookie"] ?? []) as string[], location: res.headers.location, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

async function withServer(env: Record<string, string>, fn: (base: string, sid: string, g: Grants, a: Authz) => Promise<void>): Promise<void> {
  const sessions = new FakePlatformSessions();
  sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL });
  const sid = (await sessions.openPlatformSession({ exchangeRef: REF, state: STATE, lifetime: { absoluteSeconds: 3600, idleSeconds: 600 } }))!;
  const grants = new Grants();
  const authz = new Authz();
  const server = createServer(platformRequestHandler({ authorization: authz, sessions, grants, settings: loadPlatformSettings({ ...ENV, ...env }, "LOCAL") }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, sid, grants, authz);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const JSON_H = { "content-type": "application/json" };
const withSession = (sid: string, extra: Record<string, string> = {}): Record<string, string> => ({ origin: ORIGIN, ...JSON_H, cookie: `${PLATFORM_SESSION_COOKIE}=${sid}`, ...extra });

test("TEST-CNS-1659 POST /platform/step-up: mismo origen, sesion validada, 303 al IdP con max_age=0 + prompt=login y nonce de la base; STEP_UP con sessionSid y sin principal; 404 uniforme", async () => {
  await withServer({}, async (base, sid, grants, authz) => {
    const body = JSON.stringify({ action: "REQUEST_GRANT", targetRef: CASE });
    // Sin Origin / origen ajeno / Sec-Fetch cruzado / GET / query / sin sesion / sesion falsa: 404 y la base no se toca.
    for (const h of [{ ...withSession(sid), origin: "https://evil.example" }, { ...withSession(sid), "sec-fetch-site": "cross-site" }, { ...JSON_H, origin: ORIGIN }, withSession("0".repeat(64))]) {
      assert.equal((await send(base, "POST", "/platform/step-up", h, body)).status, 404, JSON.stringify(h));
    }
    assert.equal((await send(base, "GET", "/platform/step-up", withSession(sid))).status, 404);
    assert.equal((await send(base, "POST", "/platform/step-up?action=x", withSession(sid), body)).status, 404);
    // Accion fuera del alcance o destino mal formado: 404 sin emitir nonce.
    for (const b of [{ action: "REQUEST_GRANT", targetRef: CASE, principalRef: "suplanta" }, { action: "REQUEST_GRANT", targetRef: CASE, tenantId: "x" }, { action: "APPROVE_MEMBERSHIP", targetRef: CASE }, { action: "REQUEST_GRANT", targetRef: "x" }, { action: "APPROVE_GRANT", targetRef: "x" }, { targetRef: CASE }, {}]) {
      assert.equal((await send(base, "POST", "/platform/step-up", withSession(sid), JSON.stringify(b))).status, 404, JSON.stringify(b));
    }
    assert.deepEqual(grants.calls, []);
    assert.deepEqual(authz.begins, []);
    // La base deniega el nonce (rol, solicitud ajena...): 404 y no se inicia STEP_UP.
    grants.nonce = null;
    assert.equal((await send(base, "POST", "/platform/step-up", withSession(sid), body)).status, 404);
    assert.deepEqual(authz.begins, []);
    grants.nonce = NONCE;
    grants.calls = [];
    const ok = await send(base, "POST", "/platform/step-up", withSession(sid), body);
    assert.equal(ok.status, 303);
    const target = new URL(ok.location ?? "");
    assert.equal(target.origin + target.pathname, "http://127.0.0.1:9000/authorize");
    assert.equal(target.searchParams.get("max_age"), "0");
    assert.equal(target.searchParams.get("prompt"), "login");
    assert.equal(target.searchParams.get("nonce"), NONCE, "el nonce emitido por la base viaja al IdP");
    assert.equal(target.searchParams.get("code_challenge_method"), "S256");
    const state = target.searchParams.get("state") ?? "";
    assert.match(ok.setCookie.find((c) => c.startsWith(`${OIDC_STATE_COOKIE}=`)) ?? "", new RegExp(`^${OIDC_STATE_COOKIE}=${state}; Path=/; Secure; HttpOnly; SameSite=Lax;`));
    assert.deepEqual(grants.calls, [{ op: "issue", input: { sid, action: "REQUEST_GRANT", targetRef: CASE, ttlSeconds: 600 } }]);
    assert.equal(authz.begins.length, 1);
    const b0 = (authz.begins as BeginAuthorizationInput[])[0]!;
    assert.equal(b0.kind, "STEP_UP");
    assert.equal(b0.sessionSid, sid);
    assert.equal(b0.principalRef ?? null, null, "el principal nunca sale de la request: lo resuelve la base por el sid");
    assert.equal(b0.bindingHex, sha(NONCE));
    assert.deepEqual(b0.stepUpLimit, { max: 5, windowSeconds: 600 }, "P-51 aprobado");
    assert.ok(!ok.body.includes(NONCE), "el nonce no va en el cuerpo");
  });
});

test("TEST-CNS-1660 grants: principal y tenant nunca de la request; validSeconds solo entero; DENY = 404 uniforme; P-50 por operador", async () => {
  await withServer({}, async (base, sid, grants) => {
    const reqPath = `/platform/rights-cases/${CASE}/grant-requests`;
    const apprPath = `${reqPath}/${REQ}/approval`;
    // Mismo origen y sesion obligatorios.
    assert.equal((await send(base, "POST", reqPath, { ...JSON_H, origin: "https://evil.example", cookie: `${PLATFORM_SESSION_COOKIE}=${sid}` }, "{}")).status, 404);
    assert.equal((await send(base, "POST", reqPath, { ...JSON_H, origin: ORIGIN }, "{}")).status, 404, "sin sesion");
    assert.equal((await send(base, "POST", `/platform/rights-cases/no-uuid/grant-requests`, withSession(sid), "{}")).status, 404);
    assert.equal((await send(base, "POST", `${reqPath}/no-uuid/approval`, withSession(sid), "{}")).status, 404);
    assert.deepEqual(grants.calls, []);
    // request_grant: el cuerpo no puede traer principal ni tenant; la base solo recibe sid y caseRef.
    const r1 = await send(base, "POST", reqPath, withSession(sid), JSON.stringify({ principalRef: "suplanta", tenantId: "otro", operator: "x" }));
    assert.equal(r1.status, 200);
    assert.deepEqual(JSON.parse(r1.body), { requestRef: REQ });
    assert.deepEqual(grants.calls[0], { op: "request", input: { sid, caseRef: CASE, limit: { max: 5, windowSeconds: 600 } } });
    // approve_grant: validSeconds entero o ausente; otro tipo = 404 sin tocar la base.
    grants.calls = [];
    for (const v of ["7200", 1.5, null, true]) assert.equal((await send(base, "POST", apprPath, withSession(sid), JSON.stringify({ validSeconds: v }))).status, 404, String(v));
    assert.deepEqual(grants.calls, []);
    const a1 = await send(base, "POST", apprPath, withSession(sid), JSON.stringify({ validSeconds: 3600, approverRef: "suplanta" }));
    assert.equal(a1.status, 200);
    assert.deepEqual(JSON.parse(a1.body), { grantRef: grants.grantRef });
    assert.deepEqual(grants.calls[0], { op: "approve", input: { sid, caseRef: CASE, requestRef: REQ, validSeconds: 3600, limit: { max: 5, windowSeconds: 600 } } });
    const a2 = await send(base, "POST", apprPath, withSession(sid), "{}");
    assert.equal(a2.status, 200);
    assert.equal(((grants.calls as Grants["calls"])[1]?.input as { validSeconds: number | null }).validSeconds, null, "sin validSeconds la base aplica el defecto de 2 h");
    // DENY de la base: 404 uniforme, sin motivo.
    grants.requestRef = null;
    grants.grantRef = null;
    for (const [p, b] of [[reqPath, "{}"], [apprPath, "{}"]] as const) {
      const r = await send(base, "POST", p, withSession(sid), b);
      assert.deepEqual([r.status, JSON.parse(r.body)], [404, { error: "not_found" }]);
    }
  });
  // P-50: sobre el limite por operador, 429 uniforme.
  await withServer({ CNS_PLATFORM_P50_MAX: "2" }, async (base, sid) => {
    const path = `/platform/rights-cases/${CASE}/grant-requests`;
    assert.equal((await send(base, "POST", path, withSession(sid), "{}")).status, 200);
    assert.equal((await send(base, "POST", path, withSession(sid), "{}")).status, 200);
    assert.equal((await send(base, "POST", path, withSession(sid), "{}")).status, 429);
  });
});
