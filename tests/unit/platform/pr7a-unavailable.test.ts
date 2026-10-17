// Gobierna: ADR-010 rev. 6 PR-7 sub-PR 7a (F-PR7-10, T-10; condicion de seguridad: reintento interno acotado de clase 40/55P03 antes del 503 uniforme); contracts/openapi/consent-platform.openapi.yaml (503 SERVICE_UNAVAILABLE).
// TEST-CNS-1760: clasificacion por SQLSTATE (indisponibilidad vs. dominio/privilegio/programa) y retryRolledBack acotado.
// TEST-CNS-1761: withPlatformTransaction reintenta tx revertidas (40001/55P03) con tope; 08xxx = PlatformUnavailableError; el resto = PlatformDeniedError uniforme.
// TEST-CNS-1762: ruta HTTP: indisponibilidad = 503 uniforme (mismo cuerpo salvo correlationId); error no de indisponibilidad = 404 uniforme; ningun oraculo por recurso.
// Sin base de datos. Solo sinteticos.

import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { FakePlatformSessions } from "../../helpers/fake-platform-sessions.ts";
import { withPlatformTransaction } from "../../../src/infra/adapters/postgres/platform-call.ts";
import { isRolledBackRetryable, isServiceUnavailableError, MAX_ROLLED_BACK_ATTEMPTS, retryRolledBack } from "../../../src/infra/adapters/postgres/transient-error.ts";
import { PLATFORM_SESSION_COOKIE } from "../../../src/server/entrypoints/platform/http-util.ts";
import { platformRequestHandler } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { loadPlatformSettings } from "../../../src/server/entrypoints/platform/platform-settings.ts";
import { PlatformDeniedError, PlatformUnavailableError } from "../../../src/server/ports/oidc-exchange.port.ts";
import type { BeginAuthorizationInput, ExchangeStatus, OidcAuthorizationPort } from "../../../src/server/ports/oidc-exchange.port.ts";
import type { CaseStepUpAction, PlatformGrantPort, StepUpLimit } from "../../../src/server/ports/platform-grant.port.ts";

const sqlstate = (code: string): Error => Object.assign(new Error("db"), { code });

test("TEST-CNS-1760 clasificacion: 08/40/53/57/55P03 y sockets = indisponibilidad; dominio, privilegio, datos y programa no; clase 40 y 55P03 son reintentables; retryRolledBack respeta el tope", async () => {
  for (const c of ["08006", "08001", "40001", "40P01", "53300", "57P01", "55P03", "ECONNRESET", "ECONNREFUSED"]) assert.equal(isServiceUnavailableError(sqlstate(c)), true, c);
  for (const c of ["42501", "23505", "22P02", "RV409", "RC004", "42P01", "XX000", "P0001"]) assert.equal(isServiceUnavailableError(sqlstate(c)), false, c);
  assert.equal(isServiceUnavailableError(new Error("Connection terminated unexpectedly")), true);
  assert.equal(isServiceUnavailableError(new Error("otra cosa")), false);
  assert.equal(isServiceUnavailableError(null), false);
  for (const c of ["40001", "40P01", "55P03"]) assert.equal(isRolledBackRetryable(sqlstate(c)), true, c);
  for (const c of ["08006", "53300", "57P01", "42501"]) assert.equal(isRolledBackRetryable(sqlstate(c)), false, c);

  let n = 0;
  assert.equal(await retryRolledBack(async () => { n++; if (n < 3) throw sqlstate("40001"); return "ok"; }, { sleep: async () => {} }), "ok");
  assert.equal(n, 3);
  // Espera inyectable con backoff exponencial y jitter entre intentos (no tras el ultimo ni ante errores no reintentables).
  const waits: number[] = [];
  n = 0;
  await assert.rejects(() => retryRolledBack(async () => { n++; throw sqlstate("40P01"); }, { sleep: async (ms) => { waits.push(ms); }, random: () => 0.5, baseDelayMs: 20 }));
  assert.deepEqual(waits, [20, 40], "2 esperas para 3 intentos: base * 2^(n-1) * (0.5 + random)");
  waits.length = 0;
  await assert.rejects(() => retryRolledBack(async () => { throw sqlstate("42501"); }, { sleep: async (ms) => { waits.push(ms); } }));
  assert.deepEqual(waits, []);
  n = 0;
  await assert.rejects(() => retryRolledBack(async () => { n++; throw sqlstate("55P03"); }, { sleep: async () => {} }), (e: unknown) => (e as { code?: string }).code === "55P03");
  assert.equal(n, MAX_ROLLED_BACK_ATTEMPTS);
  n = 0;
  await assert.rejects(() => retryRolledBack(async () => { n++; throw sqlstate("08006"); }, { sleep: async () => {} }));
  assert.equal(n, 1, "una conexion perdida (commit ambiguo) no se reintenta aqui");
});

function fakePool(failWith: (attempt: number) => Error | null): { pool: Parameters<typeof withPlatformTransaction>[0]; attempts: () => number; statements: string[] } {
  let attempts = 0;
  const statements: string[] = [];
  const pool = {
    async connect() {
      return {
        async query(text: string) {
          statements.push(text);
          if (text.startsWith("SELECT current_setting('app.tenant_id'")) return { rows: [{ tenant: null }], rowCount: 1 };
          if (text === "BEGIN") attempts++;
          if (text === "COMMIT") {
            const e = failWith(attempts);
            if (e !== null) throw e;
          }
          return { rows: [], rowCount: 0 };
        },
        on() { return this; },
        removeListener() { return this; },
        release() { /* sin efecto */ },
      };
    },
  };
  return { pool: pool as unknown as Parameters<typeof withPlatformTransaction>[0], attempts: () => attempts, statements };
}

test("TEST-CNS-1761 withPlatformTransaction: 40001 transitorio se reintenta (exito al 3.er intento); agotado el tope = el error crudo (el borde da 503); 08006 = PlatformUnavailableError; 22P02 = DENY uniforme", async () => {
  const ok = fakePool((a) => (a < 3 ? sqlstate("40001") : null));
  assert.equal(await withPlatformTransaction(ok.pool, null, async () => "listo"), "listo");
  assert.equal(ok.attempts(), 3);
  assert.equal(ok.statements.filter((s) => s === "ROLLBACK").length, 2);

  const exhausted = fakePool(() => sqlstate("55P03"));
  await assert.rejects(() => withPlatformTransaction(exhausted.pool, null, async () => 1), (e: unknown) => (e as { code?: string }).code === "55P03");
  assert.equal(exhausted.attempts(), MAX_ROLLED_BACK_ATTEMPTS);

  const lost = fakePool(() => sqlstate("08006"));
  await assert.rejects(() => withPlatformTransaction(lost.pool, null, async () => 1), PlatformUnavailableError);
  assert.equal(lost.attempts(), 1);

  const bad = fakePool(() => sqlstate("22P02"));
  await assert.rejects(() => withPlatformTransaction(bad.pool, null, async () => 1), PlatformDeniedError);
  assert.equal(bad.attempts(), 1);
});

// ---- HTTP ----
const ORIGIN = "http://127.0.0.1:8788";
const ENV = { CNS_PLATFORM_P49_MAX: "1000", CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "consent-platform", CNS_PLATFORM_REDIRECT_URI: `${ORIGIN}/platform/auth/callback` };
const PRINCIPAL = "0f1e2d3c-4b5a-4968-8776-655443322110";
const REF = "2f1e2d3c-4b5a-4968-8776-655443322112";
const CASE = "3f1e2d3c-4b5a-4968-8776-655443322113";
const OTHER_CASE = "6f1e2d3c-4b5a-4968-8776-655443322116";
const STATE = "s".repeat(32);

class Authz implements OidcAuthorizationPort {
  async begin(_input: BeginAuthorizationInput): Promise<string> { return REF; }
  async complete(): Promise<string | null> { return null; }
  async status(): Promise<ExchangeStatus | null> { return null; }
  async recordLimitEvent(): Promise<void> { /* sin efecto */ }
}

class FailingGrants implements PlatformGrantPort {
  error: unknown = null;
  async issueStepUpNonce(_i: { sid: string; action: CaseStepUpAction; targetRef: string; ttlSeconds: number }): Promise<string | null> { throw this.error; }
  async requestGrant(_i: { sid: string; caseRef: string; limit: StepUpLimit }): Promise<string | null> { throw this.error; }
  async approveGrant(): Promise<string | null> { throw this.error; }
}

function send(base: string, path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = request(`${base}${path}`, { method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end("{}");
  });
}

test("TEST-CNS-1762 ruta de platform: indisponibilidad de la base = 503 uniforme SERVICE_UNAVAILABLE (mismo cuerpo para cualquier caso, solo cambia correlationId); error que no es de indisponibilidad = 404 uniforme", async () => {
  const sessions = new FakePlatformSessions();
  sessions.allow(REF, STATE, { kind: "LOGIN_PLATFORM", principalRef: PRINCIPAL });
  const sid = (await sessions.openPlatformSession({ exchangeRef: REF, state: STATE, lifetime: { absoluteSeconds: 3600, idleSeconds: 600 } }))!;
  const grants = new FailingGrants();
  const server = createServer(platformRequestHandler({ authorization: new Authz(), sessions, grants, settings: loadPlatformSettings(ENV, "LOCAL") }));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const headers = { origin: ORIGIN, "content-type": "application/json", cookie: `${PLATFORM_SESSION_COOKIE}=${sid}` };
  try {
    const bodies: unknown[] = [];
    for (const [error, caseRef] of [[sqlstate("08006"), CASE], [sqlstate("40001"), OTHER_CASE], [sqlstate("55P03"), CASE], [new PlatformUnavailableError(), OTHER_CASE]] as const) {
      grants.error = error;
      const r = await send(base, `/platform/rights-cases/${caseRef}/grant-requests`, headers);
      assert.equal(r.status, 503, r.body);
      const { correlationId, ...rest } = JSON.parse(r.body) as Record<string, unknown>;
      assert.match(String(correlationId), /^[0-9a-f-]{36}$/);
      bodies.push(rest);
      assert.ok(!r.body.includes(caseRef), "el cuerpo no repite el caso");
    }
    for (const b of bodies) assert.deepEqual(b, { code: "SERVICE_UNAVAILABLE", status: 503 });
    for (const error of [sqlstate("XX000"), sqlstate("42501"), new PlatformDeniedError(), new Error("bug")]) {
      grants.error = error;
      const r = await send(base, `/platform/rights-cases/${CASE}/grant-requests`, headers);
      assert.equal(r.status, 404);
      assert.deepEqual(JSON.parse(r.body), { error: "not_found" });
    }
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});
