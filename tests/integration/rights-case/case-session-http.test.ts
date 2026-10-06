// Gobierna: CA-139 (aprobado por Carlos, 2026-10-06; P1-1 de la revision de seguridad de CA-138), SEC-CNS-018 rev. 2 D-3, GRD-CM-01/10/13,
// case-session.ts, case-confirmation.handler.ts, contracts/openapi API-CNS-136..140 y API-CNS-193 (logout CASE).
// Recorrido HTTP (CONSENT_STORE=memory) de la sesion CASE con registro en servidor y reloj inyectado (caseNowMs):
// TEST-CNS-1165 expiracion absoluta e inactividad, 1166 logout revoca (cookie robada no sirve en 136/137/138/139/140; cookies borradas;
// idempotente), 1167 rotacion de sid en login, 1168 CSRF de otra sesion rechazado (tambien en logout), 1169 sesion de otro caseRef, de otro
// tenant o sin registro rechazada (404 uniforme), 1170 dev-login solo LOCAL, mismo mecanismo y sin PII ni sid en almacen/logs. Solo sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { caseCsrfTokenFor, decodeCaseSession, deriveCaseSessionKey, encodeCaseSession, hashCaseSid } from "../../../src/server/entrypoints/http/case-session.ts";
import { APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS, APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS } from "../../../src/server/modules/common/approved-parameters.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { attestHumanAssistedVerification } from "../../contract/rh2-helper.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const ORIGIN = "http://consola-case-session.test.localhost";
const SESSION = "__Host-cns-case";
const CSRF = "__Host-cns-case-csrf";
const TENANT = "7cfbfb16-4c4d-4966-892b-0794cbd57199";
const OTHER_TENANT = "9a1e2b3c-4d5e-4f60-8a7b-1c2d3e4f5a6b";
const SECRET = Buffer.alloc(32, 7);
const KEY = deriveCaseSessionKey(SECRET);
const MIN = 60_000;
const OP1 = fixtureUuid("staff-synthetic-01");
const OP2 = fixtureUuid("staff-synthetic-02");
const APPROVER = fixtureUuid("staff-synthetic-03");
const ROSTER: readonly StaffPrincipal[] = [
  { principalRef: OP1, role: "RIGHTS_OPERATOR" },
  { principalRef: OP2, role: "RIGHTS_OPERATOR" },
  { principalRef: APPROVER, role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
];
const PROPOSAL = fixtureUuid("proposal-case-session");

interface Fx {
  readonly baseUrl: string;
  readonly store: ReturnType<typeof createInMemoryCaseSessionStore>;
  readonly clock: { now: number };
  readonly caseRef: string;
  close(): Promise<void>;
}

async function setUp(label: string, environment: Environment = "LOCAL", removed: Set<string> = new Set()): Promise<Fx> {
  const chainRef = fixtureUuid(`chain-${label}`);
  const caseRef = fixtureUuid(`case-${label}`);
  const revocationRef = fixtureUuid(`rv-${label}`);
  const consentId = `consent-${chainRef}`;
  const ports = createDefaultConsentFlowPorts({ codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 }, { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] });
  await ports.decision.repo.save({
    consentId, tenantId: TENANT, contextRef: LECTORPRO_BETA_CONFIG.contextRef, productRef: LECTORPRO_BETA_CONFIG.productRef, subjectRef: fixtureUuid(`subject-${label}`),
    decisionMakerRef: "dm:case-session", invitationRef: fixtureUuid(`inv-${label}`), verificationRef: fixtureUuid(`ver-${label}`), chainRef, state: "GRANTED",
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })), priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"], receiptRef: `receipt-${consentId}`,
  });
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  await revocationPorts.rightsCase.rightsCaseRepo.save({ caseRef, tenantId: TENANT, chainRef, revokedDecisionRef: consentId, status: "OPEN" });
  await revocationPorts.revocation.revocationRepo.save({ revocationRef, tenantId: TENANT, chainRef, caseRef, status: "REQUESTED" });
  await attestHumanAssistedVerification(revocationPorts.revocation, TENANT, revocationRef, caseRef);
  await revocationPorts.rightsCase.rightsCaseRepo.save({ caseRef, tenantId: TENANT, chainRef, revokedDecisionRef: consentId, status: "IN_VERIFICATION", revocationRef });

  const store = createInMemoryCaseSessionStore();
  const clock = { now: 1_900_000_000_000 };
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN }, ports, revocationPorts, sessionSecret: SECRET, environment,
    staffIdentity: ((inner) => ({ ...inner, findByPrincipalRef: async (ref: string) => (removed.has(ref) ? null : inner.findByPrincipalRef(ref)) }))(createInMemoryStaffIdentityAdapter(ROSTER)), caseSessions: store, caseNowMs: () => clock.now,
  });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  return { baseUrl, store, clock, caseRef, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

function cookiesOf(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of res.headers.getSetCookie()) {
    const first = line.split(";", 1)[0] ?? "";
    const eq = first.indexOf("=");
    if (eq > 0) out[first.slice(0, eq)] = first.slice(eq + 1);
  }
  return out;
}

interface Login { readonly session: string; readonly csrf: string; readonly res: Response }
async function login(fx: Fx, principalRef: string, opts: { caseRef?: string; previous?: string } = {}): Promise<Login> {
  const res = await fetch(`${fx.baseUrl}/__dev/staff-login`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(opts.previous ? { cookie: `${SESSION}=${opts.previous}` } : {}) },
    body: JSON.stringify({ tenantId: TENANT, caseRef: opts.caseRef ?? fx.caseRef, principalRef }),
  });
  const c = cookiesOf(res);
  return { session: c[SESSION] ?? "", csrf: c[CSRF] ?? "", res };
}

function call(fx: Fx, path: string, who: { session: string; csrf: string }, body: unknown = {}, over: { csrfHeader?: string } = {}): Promise<Response> {
  return fetch(`${fx.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": over.csrfHeader ?? who.csrf, cookie: `${SESSION}=${who.session}; ${CSRF}=${over.csrfHeader ?? who.csrf}` },
    body: JSON.stringify(body),
  });
}
const confirm = (fx: Fx, who: { session: string; csrf: string }, over = {}): Promise<Response> => call(fx, `/platform/rights-cases/${fx.caseRef}/confirmation`, who, { confirmationGivenOnCasePage: true }, over);

test("TEST-CNS-1165 expiracion: la sesion CASE vence a las 8 h absolutas (aunque haya actividad) y por 30 min de inactividad; el mismo 404 uniforme (reloj inyectado)", async () => {
  assert.equal(APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS, 8 * 60 * MIN);
  assert.equal(APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS, 30 * MIN);
  const fx = await setUp("1165");
  try {
    const idle = await login(fx, OP1);
    assert.equal(idle.res.status, 200);
    assert.match(idle.res.headers.getSetCookie().find((c) => c.startsWith(SESSION)) ?? "", /Max-Age=28800/);
    fx.clock.now += 29 * MIN;
    assert.equal((await confirm(fx, idle)).status, 200, "dentro de la inactividad");
    fx.clock.now += 31 * MIN;
    assert.deepEqual([(await confirm(fx, idle)).status, await (await confirm(fx, idle)).json()], [404, { status: 404 }], "30 min sin uso");

    const active = await login(fx, OP1);
    for (let i = 0; i < 16; i += 1) {
      fx.clock.now += 29 * MIN;
      assert.equal((await confirm(fx, active)).status, 200);
    }
    // 16 * 29 = 464 min < 480: sigue viva; al cruzar las 8 h absolutas (493 min) muere aunque este activa
    fx.clock.now += 29 * MIN;
    assert.equal((await confirm(fx, active)).status, 404, "pasadas 8 h absolutas");
    assert.ok(decodeCaseSession(KEY, active.session) !== null, "la firma sigue valida: la rechaza la expiracion/el registro, no el formato");
    assert.equal(decodeCaseSession(KEY, active.session, fx.clock.now), null);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1166 logout (API-CNS-193): revoca el sid en servidor; la cookie robada tras el logout no sirve en 136/137/138/139/140; borra cookies; idempotente", async () => {
  const fx = await setUp("1166");
  try {
    const op = await login(fx, OP1);
    const ap = await login(fx, APPROVER);
    const before = await confirm(fx, op);
    assert.equal(before.status, 200, "antes del logout la sesion sirve");
    const out = await call(fx, "/platform/case-session/logout", op);
    assert.equal(out.status, 200);
    assert.deepEqual(await out.json(), {});
    assert.equal(out.headers.get("cache-control"), "no-store");
    const cleared = out.headers.getSetCookie();
    assert.ok(cleared.some((c) => c.startsWith(`${SESSION}=;`) && c.includes("Max-Age=0") && c.includes("HttpOnly")));
    assert.ok(cleared.some((c) => c.startsWith(`${CSRF}=;`) && c.includes("Max-Age=0")));
    const stolen = async (who: Login, path: string, body: unknown): Promise<number> => (await call(fx, path, who, body)).status;
    const base = `/platform/rights-cases/${fx.caseRef}`;
    assert.equal(await stolen(op, `${base}/verification-proposals`, { verificationScriptVersion: "g1", stepUpAssertion: "stub" }), 404, "API-CNS-136");
    assert.equal(await stolen(op, `${base}/confirmation`, { confirmationGivenOnCasePage: true }), 404, "API-CNS-138");
    assert.equal(await stolen(op, `${base}/confirmation/cosign`, {}), 404, "API-CNS-139");
    assert.equal(await stolen(op, `${base}/verification-proposals/${PROPOSAL}/withdrawal`, { stepUpAssertion: "stub" }), 404, "API-CNS-140");
    // otra sesion (aprobador) no se afecta; su logout revoca 137
    assert.equal(await stolen(ap, `${base}/verification-proposals/${PROPOSAL}/approval`, { stepUpAssertion: "stub" }), 404, "propuesta inexistente: 404 ya (no 401/403)");
    assert.equal((await call(fx, "/platform/case-session/logout", ap)).status, 200);
    assert.equal(await stolen(ap, `${base}/verification-proposals/${PROPOSAL}/approval`, { stepUpAssertion: "stub" }), 404, "API-CNS-137 tras logout");
    assert.equal((await call(fx, "/platform/case-session/logout", op)).status, 200, "idempotente");
    assert.equal(fx.store.rows().filter((r) => r.revokedAtMs !== null).length, 2);
    // sin sesion valida solo borra cookies; sin CSRF double-submit 403
    const anon = await fetch(`${fx.baseUrl}/platform/case-session/logout`, { method: "POST", headers: { origin: ORIGIN, "x-csrf-token": "x".repeat(20), cookie: `${CSRF}=${"x".repeat(20)}` } });
    assert.equal(anon.status, 200);
    const noCsrf = await fetch(`${fx.baseUrl}/platform/case-session/logout`, { method: "POST", headers: { origin: ORIGIN, cookie: `${SESSION}=${op.session}` } });
    assert.equal(noCsrf.status, 403);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1167 rotacion: un login con la cookie previa revoca el sid anterior y emite uno nuevo (anti fixation); un login sin cookie no revoca otras sesiones", async () => {
  const fx = await setUp("1167");
  try {
    const first = await login(fx, OP1);
    const parallel = await login(fx, OP2);
    const second = await login(fx, OP1, { previous: first.session });
    assert.notEqual(second.session, first.session);
    assert.notEqual(decodeCaseSession(KEY, second.session)!.sid, decodeCaseSession(KEY, first.session)!.sid);
    assert.equal((await confirm(fx, first)).status, 404, "sid previo revocado");
    assert.equal((await confirm(fx, second)).status, 200);
    assert.equal((await call(fx, `/platform/rights-cases/${fx.caseRef}/confirmation/cosign`, parallel)).status !== 404, true, "la sesion paralela sigue viva");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1168 CSRF ligado al sid: el token de OTRA sesion CASE no sirve aunque cookie y cabecera coincidan (403); tampoco en el logout (que no revoca)", async () => {
  const fx = await setUp("1168");
  try {
    const a = await login(fx, OP1);
    const b = await login(fx, OP2);
    assert.notEqual(a.csrf, b.csrf);
    assert.equal(a.csrf, caseCsrfTokenFor(KEY, decodeCaseSession(KEY, a.session)!.sid));
    const res = await confirm(fx, a, { csrfHeader: b.csrf });
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as { code: string }).code, "CSRF_REJECTED");
    assert.equal((await call(fx, "/platform/case-session/logout", a, {}, { csrfHeader: b.csrf })).status, 403);
    assert.equal((await confirm(fx, a)).status, 200, "el logout con CSRF ajeno no revoco");
    // token aleatorio con cookie==cabecera (el esquema anterior): ya no sirve
    assert.equal((await confirm(fx, a, { csrfHeader: "csrf-aleatorio-abcdefgh" })).status, 403);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1169 una sesion de otro caseRef, de otro tenant o sin registro en servidor se rechaza con 404 uniforme (aunque la firma sea valida)", async () => {
  const fx = await setUp("1169");
  try {
    const op = await login(fx, OP1);
    const payload = decodeCaseSession(KEY, op.session)!;
    assert.equal((await call(fx, `/platform/rights-cases/${fixtureUuid("otro-caso-1169")}/confirmation`, op, { confirmationGivenOnCasePage: true })).status, 404, "otro caseRef");
    const forge = (over: Partial<typeof payload>) => {
      const p = { ...payload, ...over };
      return { session: encodeCaseSession(KEY, p), csrf: caseCsrfTokenFor(KEY, p.sid) };
    };
    assert.equal((await confirm(fx, forge({ tenantId: OTHER_TENANT }))).status, 404, "mismo sid pero otro tenant: no existe en ese tenant");
    assert.equal((await confirm(fx, forge({ caseRef: fixtureUuid("otro-caso-1169") }))).status, 404, "caseRef de la cookie no es el del registro/path");
    assert.equal((await confirm(fx, forge({ principalRef: OP2 }))).status, 404, "principal distinto del registrado");
    assert.equal((await confirm(fx, forge({ role: "APPROVER" }))).status, 404, "rol distinto del registrado");
    const unregistered = forge({ sid: "Z".repeat(43) });
    assert.equal((await confirm(fx, unregistered)).status, 404, "firma valida y sid no emitido por el servidor");
    // cookie con firma de otra clave y cookie del formato anterior (sin sid/iat/exp)
    const legacy = Buffer.from(JSON.stringify({ tenantId: TENANT, caseRef: fx.caseRef, principalRef: OP1, role: "RIGHTS_OPERATOR" })).toString("base64url");
    assert.equal((await confirm(fx, { session: `${legacy}.firma`, csrf: op.csrf })).status, 404);
    assert.equal((await confirm(fx, op)).status, 200, "la sesion legitima no se afecto");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1170 dev-login solo LOCAL y sin privilegios extra (mismo emisor, sin registro fuera de LOCAL); almacen y logs sin sid, cookie, correo ni PII", async () => {
  const printed: string[] = [];
  const origErr = console.error;
  const origLog = console.log;
  console.error = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  console.log = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  try {
    const dev = await setUp("1170-dev", "DEV");
    try {
      const res = await login(dev, OP1);
      assert.equal(res.res.status, 404);
      assert.equal(dev.store.rows().length, 0, "fuera de LOCAL no se crea ninguna sesion");
    } finally {
      await dev.close();
    }
    const fx = await setUp("1170");
    try {
      const op = await login(fx, OP1);
      assert.equal(op.res.status, 200);
      assert.deepEqual(await op.res.json(), { principalRef: OP1, role: "RIGHTS_OPERATOR" });
      const sid = decodeCaseSession(KEY, op.session)!.sid;
      assert.equal(op.csrf, caseCsrfTokenFor(KEY, sid), "mismo emisor: CSRF ligado al sid");
      assert.equal(decodeCaseSession(KEY, op.session)!.exp - decodeCaseSession(KEY, op.session)!.iat, APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS);
      await confirm(fx, op);
      await call(fx, "/platform/case-session/logout", op);
      const rows = fx.store.rows();
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.sidHash, hashCaseSid(sid));
      const stored = JSON.stringify(rows);
      for (const secret of [sid, op.session, op.csrf, "@"]) assert.ok(!stored.includes(secret), "el almacen no guarda sid, cookie, csrf ni correos");
      assert.deepEqual(Object.keys(rows[0]!).sort(), ["caseRef", "expiresAtMs", "issuedAtMs", "lastSeenAtMs", "principalRef", "revokedAtMs", "role", "sidHash", "tenantId"]);
      for (const line of printed) for (const secret of [sid, op.session, op.csrf]) assert.ok(!line.includes(secret), "logs sin sid ni cookie");
    } finally {
      await fx.close();
    }
  } finally {
    console.error = origErr;
    console.log = origLog;
  }
});

test("TEST-CNS-1171 storeMode=postgres exige un registro de sesiones CASE inyectado (fail-closed: nunca una sesion CASE en memoria sobre una base real)", () => {
  assert.throws(
    () => createConsentFlowHttpServer({ config: { allowedOrigin: ORIGIN }, sessionSecret: SECRET, environment: "LOCAL", storeMode: "postgres", ports: createDefaultConsentFlowPorts({ codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 }, { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] }) }),
    /caseSessions/,
  );
});

test("TEST-CNS-1176 P2-1: un operador dado de baja del roster con sesion vigente (o con otro rol) recibe 404 uniforme en 136/137/138/139/140", async () => {
  const removed = new Set<string>();
  const fx = await setUp("1176", "LOCAL", removed);
  try {
    const op = await login(fx, OP1);
    const ap = await login(fx, APPROVER);
    const base = `/platform/rights-cases/${fx.caseRef}`;
    assert.equal((await confirm(fx, op)).status, 200, "con membership vigente sirve");
    removed.add(OP1);
    removed.add(APPROVER);
    const calls: [string, unknown, Login][] = [
      [`${base}/verification-proposals`, { verificationScriptVersion: "g1", stepUpAssertion: "stub" }, op],
      [`${base}/verification-proposals/${PROPOSAL}/approval`, { stepUpAssertion: "stub" }, ap],
      [`${base}/confirmation`, { confirmationGivenOnCasePage: true }, op],
      [`${base}/confirmation/cosign`, {}, op],
      [`${base}/verification-proposals/${PROPOSAL}/withdrawal`, { stepUpAssertion: "stub" }, op],
    ];
    for (const [path, body, who] of calls) {
      const res = await call(fx, path, who, body);
      assert.deepEqual([res.status, await res.json()], [404, { status: 404 }], path);
    }
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1177 P2-3: el CSRF se valida antes del touch; una cookie robada sin CSRF valido no prolonga la inactividad", async () => {
  const fx = await setUp("1177");
  try {
    const op = await login(fx, OP1);
    const other = await login(fx, OP2);
    const issuedAt = fx.store.rows().find((r) => r.principalRef === OP1)!.lastSeenAtMs;
    fx.clock.now += 29 * MIN;
    assert.equal((await confirm(fx, op, { csrfHeader: other.csrf })).status, 403);
    assert.equal(fx.store.rows().find((r) => r.principalRef === OP1)!.lastSeenAtMs, issuedAt, "sin CSRF valido no se avanza last_seen_at");
    fx.clock.now += 2 * MIN;
    assert.equal((await confirm(fx, op)).status, 404, "31 min desde la ultima actividad real: inactividad");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-1183 ERR-SE-03 CASE: una sesion CASE valida con rol sin permiso (APPROVER en record_case_confirmation) recibe 403 ACTOR_NOT_ALLOWED, sin efecto", async () => {
  const fx = await setUp("1183");
  try {
    const ap = await login(fx, APPROVER);
    const res = await confirm(fx, ap);
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { code: string }).code, "ACTOR_NOT_ALLOWED");
    const op = await login(fx, OP1);
    assert.equal((await confirm(fx, op)).status, 200, "el rol permitido si ejecuta");
  } finally {
    await fx.close();
  }
});
