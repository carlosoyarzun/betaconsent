// Gobierna: CA-141 (decision de Carlos, 2026-10-06; D-2 sin fallos de autenticacion, D-3 logout fail-closed; P1-2, P2-2), specs/session.spec.yaml
// GRD-SE-14 / ERR-SE-04 / INV-SE-05, API-CNS-192 (POST /staff/logout), API-CNS-193 (POST /platform/case-session/logout), dev-login STAFF y CASE.
// Recorrido HTTP (CONSENT_STORE=memory) con un registro de eventos compartido por los dos stores de sesion:
// TEST-CNS-1198 (eventos de login, logout y rotacion por la via HTTP real; el logout idempotente, el 404 uniforme, el 403 CSRF, el 422 del dev-login,
// la purga y el touch NO escriben), 1199 (si falla la escritura del evento: 503 sin Set-Cookie ni borrado de cookies, la sesion sigue viva, la UI
// muestra "No se pudo cerrar sesion, reintenta" y el contador security_event_write_failed no lleva PII) y 1201 (session_ref nunca aparece en cookie,
// cuerpo, URL ni logs, y nunca autentica). Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { createInMemorySubjectDirectory } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts, createDefaultStaffConsolePorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { deriveCaseSessionKey, hashCaseSid } from "../../../src/server/entrypoints/http/case-session.ts";
import { decodeStaffSession, deriveStaffSessionKey, hashStaffSid } from "../../../src/server/entrypoints/http/staff-session.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-security-event.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const STAFF_CSRF = "__Host-cns-staff-csrf";
const CASE_COOKIE = "__Host-cns-case";
const CASE_CSRF = "__Host-cns-case-csrf";
const TENANT_A = LOCAL_ONLY_DEV_TENANT_ID;
const TENANT_B = LOCAL_ONLY_DEV_OTHER_TENANT_ID;
const ADMIN_A = fixtureUuid("se-admin-a");
const ADMIN_B = fixtureUuid("se-admin-b");
const OPERATOR = fixtureUuid("staff-synthetic-01");
const CONTEXT = "BETA_2026_01";
const SECRET = Buffer.alloc(32, 9);
const STAFF_KEY = deriveStaffSessionKey(SECRET);
const CASE_KEY = deriveCaseSessionKey(SECRET);
const CASE_REF = fixtureUuid("se-case");
const ROSTER: readonly StaffPrincipal[] = [
  { principalRef: ADMIN_A, role: "TENANT_ADMIN", tenantId: TENANT_A },
  { principalRef: ADMIN_B, role: "TENANT_ADMIN", tenantId: TENANT_B },
  { principalRef: OPERATOR, role: "RIGHTS_OPERATOR" },
];
const subject = { subjectRef: fixtureUuid("se-subj"), participationRef: fixtureUuid("se-part"), label: "Alumno de prueba 1" };

interface Harness {
  readonly baseUrl: string;
  readonly events: ReturnType<typeof createInMemorySecurityEventLog>;
  readonly staffSessions: ReturnType<typeof createInMemoryStaffSessionStore>;
  readonly caseSessions: ReturnType<typeof createInMemoryCaseSessionStore>;
  close(): Promise<void>;
}

async function start(environment: Environment = "LOCAL"): Promise<Harness> {
  const events = createInMemorySecurityEventLog();
  const staffSessions = createInMemoryStaffSessionStore({ securityEvents: events });
  const caseSessions = createInMemoryCaseSessionStore({ securityEvents: events });
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY);
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  await revocationPorts.rightsCase.rightsCaseRepo.save({ caseRef: CASE_REF, tenantId: TENANT_A, chainRef: fixtureUuid("se-chain"), revokedDecisionRef: fixtureUuid("se-dec"), status: "OPEN" });
  const staffIdentity = createInMemoryStaffIdentityAdapter(ROSTER);
  const staff = createDefaultStaffConsolePorts(
    ports.invitation,
    staffIdentity,
    loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
    loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
  );
  staff.catalog.seedSubject(TENANT_A, subject.subjectRef);
  staff.catalog.seedParticipation(TENANT_A, { participationRef: subject.participationRef, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  const directory = createInMemorySubjectDirectory("LOCAL", [{ tenantId: TENANT_A, subjectRef: subject.subjectRef, label: subject.label, participationRef: subject.participationRef }]);
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    revocationPorts,
    sessionSecret: SECRET,
    environment,
    staffIdentity,
    staffConsole: { ...staff, sessions: staffSessions, subjectDirectory: directory },
    caseSessions,
    staffRosterCursorKey: deriveStaffRosterCursorKey(Buffer.alloc(32, 6)),
    staffUi: { contextRef: CONTEXT, consentVersion: "v1-dev" },
    devStaffConsole: { principalRef: ADMIN_A, students: [{ label: subject.label, subjectRef: subject.subjectRef, participationRef: subject.participationRef }], contextRef: CONTEXT, consentVersion: "v1-dev" },
  });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  return { baseUrl, events, staffSessions, caseSessions, close: () => new Promise((r) => server.close(() => r())) };
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
async function staffLogin(h: Harness, principalRef = ADMIN_A, previous?: string): Promise<Login> {
  const res = await fetch(`${h.baseUrl}/__dev/staff-login`, { method: "POST", headers: { "content-type": "application/json", ...(previous ? { cookie: `${STAFF_COOKIE}=${previous}` } : {}) }, body: JSON.stringify({ principalRef }) });
  const c = cookiesOf(res);
  return { session: c[STAFF_COOKIE] ?? "", csrf: c[STAFF_CSRF] ?? "", res };
}
async function caseLogin(h: Harness, body: Record<string, unknown> = {}, previous?: string): Promise<Login> {
  const res = await fetch(`${h.baseUrl}/__dev/staff-login`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(previous ? { cookie: `${CASE_COOKIE}=${previous}` } : {}) },
    body: JSON.stringify({ tenantId: TENANT_A, caseRef: CASE_REF, principalRef: OPERATOR, ...body }),
  });
  const c = cookiesOf(res);
  return { session: c[CASE_COOKIE] ?? "", csrf: c[CASE_CSRF] ?? "", res };
}
const staffLogout = (h: Harness, who: { session: string; csrf: string }, csrfHeader = who.csrf): Promise<Response> =>
  fetch(`${h.baseUrl}/staff/logout`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrfHeader, cookie: `${STAFF_COOKIE}=${who.session}; ${STAFF_CSRF}=${csrfHeader}` }, body: "{}" });
const caseLogout = (h: Harness, who: { session: string; csrf: string }, csrfHeader = who.csrf): Promise<Response> =>
  fetch(`${h.baseUrl}/platform/case-session/logout`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrfHeader, cookie: `${CASE_COOKIE}=${who.session}; ${CASE_CSRF}=${csrfHeader}` }, body: "{}" });
const htmlLogout = (h: Harness, who: { session: string; csrf: string }): Promise<Response> =>
  fetch(`${h.baseUrl}/staff/logout`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN, cookie: `${STAFF_COOKIE}=${who.session}; ${STAFF_CSRF}=${who.csrf}` }, body: new URLSearchParams({ csrf_token: who.csrf }) });
const rosterGet = (h: Harness, who: { session: string }): Promise<Response> => fetch(`${h.baseUrl}/staff/roster`, { headers: { cookie: `${STAFF_COOKIE}=${who.session}`, "sec-fetch-site": "same-origin" } });
const types = (h: Harness, tenantId?: string): string[] => h.events.list(tenantId).map((e) => e.eventType);

async function capturingConsole<T>(fn: () => Promise<T>): Promise<{ result: T; printed: string[] }> {
  const printed: string[] = [];
  const origErr = console.error;
  const origLog = console.log;
  console.error = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  console.log = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  try {
    return { result: await fn(), printed };
  } finally {
    console.error = origErr;
    console.log = origLog;
  }
}

test("TEST-CNS-1198 eventos por HTTP: login STAFF/CASE, logout JSON/HTML (192/193) y rotacion escriben exactamente un evento; logout idempotente, 404 uniforme, 403 CSRF, dev-login 422, purga y touch no escriben", async () => {
  const h = await start();
  try {
    // STAFF: login (UI y JSON) y logout (HTML 303 y JSON 192)
    const uiLogin = await fetch(`${h.baseUrl}/staff/dev-login`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, body: new URLSearchParams({}) });
    assert.equal(uiLogin.status, 303);
    const ui = cookiesOf(uiLogin);
    const uiWho = { session: ui[STAFF_COOKIE]!, csrf: ui[STAFF_CSRF]! };
    assert.deepEqual(types(h), ["STAFF_LOGIN"]);
    const uiRow = h.staffSessions.rows().find((r) => r.sidHash === hashStaffSid(decodeStaffSession(STAFF_KEY, uiWho.session)!.sid))!;
    assert.equal(h.events.list()[0]!.sessionRef, uiRow.sessionRef, "el LOGIN lleva el session_ref de la fila");
    assert.equal((await htmlLogout(h, uiWho)).status, 303);
    assert.deepEqual(types(h), ["STAFF_LOGIN", "STAFF_LOGOUT"]);
    assert.equal((await htmlLogout(h, uiWho)).status, 303, "idempotente");
    assert.deepEqual(types(h), ["STAFF_LOGIN", "STAFF_LOGOUT"], "el segundo logout no escribe");

    const a = await staffLogin(h);
    assert.equal(a.res.status, 200);
    assert.equal(types(h).length, 3);
    assert.equal((await staffLogout(h, a)).status, 200);
    assert.equal((await staffLogout(h, a)).status, 200, "idempotente");
    assert.equal((await staffLogout(h, { session: "", csrf: "x" })).status, 200, "sin cookie de sesion: solo borra cookies");
    assert.equal((await staffLogout(h, { session: "basura.firma", csrf: "x" })).status, 200, "firma invalida: no revoca nada");
    assert.deepEqual(types(h).slice(2), ["STAFF_LOGIN", "STAFF_LOGOUT"]);
    assert.equal(types(h).length, 4);

    // 403 CSRF (cookie valida, token de otra sesion): no revoca y no escribe
    const b = await staffLogin(h);
    const n = h.events.list().length;
    assert.equal((await staffLogout(h, b, "otro-token")).status, 403);
    assert.equal(h.events.list().length, n, "403 CSRF no escribe");
    assert.equal((await rosterGet(h, b)).status, 200, "touch: GET autenticado, sin evento");
    assert.equal(h.events.list().length, n);
    // 404 uniforme: cookie revocada o de otro navegador
    await staffLogout(h, b);
    const afterLogout = h.events.list().length;
    assert.equal((await rosterGet(h, b)).status, 404);
    assert.equal((await rosterGet(h, { session: "basura" })).status, 404);
    assert.equal(h.events.list().length, afterLogout, "404 uniforme no escribe");

    // rotacion: login con la cookie previa de OTRO tenant (B) -> ROTATION en el tenant de la cookie previa + LOGIN en el nuevo
    const prev = await staffLogin(h, ADMIN_A);
    const before = h.events.list().length;
    const rotated = await staffLogin(h, ADMIN_B, prev.session);
    assert.equal(rotated.res.status, 200);
    const delta = h.events.list().slice(before);
    assert.deepEqual(delta.map((e) => [e.eventType, e.tenantId, e.actorRef]), [["SESSION_REVOKED_BY_ROTATION", TENANT_A, ADMIN_A], ["STAFF_LOGIN", TENANT_B, ADMIN_B]]);
    // cookie previa con firma invalida impuesta por un atacante: no hay ROTATION
    const k = h.events.list().length;
    assert.equal((await staffLogin(h, ADMIN_A, "basura.firma")).res.status, 200);
    assert.deepEqual(types(h).slice(k), ["STAFF_LOGIN"]);

    // purga oportunista en el login: borra la expirada y no escribe evento propio
    const T0 = Date.now();
    await h.staffSessions.create({ tenantId: TENANT_A, sidHash: "e".repeat(64), principalRef: ADMIN_A, role: "TENANT_ADMIN", issuedAtMs: T0 - 4 * 86_400_000, expiresAtMs: T0 - 3 * 86_400_000 });
    const p = h.events.list().length;
    await staffLogin(h, ADMIN_A);
    assert.equal(h.staffSessions.rows().some((r) => r.sidHash === "e".repeat(64)), false, "purgada");
    assert.equal(h.events.list().length, p + 1, "solo el LOGIN del propio login");

    // CASE: login, logout 193, rotacion, y los rechazos que no escriben
    const c0 = h.events.list().length;
    const c = await caseLogin(h);
    assert.equal(c.res.status, 200);
    const loginEvent = h.events.list()[c0]!;
    assert.deepEqual([loginEvent.eventType, loginEvent.tenantId, loginEvent.actorRef, loginEvent.actorRole, loginEvent.sessionKind, loginEvent.caseRef], ["CASE_LOGIN", TENANT_A, OPERATOR, "RIGHTS_OPERATOR", "CASE", CASE_REF]);
    assert.equal((await caseLogout(h, c, "otro-token")).status, 403);
    assert.equal(h.events.list().length, c0 + 1, "403 CSRF no escribe");
    assert.equal((await caseLogout(h, c)).status, 200);
    assert.equal((await caseLogout(h, c)).status, 200, "idempotente");
    assert.equal((await caseLogout(h, { session: "", csrf: "x" })).status, 200);
    assert.deepEqual(types(h).slice(c0), ["CASE_LOGIN", "CASE_LOGOUT"]);
    const c2 = await caseLogin(h);
    const c3 = await caseLogin(h, {}, c2.session);
    assert.equal(c3.res.status, 200);
    assert.deepEqual(types(h).slice(c0 + 2), ["CASE_LOGIN", "SESSION_REVOKED_BY_ROTATION", "CASE_LOGIN"]);
    const rejected = h.events.list().length;
    for (const body of [{ caseRef: "case-1163" }, { caseRef: fixtureUuid("otro-caso") }, { principalRef: ADMIN_A }, { principalRef: "no-existe" }, { tenantId: undefined }]) {
      assert.equal((await caseLogin(h, body)).res.status, 422, JSON.stringify(body));
    }
    assert.equal(h.events.list().length, rejected, "dev-login 422 no escribe (y un caseRef no UUID se rechaza ANTES de emitir)");
    assert.equal(h.caseSessions.rows().every((r) => /^[0-9a-f]{8}-[0-9a-f]{4}-4/.test(r.caseRef)), true);
    assert.equal(h.caseSessions.rows().filter((r) => r.sidHash === hashCaseSid("x")).length, 0);
  } finally {
    await h.close();
  }
  // fuera de LOCAL el dev-login no existe: 404 y ningun evento
  const dev = await start("DEV");
  try {
    assert.equal((await staffLogin(dev)).res.status, 404);
    assert.equal((await caseLogin(dev)).res.status, 404);
    assert.deepEqual(dev.events.list(), []);
  } finally {
    await dev.close();
  }
});

test("TEST-CNS-1199 fallo del evento: login y logout (192, 193, HTML y dev-login) responden 503 sin Set-Cookie ni borrado de cookies; la sesion sigue viva; la UI nunca muestra exito; el contador no lleva PII", async () => {
  const h = await start();
  try {
    const staff = await staffLogin(h);
    const caze = await caseLogin(h);
    const rowsBefore = [h.staffSessions.rows().length, h.caseSessions.rows().length];
    const eventsBefore = h.events.list().length;
    h.events.failWith = () => true;
    const { printed } = await capturingConsole(async () => {
      // 192 JSON
      const out = await staffLogout(h, staff);
      assert.equal(out.status, 503);
      assert.deepEqual(out.headers.getSetCookie(), [], "sin Set-Cookie ni borrado de cookies");
      assert.match(out.headers.get("content-type") ?? "", /application\/problem\+json/);
      const body = (await out.json()) as Record<string, unknown>;
      assert.deepEqual(Object.keys(body).sort(), ["code", "correlationId", "status"]);
      assert.equal(body.code, "GUARD_EVALUATOR_UNAVAILABLE");
      // 193
      const outCase = await caseLogout(h, caze);
      assert.equal(outCase.status, 503);
      assert.deepEqual(outCase.headers.getSetCookie(), []);
      // UI HTML: pagina de error, sin exito y sin borrar cookies
      const ui = await htmlLogout(h, staff);
      assert.equal(ui.status, 503);
      assert.deepEqual(ui.headers.getSetCookie(), []);
      assert.equal(ui.headers.get("location"), null, "no redirige a la entrada como si hubiera cerrado");
      const html = await ui.text();
      assert.match(html, /No se pudo cerrar sesión, reintenta\./);
      assert.doesNotMatch(html, /sesión cerrada|cerraste sesión/i);
      // login STAFF (JSON y UI) y CASE: 503 sin cookies y sin fila
      const l1 = await staffLogin(h, ADMIN_A);
      assert.equal(l1.res.status, 503);
      assert.deepEqual(l1.res.headers.getSetCookie(), []);
      const l2 = await caseLogin(h);
      assert.equal(l2.res.status, 503);
      assert.deepEqual(l2.res.headers.getSetCookie(), []);
      const l3 = await fetch(`${h.baseUrl}/staff/dev-login`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, body: new URLSearchParams({}) });
      assert.equal(l3.status, 503);
      assert.deepEqual(l3.headers.getSetCookie(), []);
      // rotacion que falla: el login con cookie previa responde 503 y la previa SIGUE viva
      const l4 = await staffLogin(h, ADMIN_A, staff.session);
      assert.equal(l4.res.status, 503);
      assert.deepEqual(l4.res.headers.getSetCookie(), []);
    });
    assert.deepEqual([h.staffSessions.rows().length, h.caseSessions.rows().length], rowsBefore, "ningun login dejo sesion");
    assert.equal(h.events.list().length, eventsBefore);
    assert.ok(h.staffSessions.rows().every((r) => r.revokedAtMs === null) && h.caseSessions.rows().every((r) => r.revokedAtMs === null), "nada se revoco");
    assert.equal((await rosterGet(h, staff)).status, 200, "la sesion STAFF sigue valida");

    // contador sin etiquetas: solo name y SQLSTATE; nunca tenant, principal, sesion, sid ni cookies
    const counter = printed.filter((l) => l.startsWith("security_event_write_failed"));
    assert.equal(counter.length, 7, "uno por fallo (192, 193, UI logout, 3 logins y la rotacion)");
    for (const line of counter) {
      assert.match(line, /^security_event_write_failed name=SecurityEventWriteError code=XX000$/);
    }
    const all = printed.join("\n");
    for (const secret of [staff.session, staff.csrf, caze.session, caze.csrf, TENANT_A, ADMIN_A, OPERATOR, CASE_REF, ...h.staffSessions.rows().map((r) => r.sessionRef)]) assert.ok(!all.includes(secret), "logs sin PII ni refs");
    assert.ok(!printed.some((l) => l.startsWith("request_failed")), "no cae al catch global (500)");

    // al restablecerse el fallo: el logout procede y escribe su evento
    h.events.failWith = null;
    assert.equal((await staffLogout(h, staff)).status, 200);
    assert.equal((await caseLogout(h, caze)).status, 200);
    assert.deepEqual(types(h).slice(eventsBefore), ["STAFF_LOGOUT", "CASE_LOGOUT"]);
  } finally {
    h.events.failWith = null;
    await h.close();
  }
});

test("TEST-CNS-1201 session_ref nunca aparece en cookie, cuerpo, URL ni logs, y nunca autentica (ni como sid, hash, CSRF, cookie o campo de cuerpo)", async () => {
  const h = await start();
  try {
    const { result: seen, printed } = await capturingConsole(async () => {
      const transcripts: string[] = [];
      const record = async (res: Response): Promise<void> => {
        transcripts.push(`${res.url}\n${[...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n")}\n${res.headers.getSetCookie().join("\n")}\n${await res.clone().text()}`);
      };
      const s = await staffLogin(h);
      await record(s.res);
      const c = await caseLogin(h);
      await record(c.res);
      await record(await rosterGet(h, s));
      const sRef = h.staffSessions.rows()[0]!.sessionRef;
      const cRef = h.caseSessions.rows()[0]!.sessionRef;

      // nunca autentica: usado como valor de cookie, sid firmado, token CSRF o campo del cuerpo
      for (const forged of [sRef, `${sRef}.${sRef}`, Buffer.from(JSON.stringify({ sid: sRef, tenantId: TENANT_A, principalRef: ADMIN_A, role: "TENANT_ADMIN", iat: Date.now(), exp: Date.now() + 1e6 })).toString("base64url") + ".firma"]) {
        const res = await rosterGet(h, { session: forged });
        assert.equal(res.status, 404);
        await record(res);
      }
      const csrfAttempt = await staffLogout(h, s, sRef);
      assert.equal(csrfAttempt.status, 403, "session_ref no es un token CSRF");
      assert.equal(h.staffSessions.rows()[0]!.revokedAtMs, null);
      const bodyAttempt = await fetch(`${h.baseUrl}/staff/logout`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": "t", cookie: `${STAFF_CSRF}=t` }, body: JSON.stringify({ sessionRef: sRef, session_ref: sRef }) });
      assert.equal(bodyAttempt.status, 200);
      assert.equal(h.staffSessions.rows()[0]!.revokedAtMs, null, "un cuerpo con session_ref no revoca ninguna sesion (solo la cookie firmada)");
      assert.equal(h.caseSessions.rows()[0]!.revokedAtMs, null);
      assert.equal(await h.staffSessions.validateAndTouch({ tenantId: TENANT_A, sidHash: hashStaffSid(sRef), principalRef: ADMIN_A, role: "TENANT_ADMIN", nowMs: Date.now(), idleTimeoutMs: 1_800_000 }), false, "no es un sid");
      assert.equal(await h.caseSessions.validateAndTouch({ tenantId: TENANT_A, sidHash: hashCaseSid(cRef), caseRef: CASE_REF, principalRef: OPERATOR, role: "RIGHTS_OPERATOR", nowMs: Date.now(), idleTimeoutMs: 1_800_000 }), false);

      // el cierre y los rechazos tampoco lo exponen
      await record(await staffLogout(h, s));
      await record(await caseLogout(h, c));
      await record(csrfAttempt);
      return { transcripts, refs: [sRef, cRef], cookies: [s.session, c.session] };
    });
    const everything = seen.transcripts.join("\n---\n") + "\n" + printed.join("\n");
    for (const ref of seen.refs) assert.ok(!everything.includes(ref), "session_ref no viaja en cabeceras, cookies, cuerpos, URL ni logs");
    // la cookie firmada tampoco lo lleva en su carga
    for (const cookie of seen.cookies) {
      const payload = Buffer.from(cookie.split(".")[0]!, "base64url").toString("utf8");
      for (const ref of seen.refs) assert.ok(!payload.includes(ref));
      assert.ok(!/session_?ref/i.test(payload));
    }
    // y el evento no guarda sid, hash, cookie ni CSRF (INV-SE-05)
    const events = JSON.stringify(h.events.list());
    for (const row of [...h.staffSessions.rows(), ...h.caseSessions.rows()]) assert.ok(!events.includes(row.sidHash), "el evento no lleva sid_hash");
    for (const secret of [...seen.cookies, ...seen.cookies.flatMap((c) => c.split("."))]) assert.ok(!events.includes(secret));
  } finally {
    await h.close();
  }
});
