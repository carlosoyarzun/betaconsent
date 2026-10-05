// Gobierna: CA-138 (SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3), staff-session.ts, staff-console.handler.ts, staff-ui.handler.ts, GRD-CM-01/10.
// Recorrido HTTP (CONSENT_STORE=memory) de la sesion STAFF con registro en servidor, reloj inyectado (staffNowMs):
// TEST-CNS-1143 logout revoca en servidor (cookie robada tras logout no sirve; UI y JSON), 1145 expiracion absoluta e inactividad,
// 1146 rotacion de sid al iniciar sesion, 1147 CSRF de otra sesion rechazado, 1149 cursor y flash de otra sesion rechazados,
// 1150 dev-login solo LOCAL, mismo mecanismo, sin PII ni sid en almacen/logs. Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { createInMemorySubjectDirectory } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import {
  createConsentFlowHttpServer,
  createDefaultConsentFlowPorts,
  createDefaultStaffConsolePorts,
} from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { decodeStaffSession, deriveStaffSessionKey, hashStaffSid } from "../../../src/server/entrypoints/http/staff-session.ts";
import { APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS, APPROVED_STAFF_SESSION_IDLE_TIMEOUT_MS } from "../../../src/server/modules/common/approved-parameters.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const ORIGIN = "http://consola-staff-session.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const CSRF_COOKIE = "__Host-cns-staff-csrf";
const FLASH_COOKIE = "__Host-cns-staff-flash";
const TENANT_A = LOCAL_ONLY_DEV_TENANT_ID;
const TENANT_B = LOCAL_ONLY_DEV_OTHER_TENANT_ID;
const ADMIN_A = fixtureUuid("sess-admin-a");
const ADMIN_B = fixtureUuid("sess-admin-b");
const ROSTER: readonly StaffPrincipal[] = [
  { principalRef: ADMIN_A, role: "TENANT_ADMIN", tenantId: TENANT_A },
  { principalRef: ADMIN_B, role: "TENANT_ADMIN", tenantId: TENANT_B },
];
const CONTEXT = "BETA_2026_01";
const GOOD_EMAIL = "apoderado1@example.invalid";
const NAV = { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } as const;
const SECRET = Buffer.alloc(32, 5);
const KEY = deriveStaffSessionKey(SECRET);
const MIN = 60_000;

const students = Array.from({ length: 3 }, (_, i) => ({
  subjectRef: fixtureUuid(`sess-subj-${i + 1}`),
  participationRef: fixtureUuid(`sess-part-${i + 1}`),
  label: `Alumno de prueba ${i + 1}`,
}));

interface Harness {
  baseUrl: string;
  staff: ReturnType<typeof createDefaultStaffConsolePorts>;
  clock: { now: number };
  close(): Promise<void>;
}

async function start(opts: { environment?: "LOCAL" | "DEV"; subjectCount?: number } = {}): Promise<Harness> {
  const subjects = opts.subjectCount === undefined ? students : Array.from({ length: opts.subjectCount }, (_, i) => ({ subjectRef: fixtureUuid(`sess-subj-${i + 1}`), participationRef: fixtureUuid(`sess-part-${i + 1}`), label: `Alumno de prueba ${i + 1}` }));
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);
  const staffIdentity = createInMemoryStaffIdentityAdapter(ROSTER);
  const staff = createDefaultStaffConsolePorts(
    ports.invitation,
    staffIdentity,
    loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
    loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
  );
  for (const s of subjects) {
    staff.catalog.seedSubject(TENANT_A, s.subjectRef);
    staff.catalog.seedParticipation(TENANT_A, { participationRef: s.participationRef, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  }
  const directory = createInMemorySubjectDirectory("LOCAL", subjects.map((s) => ({ tenantId: TENANT_A, subjectRef: s.subjectRef, label: s.label, participationRef: s.participationRef })));
  const clock = { now: Date.now() };
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    sessionSecret: SECRET,
    environment: opts.environment ?? "LOCAL",
    staffIdentity,
    staffConsole: { ...staff, subjectDirectory: directory },
    staffRosterCursorKey: deriveStaffRosterCursorKey(Buffer.alloc(32, 6)),
    staffUi: { contextRef: CONTEXT, consentVersion: "v1-dev" },
    staffNowMs: () => clock.now,
    devStaffConsole: { principalRef: ADMIN_A, students: subjects.map((s) => ({ label: s.label, subjectRef: s.subjectRef, participationRef: s.participationRef })), contextRef: CONTEXT, consentVersion: "v1-dev" },
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, staff, clock, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

const rowsOf = (h: Harness) => (h.staff.sessions as ReturnType<typeof createInMemoryStaffSessionStore>).rows();

interface Res { status: number; body: string; headers: Headers }
function getPage(h: Harness, path: string, cookie: string | undefined, headers: Record<string, string> = NAV): Promise<Res> {
  const h2: Record<string, string> = { ...headers };
  if (cookie !== undefined) h2.cookie = cookie;
  return new Promise((resolve, reject) => {
    const req = httpRequest(`${h.baseUrl}${path}`, { method: "GET", headers: h2 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const out = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (k === "set-cookie" && Array.isArray(v)) for (const c of v) out.append("set-cookie", c);
          else if (typeof v === "string") out.set(k, v);
        }
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8"), headers: out });
      });
    });
    req.on("error", reject);
    req.end();
  });
}
async function postForm(h: Harness, path: string, fields: Record<string, string>, cookie?: string): Promise<Res> {
  const res = await fetch(`${h.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(fields),
    redirect: "manual",
  });
  return { status: res.status, body: await res.text(), headers: res.headers };
}
async function postJson(h: Harness, path: string, body: unknown, cookie: string | undefined, csrf?: string): Promise<Res> {
  const res = await fetch(`${h.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, ...(cookie ? { cookie } : {}), ...(csrf ? { "x-csrf-token": csrf } : {}) },
    body: JSON.stringify(body),
    redirect: "manual",
  });
  return { status: res.status, body: await res.text(), headers: res.headers };
}
const roster = (h: Harness, cookie: string | undefined, query = ""): Promise<Res> => getPage(h, `/staff/roster${query}`, cookie, { "sec-fetch-site": "same-origin" });
const list = (h: Harness, cookie: string | undefined): Promise<Res> => getPage(h, "/staff/students", cookie);

interface Login { cookie: string; sessionValue: string; csrf: string; sid: string; setCookies: string[] }
/** Login real por la pantalla (POST /staff/dev-login). `previous` simula un navegador que ya traia una cookie. */
async function login(h: Harness, previous?: string): Promise<Login> {
  const res = await postForm(h, "/staff/dev-login", {}, previous);
  assert.equal(res.status, 303);
  const setCookies = res.headers.getSetCookie();
  const valueOf = (name: string): string => setCookies.find((c) => c.startsWith(`${name}=`))!.split(";")[0]!.slice(name.length + 1);
  const sessionValue = valueOf(STAFF_COOKIE);
  const csrf = valueOf(CSRF_COOKIE);
  const sid = decodeStaffSession(KEY, sessionValue)!.sid;
  return { cookie: `${STAFF_COOKIE}=${sessionValue}; ${CSRF_COOKIE}=${csrf}`, sessionValue, csrf, sid, setCookies };
}

test("TEST-CNS-1143 logout revoca el sid en servidor: la cookie robada tras logout no sirve (UI y JSON, lectura y escritura); el logout es idempotente", async () => {
  const h = await start();
  try {
    const s1 = await login(h);
    assert.equal((await list(h, s1.cookie)).status, 200);
    assert.equal((await roster(h, s1.cookie)).status, 200);
    const out = await postForm(h, "/staff/logout", { csrf_token: s1.csrf }, s1.cookie);
    assert.equal(out.status, 303);
    assert.ok(out.headers.getSetCookie().every((c) => c.includes("Max-Age=0")));
    assert.ok(rowsOf(h).find((r) => r.sidHash === hashStaffSid(s1.sid))!.revokedAtMs !== null, "revocada en servidor");
    // la cookie "robada" (la firma sigue siendo correcta y no ha vencido) ya no sirve en ninguna ruta
    assert.equal((await list(h, s1.cookie)).status, 404);
    assert.equal((await roster(h, s1.cookie)).status, 404);
    assert.equal((await getPage(h, "/staff/students/sent", s1.cookie)).status, 404);
    assert.equal((await postForm(h, "/staff/students/invite", { csrf_token: s1.csrf, subject: students[0]!.subjectRef, participation: students[0]!.participationRef }, s1.cookie)).status, 404);
    assert.equal((await postJson(h, "/staff/enrollments", { subjectRef: students[0]!.subjectRef, participationRef: students[0]!.participationRef }, s1.cookie, s1.csrf)).status, 404);
    // idempotente: cerrar de nuevo con la cookie ya revocada no falla ni reactiva nada
    assert.equal((await postForm(h, "/staff/logout", { csrf_token: s1.csrf }, s1.cookie)).status, 303);
    assert.equal((await list(h, s1.cookie)).status, 404);

    // equivalente JSON: POST /staff/logout con application/json y CSRF por cabecera
    const s2 = await login(h);
    assert.equal((await roster(h, s2.cookie)).status, 200);
    const noCsrf = await postJson(h, "/staff/logout", {}, s2.cookie);
    assert.equal(noCsrf.status, 403);
    assert.equal((await roster(h, s2.cookie)).status, 200, "un logout rechazado no revoca");
    const json = await postJson(h, "/staff/logout", {}, s2.cookie, s2.csrf);
    assert.equal(json.status, 200);
    assert.ok(json.headers.getSetCookie().length === 3 && json.headers.getSetCookie().every((c) => c.includes("Max-Age=0")));
    assert.equal((await roster(h, s2.cookie)).status, 404);
    assert.equal((await postJson(h, "/staff/logout", {}, s2.cookie, s2.csrf)).status, 200, "idempotente");
    // la sesion de otro navegador no se ve afectada
    const s3 = await login(h);
    assert.equal((await roster(h, s3.cookie)).status, 200);
    assert.equal((await postJson(h, "/staff/logout", {}, undefined, "x")).status, 403, "sin cookie CSRF: rechazado");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1145 expiracion: por inactividad (se desliza con el uso) y absoluta (exp), con reloj inyectado; mismo 404 uniforme sin filtrar la causa", async () => {
  const h = await start();
  try {
    assert.equal(APPROVED_STAFF_SESSION_IDLE_TIMEOUT_MS, 30 * MIN);
    const t0 = h.clock.now;
    const idle = await login(h);
    h.clock.now = t0 + 29 * MIN;
    assert.equal((await roster(h, idle.cookie)).status, 200);
    h.clock.now = t0 + 58 * MIN; // 29 min desde el ultimo uso: sigue
    assert.equal((await list(h, idle.cookie)).status, 200);
    h.clock.now = t0 + 58 * MIN + 30 * MIN + 1; // > 30 min sin uso
    const expiredRoster = await roster(h, idle.cookie);
    const expiredList = await list(h, idle.cookie);
    assert.equal(expiredRoster.status, 404);
    assert.equal(expiredList.status, 404);
    // el mismo cuerpo que una cookie inexistente / revocada / de otro tenant: la causa no se distingue
    const garbage = await roster(h, `${STAFF_COOKIE}=basura.firma`);
    assert.equal(expiredRoster.body, garbage.body);
    assert.equal(expiredRoster.body, (await roster(h, undefined)).body);
    assert.equal((await postForm(h, "/staff/students/invite", { csrf_token: idle.csrf, subject: students[0]!.subjectRef, participation: students[0]!.participationRef }, idle.cookie)).status, 404);
    assert.equal((await postJson(h, "/staff/enrollments", { subjectRef: students[0]!.subjectRef, participationRef: students[0]!.participationRef }, idle.cookie, idle.csrf)).status, 404);

    // absoluta: con actividad constante cada 20 min, deja de valer exactamente en exp
    h.clock.now = t0;
    const busy = await login(h);
    const exp = decodeStaffSession(KEY, busy.sessionValue)!.exp;
    assert.equal(exp - t0, APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS);
    let t = t0;
    while (t + 20 * MIN < exp) {
      t += 20 * MIN;
      h.clock.now = t;
      assert.equal((await roster(h, busy.cookie)).status, 200);
    }
    h.clock.now = exp - 1;
    assert.equal((await roster(h, busy.cookie)).status, 200);
    h.clock.now = exp;
    assert.equal((await roster(h, busy.cookie)).status, 404, "exp absoluta aunque haya actividad");
    // un login nuevo despues de expirar funciona (y purga las expiradas fuera de retencion)
    h.clock.now = exp + 25 * 60 * MIN;
    const fresh = await login(h);
    assert.equal((await roster(h, fresh.cookie)).status, 200);
    assert.ok(!rowsOf(h).some((r) => r.sidHash === hashStaffSid(idle.sid)), "las sesiones expiradas fuera de retencion se limpiaron");
    assert.ok(rowsOf(h).some((r) => r.sidHash === hashStaffSid(fresh.sid)));
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1146 rotacion de sid al iniciar sesion (anti fixation): cada login emite un sid nuevo aleatorio; el sid previo del navegador queda revocado; una cookie impuesta por un atacante no se adopta", async () => {
  const h = await start();
  try {
    const first = await login(h);
    const second = await login(h, first.cookie);
    assert.notEqual(second.sid, first.sid);
    assert.match(first.sid, /^[A-Za-z0-9_-]{43}$/);
    assert.equal((await list(h, first.cookie)).status, 404, "el sid previo quedo revocado por la rotacion");
    assert.equal((await list(h, second.cookie)).status, 200);
    // fixation: el atacante fija una cookie propia (formato valido, firma ajena o basura) antes del login de la victima
    const attackerCookie = `${STAFF_COOKIE}=${"A".repeat(43)}.${"B".repeat(43)}; ${CSRF_COOKIE}=attacker`;
    const victim = await login(h, attackerCookie);
    assert.ok(!victim.setCookies.join(";").includes("A".repeat(43)));
    assert.notEqual(victim.sid, "A".repeat(43));
    assert.equal((await list(h, victim.cookie)).status, 200);
    // el login por JSON (/__dev/staff-login) usa el mismo mecanismo y tambien rota
    const res = await fetch(`${h.baseUrl}/__dev/staff-login`, { method: "POST", headers: { "content-type": "application/json", cookie: victim.cookie }, body: JSON.stringify({ principalRef: ADMIN_A }) });
    assert.equal(res.status, 200);
    const jsonSession = res.headers.getSetCookie().find((c) => c.startsWith(`${STAFF_COOKIE}=`))!.split(";")[0]!.slice(STAFF_COOKIE.length + 1);
    assert.notEqual(decodeStaffSession(KEY, jsonSession)!.sid, victim.sid);
    assert.equal((await list(h, victim.cookie)).status, 404);
    assert.equal(rowsOf(h).filter((r) => r.revokedAtMs === null).length, 2, "vigentes: la segunda sesion (victim fue rotada por el login JSON, la primera por la segunda) y la del login JSON");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1147 CSRF de otra sesion rechazado: el double-submit cookie==campo no basta, el token debe ser el del sid de ESTA sesion (UI, JSON y logout)", async () => {
  const h = await start();
  try {
    const a = await login(h);
    const b = await login(h); // otro navegador, mismo principal
    assert.notEqual(a.csrf, b.csrf);
    const foreignCookie = `${STAFF_COOKIE}=${a.sessionValue}; ${CSRF_COOKIE}=${b.csrf}`;
    const form = { subject: students[0]!.subjectRef, participation: students[0]!.participationRef };
    const ui = await postForm(h, "/staff/students/invite", { ...form, csrf_token: b.csrf }, foreignCookie);
    assert.equal(ui.status, 403);
    const uiSend = await postForm(h, "/staff/students/send", { ...form, csrf_token: b.csrf, guardian_email: GOOD_EMAIL }, foreignCookie);
    assert.equal(uiSend.status, 403);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    const api = await postJson(h, "/staff/enrollments", form.subject ? { subjectRef: form.subject, participationRef: form.participation } : {}, foreignCookie, b.csrf);
    assert.equal(api.status, 403);
    assert.equal((JSON.parse(api.body) as { code: string }).code, "CSRF_REJECTED");
    assert.equal(await h.staff.enrollment.enrollmentRepo.findActive(TENANT_A, form.subject, form.participation), null);
    // logout con el token de otra sesion: rechazado y NO revoca
    assert.equal((await postForm(h, "/staff/logout", { csrf_token: b.csrf }, foreignCookie)).status, 403);
    assert.equal((await postJson(h, "/staff/logout", {}, foreignCookie, b.csrf)).status, 403);
    assert.equal((await list(h, a.cookie)).status, 200, "la sesion A sigue vigente");
    // con su propio token, la misma peticion pasa el guard de CSRF
    assert.equal((await postForm(h, "/staff/students/invite", { ...form, csrf_token: a.csrf }, a.cookie)).status, 200);
    assert.equal((await postJson(h, "/staff/enrollments", { subjectRef: form.subject, participationRef: form.participation }, a.cookie, a.csrf)).status, 201);
    // un token fabricado (cookie==campo, sin relacion con el sid) tampoco sirve
    assert.equal((await postForm(h, "/staff/students/invite", { ...form, csrf_token: "forjado" }, `${STAFF_COOKIE}=${a.sessionValue}; ${CSRF_COOKIE}=forjado`)).status, 403);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1149 el cursor de API-CNS-116 y la cookie flash estan ligados al sid: los de otra sesion (mismo principal y tenant) se rechazan", async () => {
  const h = await start({ subjectCount: 3 });
  try {
    const a = await login(h);
    const b = await login(h);
    const first = JSON.parse((await roster(h, a.cookie, "?limit=1")).body) as { nextCursor: string | null };
    assert.ok(first.nextCursor);
    const own = await roster(h, a.cookie, `?cursor=${first.nextCursor}`);
    assert.equal(own.status, 200);
    const foreign = await roster(h, b.cookie, `?cursor=${first.nextCursor}`);
    assert.equal(foreign.status, 422, "cursor de otra sesion");
    assert.equal((JSON.parse(foreign.body) as { code: string }).code, "LIST_QUERY_INVALID");
    // tras el logout, un cursor de esa sesion tampoco vale para una sesion nueva del mismo navegador
    await postForm(h, "/staff/logout", { csrf_token: a.csrf }, a.cookie);
    const a2 = await login(h);
    assert.equal((await roster(h, a2.cookie, `?cursor=${first.nextCursor}`)).status, 422);

    // flash: una confirmacion emitida para la sesion b no se muestra con la sesion a2
    const s = students[0]!;
    const sent = await postForm(h, "/staff/students/send", { csrf_token: b.csrf, subject: s.subjectRef, participation: s.participationRef, guardian_email: GOOD_EMAIL }, b.cookie);
    assert.equal(sent.status, 303);
    const flashCookie = sent.headers.getSetCookie().find((c) => c.startsWith(`${FLASH_COOKIE}=`))!.split(";")[0]!;
    assert.ok(!flashCookie.includes(b.sid), "el flash no lleva el sid en claro");
    assert.equal((await getPage(h, "/staff/students/sent", `${b.cookie}; ${flashCookie}`)).status, 200);
    assert.equal((await getPage(h, "/staff/students/sent", `${a2.cookie}; ${flashCookie}`)).status, 303, "flash de otra sesion: nada que confirmar");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1150 dev-login solo en LOCAL con el mismo mecanismo y sin privilegios extra; el almacen y los logs no contienen sid, cookie, correo ni PII", async () => {
  const captured: string[] = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  const spy = (...a: unknown[]): void => { captured.push(a.map(String).join(" ")); };
  console.log = spy; console.error = spy; console.warn = spy; console.info = spy;
  const dev = await start({ environment: "DEV" });
  const local = await start();
  try {
    // fuera de LOCAL: ni el login de la pantalla ni el JSON existen, y no se registra ninguna sesion
    assert.equal((await postForm(dev, "/staff/dev-login", {})).status, 404);
    const jsonDev = await fetch(`${dev.baseUrl}/__dev/staff-login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ principalRef: ADMIN_A }) });
    assert.equal(jsonDev.status, 404);
    assert.equal(jsonDev.headers.getSetCookie().length, 0);
    assert.equal(rowsOf(dev).length, 0);

    // en LOCAL: una fila por login, solo TENANT_ADMIN del roster, sid hasheado, cookie con Max-Age = vida absoluta
    const s = await login(local);
    assert.equal(rowsOf(local).length, 1);
    const row = rowsOf(local)[0]!;
    assert.deepEqual({ tenantId: row.tenantId, principalRef: row.principalRef, role: row.role, sidHash: row.sidHash }, { tenantId: TENANT_A, principalRef: ADMIN_A, role: "TENANT_ADMIN", sidHash: hashStaffSid(s.sid) });
    assert.equal(row.expiresAtMs - row.issuedAtMs, APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS);
    const sessionSetCookie = s.setCookies.find((c) => c.startsWith(`${STAFF_COOKIE}=`))!;
    assert.match(sessionSetCookie, /; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800$/);
    // sin privilegios extra: el dev-login de otro principal que no sea TENANT_ADMIN del roster no emite sesion
    const none = await fetch(`${local.baseUrl}/__dev/staff-login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ principalRef: "no-existe" }) });
    assert.equal(none.headers.getSetCookie().find((c) => c.startsWith(`${STAFF_COOKIE}=`)), undefined);
    assert.equal(rowsOf(local).length, 1);
    // sin PII ni sid: ni el almacen ni lo impreso
    const stored = JSON.stringify(rowsOf(local));
    assert.ok(!stored.includes(s.sid) && !stored.includes(s.sessionValue) && !stored.includes(s.csrf) && !stored.includes(GOOD_EMAIL));
    assert.ok(!/@/.test(stored), "ningun correo en el almacen");
    const sent = await postForm(local, "/staff/students/send", { csrf_token: s.csrf, subject: students[0]!.subjectRef, participation: students[0]!.participationRef, guardian_email: GOOD_EMAIL }, s.cookie);
    assert.equal(sent.status, 303);
    await postForm(local, "/staff/logout", { csrf_token: s.csrf }, s.cookie);
    const printed = captured.join("\n");
    assert.ok(!printed.includes(s.sid) && !printed.includes(s.sessionValue) && !printed.includes(s.csrf) && !printed.includes(GOOD_EMAIL) && !printed.includes(students[0]!.subjectRef));
  } finally {
    Object.assign(console, orig);
    await dev.close();
    await local.close();
  }
});
