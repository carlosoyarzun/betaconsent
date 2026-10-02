// Gobierna: REQ-CNS-036 / UX-CNS-005 (AC-01..AC-21), DEC-BR-019 (Notion), API-CNS-116 + API-CNS-105/110/111/112, SEC-CNS-018 rev. 2 (R3, R5),
// common.spec GRD-CM-01/02/07/08/10. CONSENT_STORE=memory; el equivalente sobre Postgres esta en tests/integration/postgres/staff-ui-http-pg.test.ts.
// TEST-CNS-1105 (entrada y login dev solo LOCAL), 1106 (gating de la lista), 1107 (lista: etiquetas, sin PII, cabeceras), 1108 (DECLINED=COMPLETED),
// 1109 (formulario y CSRF/Origin/Sec-Fetch), 1110 (correo invalido sin eco), 1111 (resumen), 1112 (envio feliz + PRG + confirmacion),
// 1113 (idempotencia: doble envio), 1114 (invitacion activa), 1115 (fallo a mitad de la cadena), 1116 (sesion/permiso en POST), 1117 (logout),
// 1118 (cero PII en logs), 1119 (paginacion con cursor), 1120 (lista vacia), 1121 (CSP y cabeceras en todas las respuestas HTML),
// 1122 (rutas JSON existentes intactas). Solo datos sinteticos, cero PII.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
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
import { deriveStaffSessionKey, encodeStaffSession } from "../../../src/server/entrypoints/http/staff-session.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import type { InvitationListing } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import type { InvitationState } from "../../../src/server/ports/invitation-repository.port.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const ORIGIN = "http://consola-staff-ui.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const CSRF_COOKIE = "__Host-cns-staff-csrf";
const FLASH_COOKIE = "__Host-cns-staff-flash";
const TENANT_A = LOCAL_ONLY_DEV_TENANT_ID;
const TENANT_B = LOCAL_ONLY_DEV_OTHER_TENANT_ID;
const ADMIN_A = fixtureUuid("ui-admin-a");
const ADMIN_B = fixtureUuid("ui-admin-b");
const VIEWER = fixtureUuid("ui-viewer");
const ROSTER: readonly StaffPrincipal[] = [
  { principalRef: ADMIN_A, role: "TENANT_ADMIN", tenantId: TENANT_A },
  { principalRef: ADMIN_B, role: "TENANT_ADMIN", tenantId: TENANT_B },
  { principalRef: VIEWER, role: "APPROVER", tenantId: TENANT_A },
];
const CONTEXT = "BETA_2026_01";
const GOOD_EMAIL = "apoderado1@example.invalid";
const CSRF = "csrf-ui-0123456789abcdef";
const NAV = { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } as const;

interface Student { subjectRef: string; participationRef: string; label: string }
const student = (n: number): Student => ({ subjectRef: fixtureUuid(`ui-subj-${n}`), participationRef: fixtureUuid(`ui-part-${n}`), label: `Alumno de prueba ${n}` });

interface Harness {
  baseUrl: string;
  staff: ReturnType<typeof createDefaultStaffConsolePorts>;
  sessionSecret: Buffer;
  close(): Promise<void>;
}

interface StartOptions {
  students?: readonly Student[];
  environment?: "LOCAL" | "DEV";
  withUi?: boolean;
  withDevFixture?: boolean;
  withPolicy?: boolean;
}

async function start(opts: StartOptions = {}): Promise<Harness> {
  const students = opts.students ?? [student(1), student(2), student(3)];
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);
  const staffIdentity = createInMemoryStaffIdentityAdapter(ROSTER);
  const staff = createDefaultStaffConsolePorts(
    ports.invitation,
    staffIdentity,
    opts.withPolicy === false ? undefined : loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
    loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
  );
  for (const s of students) {
    staff.catalog.seedSubject(TENANT_A, s.subjectRef);
    staff.catalog.seedParticipation(TENANT_A, { participationRef: s.participationRef, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  }
  const directory = createInMemorySubjectDirectory("LOCAL", students.map((s) => ({ tenantId: TENANT_A, subjectRef: s.subjectRef, label: s.label, participationRef: s.participationRef })));
  const sessionSecret = randomBytes(32);
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    sessionSecret,
    environment: opts.environment ?? "LOCAL",
    staffIdentity,
    staffConsole: { ...staff, subjectDirectory: directory },
    staffRosterCursorKey: deriveStaffRosterCursorKey(randomBytes(32)),
    ...(opts.withUi === false ? {} : { staffUi: { contextRef: CONTEXT, consentVersion: "v1-dev" } }),
    ...(opts.withDevFixture === false
      ? {}
      : { devStaffConsole: { principalRef: ADMIN_A, students: students.map((s) => ({ label: s.label, subjectRef: s.subjectRef, participationRef: s.participationRef })), contextRef: CONTEXT, consentVersion: "v1-dev" } }),
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, staff, sessionSecret, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function session(h: Harness, principalRef = ADMIN_A, tenantId = TENANT_A, role: StaffPrincipal["role"] = "TENANT_ADMIN"): string {
  return `${STAFF_COOKIE}=${encodeStaffSession(deriveStaffSessionKey(h.sessionSecret), { tenantId, principalRef, role })}; ${CSRF_COOKIE}=${CSRF}`;
}

interface Res { status: number; html: string; headers: Headers }
/** GET con node:http: fetch (undici) fija solo sec-fetch-mode=cors / sec-fetch-dest=empty y pisaria los de una navegacion. */
async function getPage(h: Harness, path: string, headers: Record<string, string | undefined> = {}, cookie?: string): Promise<Res> {
  const h2: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) if (v !== undefined) h2[k] = v;
  if (cookie) h2.cookie = cookie;
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
        resolve({ status: res.statusCode ?? 0, html: Buffer.concat(chunks).toString("utf8"), headers: out });
      });
    });
    req.on("error", reject);
    req.end();
  });
}
async function postForm(h: Harness, path: string, fields: Record<string, string>, opts: { cookie?: string; origin?: string | null; site?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (opts.origin !== null) headers.origin = opts.origin ?? ORIGIN;
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.site) headers["sec-fetch-site"] = opts.site;
  const res = await fetch(`${h.baseUrl}${path}`, { method: "POST", headers, body: new URLSearchParams(fields), redirect: "manual" });
  return { status: res.status, html: await res.text(), headers: res.headers };
}

const listGet = (h: Harness, cookie?: string, query = ""): Promise<Res> => getPage(h, `/staff/students${query}`, NAV, cookie ?? session(h));
const invitationCount = async (h: Harness): Promise<number> =>
  (await (h.staff.issuance.invitation.invitationRepo as unknown as InvitationListing).listByTenant(TENANT_A)).length;
const logCount = async (h: Harness, tenantId = TENANT_A): Promise<number> => (await h.staff.accessLog.listByTenant(tenantId)).filter((r) => r.action === "STAFF_ROSTER_READ").length;
const fields = (s: Student, extra: Record<string, string> = {}): Record<string, string> => ({ csrf_token: CSRF, subject: s.subjectRef, participation: s.participationRef, ...extra });
const h1Of = (html: string): string => html.match(/<h1[^>]*>([^<]*)<\/h1>/)?.[1] ?? "";

async function seedInvitation(h: Harness, subjectRef: string, state: InvitationState, expiresInMs: number | null, n: string): Promise<void> {
  await h.staff.issuance.invitation.invitationRepo.save({
    invitationRef: fixtureUuid(`ui-inv-${n}`),
    tenantId: TENANT_A,
    contextRef: CONTEXT,
    productRef: "LECTORPRO",
    subjectRef,
    state,
    ...(expiresInMs !== null ? { expiresAt: new Date(Date.now() + expiresInMs) } : {}),
  });
}

test("TEST-CNS-1105 entrada: sin sesion muestra el acceso deshabilitado y ninguna lista; el boton dev existe solo en LOCAL y el POST dev-login no existe fuera de LOCAL", async () => {
  const local = await start();
  try {
    const entry = await getPage(local, "/staff");
    assert.equal(entry.status, 200);
    assert.equal(h1Of(entry.html), "Consola del colegio");
    assert.ok(entry.html.includes('aria-disabled="true" aria-describedby="login-help"'));
    assert.ok(entry.html.includes("Iteración 0 · Solo datos sintéticos"));
    assert.ok(entry.html.includes("Entrar (solo desarrollo)"), "en LOCAL el boton dev esta claramente rotulado");
    assert.ok(!entry.html.includes("Alumno de prueba"), "sin sesion no hay lista");
    // con sesion, la entrada lleva a la lista
    const withSession = await getPage(local, "/staff", {}, session(local));
    assert.equal(withSession.status, 303);
    assert.equal(withSession.headers.get("location"), "/staff/students");
  } finally {
    await local.close();
  }
  for (const variant of [{ environment: "DEV" as const }, { withDevFixture: false }]) {
    const other = await start(variant);
    try {
      const entry = await getPage(other, "/staff");
      assert.equal(entry.status, 200);
      assert.ok(!entry.html.includes("Entrar (solo desarrollo)") && !entry.html.includes("dev-login"), "fuera de LOCAL (o sin fixture) no existe el boton dev");
      const login = await postForm(other, "/staff/dev-login", {});
      assert.equal(login.status, 404);
      assert.deepEqual(JSON.parse(login.html), { status: 404 });
      assert.equal(login.headers.get("set-cookie"), null);
    } finally {
      await other.close();
    }
  }
  // Sin la configuracion staffUi, ninguna ruta de pantalla existe.
  const off = await start({ withUi: false });
  try {
    for (const path of ["/staff", "/staff/students", "/staff/students/sent"]) assert.equal((await getPage(off, path, NAV, session(off))).status, 404, path);
    assert.equal((await postForm(off, "/staff/students/invite", fields(student(1)), { cookie: session(off) })).status, 404);
  } finally {
    await off.close();
  }
});

test("TEST-CNS-1105 login dev (LOCAL): Origin exacto, emite la sesion STAFF del TENANT_ADMIN sintetico y lleva a la lista; Origin ajeno -> 403 sin cookies", async () => {
  const h = await start();
  try {
    const bad = await postForm(h, "/staff/dev-login", {}, { origin: "http://evil.test" });
    assert.equal(bad.status, 403);
    assert.equal(bad.headers.get("set-cookie"), null);
    const none = await postForm(h, "/staff/dev-login", {}, { origin: null });
    assert.equal(none.status, 403);
    const ok = await postForm(h, "/staff/dev-login", {});
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.get("location"), "/staff/students");
    const cookies = ok.headers.getSetCookie().map((c) => c.split(";")[0]!);
    assert.ok(cookies.some((c) => c.startsWith(`${STAFF_COOKIE}=`)) && cookies.some((c) => c.startsWith(`${CSRF_COOKIE}=`)));
    // la sesion obtenida abre la lista (mismo gating completo)
    const list = await getPage(h, "/staff/students", NAV, cookies.join("; "));
    assert.equal(list.status, 200);
    assert.equal(h1Of(list.html), "Alumnos del colegio");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1106 lista: Sec-Fetch (same-origin o none+navigate+document), Origin, sesion y rol; un gating fallido no escribe access_log; un GET valido escribe exactamente una fila", async () => {
  const h = await start();
  try {
    const cookie = session(h);
    const cases: Array<[string, Record<string, string | undefined>, number]> = [
      ["sin Sec-Fetch-Site", {}, 404],
      ["cross-site", { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, 404],
      ["same-site", { "sec-fetch-site": "same-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, 404],
      ["none sin mode/dest", { "sec-fetch-site": "none" }, 404],
      ["none + cors", { "sec-fetch-site": "none", "sec-fetch-mode": "cors", "sec-fetch-dest": "document" }, 404],
      ["none + iframe", { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe" }, 404],
      ["Origin ajeno", { ...NAV, origin: "http://evil.test" }, 404],
    ];
    for (const [name, headers, status] of cases) {
      const res = await getPage(h, "/staff/students", headers, cookie);
      assert.equal(res.status, status, name);
      assert.equal(h1Of(res.html), "No pudimos abrir esta página", name);
    }
    assert.equal(await logCount(h), 0, "ningun gating fallido escribe access_log");
    const noSession = await getPage(h, "/staff/students", NAV);
    assert.equal(noSession.status, 404);
    const viewer = await getPage(h, "/staff/students", NAV, session(h, VIEWER, TENANT_A, "APPROVER"));
    assert.equal(viewer.status, 403);
    assert.equal(h1Of(viewer.html), "No tienes permiso para esta acción");
    const tampered = await getPage(h, "/staff/students", NAV, `${STAFF_COOKIE}=forjada.abc; ${CSRF_COOKIE}=${CSRF}`);
    assert.equal(tampered.status, 404);
    assert.equal(await logCount(h), 0);
    // validos: same-origin y navegacion directa; cada uno exactamente una fila
    const sameOrigin = await getPage(h, "/staff/students", { "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", origin: ORIGIN }, cookie);
    assert.equal(sameOrigin.status, 200);
    assert.equal(await logCount(h), 1);
    const direct = await listGet(h);
    assert.equal(direct.status, 200);
    assert.equal(await logCount(h), 2, "una fila por GET valido, igual que el JSON");
    // cursor invalido: 422 con pagina de error, sin fila
    const badCursor = await listGet(h, undefined, "?cursor=c1.forjado");
    assert.equal(badCursor.status, 422);
    const unknownParam = await listGet(h, undefined, "?otro=1");
    assert.equal(unknownParam.status, 422);
    assert.equal(await logCount(h), 2);
    // el access_log del otro tenant no se toca
    assert.equal(await logCount(h, TENANT_B), 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1107 lista: etiqueta por estado, 'Invitar' solo en sin invitar, sin correo, sin subjectRef en URLs, orden y conteos no revelan el sentido", async () => {
  const subjects = [student(1), student(2), student(3), student(4), student(5), student(6)];
  const h = await start({ students: subjects });
  try {
    await seedInvitation(h, subjects[1]!.subjectRef, "DRAFT", null, "2");
    await seedInvitation(h, subjects[2]!.subjectRef, "VERIFIED", 3_600_000, "3");
    await seedInvitation(h, subjects[3]!.subjectRef, "COMPLETED", null, "4");
    await seedInvitation(h, subjects[4]!.subjectRef, "DECLINED", null, "5");
    await seedInvitation(h, subjects[5]!.subjectRef, "SENT", -3_600_000, "6"); // vencida perezosa
    const res = await listGet(h);
    assert.equal(res.status, 200);
    const rows = [...res.html.matchAll(/<th scope="row">([^<]*)<\/th>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>/g)];
    assert.equal(rows.length, 6);
    const badges = rows.map((r) => r[2]!.replace(/<[^>]+>/g, "").trim()).sort();
    assert.deepEqual(badges, ["Cerrada sin decisión", "Decisión registrada", "Decisión registrada", "Enviada", "Envío incompleto", "Sin invitar"]);
    assert.equal(res.html.split(">Invitar</button>").length - 1, 1, "una sola accion: el alumno sin invitar");
    assert.equal(res.html.split("Sin acciones").length - 1, 5);
    assert.ok(!res.html.includes(GOOD_EMAIL) && !/guardian|recipient|token|invitationRef|expiresAt/i.test(res.html.replace(/Correo del apoderado|csrf_token/g, "")));
    for (const m of res.html.matchAll(/(?:href|action)="([^"]*)"/g)) {
      for (const s of subjects) assert.ok(!m[1]!.includes(s.subjectRef) && !m[1]!.includes(s.participationRef), "refs fuera de las URLs");
    }
    // Las refs viajan solo como campos ocultos del formulario POST de la fila 'Invitar' (con CSRF).
    assert.match(res.html, /<form method="post" action="\/staff\/students\/invite" class="lp-staff-row-form">/);
    assert.equal(res.html.split(subjects[0]!.subjectRef).length - 1, 1);
    // jamas hay etiquetas de apertura/verificacion ni el sentido
    for (const f of ["canjead", "abierta", "verificada", "aceptad", "rechazad"]) assert.ok(!res.html.toLowerCase().includes(f), f);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1108 lista: COMPLETED y DECLINED producen HTML byte-identico (salvo refs); tambien cambiando created_at", async () => {
  const out: string[] = [];
  for (const state of ["COMPLETED", "DECLINED"] as const) {
    const s = student(1);
    const h = await start({ students: [s] });
    try {
      await seedInvitation(h, s.subjectRef, state, state === "COMPLETED" ? null : -1000, `dec-${state}`);
      const res = await listGet(h);
      assert.equal(res.status, 200);
      out.push(res.html.replaceAll(s.subjectRef, "SUBJECT").replaceAll(s.participationRef, "PART"));
    } finally {
      await h.close();
    }
  }
  assert.equal(out[0], out[1]);
  assert.equal(Buffer.byteLength(out[0]!), Buffer.byteLength(out[1]!));
  assert.ok(out[0]!.includes("Decisión registrada"));
});

test("TEST-CNS-1109 formulario: POST invite con CSRF/Origin muestra el alumno del tenant; sin CSRF, con Origin ajeno o Sec-Fetch cross-site -> 403 sin efecto; refs ajenas o malformadas -> 404; nunca refs en la URL", async () => {
  const s = student(1);
  const h = await start();
  try {
    const cookie = session(h);
    const ok = await postForm(h, "/staff/students/invite", fields(s), { cookie });
    assert.equal(ok.status, 200);
    assert.equal(h1Of(ok.html), "Invitar al apoderado de Alumno de prueba 1");
    assert.match(ok.html, /<input id="guardian-email" name="guardian_email" type="email" autocomplete="off" required/);
    assert.ok(ok.html.includes('action="/staff/students/review"') && ok.html.includes(">Revisar invitación</button>"));
    assert.ok(!ok.html.includes('value="apoderado'), "sin valor preseleccionado");
    for (const m of ok.html.matchAll(/(?:href|action|formaction)="([^"]*)"/g)) assert.ok(!m[1]!.includes(s.subjectRef) && !m[1]!.includes(s.participationRef));
    const csrfBad = await postForm(h, "/staff/students/invite", { ...fields(s), csrf_token: "otro" }, { cookie });
    assert.equal(csrfBad.status, 403);
    assert.equal(h1Of(csrfBad.html), "No pudimos procesar el formulario");
    const noCsrf = await postForm(h, "/staff/students/invite", { subject: s.subjectRef, participation: s.participationRef }, { cookie });
    assert.equal(noCsrf.status, 403);
    const originBad = await postForm(h, "/staff/students/review", fields(s, { guardian_email: GOOD_EMAIL }), { cookie, origin: "http://evil.test" });
    assert.equal(originBad.status, 403);
    const noOrigin = await postForm(h, "/staff/students/review", fields(s, { guardian_email: GOOD_EMAIL }), { cookie, origin: null });
    assert.equal(noOrigin.status, 403);
    const cross = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie, site: "cross-site" });
    assert.equal(cross.status, 403);
    const sameSite = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie, site: "same-site" });
    assert.equal(sameSite.status, 403);
    // ningun intento rechazado creo nada
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal(await invitationCount(h), 0);
    // refs malformadas / alumno de otro tenant: 404 uniforme ("sesion vencida o alumno no disponible")
    const malformed = await postForm(h, "/staff/students/invite", { ...fields(s), subject: "no-es-ref" }, { cookie });
    assert.equal(malformed.status, 404);
    const otherTenant = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie: session(h, ADMIN_B, TENANT_B) });
    assert.equal(otherTenant.status, 404, "el tenant sale de la sesion: el alumno de A no existe para B");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1110 correo invalido: el error queda junto al campo con aria-invalid/describedby, sin reflejar el valor, sin crear nada; no hay opcion sin destinatario", async () => {
  const s = student(1);
  const h = await start();
  try {
    const cookie = session(h);
    for (const [path, extra] of [["/staff/students/review", {}], ["/staff/students/send", {}]] as const) {
      const reserved = await postForm(h, path, fields(s, { guardian_email: "apoderado1@gmail.com", ...extra }), { cookie });
      assert.equal(reserved.status, 422, path);
      assert.ok(reserved.html.includes("Error: este correo no es válido para la fase de prueba. Usa un correo que termine en @example.invalid."));
      assert.ok(!reserved.html.includes("gmail"), "no se refleja el valor ingresado");
      assert.match(reserved.html, /aria-describedby="guardian-email-help guardian-email-error" aria-invalid="true" autofocus/);
      assert.ok(reserved.html.includes('role="alert"') && reserved.html.includes("Hay 1 campo por corregir"));
      assert.equal(h1Of(reserved.html), "Invitar al apoderado de Alumno de prueba 1");
      for (const bad of ["apoderado1@", "sin-arroba", "", "  ", "a b@example.invalid", "x@@example.invalid"]) {
        const res = await postForm(h, path, fields(s, { guardian_email: bad }), { cookie });
        assert.equal(res.status, 422, `${path} ${JSON.stringify(bad)}`);
        assert.ok(res.html.includes("Error: escribe un correo con el formato nombre@dominio.") || res.html.includes("Error: este correo no es válido"));
        if (bad.trim().length > 0) assert.ok(!res.html.includes(`value="${bad}"`) && !res.html.includes(bad.replace(/ /g, "&")));
      }
    }
    assert.ok(!(await postForm(h, "/staff/students/review", fields(s), { cookie })).html.includes("Revisa la invitación antes de enviarla"), "sin correo no hay resumen (obligatorio, sin 'sin destinatario')");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal((await invitationCount(h)), 0, "no se creo ninguna invitacion");
    // la lista sigue mostrando 'Sin invitar' (ni siquiera quedo una matricula huerfana)
    const list = await listGet(h);
    assert.equal(list.html.split(">Invitar</button>").length - 1, 3);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1111 resumen: muestra alumno y correo, marcador legal, 'Enviar invitacion' y 'Volver a editar' de igual peso sin casilla; no llama a ningun endpoint; 'Volver a editar' conserva el correo", async () => {
  const s = student(2);
  const h = await start();
  try {
    const cookie = session(h);
    const review = await postForm(h, "/staff/students/review", fields(s, { guardian_email: ` ${GOOD_EMAIL} ` }), { cookie });
    assert.equal(review.status, 200);
    assert.equal(h1Of(review.html), "Revisa la invitación antes de enviarla");
    assert.ok(review.html.includes(`Correo del apoderado: ${GOOD_EMAIL}`) && review.html.includes("Alumno: Alumno de prueba 2"));
    assert.ok(review.html.includes("COPY LEGAL PENDIENTE — Carlos"));
    assert.ok(review.html.includes("El enlace no se muestra en esta pantalla."));
    assert.equal(review.html.split("lp-staff-btn-secondary\">Enviar invitación</button>").length - 1, 1);
    assert.equal(review.html.split("lp-staff-btn-secondary\">Volver a editar</button>").length - 1, 1);
    assert.ok(!review.html.includes("lp-btn-primary") && !/type="checkbox"/.test(review.html));
    for (const m of review.html.matchAll(/(?:href|action|formaction)="([^"]*)"/g)) assert.ok(!m[1]!.includes("@") && !m[1]!.includes(s.subjectRef));
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal((await invitationCount(h)), 0, "el resumen no crea nada");
    // Volver a editar: POST al formulario con los campos ocultos del resumen -> correo conservado
    const back = await postForm(h, "/staff/students/invite", fields(s, { guardian_email: GOOD_EMAIL }), { cookie });
    assert.equal(back.status, 200);
    assert.ok(back.html.includes(`value="${GOOD_EMAIL}"`));
    // el resumen no filtra el correo a la lista
    assert.ok(!(await listGet(h)).html.includes(GOOD_EMAIL));
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1112 envio feliz: EN0->I1->I2->I3, PRG (303 sin refs ni correo en la URL), confirmacion sin correo ni enlace, la fila pasa a Enviada sin accion; el enlace solo sale por el sink", async () => {
  const s = student(1);
  const h = await start();
  try {
    const cookie = session(h);
    const sent = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie });
    assert.equal(sent.status, 303);
    const location = sent.headers.get("location") ?? "";
    assert.equal(location, "/staff/students/sent");
    assert.equal(sent.html, "", "PRG: la respuesta del POST no lleva cuerpo");
    const flash = sent.headers.getSetCookie().find((c) => c.startsWith(`${FLASH_COOKIE}=`)) ?? "";
    assert.ok(flash.includes("HttpOnly") && flash.includes("Secure") && flash.includes("SameSite=Lax") && flash.includes("Max-Age=120"));
    const flashValue = flash.split(";")[0]!.slice(FLASH_COOKIE.length + 1);
    const flashBody = Buffer.from(flashValue.split(".")[0]!, "base64url").toString("utf8");
    assert.ok(!flashBody.includes(GOOD_EMAIL) && !flashBody.includes(s.subjectRef) && !flashBody.includes(s.participationRef), "la cookie flash solo lleva la etiqueta sintetica");
    // GET de confirmacion (con la cookie flash, como la enviaria el navegador)
    const conf = await getPage(h, location, { "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, `${cookie}; ${FLASH_COOKIE}=${flashValue}`);
    assert.equal(conf.status, 200);
    assert.equal(h1Of(conf.html), "Invitación enviada");
    assert.ok(conf.html.includes("Estado de Alumno de prueba 1: Enviada. El enlace no se muestra aquí por seguridad."));
    assert.ok(conf.html.includes('role="status" aria-live="polite"') && conf.html.includes("COPY LEGAL PENDIENTE — Carlos"));
    assert.ok(!conf.html.includes(GOOD_EMAIL) && !/\/i\/|http:\/\//i.test(conf.html.replace(/csrf_token/g, "")) && !/invitationPath|recipient/i.test(conf.html), "ni correo, ni enlace, ni token");
    assert.ok(conf.html.includes(">Volver a la lista</a>") && conf.html.includes(">Invitar a otro alumno</a>"));
    // el enlace entregado existe SOLO en el sink de desarrollo
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
    assert.ok(!sent.html.includes(h.staff.invitationLinkSink.sent[0]!.invitationPath) && !conf.html.includes(h.staff.invitationLinkSink.sent[0]!.invitationPath));
    // la lista: Enviada, sin accion para ese alumno
    const list = await listGet(h);
    const row = list.html.match(/<th scope="row">Alumno de prueba 1<\/th>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>/)!;
    assert.ok(row[1]!.includes("Enviada") && row[2]!.includes("Sin acciones"));
    assert.ok(!list.html.includes(GOOD_EMAIL));
    // una recarga/otra sesion sin flash vigente vuelve a la lista (nada que confirmar)
    const noFlash = await getPage(h, "/staff/students/sent", NAV, cookie);
    assert.equal(noFlash.status, 303);
    assert.equal(noFlash.headers.get("location"), "/staff/students");
    const otherSession = await getPage(h, "/staff/students/sent", NAV, `${session(h, ADMIN_B, TENANT_B)}; ${FLASH_COOKIE}=${flashValue}`);
    assert.equal(otherSession.status, 303, "la cookie flash no sirve con otra sesion");
    const forged = await getPage(h, "/staff/students/sent", NAV, `${cookie}; ${FLASH_COOKIE}=${flashValue.slice(0, -2)}xx`);
    assert.equal(forged.status, 303);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1113 idempotencia determinista: doble clic o recarga del envio no crea segunda matricula ni segunda invitacion ni segundo mensaje", async () => {
  const s = student(1);
  const h = await start();
  try {
    const cookie = session(h);
    const [a, b] = await Promise.all([
      postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie }),
      postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie }),
    ]);
    const c = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie });
    // Con concurrencia estricta puede que la segunda vea un conflicto; nunca hay dos efectos.
    for (const r of [a, b, c]) assert.ok([303, 409, 500].includes(r.status), `status ${r.status}`);
    assert.ok([a, b, c].some((r) => r.status === 303));
    assert.ok(c.status === 303, "el reenvio posterior reproduce la respuesta guardada");
    assert.equal((await invitationCount(h)), 1, "una sola invitacion");
    assert.equal(h.staff.invitationLinkSink.sent.length, 1, "un solo mensaje entregado");
    // misma cadena con OTRO correo (formulario viejo): conflicto de idempotencia presentado como "ya tiene una invitacion activa", sin efecto ni eco
    const other = await postForm(h, "/staff/students/send", fields(s, { guardian_email: "otro@example.invalid" }), { cookie });
    assert.equal(other.status, 409);
    assert.ok(other.html.includes("Este alumno ya tiene una invitación activa.") && !other.html.includes("otro@example.invalid"));
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1114 invitacion activa: un alumno con invitacion en curso ve el aviso 409 sin formulario; no hay efecto", async () => {
  const s = student(3);
  const h = await start();
  try {
    await seedInvitation(h, s.subjectRef, "SENT", 3_600_000, "active");
    const cookie = session(h);
    const res = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie });
    assert.equal(res.status, 409);
    assert.equal(h1Of(res.html), "Invitar al apoderado de Alumno de prueba 3");
    assert.ok(res.html.includes("Este alumno ya tiene una invitación activa.") && res.html.includes("Revisa su estado en la lista."));
    assert.ok(res.html.includes('role="alert"') && res.html.includes('>Volver a la lista</a>'));
    assert.ok(!res.html.includes("guardian_email") && !res.html.includes(GOOD_EMAIL));
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal((await invitationCount(h)), 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1115 fallo a mitad de la cadena (I2 sin politica de emision): se detiene sin compensar ni reintento, avisa que pudo quedar a medias y la lista muestra 'Envio incompleto' sin acciones", async () => {
  const s = student(1);
  const h = await start({ withPolicy: false });
  try {
    const cookie = session(h);
    const res = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie });
    assert.equal(res.status, 503);
    assert.equal(h1Of(res.html), "No pudimos completar el envío");
    assert.ok(res.html.includes("El servicio de invitaciones no está configurado."));
    assert.ok(res.html.includes("No la repitas por tu cuenta") && res.html.includes("no puede reinvitarse"));
    assert.ok(!/Reintentar|ERR-|GUARD_|REF-0000|@/.test(res.html.replace(/@example\.invalid/g, "")), "sin Reintentar, sin codigos internos, sin refs");
    assert.ok(!res.html.includes(GOOD_EMAIL));
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    const list = await listGet(h);
    const row = list.html.match(/<th scope="row">Alumno de prueba 1<\/th>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>/)!;
    assert.ok(row[1]!.includes("Envío incompleto") && row[2]!.includes("Sin acciones"));
    assert.ok(!list.html.includes("Reintentar"));
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1116 envio sin sesion o con rol sin permiso: 404 'sesion vencida o alumno no disponible' / 403 de permiso, sin efecto y sin distinguir causas en el 404", async () => {
  const s = student(1);
  const h = await start();
  try {
    const noSession = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie: `${CSRF_COOKIE}=${CSRF}` });
    assert.equal(noSession.status, 404);
    assert.equal(h1Of(noSession.html), "No pudimos abrir esta página");
    assert.ok(noSession.html.includes("Tu sesión venció o el alumno ya no está disponible."));
    const viewer = await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie: session(h, VIEWER, TENANT_A, "APPROVER") });
    assert.equal(viewer.status, 403);
    assert.equal(h1Of(viewer.html), "No tienes permiso para esta acción");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal((await invitationCount(h)), 0);
    // metodos no previstos siguen sin existir
    const get = await getPage(h, "/staff/students/send", NAV, session(h));
    assert.equal(get.status, 404);
    assert.deepEqual(JSON.parse(get.html), { status: 404 });
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1117 cerrar sesion: exige CSRF/Origin, borra las cookies y la siguiente lista responde 404 uniforme", async () => {
  const h = await start();
  try {
    const cookie = session(h);
    assert.equal((await postForm(h, "/staff/logout", { csrf_token: "otro" }, { cookie })).status, 403);
    assert.equal((await postForm(h, "/staff/logout", { csrf_token: CSRF }, { cookie, origin: "http://evil.test" })).status, 403);
    const out = await postForm(h, "/staff/logout", { csrf_token: CSRF }, { cookie });
    assert.equal(out.status, 303);
    assert.equal(out.headers.get("location"), "/staff");
    const cleared = out.headers.getSetCookie();
    assert.ok(cleared.length === 3 && cleared.every((c) => c.includes("Max-Age=0")));
    assert.ok(cleared.some((c) => c.startsWith(`${STAFF_COOKIE}=;`)) && cleared.some((c) => c.startsWith(`${CSRF_COOKIE}=;`)));
    assert.equal((await getPage(h, "/staff/students", NAV)).status, 404);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1118 cero PII en logs: durante todo el recorrido no se imprime subjectRef, participationRef, correo ni cursor", async () => {
  const subjects = Array.from({ length: 52 }, (_, i) => student(i + 1));
  const captured: string[] = [];
  const spy = (orig: (...a: unknown[]) => void) => (...a: unknown[]) => { captured.push(a.map(String).join(" ")); void orig; };
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  console.log = spy(orig.log); console.error = spy(orig.error); console.warn = spy(orig.warn); console.info = spy(orig.info); console.debug = spy(orig.debug);
  const h = await start({ students: subjects });
  try {
    const cookie = session(h);
    const list = await listGet(h);
    const cursor = decodeURIComponent(list.html.match(/href="\/staff\/students\?cursor=([^"]+)"/)![1]!.replace(/&amp;/g, "&"));
    await getPage(h, `/staff/students?cursor=${encodeURIComponent(cursor)}`, NAV, cookie);
    await postForm(h, "/staff/students/invite", fields(subjects[0]!), { cookie });
    await postForm(h, "/staff/students/review", fields(subjects[0]!, { guardian_email: "apoderado1@gmail.com" }), { cookie });
    await postForm(h, "/staff/students/review", fields(subjects[0]!, { guardian_email: GOOD_EMAIL }), { cookie });
    await postForm(h, "/staff/students/send", fields(subjects[0]!, { guardian_email: GOOD_EMAIL }), { cookie });
    await getPage(h, `/staff/students?cursor=forjado`, NAV, cookie);
    const all = captured.join("\n");
    assert.ok(!all.includes(GOOD_EMAIL) && !all.includes("gmail") && !all.includes(cursor) && !all.includes("c1."), "sin correo ni cursor");
    for (const s of subjects) assert.ok(!all.includes(s.subjectRef) && !all.includes(s.participationRef), "sin refs de alumno");
  } finally {
    Object.assign(console, orig);
    await h.close();
  }
});

test("TEST-CNS-1119 paginacion: con mas de 50 alumnos la lista ofrece 'Ver mas' con el cursor cifrado (sin refs), la segunda pagina completa el listado y un cursor invalido muestra el error", async () => {
  const subjects = Array.from({ length: 52 }, (_, i) => student(i + 1));
  const h = await start({ students: subjects });
  try {
    const first = await listGet(h);
    assert.equal(first.status, 200);
    assert.equal(first.html.split('<th scope="row">').length - 1, 50);
    const href = first.html.match(/href="(\/staff\/students\?cursor=[^"]+)"/)![1]!.replace(/&amp;/g, "&");
    for (const s of subjects) assert.ok(!href.includes(s.subjectRef), "el cursor no lleva refs en claro");
    const second = await getPage(h, href, NAV, session(h));
    assert.equal(second.status, 200);
    assert.equal(second.html.split('<th scope="row">').length - 1, 2);
    assert.ok(!second.html.includes("Ver más alumnos"));
    const bad = await getPage(h, "/staff/students?cursor=c1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NAV, session(h));
    assert.equal(bad.status, 422);
    assert.equal(h1Of(bad.html), "No pudimos mostrar esa página");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1120 lista vacia: estado propio sin tono de error; sin alumnos no hay tabla", async () => {
  const h = await start({ students: [] });
  try {
    const res = await listGet(h);
    assert.equal(res.status, 200);
    assert.equal(h1Of(res.html), "Alumnos del colegio");
    assert.ok(res.html.includes("Todavía no hay alumnos en este colegio") && !res.html.includes("<table"));
    assert.ok(!res.html.includes('role="alert"'));
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1121 CSP estricta y cabeceras de seguridad en TODA respuesta HTML de /staff (incluidas 303 y errores); sin JS, estilos inline ni recursos externos", async () => {
  const s = student(1);
  const h = await start();
  try {
    const cookie = session(h);
    const responses: Res[] = [
      await getPage(h, "/staff"),
      await listGet(h),
      await getPage(h, "/staff/students", {}, cookie), // 404
      await getPage(h, "/staff/students", NAV, session(h, VIEWER, TENANT_A, "APPROVER")), // 403
      await postForm(h, "/staff/students/invite", fields(s), { cookie }),
      await postForm(h, "/staff/students/review", fields(s, { guardian_email: GOOD_EMAIL }), { cookie }),
      await postForm(h, "/staff/students/review", fields(s, { guardian_email: "x@gmail.com" }), { cookie }),
      await postForm(h, "/staff/students/invite", { ...fields(s), csrf_token: "no" }, { cookie }),
      await postForm(h, "/staff/students/send", fields(s, { guardian_email: GOOD_EMAIL }), { cookie }), // 303
    ];
    for (const r of responses) {
      const csp = r.headers.get("content-security-policy") ?? "";
      for (const d of ["default-src 'self'", "script-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"]) assert.ok(csp.includes(d), `${r.status}: ${d}`);
      assert.ok(!/unsafe-inline|unsafe-eval|\*|https?:/.test(csp));
      assert.equal(r.headers.get("cache-control"), "no-store");
      assert.equal(r.headers.get("referrer-policy"), "no-referrer");
      assert.equal(r.headers.get("x-content-type-options"), "nosniff");
      assert.equal(r.headers.get("cross-origin-resource-policy"), "same-origin");
      assert.equal(r.headers.get("etag"), null);
      assert.match(r.headers.get("content-type") ?? "", /^text\/html; charset=utf-8/);
      assert.ok(!/<script|<style|\sstyle=|\son[a-z]+=|https?:\/\/(?!consola)/i.test(r.html));
    }
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1122 las rutas JSON existentes no chocan: GET /staff/roster sigue siendo JSON y los POST /staff/enrollments e /staff/invitations/... siguen respondiendo JSON", async () => {
  const h = await start();
  try {
    const cookie = session(h);
    const roster = await fetch(`${h.baseUrl}/staff/roster`, { headers: { cookie, "sec-fetch-site": "same-origin" } });
    assert.equal(roster.status, 200);
    assert.match(roster.headers.get("content-type") ?? "", /^application\/json/);
    const body = (await roster.json()) as { items: unknown[] };
    assert.equal(body.items.length, 3);
    const enr = await fetch(`${h.baseUrl}/staff/enrollments`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, cookie, "x-csrf-token": CSRF }, body: JSON.stringify({ subjectRef: student(1).subjectRef, participationRef: student(1).participationRef }) });
    assert.equal(enr.status, 201);
    assert.match(enr.headers.get("content-type") ?? "", /^application\/json/);
    const noSession = await fetch(`${h.baseUrl}/staff/invitations`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN } , body: "{}" });
    assert.equal(noSession.status, 403);
    assert.equal((await fetch(`${h.baseUrl}/staff/students/otra`, { headers: NAV })).status, 404);
  } finally {
    await h.close();
  }
});
