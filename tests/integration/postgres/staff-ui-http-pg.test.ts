// Gobierna: SEC-CNS-019 (requisito previo de seguridad de la UI del colegio), API-CNS-116 (GET /staff/roster), REQ-CNS-036 / UX-CNS-005
// (pantallas del colegio), DEC-BR-019 (Notion), SEC-CNS-018 rev. 2 (R3, R5), invitation.spec INV-IV-09. CONSENT_STORE=postgres:
// el servidor se arma igual que dev.ts con createPostgresFlowPorts (vista app.staff_roster_invitation_status tras SET LOCAL ROLE
// staff_roster_reader; ops.access_log como app_rw). TEST-CNS-1123 (GET /staff/roster JSON), 1124 (pagina HTML de la lista),
// 1125 (recorrido HTML completo: dev-login -> lista -> formulario -> resumen -> envio -> confirmacion -> lista Enviada).
// Requiere Postgres real (harness.ts). Solo datos sinteticos, cero PII.

import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Client } from "pg";

import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemorySubjectDirectory } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import { openPostgresStore } from "../../../src/infra/adapters/postgres/store.ts";
import { applyLocalFixtures, loadLocalFixtures } from "../../../src/infra/adapters/postgres/local-fixtures.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ADMIN_PRINCIPAL_REF,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_STAFF_STUDENTS,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { createConsentFlowHttpServer, createPostgresFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { deriveStaffSessionKey, encodeStaffSession } from "../../../src/server/entrypoints/http/staff-session.ts";
import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import { deriveDecisionMakerRefKey } from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, type PgTestContext } from "./harness.ts";

const ORIGIN = "http://consola-staff-ui-pg.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const CSRF_COOKIE = "__Host-cns-staff-csrf";
const FLASH_COOKIE = "__Host-cns-staff-flash";
const CSRF = "csrf-ui-pg-0123456789abcdef";
const NAV = { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } as const;
const GOOD_EMAIL = "apoderado1@example.invalid";

interface Boot {
  readonly baseUrl: string;
  readonly sessionSecret: Buffer;
  readonly failed: string[];
  close(): Promise<void>;
}

async function boot(ctx: PgTestContext, roster: readonly StaffPrincipal[], directory: Array<{ tenantId: string; subjectRef: string; label: string; participationRef: string | null }>, withDevFixture: boolean): Promise<Boot> {
  // SEC-CNS-017 F5: cualquier throw no capturado de una ruta deja `request_failed` en el log; close() exige que no haya ninguno.
  const failed: string[] = [];
  const realConsoleError = console.error;
  console.error = (...a: unknown[]) => {
    const line = a.join(" ");
    if (line.startsWith("request_failed")) failed.push(line);
    else realConsoleError(...a);
  };
  const store = await openPostgresStore({
    environment: "LOCAL",
    idempotencyPolicy: loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
    env: { CNS_DATABASE_URL: ctx.urlFor("app_rw") },
  });
  const staffIdentity = createInMemoryStaffIdentityAdapter(roster);
  const bundle = createPostgresFlowPorts(store, {
    otpPolicy: loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY),
    relationshipConfig: loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG),
    recoveryTokenPolicy: loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY),
    staffIdentity,
    chainRefKey: deriveChainRefKey(Buffer.alloc(32, 9)),
    decisionMakerRefKey: deriveDecisionMakerRefKey(Buffer.alloc(32, 8)),
    invitationIssuancePolicy: loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
    subjectDirectory: createInMemorySubjectDirectory("LOCAL", directory),
  });
  const sessionSecret = randomBytes(32);
  const server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports: bundle.ports,
    revocationPorts: bundle.revocationPorts,
    sessionSecret,
    environment: "LOCAL",
    staffIdentity,
    staffConsole: bundle.staffConsole,
    storeMode: "postgres",
    staffRosterCursorKey: deriveStaffRosterCursorKey(randomBytes(32)),
    staffUi: { contextRef: LECTORPRO_BETA_CONFIG.contextRef, consentVersion: "v1-dev" },
    ...(withDevFixture
      ? { devStaffConsole: { principalRef: LOCAL_ONLY_DEV_STAFF_ADMIN_PRINCIPAL_REF, students: LOCAL_ONLY_DEV_STAFF_STUDENTS, contextRef: LECTORPRO_BETA_CONFIG.contextRef, consentVersion: "v1-dev" } }
      : {}),
  });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  return {
    baseUrl,
    sessionSecret,
    failed,
    async close() {
      console.error = realConsoleError;
      await new Promise((resolve) => server.close(() => resolve(undefined)));
      await store.close();
      assert.deepEqual(failed, [], "ninguna ruta HTTP debe lanzar (OutsideTransactionError u otro) en Postgres");
    },
  };
}

interface Res { status: number; body: string; headers: Headers }
/** GET con node:http (fetch fija sec-fetch-mode=cors y pisaria los de una navegacion). */
function get(env: Boot, path: string, headers: Record<string, string>, cookie: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(`${env.baseUrl}${path}`, { method: "GET", headers: { ...headers, cookie } }, (res) => {
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
async function postForm(env: Boot, path: string, fields: Record<string, string>, cookie?: string): Promise<Res> {
  const res = await fetch(`${env.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(fields),
    redirect: "manual",
  });
  return { status: res.status, body: await res.text(), headers: res.headers };
}

const session = (env: Boot, principalRef: string, tenantId: string): string =>
  `${STAFF_COOKIE}=${encodeStaffSession(deriveStaffSessionKey(env.sessionSecret), { tenantId, principalRef, role: "TENANT_ADMIN" })}; ${CSRF_COOKIE}=${CSRF}`;

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/g;
/** Normaliza refs y el correlationId: lo unico que puede diferir entre COMPLETED y DECLINED. */
const normalize = (s: string): string => s.replace(UUID, "REF");
const stableHeaders = (h: Headers): Array<[string, string]> => [...h.entries()].filter(([k]) => !["date", "content-length", "connection", "keep-alive", "set-cookie"].includes(k)).sort();

async function accessLogCount(admin: Client, tenantId: string): Promise<number> {
  const r = await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM ops.access_log WHERE tenant_id = $1 AND action = 'STAFF_ROSTER_READ' AND resource_type = 'STAFF_ROSTER'", [tenantId]);
  return Number(r.rows[0]?.n);
}

/** Una escena minima: un alumno etiquetado con una invitacion en `state`, en un tenant propio. */
async function seedDecision(admin: Client, tenantId: string, tag: string, state: "COMPLETED" | "DECLINED"): Promise<{ subjectRef: string; participationRef: string }> {
  const subjectRef = fixtureUuid(`ui-pg-subj-${tag}`);
  const participationRef = fixtureUuid(`ui-pg-part-${tag}`);
  await admin.query("INSERT INTO app.subject (tenant_id, subject_ref) VALUES ($1, $2)", [tenantId, subjectRef]);
  await admin.query("INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, $2, 'CTX_PG', 'LECTORPRO', 'ACTIVE')", [tenantId, participationRef]);
  await admin.query(
    `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, expires_at, created_at)
     VALUES ($1, $2, 'CTX_PG', 'LECTORPRO', $3, $4, NULL, now() - interval '1 day')`,
    [tenantId, fixtureUuid(`ui-pg-inv-${tag}`), subjectRef, state],
  );
  return { subjectRef, participationRef };
}

async function twoDecisionTenants(ctx: PgTestContext, scope: string) {
  const admin = await ctx.connectAsSuperuser();
  const tenantC = fixtureUuid(`ui-pg-tenant-C-${scope}`);
  const tenantD = fixtureUuid(`ui-pg-tenant-D-${scope}`);
  const adminC = fixtureUuid(`ui-pg-admin-C-${scope}`);
  const adminD = fixtureUuid(`ui-pg-admin-D-${scope}`);
  const c = await seedDecision(admin, tenantC, `C-${scope}`, "COMPLETED");
  const d = await seedDecision(admin, tenantD, `D-${scope}`, "DECLINED");
  const roster: StaffPrincipal[] = [
    { principalRef: adminC, role: "TENANT_ADMIN", tenantId: tenantC },
    { principalRef: adminD, role: "TENANT_ADMIN", tenantId: tenantD },
  ];
  const directory = [
    { tenantId: tenantC, subjectRef: c.subjectRef, label: "Alumno de prueba 1", participationRef: c.participationRef },
    { tenantId: tenantD, subjectRef: d.subjectRef, label: "Alumno de prueba 1", participationRef: d.participationRef },
  ];
  return { admin, tenantC, tenantD, adminC, adminD, roster, directory };
}

pgTest("TEST-CNS-1123 pg http: GET /staff/roster -> 200, exactamente 1 fila en ops.access_log por request y una invitacion COMPLETED vs DECLINED producen respuestas identicas byte a byte (salvo refs)", async (ctx) => {
  const s = await twoDecisionTenants(ctx, "json");
  const env = await boot(ctx, s.roster, s.directory, false);
  try {
    const ask = (principal: string, tenant: string) => get(env, "/staff/roster", { "sec-fetch-site": "same-origin" }, session(env, principal, tenant));
    assert.equal(await accessLogCount(s.admin, s.tenantC), 0);
    const completed = await ask(s.adminC, s.tenantC);
    const declined = await ask(s.adminD, s.tenantD);
    assert.equal(completed.status, 200, completed.body);
    assert.equal(declined.status, 200, declined.body);
    assert.equal(await accessLogCount(s.admin, s.tenantC), 1, "exactamente una fila para el tenant de COMPLETED");
    assert.equal(await accessLogCount(s.admin, s.tenantD), 1, "exactamente una fila para el tenant de DECLINED");
    const json = JSON.parse(completed.body) as { items: Array<{ invitationStatus: string; participationRef: unknown }>; nextCursor: unknown };
    assert.equal(json.items.length, 1);
    assert.equal(json.items[0]!.invitationStatus, "DECISION_RECORDED");
    assert.equal(normalize(completed.body), normalize(declined.body));
    assert.equal(Buffer.byteLength(completed.body), Buffer.byteLength(declined.body));
    assert.deepEqual(stableHeaders(completed.headers), stableHeaders(declined.headers));
    // un segundo GET suma exactamente otra fila; un gating fallido no suma
    await ask(s.adminC, s.tenantC);
    assert.equal(await accessLogCount(s.admin, s.tenantC), 2);
    const noSite = await get(env, "/staff/roster", {}, session(env, s.adminC, s.tenantC));
    assert.equal(noSite.status, 404);
    assert.equal(await accessLogCount(s.admin, s.tenantC), 2);
  } finally {
    await env.close();
    await s.admin.end();
  }
});

pgTest("TEST-CNS-1124 pg http: GET /staff/students (HTML) -> 200, exactamente 1 fila en ops.access_log y COMPLETED vs DECLINED producen HTML identico byte a byte (salvo refs); mismo gating Sec-Fetch que el JSON (R5)", async (ctx) => {
  const s = await twoDecisionTenants(ctx, "html");
  const env = await boot(ctx, s.roster, s.directory, false);
  try {
    const ask = (principal: string, tenant: string, headers: Record<string, string> = NAV) => get(env, "/staff/students", headers, session(env, principal, tenant));
    const completed = await ask(s.adminC, s.tenantC);
    const declined = await ask(s.adminD, s.tenantD);
    assert.equal(completed.status, 200);
    assert.equal(declined.status, 200);
    assert.equal(await accessLogCount(s.admin, s.tenantC), 1);
    assert.equal(await accessLogCount(s.admin, s.tenantD), 1);
    assert.ok(completed.body.includes("Decisión registrada") && !completed.body.includes("Invitar</button>"));
    assert.equal(normalize(completed.body), normalize(declined.body));
    assert.equal(Buffer.byteLength(normalize(completed.body)), Buffer.byteLength(normalize(declined.body)));
    assert.deepEqual(stableHeaders(completed.headers), stableHeaders(declined.headers));
    assert.match(completed.headers.get("content-security-policy") ?? "", /script-src 'none'/);
    // R5: none solo con navigate+document; same-origin tambien; sin cabecera o cross-site no escribe fila
    assert.equal((await ask(s.adminC, s.tenantC, { "sec-fetch-site": "same-origin" })).status, 200);
    assert.equal(await accessLogCount(s.admin, s.tenantC), 2);
    for (const headers of [{} as Record<string, string>, { "sec-fetch-site": "none" }, { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, { "sec-fetch-site": "none", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }]) {
      assert.equal((await ask(s.adminC, s.tenantC, headers)).status, 404, JSON.stringify(headers));
    }
    assert.equal(await accessLogCount(s.admin, s.tenantC), 2, "un gating fallido no escribe access_log");
    // el HTML y el JSON de la misma peticion comparten proyeccion: mismo numero de filas y mismos estados
    const json = JSON.parse((await get(env, "/staff/roster", { "sec-fetch-site": "same-origin" }, session(env, s.adminC, s.tenantC))).body) as { items: unknown[] };
    assert.equal(json.items.length, completed.body.split('<th scope="row">').length - 1);
  } finally {
    await env.close();
    await s.admin.end();
  }
});

pgTest("TEST-CNS-1125 pg http: recorrido HTML completo (dev-login -> lista -> formulario -> resumen -> envio -> confirmacion -> lista Enviada) sobre Postgres; doble envio idempotente; la BD persiste una sola invitacion SENT", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, loadLocalFixtures(new URL("../../../db/fixtures/local", import.meta.url).pathname), { environment: "LOCAL" });
  const directory = LOCAL_ONLY_DEV_STAFF_STUDENTS.map((st) => ({ tenantId: LOCAL_ONLY_DEV_TENANT_ID, subjectRef: st.subjectRef, label: st.label, participationRef: st.participationRef }));
  const env = await boot(ctx, [...LOCAL_ONLY_DEV_STAFF_ROSTER], directory, true);
  const admin = await ctx.connectAsSuperuser();
  const captured: string[] = [];
  const realLog = console.log;
  console.log = (...a: unknown[]) => { captured.push(a.map(String).join(" ")); };
  try {
    const login = await postForm(env, "/staff/dev-login", {});
    assert.equal(login.status, 303);
    assert.equal(login.headers.get("location"), "/staff/students");
    const cookies = login.headers.getSetCookie().map((c) => c.split(";")[0]!);
    const csrf = cookies.find((c) => c.startsWith(`${CSRF_COOKIE}=`))!.slice(CSRF_COOKIE.length + 1);
    const jar = cookies.join("; ");

    const list1 = await get(env, "/staff/students", NAV, jar);
    assert.equal(list1.status, 200);
    assert.equal(list1.body.split(">Invitar</button>").length - 1, LOCAL_ONLY_DEV_STAFF_STUDENTS.length, "6 alumnos sin invitar");
    const student = LOCAL_ONLY_DEV_STAFF_STUDENTS[0]!;
    const fields = { csrf_token: csrf, subject: student.subjectRef, participation: student.participationRef };

    const form = await postForm(env, "/staff/students/invite", fields, jar);
    assert.equal(form.status, 200);
    assert.ok(form.body.includes("Invitar al apoderado de Alumno de prueba 1"));
    const bad = await postForm(env, "/staff/students/review", { ...fields, guardian_email: "apoderado1@gmail.com" }, jar);
    assert.equal(bad.status, 422);
    assert.ok(!bad.body.includes("gmail"));
    const review = await postForm(env, "/staff/students/review", { ...fields, guardian_email: GOOD_EMAIL }, jar);
    assert.equal(review.status, 200);
    assert.ok(review.body.includes(`Correo del apoderado: ${GOOD_EMAIL}`) && review.body.includes("COPY LEGAL PENDIENTE — Carlos"));
    const countInvitations = async (): Promise<number> => Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM app.invitation WHERE tenant_id = $1", [LOCAL_ONLY_DEV_TENANT_ID])).rows[0]?.n);
    assert.equal(await countInvitations(), 0, "el resumen no crea nada");

    const sentFields = { ...fields, guardian_email: GOOD_EMAIL };
    const sent = await postForm(env, "/staff/students/send", sentFields, jar);
    assert.equal(sent.status, 303, sent.body);
    assert.equal(sent.headers.get("location"), "/staff/students/sent");
    const flash = sent.headers.getSetCookie().find((c) => c.startsWith(`${FLASH_COOKIE}=`))!.split(";")[0]!;
    const conf = await get(env, "/staff/students/sent", { "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, `${jar}; ${flash}`);
    assert.equal(conf.status, 200);
    assert.ok(conf.body.includes("Estado de Alumno de prueba 1: Enviada.") && !conf.body.includes(GOOD_EMAIL));
    // doble envio / recarga: idempotente, una sola invitacion y un solo mensaje entregado
    const again = await postForm(env, "/staff/students/send", sentFields, jar);
    assert.equal(again.status, 303);
    assert.equal(await countInvitations(), 1);
    const row = (await admin.query<{ state: string }>("SELECT state FROM app.invitation WHERE tenant_id = $1", [LOCAL_ONLY_DEV_TENANT_ID])).rows;
    assert.deepEqual(row.map((r) => r.state), ["SENT"]);

    const list2 = await get(env, "/staff/students", NAV, jar);
    assert.equal(list2.status, 200);
    const first = list2.body.match(/<th scope="row">Alumno de prueba 1<\/th>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>/)!;
    assert.ok(first[1]!.includes("Enviada") && first[2]!.includes("Sin acciones"));
    assert.equal(list2.body.split(">Invitar</button>").length - 1, LOCAL_ONLY_DEV_STAFF_STUDENTS.length - 1);
    assert.ok(!list2.body.includes(GOOD_EMAIL));
    // reenviar el formulario de un alumno ya invitado (otro correo): 409 uniforme, sin efecto
    const dup = await postForm(env, "/staff/students/send", { ...fields, guardian_email: "otro@example.invalid" }, jar);
    assert.equal(dup.status, 409);
    assert.ok(dup.body.includes("Este alumno ya tiene una invitación activa.") && !dup.body.includes("otro@example.invalid"));
    assert.equal(await countInvitations(), 1);
    // el access_log del tenant: una fila por GET de la lista (2), ninguna por los POST
    assert.equal(await accessLogCount(admin, LOCAL_ONLY_DEV_TENANT_ID), 2);
    // cero PII en logs
    const all = captured.join("\n");
    assert.ok(!all.includes(GOOD_EMAIL) && !all.includes("gmail"));
    for (const st of LOCAL_ONLY_DEV_STAFF_STUDENTS) assert.ok(!all.includes(st.subjectRef) && !all.includes(st.participationRef));
  } finally {
    console.log = realLog;
    await env.close();
    await admin.end();
  }
});
