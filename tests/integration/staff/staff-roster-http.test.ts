// Gobierna: contracts/openapi API-CNS-116 (GET /staff/roster), api-payloads.schema.json StaffRosterPage, REQ-CNS-036 AC-04..AC-09,
// DEC-BR-019, SEC-CNS-018 rev. 2 (R3, R4, R5, R6), common.spec GRD-CM-01/02/07, ERR-CM-13. CONSENT_STORE=memory.
// TEST-CNS-1080 (200, forma, cabeceras, sin canal/email, DECLINED=COMPLETED), 1081 (gating y access_log), 1082 (cursor), 1083 (query),
// 1084 (503 si falla access_log; el GET no escribe estado), 1089 (directorio y participationRef), 1090 (aislamiento cross-tenant).
// Solo datos sinteticos, cero PII.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createInMemoryAccessLogAdapter } from "../../../src/infra/adapters/in-memory-access-log.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemoryStaffRosterReader } from "../../../src/infra/adapters/in-memory-staff-roster.adapter.ts";
import { createInMemorySubjectDirectory } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import type { InvitationListing } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import {
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
import type { StaffConsolePorts } from "../../../src/server/entrypoints/http/staff-console.handler.ts";
import { handleListStaffRoster } from "../../../src/server/entrypoints/http/staff-roster.handler.ts";
import { deriveStaffSessionKey } from "../../../src/server/entrypoints/http/staff-session.ts";
import { mintStaffSession } from "./staff-session-helper.ts";
import { loadRightsCaseHttpConfig } from "../../../src/server/entrypoints/http/config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import type { InvitationState } from "../../../src/server/ports/invitation-repository.port.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { validateApiPayload } from "../../contract/schema-lite.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-staff.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const TENANT_A = LOCAL_ONLY_DEV_TENANT_ID;
const TENANT_B = LOCAL_ONLY_DEV_OTHER_TENANT_ID;
const ADMIN_A = fixtureUuid("roster-admin-a");
const ADMIN_A2 = fixtureUuid("roster-admin-a2");
const ADMIN_B = fixtureUuid("roster-admin-b");
const VIEWER = fixtureUuid("roster-viewer");
const ROSTER: readonly StaffPrincipal[] = [
  { principalRef: ADMIN_A, role: "TENANT_ADMIN", tenantId: TENANT_A },
  { principalRef: ADMIN_A2, role: "TENANT_ADMIN", tenantId: TENANT_A },
  { principalRef: ADMIN_B, role: "TENANT_ADMIN", tenantId: TENANT_B },
  { principalRef: VIEWER, role: "APPROVER", tenantId: TENANT_A },
];
const CONTEXT = "BETA_2026_01";
const SHARED = fixtureUuid("roster-shared-subject");

interface Harness {
  baseUrl: string;
  staff: ReturnType<typeof createDefaultStaffConsolePorts>;
  console: StaffConsolePorts;
  sessionSecret: Buffer;
  cursorKey: Buffer;
  close(): Promise<void>;
}

async function start(opts: { subjects?: Array<{ tenantId: string; subjectRef: string; label?: string; participationRef?: string | null }>; failingAccessLog?: boolean } = {}): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const staffIdentity = createInMemoryStaffIdentityAdapter(ROSTER);
  const staff = createDefaultStaffConsolePorts(ports.invitation, staffIdentity, loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY));
  const subjects = opts.subjects ?? [];
  for (const s of subjects) staff.catalog.seedSubject(s.tenantId, s.subjectRef);
  for (const tenantId of new Set(subjects.map((s) => s.tenantId))) {
    staff.catalog.seedParticipation(tenantId, { participationRef: fixtureUuid(`roster-part-${tenantId}`), contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  }
  const directory = createInMemorySubjectDirectory(
    "LOCAL",
    subjects.filter((s) => s.label !== undefined).map((s) => ({ tenantId: s.tenantId, subjectRef: s.subjectRef, label: s.label as string, participationRef: s.participationRef ?? null })),
  );
  let roster = staff.roster;
  if (opts.failingAccessLog) {
    const real = createInMemoryAccessLogAdapter();
    const { uow } = createInMemoryTenancy({
      ledger: ports.invitation.ledger,
      invitationRepo: ports.invitation.invitationRepo,
      enrollmentRepo: staff.issuance.enrollmentRepo,
      tenantCatalog: staff.catalog,
      accessLog: { ...real, record: async () => { throw new Error("log caido"); } },
    });
    roster = createInMemoryStaffRosterReader({
      uow,
      invitations: ports.invitation.invitationRepo as unknown as InvitationListing,
      enrollments: staff.issuance.enrollmentRepo as never,
      catalog: staff.catalog,
    });
  }
  const consolePorts: StaffConsolePorts = { ...staff, ...(roster ? { roster } : {}), subjectDirectory: directory };
  const sessionSecret = randomBytes(32);
  const cursorKey = deriveStaffRosterCursorKey(randomBytes(32));
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    sessionSecret,
    environment: "LOCAL",
    staffIdentity,
    staffConsole: consolePorts,
    staffRosterCursorKey: cursorKey,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({ baseUrl: `http://127.0.0.1:${address.port}`, staff, console: consolePorts, sessionSecret, cursorKey, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function sessionFor(h: Harness, principalRef: string, tenantId: string, role: StaffPrincipal["role"] = "TENANT_ADMIN"): string {
  return mintStaffSession(h.console.sessions, deriveStaffSessionKey(h.sessionSecret), { tenantId, principalRef, role }).cookieValue;
}

interface GetOptions { session?: string | undefined; site?: string | undefined | null; origin?: string | undefined }
async function get(h: Harness, query: string, opts: GetOptions = {}): Promise<{ status: number; raw: string; json: Record<string, unknown>; headers: Headers }> {
  const headers: Record<string, string> = {};
  if (opts.site !== null) headers["sec-fetch-site"] = opts.site ?? "same-origin";
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.session !== undefined) headers.cookie = `${STAFF_COOKIE}=${opts.session}`;
  const res = await fetch(`${h.baseUrl}/staff/roster${query}`, { headers });
  const raw = await res.text();
  return { status: res.status, raw, json: raw ? (JSON.parse(raw) as Record<string, unknown>) : {}, headers: res.headers };
}

const strip = (raw: string): string => raw.replace(/"correlationId":"[^"]*"/, '"correlationId":"X"');
const logCount = async (h: Harness, tenantId: string): Promise<number> =>
  (await h.staff.accessLog.listByTenant(tenantId)).filter((r) => r.action === "STAFF_ROSTER_READ").length;

async function seedInvitation(h: Harness, tenantId: string, subjectRef: string, state: InvitationState, expiresInMs: number | null, n: string): Promise<void> {
  await h.console.issuance.invitation.invitationRepo.save({
    invitationRef: fixtureUuid(`roster-inv-${n}`),
    tenantId,
    contextRef: CONTEXT,
    productRef: "LECTORPRO",
    subjectRef,
    state,
    ...(expiresInMs !== null ? { expiresAt: new Date(Date.now() + expiresInMs) } : {}),
  });
}

test("TEST-CNS-1080 200: valida StaffRosterPage, mapeo de estados, cabeceras, sin ETag, sin email/canal ni campos prohibidos", async () => {
  const subj = Array.from({ length: 5 }, (_, i) => fixtureUuid(`roster-1080-${i}`));
  const h = await start({ subjects: subj.map((subjectRef, i) => ({ tenantId: TENANT_A, subjectRef, label: `Alumno de prueba ${i + 1}` })) });
  try {
    await seedInvitation(h, TENANT_A, subj[1]!, "DRAFT", null, "1");
    await seedInvitation(h, TENANT_A, subj[2]!, "VERIFIED", 3_600_000, "2");
    await seedInvitation(h, TENANT_A, subj[3]!, "COMPLETED", null, "3");
    await seedInvitation(h, TENANT_A, subj[4]!, "SENT", -3_600_000, "4");
    const res = await get(h, "", { session: sessionFor(h, ADMIN_A, TENANT_A) });
    assert.equal(res.status, 200, res.raw);
    assert.ok(validateApiPayload("StaffRosterPage", res.json).ok, JSON.stringify(validateApiPayload("StaffRosterPage", res.json)));
    const items = res.json.items as Array<Record<string, unknown>>;
    const status = new Map(items.map((i) => [i.subjectRef, i.invitationStatus]));
    assert.deepEqual([...status.entries()].sort().map(([, v]) => v).sort(), ["CLOSED_WITHOUT_DECISION", "DECISION_RECORDED", "NOT_INVITED", "PENDING_SEND", "SENT"]);
    assert.equal(res.json.nextCursor, null);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("cross-origin-resource-policy"), "same-origin");
    assert.equal(res.headers.get("content-security-policy"), "frame-ancestors 'none'");
    assert.equal(res.headers.get("etag"), null);
    assert.equal(res.headers.get("last-modified"), null);
    assert.equal(res.headers.get("access-control-allow-origin"), null);
    assert.match(res.headers.get("content-type") ?? "", /^application\/json/);
    for (const forbidden of ["@", "invitationRef", "recipient", "tokenHash", "expiresAt", "sentOn", "state\"", "enrollmentRef", "consentVersion", "reasonCode", "tenant"]) {
      assert.ok(!res.raw.includes(forbidden), `la respuesta no debe contener ${forbidden}`);
    }
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1080 DECLINED y COMPLETED son indistinguibles en cuerpo, cabeceras y tamano", async () => {
  const out: Array<{ raw: string; headers: Array<[string, string]> }> = [];
  for (const state of ["COMPLETED", "DECLINED"] as const) {
    const subjectRef = fixtureUuid("roster-1080-same");
    const h = await start({ subjects: [{ tenantId: TENANT_A, subjectRef, label: "Alumno de prueba 1" }] });
    try {
      await seedInvitation(h, TENANT_A, subjectRef, state, null, `dec-${state}`);
      const res = await get(h, "", { session: sessionFor(h, ADMIN_A, TENANT_A) });
      assert.equal(res.status, 200);
      out.push({ raw: res.raw, headers: [...res.headers.entries()].filter(([k]) => !["date", "content-length", "connection", "keep-alive"].includes(k)).sort() });
    } finally {
      await h.close();
    }
  }
  assert.equal(out[0]!.raw, out[1]!.raw);
  assert.equal(Buffer.byteLength(out[0]!.raw), Buffer.byteLength(out[1]!.raw));
  assert.deepEqual(out[0]!.headers, out[1]!.headers);
});

test("TEST-CNS-1081 gating: Sec-Fetch-Site/Origin/sesion/rol; un gating fallido no escribe access_log; un GET valido escribe exactamente una fila", async () => {
  const subjectRef = fixtureUuid("roster-1081");
  const h = await start({ subjects: [{ tenantId: TENANT_A, subjectRef, label: "Alumno de prueba 1" }] });
  try {
    const ok = sessionFor(h, ADMIN_A, TENANT_A);
    const cases: Array<[string, GetOptions, number]> = [
      ["sin Sec-Fetch-Site", { session: ok, site: null }, 404],
      ["cross-site", { session: ok, site: "cross-site" }, 404],
      ["same-site", { session: ok, site: "same-site" }, 404],
      ["none", { session: ok, site: "none" }, 404],
      ["Origin ajeno", { session: ok, origin: "http://otro.test" }, 404],
      ["sin sesion", {}, 404],
      ["sesion basura", { session: "basura.firma" }, 404],
      ["sesion de principal fuera del roster", { session: sessionFor(h, fixtureUuid("fantasma"), TENANT_A) }, 404],
      ["sesion con tenant distinto al del roster", { session: sessionFor(h, ADMIN_A, TENANT_B) }, 404],
      ["rol distinto de TENANT_ADMIN", { session: sessionFor(h, VIEWER, TENANT_A, "APPROVER") }, 403],
    ];
    for (const [label, opts, status] of cases) {
      const res = await get(h, "", opts);
      assert.equal(res.status, status, label);
      assert.equal(res.headers.get("cache-control"), "no-store", `${label}: no-store tambien en errores`);
    }
    assert.equal(await logCount(h, TENANT_A), 0, "ningun gating fallido escribe access_log");
    assert.equal((await get(h, "?limit=0", { session: ok })).status, 422);
    assert.equal(await logCount(h, TENANT_A), 0, "query invalida tampoco escribe");
    assert.equal((await get(h, "", { session: ok, origin: ORIGIN })).status, 200);
    assert.equal(await logCount(h, TENANT_A), 1);
    assert.equal((await get(h, "?limit=1", { session: ok })).status, 200);
    assert.equal(await logCount(h, TENANT_A), 2);
    const row = (await h.staff.accessLog.listByTenant(TENANT_A))[0]!;
    assert.deepEqual([row.actorRef, row.actorRole, row.action, row.resourceType, row.resourceRef], [ADMIN_A, "TENANT_ADMIN", "STAFF_ROSTER_READ", "STAFF_ROSTER", TENANT_A]);
    // Los 404 de sesion son byte-identicos entre si (sin oraculo).
    const a = await get(h, "", {});
    const b = await get(h, "", { session: "basura.firma" });
    assert.equal(a.raw, b.raw);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1082 cursor: pagina sin duplicar; manipulado, de otro principal, de otro tenant, version desconocida -> 422 uniforme; expirado -> 422", async () => {
  const subj = Array.from({ length: 7 }, (_, i) => fixtureUuid(`roster-1082-${i}`));
  const h = await start({ subjects: subj.map((subjectRef) => ({ tenantId: TENANT_A, subjectRef })) });
  try {
    await h.staff.catalog.seedSubject(TENANT_B, fixtureUuid("roster-1082-b"));
    const session = sessionFor(h, ADMIN_A, TENANT_A);
    const seen: string[] = [];
    let cursor: string | null = null;
    let first: string | null = null;
    for (let i = 0; i < 10; i += 1) {
      const res = await get(h, `?limit=3${cursor ? `&cursor=${cursor}` : ""}`, { session });
      assert.equal(res.status, 200, res.raw);
      assert.ok(validateApiPayload("StaffRosterPage", res.json).ok);
      for (const item of res.json.items as Array<{ subjectRef: string }>) seen.push(item.subjectRef);
      cursor = res.json.nextCursor as string | null;
      first ??= cursor;
      if (cursor === null) break;
    }
    assert.deepEqual(seen, [...subj].sort(), "orden C, sin duplicar ni saltar");
    assert.ok(first);
    const bodies = new Set<string>();
    const expect422 = async (label: string, query: string, who = session): Promise<void> => {
      const res = await get(h, query, { session: who });
      assert.equal(res.status, 422, label);
      assert.equal((res.json as { code?: string }).code, "LIST_QUERY_INVALID");
      bodies.add(strip(res.raw));
    };
    await expect422("alterado", `?cursor=${first.slice(0, -2)}${first.endsWith("AA") ? "BB" : "AA"}`);
    await expect422("otro principal (mismo tenant)", `?cursor=${first}`, sessionFor(h, ADMIN_A2, TENANT_A));
    await expect422("otro tenant", `?cursor=${first}`, sessionFor(h, ADMIN_B, TENANT_B));
    await expect422("version desconocida", `?cursor=c2.${first.slice(3)}`);
    await expect422("sin prefijo", `?cursor=${first.slice(3)}`);
    assert.equal(bodies.size, 1, "mismo cuerpo en todos los casos");
    assert.ok(!bodies.values().next().value!.includes(first), "sin eco del cursor");
    // Expirado: el handler recibe un reloj 16 min adelante.
    const key = deriveStaffSessionKey(h.sessionSecret);
    const late = await handleListStaffRoster(
      { cookieHeader: `${STAFF_COOKIE}=${sessionFor(h, ADMIN_A, TENANT_A)}`, originHeader: undefined, secFetchSiteHeader: "same-origin", rawQuery: `cursor=${first}` },
      h.console,
      loadRightsCaseHttpConfig({ allowedOrigin: ORIGIN }),
      key,
      h.cursorKey,
      () => Date.now() + 16 * 60_000,
    );
    assert.equal(late.status, 422);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1083 query: limit 1 y 100 validos; 0, 101, no numerico, repetido, parametro desconocido o cursor vacio -> 422 identico", async () => {
  const h = await start({ subjects: [{ tenantId: TENANT_A, subjectRef: fixtureUuid("roster-1083") }] });
  try {
    const session = sessionFor(h, ADMIN_A, TENANT_A);
    for (const q of ["?limit=1", "?limit=100"]) assert.equal((await get(h, q, { session })).status, 200, q);
    const bodies = new Set<string>();
    for (const q of ["?limit=0", "?limit=101", "?limit=abc", "?limit=-1", "?limit=1&limit=2", "?foo=bar", "?tenantId=x", "?organizationId=x", "?cursor=", "?limit="]) {
      const res = await get(h, q, { session });
      assert.equal(res.status, 422, q);
      bodies.add(strip(res.raw));
    }
    assert.equal(bodies.size, 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1084 http: si el access_log falla -> 503 sin datos; el GET no crea invitaciones ni enrollments (T-05)", async () => {
  const subjectRef = fixtureUuid("roster-1084");
  const h = await start({ subjects: [{ tenantId: TENANT_A, subjectRef, label: "Alumno de prueba 1" }], failingAccessLog: true });
  try {
    const res = await get(h, "", { session: sessionFor(h, ADMIN_A, TENANT_A) });
    assert.equal(res.status, 503);
    assert.equal((res.json as { code?: string }).code, "GUARD_EVALUATOR_UNAVAILABLE");
    assert.ok(!res.raw.includes(subjectRef));
    assert.match(res.headers.get("content-type") ?? "", /problem\+json/);
    assert.deepEqual((h.console.issuance.invitation.invitationRepo as unknown as InvitationListing).listByTenant(TENANT_A), []);
    // Sin lector configurado: tambien 503 (fail-closed).
    const { roster: _omit, ...withoutRoster } = h.console;
    void _omit;
    const server = createConsentFlowHttpServer({ staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ORIGIN }, ports: createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET), sessionSecret: h.sessionSecret, environment: "LOCAL", staffIdentity: createInMemoryStaffIdentityAdapter(ROSTER), staffConsole: withoutRoster });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/staff/roster`;
      const r2 = await fetch(url, { headers: { "sec-fetch-site": "same-origin", cookie: `${STAFF_COOKIE}=${sessionFor(h, ADMIN_A, TENANT_A)}` } });
      assert.equal(r2.status, 503);
    } finally {
      await new Promise((r) => server.close(() => r(undefined)));
    }
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1089 etiqueta solo con el patron (si no null); participationRef solo en NOT_INVITED: matricula activa > directorio > null", async () => {
  const [s1, s2, s3, s4] = ["a", "b", "c", "d"].map((x) => fixtureUuid(`roster-1089-${x}`)) as [string, string, string, string];
  const dirPart = fixtureUuid("roster-1089-dir");
  const enrPart = fixtureUuid("roster-1089-enr");
  const h = await start({
    subjects: [
      { tenantId: TENANT_A, subjectRef: s1, label: "Alumno de prueba 1", participationRef: dirPart },
      { tenantId: TENANT_A, subjectRef: s2, label: "Juan Perez Gonzalez", participationRef: dirPart },
      { tenantId: TENANT_A, subjectRef: s3, label: "Alumno de prueba 3", participationRef: dirPart },
      { tenantId: TENANT_A, subjectRef: s4 },
    ],
  });
  try {
    await seedInvitation(h, TENANT_A, s3, "SENT", 3_600_000, "1089");
    const part = h.staff.catalog.listParticipations(TENANT_A)[0]!;
    await h.staff.issuance.enrollmentRepo.save({ enrollmentRef: fixtureUuid("roster-1089-e"), tenantId: TENANT_A, subjectRef: s4, participationRef: part.participationRef, state: "ACTIVE" });
    void enrPart;
    const res = await get(h, "", { session: sessionFor(h, ADMIN_A, TENANT_A) });
    const by = new Map((res.json.items as Array<Record<string, unknown>>).map((i) => [i.subjectRef, i]));
    assert.deepEqual(by.get(s1), { subjectRef: s1, participationRef: dirPart, subjectLabel: "Alumno de prueba 1", invitationStatus: "NOT_INVITED" });
    assert.equal(by.get(s2)?.subjectLabel, null, "etiqueta fuera del patron -> null");
    assert.ok(!res.raw.includes("Juan"));
    assert.deepEqual(by.get(s3), { subjectRef: s3, participationRef: null, subjectLabel: "Alumno de prueba 3", invitationStatus: "SENT" });
    assert.deepEqual(by.get(s4), { subjectRef: s4, participationRef: part.participationRef, subjectLabel: null, invitationStatus: "NOT_INVITED" }, "la matricula activa gana y sin directorio la etiqueta es null");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1090 aislamiento cross-tenant: un subject_ref compartido no cruza estado, etiqueta ni participacion; la sesion del otro tenant no ve nada ajeno", async () => {
  const onlyB = fixtureUuid("roster-1090-b");
  const h = await start({
    subjects: [
      { tenantId: TENANT_A, subjectRef: SHARED, label: "Alumno de prueba 1" },
      { tenantId: TENANT_B, subjectRef: SHARED },
      { tenantId: TENANT_B, subjectRef: onlyB },
    ],
  });
  try {
    await seedInvitation(h, TENANT_A, SHARED, "COMPLETED", null, "1090");
    const a = await get(h, "", { session: sessionFor(h, ADMIN_A, TENANT_A) });
    const b = await get(h, "", { session: sessionFor(h, ADMIN_B, TENANT_B) });
    assert.deepEqual((a.json.items as Array<Record<string, unknown>>).map((i) => [i.subjectRef, i.invitationStatus, i.subjectLabel]), [[SHARED, "DECISION_RECORDED", "Alumno de prueba 1"]]);
    assert.deepEqual(
      (b.json.items as Array<Record<string, unknown>>).map((i) => [i.subjectRef, i.invitationStatus, i.subjectLabel]).sort(),
      [[SHARED, "NOT_INVITED", null], [onlyB, "NOT_INVITED", null]].sort(),
    );
    assert.equal(await logCount(h, TENANT_A), 1);
    assert.equal(await logCount(h, TENANT_B), 1);
  } finally {
    await h.close();
  }
});
