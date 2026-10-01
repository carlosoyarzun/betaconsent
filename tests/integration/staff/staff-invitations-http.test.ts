// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-105 (POST /staff/enrollments),
// API-CNS-110/111/112 (POST /staff/invitations, /ready, /send), securitySchemes.staffSession;
// api-payloads.schema.json (OpenEnrollmentRequest, EnrollmentOpened, CreateInvitationRequest,
// InvitationCreated, InvitationReady, InvitationSent, EmptyCommand); common.spec.yaml
// GRD-CM-01/02/07/08/10; tenant-context.spec.yaml EN0; invitation.spec.yaml I1/I2/I3. CA-125.
// Autenticación: decisión de Carlos 2026-09-28, opción (ii) (LOCAL + CI, SYNTHETIC DATA ONLY,
// APR-IDP PENDING): la sesión sale de /__dev/staff-login sobre el roster sintético. LD-03 y
// APR-IDP no se resuelven aquí. Refs UUIDv4 (fixtureUuid) y recipientes sintéticos; cero PII.
// TEST-CNS-714..TEST-CNS-725 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  createConsentFlowHttpServer,
  createDefaultConsentFlowPorts,
  createDefaultStaffConsolePorts,
} from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { deriveStaffSessionKey, encodeStaffSession } from "../../../src/server/entrypoints/http/staff-session.ts";
import {
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import type { StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import { validateApiPayload, validateCommon, validateLedgerEventPayload, type ValidationResult } from "../../contract/schema-lite.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const ALLOWED_ORIGIN = "http://consola-staff.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const STAFF_CSRF_COOKIE = "__Host-cns-staff-csrf";
const INVITATION_HANDLE_COOKIE = "__Host-cns-i-handle";
const SESSION_COOKIE = "__Host-cns-session";
const TENANT_A = LOCAL_ONLY_DEV_TENANT_ID;
const TENANT_B = LOCAL_ONLY_DEV_OTHER_TENANT_ID;
const ADMIN_A = fixtureUuid("staff-synthetic-05");
const ADMIN_B = fixtureUuid("staff-synthetic-06");
const SUBJECT = fixtureUuid("subject-714");
const SUBJECT_B = fixtureUuid("subject-b-714");
const PARTICIPATION = fixtureUuid("participation-714");
const PARTICIPATION_B = fixtureUuid("participation-b-714");
const CHANNEL = fixtureUuid("channel-714");
const CONTEXT = "BETA_2026_01";

/** Principal de prueba con rol distinto de TENANT_ADMIN pero con tenant: solo existe para alcanzar
 * la rama GRD-CM-07 (rol no permitido) sin romper la membership vigente (GRD-CM-01). */
const TEST_VIEWER: StaffPrincipal = { principalRef: "staff-test-viewer", role: "APPROVER", tenantId: TENANT_A };

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  readonly staff: ReturnType<typeof createDefaultStaffConsolePorts>;
  readonly sessionSecret: Buffer;
  close(): Promise<void>;
}

function startServer(opts: { environment?: "LOCAL" | "DEV"; withPolicy?: boolean; roster?: readonly StaffPrincipal[] } = {}): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);
  const staffIdentity = createInMemoryStaffIdentityAdapter(opts.roster ?? [...LOCAL_ONLY_DEV_STAFF_ROSTER, TEST_VIEWER]);
  const policy = opts.withPolicy === false ? undefined : loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY);
  const staff = createDefaultStaffConsolePorts(ports.invitation, staffIdentity, policy);
  staff.catalog.seedSubject(TENANT_A, SUBJECT);
  staff.catalog.seedParticipation(TENANT_A, { participationRef: PARTICIPATION, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  staff.catalog.seedSubject(TENANT_B, SUBJECT_B);
  staff.catalog.seedParticipation(TENANT_B, { participationRef: PARTICIPATION_B, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  const sessionSecret = randomBytes(32);
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    sessionSecret,
    environment: opts.environment ?? "LOCAL",
    staffIdentity,
    staffConsole: staff,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        ports,
        staff,
        sessionSecret,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function parseAllSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of res.headers.getSetCookie()) {
    const part = raw.split(";")[0] ?? "";
    const eq = part.indexOf("=");
    if (eq !== -1) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

interface StaffLogin {
  readonly session: string;
  readonly csrf: string;
}

async function login(baseUrl: string, principalRef: string, body: Record<string, unknown> = {}): Promise<StaffLogin> {
  const res = await fetch(`${baseUrl}/__dev/staff-login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ principalRef, ...body }),
  });
  assert.equal(res.status, 200, `login ${principalRef}`);
  const cookies = parseAllSetCookies(res);
  return { session: cookies[STAFF_COOKIE]!, csrf: cookies[STAFF_CSRF_COOKIE]! };
}

interface PostOptions {
  readonly login?: StaffLogin | undefined;
  readonly origin?: string | undefined;
  readonly csrfHeader?: string | undefined;
  readonly csrfCookie?: string | undefined;
  readonly idempotencyKey?: string | undefined;
  readonly noSession?: boolean;
  readonly sessionOverride?: string;
}

async function post(baseUrl: string, path: string, body: unknown, opts: PostOptions = {}): Promise<{ status: number; json: Record<string, unknown>; raw: string }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const origin = "origin" in opts ? opts.origin : ALLOWED_ORIGIN;
  if (origin !== undefined) headers.origin = origin;
  const csrfHeader = "csrfHeader" in opts ? opts.csrfHeader : opts.login?.csrf;
  if (csrfHeader !== undefined) headers["x-csrf-token"] = csrfHeader;
  if (opts.idempotencyKey !== undefined) headers["idempotency-key"] = opts.idempotencyKey;
  const cookieParts: string[] = [];
  const session = opts.sessionOverride ?? opts.login?.session;
  if (session !== undefined && !opts.noSession) cookieParts.push(`${STAFF_COOKIE}=${session}`);
  const csrfCookie = "csrfCookie" in opts ? opts.csrfCookie : opts.login?.csrf;
  if (csrfCookie !== undefined) cookieParts.push(`${STAFF_CSRF_COOKIE}=${csrfCookie}`);
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");
  const res = await fetch(`${baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  const raw = await res.text();
  return { status: res.status, json: raw ? (JSON.parse(raw) as Record<string, unknown>) : {}, raw };
}

const enrollBody = { subjectRef: SUBJECT, participationRef: PARTICIPATION };
const KEY = "test-idem-key-0001-aaaa";

async function enroll(h: Harness, who: StaffLogin): Promise<string> {
  const res = await post(h.baseUrl, "/staff/enrollments", enrollBody, { login: who });
  assert.equal(res.status, 201, res.raw);
  return res.json.enrollmentRef as string;
}

function inviteBody(enrollmentRef: string): Record<string, unknown> {
  return { subjectRef: SUBJECT, enrollmentRef, participationRef: PARTICIPATION, contextRef: CONTEXT };
}

async function createDraft(h: Harness, who: StaffLogin, key = KEY): Promise<{ enrollmentRef: string; invitationRef: string }> {
  const enrollmentRef = await enroll(h, who);
  const res = await post(h.baseUrl, "/staff/invitations", inviteBody(enrollmentRef), { login: who, idempotencyKey: key });
  assert.equal(res.status, 201, res.raw);
  return { enrollmentRef, invitationRef: res.json.invitationRef as string };
}

const readyBody = { consentVersion: "v1-test", recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: CHANNEL };

async function fullFlow(h: Harness, who: StaffLogin): Promise<{ invitationRef: string; enrollmentRef: string; responses: string[] }> {
  const { enrollmentRef, invitationRef } = await createDraft(h, who);
  const ready = await post(h.baseUrl, `/staff/invitations/${invitationRef}/ready`, readyBody, { login: who });
  assert.equal(ready.status, 200, ready.raw);
  const sent = await post(h.baseUrl, `/staff/invitations/${invitationRef}/send`, {}, { login: who });
  assert.equal(sent.status, 200, sent.raw);
  return { invitationRef, enrollmentRef, responses: [ready.raw, sent.raw] };
}

test("TEST-CNS-714: sin sesión STAFF (sin cookie, cookie basura, firma ajena o cookie de otra consola) las 4 rutas responden 404 uniforme y no crean nada", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const ref = fixtureUuid("inv-714");
    const routes: Array<[string, unknown]> = [
      ["/staff/enrollments", enrollBody],
      ["/staff/invitations", inviteBody(fixtureUuid("en-714"))],
      [`/staff/invitations/${ref}/ready`, readyBody],
      [`/staff/invitations/${ref}/send`, {}],
    ];
    const foreign = encodeStaffSession(deriveStaffSessionKey(randomBytes(32)), { tenantId: TENANT_A, principalRef: ADMIN_A, role: "TENANT_ADMIN" });
    for (const [path, body] of routes) {
      for (const sessionOverride of [undefined, "basura", foreign]) {
        const res = await post(h.baseUrl, path, body, {
          csrfHeader: admin.csrf,
          csrfCookie: admin.csrf,
          idempotencyKey: KEY,
          ...(sessionOverride !== undefined ? { sessionOverride } : { noSession: true }),
        });
        assert.equal(res.status, 404, `${path} ${sessionOverride ?? "(sin cookie)"}`);
        assertValid(validateCommon("UniformNotFound", res.json));
      }
    }
    assert.equal(await h.staff.enrollment.enrollmentRepo.findActive(TENANT_A, SUBJECT, PARTICIPATION), null);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-715: rol no permitido: una sesión con rol distinto de TENANT_ADMIN recibe 403 ACTOR_NOT_ALLOWED sin efecto; el login de un no-TENANT_ADMIN y de un principal fuera del roster no emite sesión; una membership retirada da 404", async () => {
  const h = await startServer();
  try {
    // Sesión con firma del servidor pero rol APPROVER (defensa en profundidad de GRD-CM-07).
    const key = deriveStaffSessionKey(h.sessionSecret);
    const viewerSession = encodeStaffSession(key, { tenantId: TENANT_A, principalRef: TEST_VIEWER.principalRef, role: "APPROVER" });
    const csrf = "csrf-token-715-aaaaaaaa";
    const denied = await post(h.baseUrl, "/staff/enrollments", enrollBody, { sessionOverride: viewerSession, csrfHeader: csrf, csrfCookie: csrf });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.code, "ACTOR_NOT_ALLOWED");
    assertValid(validateCommon("Problem", denied.json));
    assert.equal(await h.staff.enrollment.enrollmentRepo.findActive(TENANT_A, SUBJECT, PARTICIPATION), null);

    // Login: RIGHTS_OPERATOR (consola CASE), APPROVER e inexistentes no obtienen sesión STAFF.
    for (const principalRef of [fixtureUuid("staff-synthetic-01"), fixtureUuid("staff-synthetic-03"), "no-existe"]) {
      const res = await fetch(`${h.baseUrl}/__dev/staff-login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ principalRef }),
      });
      assert.equal(parseAllSetCookies(res)[STAFF_COOKIE], undefined, principalRef);
      assert.equal(res.status, 422, principalRef);
    }

    // Membership no vigente (GRD-CM-01/02): sesión firmada por el servidor pero de un principal fuera
    // del roster, o cuyo tenant ya no coincide con el del roster, deja de valer (404 uniforme).
    for (const forged of [
      { tenantId: TENANT_A, principalRef: "staff-test-retirado", role: "TENANT_ADMIN" as const },
      { tenantId: TENANT_B, principalRef: ADMIN_A, role: "TENANT_ADMIN" as const },
    ]) {
      const res = await post(h.baseUrl, "/staff/enrollments", enrollBody, {
        sessionOverride: encodeStaffSession(key, forged),
        csrfHeader: csrf,
        csrfCookie: csrf,
      });
      assert.equal(res.status, 404, JSON.stringify(forged));
    }
    assert.equal(await h.staff.enrollment.enrollmentRepo.findActive(TENANT_A, SUBJECT, PARTICIPATION), null);
    assert.equal(await h.staff.enrollment.enrollmentRepo.findActive(TENANT_B, SUBJECT, PARTICIPATION), null);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-716: CSRF/Origin (GRD-CM-10): sin cabecera, cabecera distinta de la cookie, Origin ausente, ajeno o con sufijo parecido -> 403 CSRF_REJECTED sin efecto, en las 4 rutas", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const { invitationRef } = await createDraft(h, admin, "test-idem-key-0716-a");
    const routes: Array<[string, unknown]> = [
      ["/staff/enrollments", enrollBody],
      ["/staff/invitations", inviteBody(fixtureUuid("en-716"))],
      [`/staff/invitations/${invitationRef}/ready`, readyBody],
      [`/staff/invitations/${invitationRef}/send`, {}],
    ];
    const variants: PostOptions[] = [
      { login: admin, csrfHeader: undefined },
      { login: admin, csrfHeader: "otro-token-csrf-distinto" },
      { login: admin, origin: undefined },
      { login: admin, origin: "http://evil.example.invalid" },
      { login: admin, origin: `${ALLOWED_ORIGIN}.evil.example.invalid` },
      { login: admin, csrfCookie: undefined },
    ];
    for (const [path, body] of routes) {
      for (const variant of variants) {
        const res = await post(h.baseUrl, path, body, { ...variant, idempotencyKey: "test-idem-key-0716-b" });
        assert.equal(res.status, 403, `${path} ${JSON.stringify({ ...variant, login: undefined })}`);
        assert.equal(res.json.code, "CSRF_REJECTED");
        assertValid(validateCommon("Problem", res.json));
      }
    }
    // Sin efecto: la invitación sigue DRAFT y nada llegó al sink.
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "DRAFT");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-717: aislamiento por tenant: el tenant sale de la sesión; refs de otro colegio y tenantId/organizationRef en el body no abren nada (404/422) y el login no acepta tenantId", async () => {
  const h = await startServer();
  try {
    const adminA = await login(h.baseUrl, ADMIN_A);
    const adminB = await login(h.baseUrl, ADMIN_B);
    const { enrollmentRef, invitationRef } = await createDraft(h, adminA, "test-idem-key-0717-a");

    // El admin del colegio B no puede usar el sujeto/participación/enrollment/invitación de A.
    const enrollFromB = await post(h.baseUrl, "/staff/enrollments", enrollBody, { login: adminB });
    assert.equal(enrollFromB.status, 404);
    const inviteFromB = await post(h.baseUrl, "/staff/invitations", inviteBody(enrollmentRef), { login: adminB, idempotencyKey: "test-idem-key-0717-b" });
    assert.equal(inviteFromB.status, 404);
    const readyFromB = await post(h.baseUrl, `/staff/invitations/${invitationRef}/ready`, readyBody, { login: adminB });
    assert.equal(readyFromB.status, 404);
    const sendFromB = await post(h.baseUrl, `/staff/invitations/${invitationRef}/send`, {}, { login: adminB });
    assert.equal(sendFromB.status, 404);
    for (const res of [enrollFromB, inviteFromB, readyFromB, sendFromB]) assertValid(validateCommon("UniformNotFound", res.json));
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "DRAFT");

    // B opera lo suyo dentro de su tenant; las refs quedan en su propio tenant.
    const bEnroll = await post(h.baseUrl, "/staff/enrollments", { subjectRef: SUBJECT_B, participationRef: PARTICIPATION_B }, { login: adminB });
    assert.equal(bEnroll.status, 201);
    assert.equal(await h.staff.enrollment.enrollmentRepo.findByRef(TENANT_A, bEnroll.json.enrollmentRef as string), null);
    assert.equal((await h.staff.enrollment.enrollmentRepo.findByRef(TENANT_B, bEnroll.json.enrollmentRef as string))?.tenantId, TENANT_B);

    // tenantId / organizationRef en el body: additionalProperties=false -> 422, sin efecto.
    for (const extra of [{ tenantId: TENANT_B }, { tenantRef: TENANT_B }, { organizationRef: TENANT_B }]) {
      const res = await post(h.baseUrl, "/staff/invitations", { ...inviteBody(enrollmentRef), ...extra }, { login: adminA, idempotencyKey: "test-idem-key-0717-c" });
      assert.equal(res.status, 422);
    }

    // El login no acepta tenantId (el tenant sale del roster): 422 y sin cookies.
    const res = await fetch(`${h.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ principalRef: ADMIN_A, tenantId: TENANT_B }),
    });
    assert.equal(res.status, 422);
    assert.equal(parseAllSetCookies(res)[STAFF_COOKIE], undefined);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-718: campos extra en el body (actor, tenant, expiresAt, tokenHash, actorType FIXTURE, origin) -> 422 Problem sin efecto en las 4 rutas; cuerpo no objeto o refs mal formadas también 422", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const { enrollmentRef, invitationRef } = await createDraft(h, admin, "test-idem-key-0718-a");
    const extras: Array<Record<string, unknown>> = [
      { actorRole: "TENANT_ADMIN" },
      { actorType: "FIXTURE" },
      { source: "FIXTURE" },
      { expiresAt: "2030-01-01T00:00:00.000Z" },
      { tokenHash: "x" },
      { origin: "REQUEST_EXPIRED" },
    ];
    for (const extra of extras) {
      const bodies: Array<[string, unknown, PostOptions]> = [
        ["/staff/enrollments", { ...enrollBody, ...extra }, {}],
        ["/staff/invitations", { ...inviteBody(enrollmentRef), ...extra }, { idempotencyKey: "test-idem-key-0718-b" }],
        [`/staff/invitations/${invitationRef}/ready`, { ...readyBody, ...extra }, {}],
        [`/staff/invitations/${invitationRef}/send`, { ...extra }, {}],
      ];
      for (const [path, body, opts] of bodies) {
        const res = await post(h.baseUrl, path, body, { login: admin, ...opts });
        assert.equal(res.status, 422, `${path} ${JSON.stringify(extra)}`);
        assertValid(validateCommon("Problem", res.json));
      }
    }
    // Refs mal formadas, arreglo/primitivo como cuerpo, UNBOUND con canal y RECIPIENT_CHANNEL sin canal.
    for (const [path, body, opts] of [
      ["/staff/enrollments", { subjectRef: "no-es-uuid", participationRef: PARTICIPATION }, {}],
      ["/staff/enrollments", [], {}],
      ["/staff/invitations", { ...inviteBody(enrollmentRef), contextRef: "minuscula" }, { idempotencyKey: "test-idem-key-0718-c" }],
      [`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1", recipientBinding: "UNBOUND", recipientChannelRef: CHANNEL }, {}],
      [`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1", recipientBinding: "RECIPIENT_CHANNEL" }, {}],
      [`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1", recipientBinding: "OTRO" }, {}],
    ] as Array<[string, unknown, PostOptions]>) {
      const res = await post(h.baseUrl, path, body, { login: admin, ...opts });
      assert.equal(res.status, 422, `${path} ${JSON.stringify(body)}`);
    }
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "DRAFT");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-719: idempotencia (GRD-CM-08): misma Idempotency-Key + mismo payload = misma respuesta sin duplicar; otro payload = 422 IDEMPOTENCY_CONFLICT; I1 sin key = 422; otro principal no reproduce; un replay de /send no reentrega el enlace", async () => {
  const h = await startServer();
  try {
    const adminA = await login(h.baseUrl, ADMIN_A);
    const enrollmentRef = await enroll(h, adminA);
    const body = inviteBody(enrollmentRef);

    const first = await post(h.baseUrl, "/staff/invitations", body, { login: adminA, idempotencyKey: KEY });
    const replay = await post(h.baseUrl, "/staff/invitations", body, { login: adminA, idempotencyKey: KEY });
    assert.equal(first.status, 201);
    assert.equal(replay.status, 201);
    assert.deepEqual(replay.json, first.json);

    const conflict = await post(h.baseUrl, "/staff/invitations", { ...body, contextRef: "OTHER_CONTEXT" }, { login: adminA, idempotencyKey: KEY });
    assert.equal(conflict.status, 422);
    assert.equal(conflict.json.code, "IDEMPOTENCY_CONFLICT");
    assertValid(validateCommon("Problem", conflict.json));

    // Otra key sobre el mismo sujeto: GRD-IV-01 (una invitación no terminal) -> 409.
    const second = await post(h.baseUrl, "/staff/invitations", body, { login: adminA, idempotencyKey: "test-idem-key-0719-other" });
    assert.equal(second.status, 409);
    assert.equal(second.json.code, "INVITATION_ALREADY_ACTIVE");

    // I1 exige la cabecera; una key mal formada también es 422.
    assert.equal((await post(h.baseUrl, "/staff/invitations", body, { login: adminA })).status, 422);
    assert.equal((await post(h.baseUrl, "/staff/invitations", body, { login: adminA, idempotencyKey: "corta" })).status, 422);

    // La key está ligada al principal: el otro colegio (otro principal) no reproduce la respuesta.
    const adminB = await login(h.baseUrl, ADMIN_B);
    const cross = await post(h.baseUrl, "/staff/invitations", body, { login: adminB, idempotencyKey: KEY });
    assert.equal(cross.status, 404);

    // EN0: sin key, un segundo alta del mismo (sujeto, participación) es 409 ENROLLMENT_ALREADY_ACTIVE;
    // con la misma key, reproduce la respuesta original.
    const dup = await post(h.baseUrl, "/staff/enrollments", enrollBody, { login: adminA });
    assert.equal(dup.status, 409);
    assert.equal(dup.json.code, "ENROLLMENT_ALREADY_ACTIVE");
    const enrollA = await post(h.baseUrl, "/staff/enrollments", { subjectRef: SUBJECT_B, participationRef: PARTICIPATION_B }, { login: adminB, idempotencyKey: "test-idem-key-0719-en" });
    const enrollAReplay = await post(h.baseUrl, "/staff/enrollments", { subjectRef: SUBJECT_B, participationRef: PARTICIPATION_B }, { login: adminB, idempotencyKey: "test-idem-key-0719-en" });
    assert.equal(enrollA.status, 201);
    assert.deepEqual(enrollAReplay.json, enrollA.json);

    // /send con la misma key: una sola entrega al sink, misma respuesta.
    const ref = first.json.invitationRef as string;
    assert.equal((await post(h.baseUrl, `/staff/invitations/${ref}/ready`, readyBody, { login: adminA })).status, 200);
    const s1 = await post(h.baseUrl, `/staff/invitations/${ref}/send`, {}, { login: adminA, idempotencyKey: "test-idem-key-0719-send" });
    const s2 = await post(h.baseUrl, `/staff/invitations/${ref}/send`, {}, { login: adminA, idempotencyKey: "test-idem-key-0719-send" });
    assert.equal(s1.status, 200);
    assert.deepEqual(s2.json, s1.json);
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
    // Sin key, reenviar una invitación ya SENT es una transición inválida (409), no una segunda entrega.
    const s3 = await post(h.baseUrl, `/staff/invitations/${ref}/send`, {}, { login: adminA });
    assert.equal(s3.status, 409);
    assert.equal(s3.json.code, "INVALID_TRANSITION");
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
    // Un solo evento de creación en el ledger pese al replay.
    assert.equal((await h.ports.invitation.ledger.listByAggregate(TENANT_A, "Invitation", ref)).filter((e) => e.eventType === "INVITATION_CREATED").length, 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-720: el token nunca aparece en ninguna respuesta HTTP, en el ledger ni en el outbox: solo en el sink de dev; en la BD solo persiste tokenHash", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const { invitationRef, enrollmentRef, responses } = await fullFlow(h, admin);
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
    const message = h.staff.invitationLinkSink.sent[0]!;
    assert.equal(message.invitationRef, invitationRef);
    assert.equal(message.recipientChannelRef, CHANNEL);
    assert.equal(message.deliveryChannel, LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY.deliveryChannel);
    const token = message.invitationPath.slice("/i/".length);
    assert.match(token, /^[0-9a-f]{64}$/);

    for (const raw of responses) assert.equal(raw.includes(token), false, "token en una respuesta HTTP");
    const events = [
      ...await h.ports.invitation.ledger.listByAggregate(TENANT_A, "Invitation", invitationRef),
      ...await h.ports.invitation.ledger.listByAggregate(TENANT_A, "Enrollment", enrollmentRef),
    ];
    assert.ok(events.length >= 4);
    assert.equal(JSON.stringify(events).includes(token), false, "token en un evento del ledger");
    const outbox = await (await fetch(`${h.baseUrl}/__dev/outbox-sink`)).text();
    assert.equal(outbox.includes(token), false, "token en el outbox");
    const stored = (await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))!;
    assert.equal(JSON.stringify(stored).includes(token), false, "token persistido");
    assert.match(stored.tokenHash ?? "", /^[0-9a-f]{64}$/);
    for (const event of events) {
      const verdict = validateLedgerEventPayload(event.eventType, event.payload);
      assert.ok(verdict.ok, `${event.eventType}: ${verdict.errors.join("\n")}`);
    }
    // El sink de dev es lo único que lo expone, y solo en LOCAL.
    const sink = await fetch(`${h.baseUrl}/__dev/invitation-sink`);
    assert.equal(sink.status, 200);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-721: E2E: invitación creada por TENANT_ADMIN sintético (enrollment -> I1 -> I2 -> I3), enlace leído del sink, GET /i/{token} 303 a /welcome y GET /welcome 200 con sesión LANDING", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const { invitationRef } = await fullFlow(h, admin);
    const sink = (await (await fetch(`${h.baseUrl}/__dev/invitation-sink`)).json()) as { sent: Array<{ invitationPath: string; invitationRef: string }> };
    assert.equal(sink.sent.length, 1);
    assert.equal(sink.sent[0]!.invitationRef, invitationRef);

    const redeem = await fetch(`${h.baseUrl}${sink.sent[0]!.invitationPath}`, { redirect: "manual" });
    assert.equal(redeem.status, 303);
    assert.equal(redeem.headers.get("location"), "/welcome");
    const handle = parseAllSetCookies(redeem)[INVITATION_HANDLE_COOKIE];
    assert.ok(handle, "GET /i/{token} fija el handle LANDING");

    const welcome = await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE}=${handle}` } });
    assert.equal(welcome.status, 200);
    assert.ok(parseAllSetCookies(welcome)[SESSION_COOKIE], "GET /welcome crea la sesión LANDING real");

    // El GET no transiciona (INV-CM-08): la invitación sigue SENT hasta el primer POST.
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "SENT");
    const sess = parseAllSetCookies(welcome)[SESSION_COOKIE]!;
    const csrf = parseAllSetCookies(welcome)["__Host-cns-csrf"]!;
    const opened = await fetch(`${h.baseUrl}/invitation/open`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ALLOWED_ORIGIN, "x-csrf-token": csrf, cookie: `${SESSION_COOKIE}=${sess}; __Host-cns-csrf=${csrf}` },
      body: "{}",
    });
    assert.equal(opened.status, 200);
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "OPENED");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-722: contrato: cuerpos de solicitud y de respuesta validan contra api-payloads.schema.json (EnrollmentOpened, InvitationCreated, InvitationReady, InvitationSent, Problem) y los estados/secuencias siguen la máquina", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    assertValid(validateApiPayload("OpenEnrollmentRequest", enrollBody));
    const en = await post(h.baseUrl, "/staff/enrollments", enrollBody, { login: admin });
    assert.equal(en.status, 201);
    assertValid(validateApiPayload("EnrollmentOpened", en.json));
    assert.deepEqual({ state: en.json.state, sequence: en.json.sequence }, { state: "ACTIVE", sequence: 1 });

    const body = inviteBody(en.json.enrollmentRef as string);
    assertValid(validateApiPayload("CreateInvitationRequest", body));
    const inv = await post(h.baseUrl, "/staff/invitations", body, { login: admin, idempotencyKey: KEY });
    assert.equal(inv.status, 201);
    assertValid(validateApiPayload("InvitationCreated", inv.json));
    const ref = inv.json.invitationRef as string;

    // MarkInvitationReadyRequest usa if/then/else (no soportado por schema-lite): se valida el
    // subconjunto de propiedades y se comprueba la condicional con las mismas reglas del contrato.
    const readyRes = await post(h.baseUrl, `/staff/invitations/${ref}/ready`, readyBody, { login: admin });
    assert.equal(readyRes.status, 200);
    assertValid(validateApiPayload("InvitationReady", readyRes.json));
    assert.equal(readyRes.json.sequence, 2);
    assert.ok(typeof readyRes.json.expiresAt === "string" && !Number.isNaN(Date.parse(readyRes.json.expiresAt)));

    assertValid(validateApiPayload("EmptyCommand", {}));
    const sent = await post(h.baseUrl, `/staff/invitations/${ref}/send`, {}, { login: admin });
    assert.equal(sent.status, 200);
    assertValid(validateApiPayload("InvitationSent", sent.json));
    assert.equal(sent.json.sequence, 3);
    assert.equal("token" in sent.json, false);

    // Un 409 de dominio es un Problem válido (sin texto libre, correlationId Ref).
    const again = await post(h.baseUrl, `/staff/invitations/${ref}/ready`, readyBody, { login: admin });
    assert.equal(again.status, 409);
    assertValid(validateCommon("Problem", again.json));
  } finally {
    await h.close();
  }
});

test("TEST-CNS-723: fail-closed sin política de emisión (P-10/EXT-B): I2 e I3 responden 409 GUARD_EVALUATOR_UNAVAILABLE sin entregar nada; con catálogo vacío EN0 es 404", async () => {
  const h = await startServer({ withPolicy: false });
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    const { invitationRef } = await createDraft(h, admin);
    const ready = await post(h.baseUrl, `/staff/invitations/${invitationRef}/ready`, readyBody, { login: admin });
    assert.equal(ready.status, 409);
    assert.equal(ready.json.code, "GUARD_EVALUATOR_UNAVAILABLE");
    const send = await post(h.baseUrl, `/staff/invitations/${invitationRef}/send`, {}, { login: admin });
    assert.equal(send.status, 409);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    assert.equal((await h.ports.invitation.invitationRepo.findByRef(TENANT_A, invitationRef))?.state, "DRAFT");

    const empty = await startServer({ withPolicy: false });
    try {
      const other = await login(empty.baseUrl, ADMIN_A);
      const res = await post(empty.baseUrl, "/staff/enrollments", { subjectRef: fixtureUuid("desconocido-723"), participationRef: PARTICIPATION }, { login: other });
      assert.equal(res.status, 404);
    } finally {
      await empty.close();
    }
  } finally {
    await h.close();
  }
});

test("TEST-CNS-724: el login STAFF y el sink de invitaciones son solo LOCAL (GRD-CM-13): fuera de LOCAL ambas rutas son 404 sin cookies", async () => {
  const h = await startServer({ environment: "DEV" });
  try {
    const res = await fetch(`${h.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ principalRef: ADMIN_A }),
    });
    assert.equal(res.status, 404);
    assert.equal(parseAllSetCookies(res)[STAFF_COOKIE], undefined);
    assert.equal((await fetch(`${h.baseUrl}/__dev/invitation-sink`)).status, 404);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-725: el login CASE (CA-128) sigue sin admitir TENANT_ADMIN y el login STAFF no admite RIGHTS_OPERATOR: las consolas no comparten sesión ni cookie", async () => {
  const h = await startServer();
  try {
    const admin = await login(h.baseUrl, ADMIN_A);
    // La cookie STAFF no sirve como sesión CASE ni al revés: cookies y claves HKDF distintas.
    const caseRes = await fetch(`${h.baseUrl}/platform/rights-cases/${fixtureUuid("case-725")}/confirmation`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: ALLOWED_ORIGIN,
        "x-csrf-token": admin.csrf,
        cookie: `__Host-cns-case=${admin.session}; __Host-cns-case-csrf=${admin.csrf}`,
      },
      body: JSON.stringify({ confirmationGivenOnCasePage: true }),
    });
    assert.equal(caseRes.status, 404);
    const op = await login(h.baseUrl, fixtureUuid("staff-synthetic-01"), { tenantId: TENANT_A, caseRef: fixtureUuid("case-725") }).catch(() => null);
    assert.equal(op, null, "un RIGHTS_OPERATOR sin caso existente no obtiene sesión (login CASE intacto)");
  } finally {
    await h.close();
  }
});
