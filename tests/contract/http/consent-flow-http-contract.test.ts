// Gobierna: contracts/openapi/consent-it0.openapi.yaml (API-CNS-101, API-CNS-115,
// API-CNS-120, API-CNS-121, API-CNS-127, API-CNS-149) y contracts/schemas/api-payloads
// .schema.json + contracts/schemas/common.schema.json (InvitationOpenedAck, UniformAccepted,
// OtpVerified, OtpRejected, DecisionRecorded, InReviewAck, Problem, UniformNotFound).
// Fix P1 (CA-116): POST /invitation/open respondía {invitationRef, state} en vez de
// InvitationOpenedAck ({result: "OPENED"}, additionalProperties: false;
// contracts/schemas/api-payloads.schema.json:303-315). Este archivo levanta el servidor HTTP
// real (node:http) en un puerto efímero de localhost por cada test y valida el CUERPO de la
// respuesta de cada endpoint HTTP existente contra su schema del contrato con el validador
// propio de tests/contract/http/schema-lite.ts (sin dependencias nuevas).
// TEST-CNS-512..TEST-CNS-524 (traceability/test-matrix.csv).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import {
  createRightsCaseHttpServer,
  createDefaultInMemoryPorts,
  type RightsCaseInMemoryPorts,
} from "../../../src/server/entrypoints/http/server.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { validateApiPayload, validateCommon, type ValidationResult } from "../schema-lite.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const MANAGE_COOKIE_NAME = "__Host-cns-manage";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+channel-contract@example.invalid";

// LOCAL-only sintético (D4, no es default de producción): ver otp-policy.config.ts.
// SEC-CNS-021 PR-4: P-06 aprobado (3 envios/h, el inicial incluido) rige; solo se anula la separacion de 60 s (LOCAL_ONLY) para poder reenviar de inmediato.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, minResendIntervalMs: 0 };
// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

interface ConsentFlowHarness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startConsentFlowServer(): Promise<ConsentFlowHarness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const server: Server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        ports,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function parseSetCookie(res: Response): Record<string, string> {
  const raw = res.headers.get("set-cookie") ?? "";
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

/** GET /welcome puede fijar sesión + CSRF en la misma respuesta; getSetCookie() (undici) los
 * mantiene separados, a diferencia de parseSetCookie (un solo Set-Cookie). */
function parseAllSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  const raws = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie") ?? ""];
  for (const raw of raws) {
    for (const part of raw.split(";")) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      const name = part.slice(0, eq).trim();
      if (!out[name]) out[name] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

interface PostOpts {
  readonly path: string;
  readonly origin?: string;
  readonly csrfHeader?: string;
  readonly csrfCookie?: string;
  readonly sessionCookie?: string;
  readonly body?: unknown;
}

async function post(baseUrl: string, opts: PostOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);
  if (opts.sessionCookie !== undefined) cookieParts.push(`${SESSION_COOKIE_NAME}=${opts.sessionCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}${opts.path}`, { method: "POST", headers, body: JSON.stringify(opts.body ?? {}) });
}

const VALID_CSRF = { origin: ALLOWED_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh" };

async function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string): Promise<string> {
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef, { deliveryChannel: "CONSENT_APP_EMAIL" });
  return token;
}

/** SEC-CNS-014 (Carlos, 2026-09-28): GET /i/{token} ya no fija la sesión directamente, solo el
 * handle INVITATION_LANDING; la sesión real la fija GET /welcome al resolverlo. */
async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const first = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(first)[INVITATION_HANDLE_COOKIE_NAME];
  if (!handleCookie) return undefined;
  const second = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  return parseAllSetCookies(second)[SESSION_COOKIE_NAME];
}

/** Recorre invitación -> canje -> I4 -> V1 -> V3 y devuelve la sesión verificada, lista para
 * /decision/submit (API-CNS-127). */
async function bringToVerifiedSession(harness: ConsentFlowHarness, invitationRef: string, subjectRef: string): Promise<string> {
  const token = await seedSentInvitation(harness.ports, invitationRef, subjectRef);
  const landingSession = await redeem(harness.baseUrl, token);
  const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
  const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
  const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
  const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];

  const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
  const code = sink.sent[sink.sent.length - 1]?.code ?? "";
  const submitted = await post(harness.baseUrl, {
    path: "/otp/submit",
    ...VALID_CSRF,
    sessionCookie: sessionAfterRequest,
    body: { code },
  });
  const sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME];
  assert.ok(sessionCookie, "V3 debe fijar la cookie de sesión verificada");
  return sessionCookie;
}

/** Recorre C2 completo (POST /decision/steps) en orden: CONTEXT_INFORMATION_VIEWED,
 * CONSENT_VERSION_VIEWED, DECISION_MAKER_AUTHORITY_DECLARED, SUBJECT_CONFIRMED. Devuelve la
 * cookie de sesión final (con `consentId` ya fijado por C1 perezoso). */
async function completeDecisionSteps(harness: ConsentFlowHarness, sessionCookie: string): Promise<string> {
  const steps: unknown[] = [
    { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    { stepKind: "CONSENT_VERSION_VIEWED" },
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
    { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
  ];
  let cookie = sessionCookie;
  for (const body of steps) {
    const res = await post(harness.baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: cookie, body });
    assert.equal(res.status, 200, `paso ${JSON.stringify(body)} debía responder 200`);
    const nextCookie = parseSetCookie(res)[SESSION_COOKIE_NAME];
    if (nextCookie) cookie = nextCookie;
  }
  return cookie;
}

// ---------------------------------------------------------------------------
// GET /i/{token} (API-CNS-101)
// ---------------------------------------------------------------------------

test("TEST-CNS-512: GET /i/{token} válido responde 303 con Location sin token (RedeemSeeOther, contracts/openapi headers.Location)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-512"), fixtureUuid("subject-512"));
    const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(res.status, 303);
    const location = res.headers.get("location") ?? "";
    assert.match(location, /^\/[a-z-]+$/, "Location debe ser una ruta relativa sin token (contracts/openapi headers.Location)");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-513: GET /i/{token} inexistente responde el mismo 303 uniforme que un token válido (SEC-CNS-014, Carlos 2026-09-28); GET /welcome subsiguiente sirve el 404 UniformNotFound-equivalente en HTML (welcome-http.test.ts TEST-CNS-539)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const res = await fetch(`${harness.baseUrl}/i/this-token-does-not-exist`, { redirect: "manual" });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "/welcome");
    assert.equal(res.headers.get("content-type"), "application/json");
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /invitation/open (API-CNS-115) — el P1 reportado: InvitationOpenedAck
// ---------------------------------------------------------------------------

test("TEST-CNS-514: POST /invitation/open válido responde InvitationOpenedAck ({result: OPENED}), no {invitationRef, state} (P1, api-payloads.schema.json:303-315)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-514"), fixtureUuid("subject-514"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    assert.equal(res.status, 200);
    const body = await res.json();
    assertValid(validateApiPayload("InvitationOpenedAck", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-515: POST /invitation/open sin CSRF responde Problem (403, common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-515"), fixtureUuid("subject-515"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", sessionCookie: landingSession });
    assert.equal(res.status, 403);
    const body = await res.json();
    assertValid(validateCommon("Problem", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-516: POST /invitation/open sin sesión LANDING responde 404 UniformNotFound (common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF });
    assert.equal(res.status, 404);
    const body = await res.json();
    assertValid(validateCommon("UniformNotFound", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /otp/request (API-CNS-120)
// ---------------------------------------------------------------------------

test("TEST-CNS-517: POST /otp/request responde UniformAccepted ({result: RECEIVED}), no {result: ACCEPTED} (P1, common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-517"), fixtureUuid("subject-517"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const res = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    assert.equal(res.status, 202);
    const body = await res.json();
    assertValid(validateCommon("UniformAccepted", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /otp/resend (API-CNS-122, V2r)
// ---------------------------------------------------------------------------

test("TEST-CNS-551: POST /otp/resend responde UniformAccepted ({result: RECEIVED}), mismo esquema que /otp/request (common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-551"), fixtureUuid("subject-551"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    const res = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
    assert.equal(res.status, 202);
    const body = await res.json();
    assertValid(validateCommon("UniformAccepted", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-552: POST /otp/resend agotado el límite (P-06) responde Problem (409, common.schema.json) con content-type application/problem+json", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-552"), fixtureUuid("subject-552"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    // D8: el envio inicial (V1) cuenta; con P-06 aprobado (3/h) caben V1 + 2 reenvios.
    for (let i = 0; i < 2; i += 1) {
      await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
    }
    const res = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
    assert.equal(res.status, 409);
    assert.match(res.headers.get("content-type") ?? "", /application\/problem\+json/);
    const body = await res.json();
    assertValid(validateCommon("Problem", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /otp/submit (API-CNS-121)
// ---------------------------------------------------------------------------

test("TEST-CNS-518: POST /otp/submit con código correcto responde OtpVerified ({result, scope}) (P1: faltaba scope, api-payloads.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-518"), fixtureUuid("subject-518"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];
    const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[sink.sent.length - 1]?.code ?? "";

    const res = await post(harness.baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie: sessionAfterRequest, body: { code } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assertValid(validateApiPayload("OtpVerified", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-519: POST /otp/submit con código incorrecto responde OtpRejected (422) con un code del enum del contrato, no \"OTP_REJECTED\" (P1, api-payloads.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-519"), fixtureUuid("subject-519"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];

    const res = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code: "000000" },
    });
    assert.equal(res.status, 422);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "OTP_CODE_REJECTED");
    assertValid(validateApiPayload("OtpRejected", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /decision/submit (API-CNS-127)
// ---------------------------------------------------------------------------

test("TEST-CNS-565: POST /decision/steps CONSENT_VERSION_VIEWED responde DecisionStepRecorded con servedVersion (api-payloads.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-565"), fixtureUuid("subject-565"));
    const res = await post(harness.baseUrl, {
      path: "/decision/steps",
      ...VALID_CSRF,
      sessionCookie: verifiedSession,
      body: { stepKind: "CONSENT_VERSION_VIEWED" },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assertValid(validateApiPayload("DecisionStepRecorded", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-520: POST /decision/submit GRANTED responde DecisionRecorded con receiptRef (P1: faltaba, api-payloads.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-520"), fixtureUuid("subject-520"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assertValid(validateApiPayload("DecisionRecorded", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-521: POST /decision/submit sin sesión verificada responde 404 UniformNotFound (common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const res = await post(harness.baseUrl, { path: "/decision/submit", ...VALID_CSRF, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 404);
    const body = await res.json();
    assertValid(validateCommon("UniformNotFound", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-522: POST /decision/submit con finalidad requerida faltante responde Problem (422) con code PURPOSE_SELECTION_INVALID, no el ID interno ERR-CD-02 (P1, common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-522"), fixtureUuid("subject-522"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const incompletePurposes = GRANT_ALL.slice(1); // falta una finalidad requerida (GRD-CD-06/07).
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: incompletePurposes },
    });
    assert.equal(res.status, 422);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "PURPOSE_SELECTION_INVALID");
    assertValid(validateCommon("Problem", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// POST /rights-case/resume (API-CNS-149)
// ---------------------------------------------------------------------------

interface RightsCaseHarness {
  readonly baseUrl: string;
  readonly ports: RightsCaseInMemoryPorts;
  close(): Promise<void>;
}

function startRightsCaseServer(): Promise<RightsCaseHarness> {
  const ports = createDefaultInMemoryPorts();
  const server: Server = createRightsCaseHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        ports,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function seedOpenChannelUnreachableCase(ports: RightsCaseInMemoryPorts, handle: string): Promise<void> {
  ports.tenantHandle.issue({ handle, tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", chainRef: fixtureUuid("chain-1"), revokedDecisionRef: fixtureUuid("decision-1") });
  await ports.rightsCaseRepo.save({
    caseRef: fixtureUuid("case-1"),
    tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73",
    chainRef: fixtureUuid("chain-1"),
    revokedDecisionRef: fixtureUuid("decision-1"),
    status: "OPEN",
    origin: "CHANNEL_UNREACHABLE",
  });
}

async function postResume(
  baseUrl: string,
  opts: { origin?: string; csrfHeader?: string; csrfCookie?: string; manageHandle?: string },
): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.manageHandle !== undefined) cookieParts.push(`${MANAGE_COOKIE_NAME}=${opts.manageHandle}`);
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}/rights-case/resume`, { method: "POST", headers, body: "{}" });
}

test("TEST-CNS-523: POST /rights-case/resume responde InReviewAck (api-payloads.schema.json)", async () => {
  const harness = await startRightsCaseServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-A");
    const res = await postResume(harness.baseUrl, {
      origin: ALLOWED_ORIGIN,
      csrfHeader: "token-123",
      csrfCookie: "token-123",
      manageHandle: "handle-A",
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assertValid(validateApiPayload("InReviewAck", body));
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-524: POST /rights-case/resume sin CSRF responde Problem (403, common.schema.json)", async () => {
  const harness = await startRightsCaseServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-B");
    const res = await postResume(harness.baseUrl, { manageHandle: "handle-B" });
    assert.equal(res.status, 403);
    const body = await res.json();
    assertValid(validateCommon("Problem", body));
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// content-type de Problem/CsrfRejected/OtpRejected (P1: contracts/openapi/consent-it0
// .openapi.yaml fija application/problem+json en components.responses.CsrfRejected (~L196-200),
// components.responses.Problem (~L201-205) y /otp/submit '422' OtpRejected (~L660-664); el
// transporte respondía siempre application/json).
// ---------------------------------------------------------------------------

test("TEST-CNS-532: POST /invitation/open sin CSRF responde con content-type application/problem+json (CsrfRejected)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-532"), fixtureUuid("subject-532"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", sessionCookie: landingSession });
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("content-type"), "application/problem+json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-533: POST /otp/submit con código incorrecto responde con content-type application/problem+json (OtpRejected)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-533"), fixtureUuid("subject-533"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];

    const res = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code: "000000" },
    });
    assert.equal(res.status, 422);
    assert.equal(res.headers.get("content-type"), "application/problem+json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-534: POST /decision/submit con finalidad requerida faltante responde con content-type application/problem+json (Problem)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-534"), fixtureUuid("subject-534"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const incompletePurposes = GRANT_ALL.slice(1);
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: incompletePurposes },
    });
    assert.equal(res.status, 422);
    assert.equal(res.headers.get("content-type"), "application/problem+json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-535: POST /rights-case/resume sin CSRF responde con content-type application/problem+json (CsrfRejected)", async () => {
  const harness = await startRightsCaseServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-535");
    const res = await postResume(harness.baseUrl, { manageHandle: "handle-535" });
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("content-type"), "application/problem+json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-536: POST /invitation/open válido sigue respondiendo application/json (regresión: no todo pasó a problem+json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-536"), fixtureUuid("subject-536"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "application/json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-537: GET /i/{token} inexistente responde 303 (RedeemSeeOther) con content-type application/json, idéntico byte a byte al de un token válido salvo el cuerpo vacío común a ambos (SEC-CNS-014, Carlos 2026-09-28: cierra el oráculo 303 válido / 404 inválido)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-537"), fixtureUuid("subject-537"));
    const valid = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    const invalid = await fetch(`${harness.baseUrl}/i/this-token-does-not-exist`, { redirect: "manual" });
    assert.equal(valid.status, 303);
    assert.equal(invalid.status, 303);
    assert.equal(valid.headers.get("location"), invalid.headers.get("location"));
    assert.equal(valid.headers.get("content-type"), "application/json");
    assert.equal(invalid.headers.get("content-type"), "application/json");
    assert.deepEqual(await valid.json(), await invalid.json());
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// GET /r/{token} (API-CNS-103, RecoveryRedeemSeeOther)
// ---------------------------------------------------------------------------

test("TEST-CNS-603: GET /r/{token} responde 303 con Location que valida contra el pattern del contrato (headers.Location, /recovery/confirm tiene dos segmentos)", async () => {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const CONTRACT_TENANT_ID = "fa095521-552d-4810-8a4a-8e117557b629";
  await ports.decision.repo.save({
    consentId: fixtureUuid("consent-603"),
    tenantId: CONTRACT_TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-603"),
    decisionMakerRef: "dm:603",
    invitationRef: fixtureUuid("inv-603-seed"),
    verificationRef: fixtureUuid("ver-603-seed"),
    chainRef: fixtureUuid("chain-603"),
    state: "GRANTED",
    purposes: GRANT_ALL,
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: "receipt-603",
  });
  const revocationPorts: RevocationFlowPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({
    handle: "mgmt-token-603",
    tenantId: CONTRACT_TENANT_ID,
    chainRef: fixtureUuid("chain-603"),
    revokedDecisionRef: fixtureUuid("consent-603"),
  });
  const server: Server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports, revocationPorts });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
  try {
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-603`, { redirect: "manual" });
    const handleCookie = parseSetCookie(redeemed)["__Host-cns-m-handle"];
    const manage = await fetch(`${baseUrl}/manage`, { headers: { cookie: `__Host-cns-m-handle=${handleCookie}` } });
    const sessionCookie = parseAllSetCookies(manage)[SESSION_COOKIE_NAME];
    const rv0 = await post(baseUrl, { path: "/manage/recovery-link", ...VALID_CSRF, sessionCookie });
    assert.equal(rv0.status, 202);
    const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
    const message = sink.sent[sink.sent.length - 1];
    assert.ok(message);
    const match = message.recoveryPath.match(/^\/r\/(.+)$/);
    assert.ok(match);
    const token = match![1]!;

    const res = await fetch(`${baseUrl}/r/${token}`, { redirect: "manual" });
    assert.equal(res.status, 303);
    const location = res.headers.get("location") ?? "";
    assert.match(location, /^\/[a-z-]+(\/[a-z-]+)*$/, "Location debe cumplir contracts/openapi headers.Location");
    assert.equal(location, "/recovery/confirm");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
