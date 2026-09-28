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

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import {
  createRightsCaseHttpServer,
  createDefaultInMemoryPorts,
  type RightsCaseInMemoryPorts,
} from "../../../src/server/entrypoints/http/server.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { validateApiPayload, validateCommon, type ValidationResult } from "../schema-lite.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const MANAGE_COOKIE_NAME = "__Host-cns-manage";
const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+channel-contract@example.invalid";

// LOCAL-only sintético (D4, no es default de producción): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["IT0_SYNTHETIC_GUARDIAN"] };
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
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
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

function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string): string {
  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
  return token;
}

async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const res = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  return parseSetCookie(res)[SESSION_COOKIE_NAME];
}

/** Recorre invitación -> canje -> I4 -> V1 -> V3 y devuelve la sesión verificada, lista para
 * /decision/submit (API-CNS-127). */
async function bringToVerifiedSession(harness: ConsentFlowHarness, invitationRef: string, subjectRef: string): Promise<string> {
  const token = seedSentInvitation(harness.ports, invitationRef, subjectRef);
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
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "IT0_SYNTHETIC_GUARDIAN", authorityDeclared: true },
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
    const token = seedSentInvitation(harness.ports, "inv-512", "subject-512@example.invalid");
    const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(res.status, 303);
    const location = res.headers.get("location") ?? "";
    assert.match(location, /^\/[a-z-]+$/, "Location debe ser una ruta relativa sin token (contracts/openapi headers.Location)");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-513: GET /i/{token} inexistente responde 404 UniformNotFound (contracts/common.schema.json)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const res = await fetch(`${harness.baseUrl}/i/this-token-does-not-exist`, { redirect: "manual" });
    assert.equal(res.status, 404);
    const body = await res.json();
    assertValid(validateCommon("UniformNotFound", body));
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
    const token = seedSentInvitation(harness.ports, "inv-514", "subject-514@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-515", "subject-515@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-517", "subject-517@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-551", "subject-551@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-552", "subject-552@example.invalid");
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    for (let i = 0; i < LOCAL_ONLY_TEST_OTP_POLICY.maxResends; i += 1) {
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
    const token = seedSentInvitation(harness.ports, "inv-518", "subject-518@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-519", "subject-519@example.invalid");
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
    const verifiedSession = await bringToVerifiedSession(harness, "inv-565", "subject-565@example.invalid");
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
    const verifiedSession = await bringToVerifiedSession(harness, "inv-520", "subject-520@example.invalid");
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
    const verifiedSession = await bringToVerifiedSession(harness, "inv-522", "subject-522@example.invalid");
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

function seedOpenChannelUnreachableCase(ports: RightsCaseInMemoryPorts, handle: string): void {
  ports.tenantHandle.issue({ handle, tenantId: "tenant-1", chainRef: "chain-1", revokedDecisionRef: "decision-1" });
  ports.rightsCaseRepo.save({
    caseRef: "case-1",
    tenantId: "tenant-1",
    chainRef: "chain-1",
    revokedDecisionRef: "decision-1",
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
    seedOpenChannelUnreachableCase(harness.ports, "handle-A");
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
    seedOpenChannelUnreachableCase(harness.ports, "handle-B");
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
    const token = seedSentInvitation(harness.ports, "inv-532", "subject-532@example.invalid");
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
    const token = seedSentInvitation(harness.ports, "inv-533", "subject-533@example.invalid");
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
    const verifiedSession = await bringToVerifiedSession(harness, "inv-534", "subject-534@example.invalid");
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
    seedOpenChannelUnreachableCase(harness.ports, "handle-535");
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
    const token = seedSentInvitation(harness.ports, "inv-536", "subject-536@example.invalid");
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "application/json");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-537: GET /i/{token} inexistente (UniformNotFound, 404) sigue respondiendo application/json, no problem+json (contracts/openapi UniformNotFound)", async () => {
  const harness = await startConsentFlowServer();
  try {
    const res = await fetch(`${harness.baseUrl}/i/this-token-does-not-exist`, { redirect: "manual" });
    assert.equal(res.status, 404);
    assert.equal(res.headers.get("content-type"), "application/json");
  } finally {
    await harness.close();
  }
});
