// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-127 (POST /decision/submit,
// consolida C1/C2/C3/C5 en un solo POST IT0, ver x-scope-note en consent-flow.handler.ts);
// specs/state-machines/consent-decision.spec.yaml C1/C2/C3/C5; SM-CNS-001 R0.2 (actor/refs
// derivados de la sesión, nunca del body). `bringToVerifiedSession` recorre GET /i/{token}
// (API-CNS-101, P-12) -> POST /invitation/open -> V1 -> V3.
// TEST-CNS-504..TEST-CNS-506 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+channel-2@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
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

/** Recorre invitación -> OTP hasta dejar una sesión verificada (post-V3), lista para
 * /decision/submit. Devuelve la cookie de sesión verificada. */
async function bringToVerifiedSession(harness: Harness, invitationRef: string, subjectRef: string): Promise<string> {
  createInvitation(harness.ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  markInvitationReady(harness.ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(harness.ports.invitation, TENANT_ID, "INVITER", invitationRef);

  const redeemed = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
  const landingSession = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];
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

/** Recorre C2 (POST /decision/steps) completo: CONTEXT_INFORMATION_VIEWED,
 * CONSENT_VERSION_VIEWED, DECISION_MAKER_AUTHORITY_DECLARED y SUBJECT_CONFIRMED, en ese orden.
 * Devuelve la cookie de sesión final (con `consentId` ya fijado por C1 perezoso). */
async function completeDecisionSteps(harness: Harness, sessionCookie: string): Promise<string> {
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

test("TEST-CNS-504: sin sesión verificada (sin pasar por V3), /decision/submit -> 404 uniforme", async () => {
  const harness = await startServer();
  try {
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(res.status, 404);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-564: /decision/submit sin haber completado los pasos de C2 (incluido DECISION_MAKER_AUTHORITY_DECLARED) -> 409 DECISION_STEPS_INCOMPLETE (ERR-CD-04, GRD-CD-05)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, "inv-564", "subject-564@example.invalid");

    // Ningún POST /decision/steps previo: la sesión no tiene consentId todavía, así que el
    // servidor ni siquiera puede resolver una decisión PENDING (404 uniforme, mismo patrón que
    // TEST-CNS-504 sin sesión verificada: "sin pasos" y "sin decisión iniciada" son
    // indistinguibles en este slice porque C1 es perezoso, ver x-scope-note del handler).
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: verifiedSession,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(res.status, 404);

    // Con C1 ya iniciado (un paso registrado) pero SIN completar los 4 pasos de C2, el submit sí
    // resuelve la decisión PENDING y falla por GRD-CD-05 (prior_steps_complete): ERR-CD-04 ->
    // DECISION_STEPS_INCOMPLETE (EXTERNAL_ERROR_CODE, consent-flow.handler.ts).
    const oneStepDone = await post(harness.baseUrl, {
      path: "/decision/steps",
      ...VALID_CSRF,
      sessionCookie: verifiedSession,
      body: { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    });
    assert.equal(oneStepDone.status, 200);
    const sessionWithConsentId = parseSetCookie(oneStepDone)[SESSION_COOKIE_NAME] ?? verifiedSession;

    const incomplete = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionWithConsentId,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(incomplete.status, 409);
    const body = (await incomplete.json()) as { code: string };
    assert.equal(body.code, "DECISION_STEPS_INCOMPLETE");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-505: /decision/submit ignora decisionMakerRef del body; el actor se deriva de la sesión (C1/C2/C3 -> GRANTED, dispara I6)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, "inv-505", "subject-505@example.invalid");
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);

    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: GRANT_ALL, decisionMakerRef: "attacker-supplied-dm" },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { consentId: string; state: string };
    assert.equal(body.state, "GRANTED");

    const decision = harness.ports.decision.repo.findByConsentId(TENANT_ID, body.consentId);
    // El decisionMakerRef persistido nunca es el valor "attacker-supplied-dm" del body.
    assert.notEqual(decision?.decisionMakerRef, "attacker-supplied-dm");
    assert.equal(harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-505")?.state, "COMPLETED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-506: /decision/submit con >=1 finalidad requerida en DECLINE -> DECLINED, dispara I7", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, "inv-506", "subject-506@example.invalid");
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const purposes = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose, i) => ({
      purpose,
      choice: i === 0 ? ("DECLINE" as const) : ("GRANT" as const),
    }));

    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { state: string };
    assert.equal(body.state, "DECLINED");
    assert.equal(harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-506")?.state, "DECLINED");
  } finally {
    await harness.close();
  }
});
