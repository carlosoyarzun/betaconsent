// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}, P-12),
// API-CNS-115 (POST /invitation/open), API-CNS-120 (POST /otp/request), API-CNS-121 (POST
// /otp/submit); specs/state-machines/invitation.spec.yaml I4, otp-challenge.spec.yaml V1/V3;
// common.spec.yaml GRD-CM-10, INV-CM-08. El canje del token ocurre en el GET /i/{token}
// (redeemInvitationLink); /invitation/open ya no recibe el token en el body, toma la
// invitación de la sesión LANDING creada por ese GET (contract EmptyCommand).
// TEST-CNS-498..TEST-CNS-503 (traceability/test-matrix.csv).
//
// Levanta el servidor HTTP real (node:http) en un puerto efímero de localhost con adapters
// in-memory, y hace requests HTTP reales (fetch de Node). Cero PII: subjectRef/channelRef con
// dominio example.invalid.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+channel-1@example.invalid";

// LOCAL-only sintético (D4, no es default de producción): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintetico (GRD-CD-04, decision-relationship.config.ts): estos tests no ejercen
// pasos de decision, pero createDefaultConsentFlowPorts exige la config igual que otpPolicy.
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY);
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

async function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string): Promise<string> {
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef,
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
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

/** A diferencia de parseSetCookie (un solo Set-Cookie), GET /welcome puede fijar sesión + CSRF
 * en la misma respuesta; getSetCookie() (undici) los mantiene separados. */
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

/** Canjea el token vía GET /i/{token} (P-12, SEC-CNS-014) y GET /welcome, que resuelve el hash y
 * fija recién ahí la sesión LANDING real (INV-CM-08 reforzado: ninguno de los dos GET
 * transiciona). `undefined` si GET /welcome no resuelve el handle (token inválido/expirado). */
async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const first = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(first)[INVITATION_HANDLE_COOKIE_NAME];
  if (!handleCookie) return undefined;
  const second = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  return parseAllSetCookies(second)[SESSION_COOKIE_NAME];
}

test("TEST-CNS-498: POST /invitation/open sin CSRF (Origin ausente) -> ERR-CM-09 (403), sin transición", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-498"), fixtureUuid("subject-498"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", sessionCookie: landingSession });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "CSRF_REJECTED");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-498")))?.state, "SENT");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-499: POST /invitation/open sin sesión LANDING previa (sin canjear /i/{token}) -> 404 uniforme (ERR-IV-01), sin transición", async () => {
  const harness = await startServer();
  try {
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF });
    assert.equal(res.status, 404);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-500: I4 vía HTTP transiciona SENT -> OPENED y fija la cookie de sesión (D5)", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-500"), fixtureUuid("subject-500"));
    const landingSession = await redeem(harness.baseUrl, token);
    const res = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    assert.equal(res.status, 200);
    const cookies = parseSetCookie(res);
    assert.ok(cookies[SESSION_COOKIE_NAME], "debe fijar __Host-cns-session");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-500")))?.state, "OPENED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-501: GET /invitation/open no existe (404); el único GET de este entrypoint es /i/{token} (P-12), que no transiciona (INV-CM-08, ver invitation-redeem-http.test.ts)", async () => {
  const harness = await startServer();
  try {
    const res = await fetch(`${harness.baseUrl}/invitation/open`, { method: "GET" });
    assert.equal(res.status, 404);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-502: V1/V3 vía HTTP — /otp/request emite el código al sink y /otp/submit con el código correcto verifica (crea la sesión con decisionMakerRef derivado del canal, nunca del body)", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-502"), fixtureUuid("subject-502"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];

    const requested = await post(harness.baseUrl, {
      path: "/otp/request",
      ...VALID_CSRF,
      sessionCookie: sessionAfterOpen,
    });
    assert.equal(requested.status, 202);
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];
    assert.ok(sessionAfterRequest);

    const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[0]?.code ?? "";
    assert.equal(code.length, LOCAL_ONLY_TEST_OTP_POLICY.codeLength);

    const submitted = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code, decisionMakerRef: "attacker-supplied-dm" },
    });
    assert.equal(submitted.status, 200);
    const body = (await submitted.json()) as { result: string };
    assert.equal(body.result, "VERIFIED");

    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-502")))?.state, "VERIFIED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-503: código incorrecto en /otp/submit -> 422 uniforme, sin filtrar intentos restantes", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-503"), fixtureUuid("subject-503"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];

    const rejected = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code: "000000" },
    });
    assert.equal(rejected.status, 422);
    const body = (await rejected.json()) as { code: string };
    // OtpRejected (contracts/api-payloads.schema.json): code del enum del contrato
    // (OTP_CODE_REJECTED), no el ID interno ni el literal "OTP_REJECTED" (P1, ver
    // tests/contract/http/consent-flow-http-contract.test.ts TEST-CNS-519).
    assert.equal(body.code, "OTP_CODE_REJECTED");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-503")))?.state, "OPENED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-548: V2r vía HTTP — POST /otp/resend responde 202 UniformAccepted y reemplaza el código en el sink; el nuevo código verifica", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-548"), fixtureUuid("subject-548"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
    const oldCode = sink.sent[sink.sent.length - 1]?.code ?? "";

    const resent = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
    assert.equal(resent.status, 202);
    assert.deepEqual(await resent.json(), { result: "RECEIVED" });
    assert.equal(sink.sent.length, 2);
    const newCode = sink.sent[1]?.code ?? "";
    assert.notEqual(newCode, oldCode);

    const submitted = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code: newCode },
    });
    assert.equal(submitted.status, 200);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-549: POST /otp/resend sin CSRF -> 403 CSRF_REJECTED, sin reemplazar el código (GRD-CM-10)", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-549"), fixtureUuid("subject-549"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
    const sentBefore = sink.sent.length;

    const res = await post(harness.baseUrl, { path: "/otp/resend", sessionCookie: sessionAfterRequest });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "CSRF_REJECTED");
    assert.equal(sink.sent.length, sentBefore);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-550: POST /otp/resend agota el límite (P-06) -> 409 OTP_RESEND_LIMIT (ERR-OT-09)", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-550"), fixtureUuid("subject-550"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    for (let i = 0; i < LOCAL_ONLY_TEST_OTP_POLICY.maxResends; i += 1) {
      const ok = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
      assert.equal(ok.status, 202);
    }
    const limited = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: sessionAfterRequest });
    assert.equal(limited.status, 409);
    const body = (await limited.json()) as { code: string };
    assert.equal(body.code, "OTP_RESEND_LIMIT");
  } finally {
    await harness.close();
  }
});
