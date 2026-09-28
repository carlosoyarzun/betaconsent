// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-102 (GET /m/{token}),
// API-CNS-120/121 (guardsByScope MANAGE/REVOCATION), API-CNS-130..134 (R1/R2/R3/R8/RV0);
// specs/state-machines/revocation.spec.yaml R1/R2/R3/R8; otp-challenge.spec.yaml V1/V3/V4
// byScope REVOCATION/MANAGE (INV-OT-06). CA-116 (UX-CNS-004, PR1 gestión/retiro self-service).
// Recorre el camino feliz completo por HTTP real (node:http en un puerto efímero de
// localhost): GET /m/{token} sobre una decisión GRANTED ya sembrada -> verificación MANAGE ->
// estado -> retiro (R1) -> verificación REVOCATION (R2) -> confirmación (R3->R4, APPLIED).
// Agrega un caso de cancelación (R8) y uno de bloqueo por intentos (V4, INV-OT-06: nunca
// FAILED de la Revocation).
// TEST-CNS-581..TEST-CNS-585.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const TENANT_ID = "tenant-mgmt";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const VALID_CSRF = { origin: ALLOWED_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh" };

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

function post(baseUrl: string, opts: PostOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);
  if (opts.sessionCookie !== undefined) cookieParts.push(`${SESSION_COOKIE_NAME}=${opts.sessionCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}${opts.path}`, { method: "POST", headers, body: JSON.stringify(opts.body ?? {}) });
}

interface Fixture {
  readonly ports: ConsentFlowPorts;
  readonly revocationPorts: RevocationFlowPorts;
  readonly server: Server;
  readonly baseUrl: string;
  readonly token: string;
}

async function setUp(chainRef: string, consentId: string, mgmtToken: string): Promise<Fixture> {
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: "subject-mgmt@example.invalid",
    decisionMakerRef: "dm:mgmt-seed",
    invitationRef: "inv-mgmt-seed",
    verificationRef: "ver-mgmt-seed",
    chainRef,
    state: "GRANTED",
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: `receipt-${consentId}`,
  });
  const revocationPorts = createDefaultRevocationFlowPorts(ports.decision.ledger);
  (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({
    handle: mgmtToken,
    tenantId: TENANT_ID,
    chainRef,
    revokedDecisionRef: consentId,
  });

  const server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports, revocationPorts });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
  return { ports, revocationPorts, server, baseUrl, token: mgmtToken };
}

test("TEST-CNS-581: GET /m/{token} -> verificación MANAGE -> estado -> R1 -> verificación REVOCATION -> R2 -> R3 llega a APPLIED; cadena del ledger consecutiva", async () => {
  const { ports, server, baseUrl } = await setUp("chain-581", "consent-581", "mgmt-token-581");
  try {
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-581`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    assert.equal(redeemed.headers.get("location"), "/manage");
    let sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const manageEntry = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    assert.equal(manageEntry.status, 200);
    assert.match(await manageEntry.text(), /start-verify-btn/);

    const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    assert.equal(requested.status, 202);
    sessionCookie = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const manageCode = sink.sent[sink.sent.length - 1]?.code ?? "";
    assert.ok(manageCode.length > 0);

    const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: manageCode } });
    assert.equal(submitted.status, 200);
    assert.deepEqual(await submitted.json(), { result: "VERIFIED", scope: "MANAGE" });
    sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const manageStatus = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    assert.equal(manageStatus.status, 200);
    assert.match(await manageStatus.text(), /start-revocation-btn/);

    const r1 = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie });
    assert.equal(r1.status, 200);
    const r1Body = (await r1.json()) as { revocationRef: string; status: string };
    assert.equal(r1Body.status, "REQUESTED");
    sessionCookie = parseSetCookie(r1)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const requestedRevOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    assert.equal(requestedRevOtp.status, 202);
    sessionCookie = parseSetCookie(requestedRevOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const revCode = sink.sent[sink.sent.length - 1]?.code ?? "";
    assert.ok(revCode.length > 0 && revCode !== manageCode);

    const submittedRev = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: revCode } });
    assert.equal(submittedRev.status, 200);
    assert.deepEqual(await submittedRev.json(), { result: "VERIFIED", scope: "REVOCATION" });
    sessionCookie = parseSetCookie(submittedRev)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const confirmPage = await fetch(`${baseUrl}/manage/revocation/confirm`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    assert.equal(confirmPage.status, 200);
    assert.match(await confirmPage.text(), /LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro \(total, sin retiro parcial\) e irreversibilidad desde esta pantalla \(protocolo l\.423\)/);

    const r2 = await post(baseUrl, { path: "/manage/revocation/verify", ...VALID_CSRF, sessionCookie });
    assert.equal(r2.status, 200);
    assert.equal((await r2.json() as { status: string }).status, "VERIFIED");

    const r3 = await post(baseUrl, { path: "/manage/revocation/confirm", ...VALID_CSRF, sessionCookie });
    assert.equal(r3.status, 200);
    const r3Body = (await r3.json()) as { revocationRef: string; status: string };
    assert.equal(r3Body.status, "APPLIED");

    const events = ports.decision.ledger.listByAggregate(TENANT_ID, "Revocation", r3Body.revocationRef);
    assert.deepEqual(
      events.map((e) => e.eventType),
      ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED"],
    );
    const sequences = events.map((e) => e.sequence).sort((a, b) => a - b);
    assert.deepEqual(sequences, [1, 2, 3, 4]);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-582: R8 (cancelar solicitud de retiro) desde REQUESTED responde FAILED; el consentimiento sigue vigente (no llega a APPLIED)", async () => {
  const { ports, server, baseUrl } = await setUp("chain-582", "consent-582", "mgmt-token-582");
  try {
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-582`, { redirect: "manual" });
    let sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const manageCode = sink.sent[sink.sent.length - 1]?.code ?? "";
    const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: manageCode } });
    sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const r1 = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(r1)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const r8 = await post(baseUrl, { path: "/manage/revocation/withdraw", ...VALID_CSRF, sessionCookie });
    assert.equal(r8.status, 200);
    const r8Body = (await r8.json()) as { status: string };
    assert.equal(r8Body.status, "FAILED");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-583: bloqueo por intentos incorrectos en scope REVOCATION (V4, LOCKED) nunca falla la Revocation (INV-OT-06); RV0 y RC1 fuente BEARER siguen respondiendo", async () => {
  const { ports, revocationPorts, server, baseUrl } = await setUp("chain-583", "consent-583", "mgmt-token-583");
  try {
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-583`, { redirect: "manual" });
    let sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const requestedMgmtOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requestedMgmtOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const manageCode = sink.sent[sink.sent.length - 1]?.code ?? "";
    const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: manageCode } });
    sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const r1 = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(r1)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const requestedRevOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requestedRevOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;

    let lastStatus = 0;
    let lastBody: { code?: string } = {};
    for (let i = 0; i < LOCAL_ONLY_TEST_OTP_POLICY.maxAttempts; i += 1) {
      const wrong = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: "000000" } });
      lastStatus = wrong.status;
      lastBody = (await wrong.json()) as { code?: string };
    }
    assert.equal(lastStatus, 422);
    assert.equal(lastBody.code, "OTP_LOCKED");

    // INV-OT-06: la Revocation sigue REQUESTED (nunca FAILED por el bloqueo del OTP).
    const r1Body = (await r1.json()) as { revocationRef: string };
    const revocation = revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, r1Body.revocationRef);
    assert.equal(revocation?.status, "REQUESTED");

    // Las dos vías reales del estado bloqueado (INV-OT-06) siguen disponibles con solo el
    // handle MANAGE_ENTRY (no exigen sesión MANAGE verificada, ver revocation-flow.handler.ts).
    const rv0 = await post(baseUrl, { path: "/manage/recovery-link", ...VALID_CSRF, sessionCookie });
    assert.equal(rv0.status, 202);

    const rc1 = await post(baseUrl, { path: "/rights-case/open", ...VALID_CSRF, sessionCookie });
    assert.equal(rc1.status, 200);
    assert.equal((await rc1.json() as { result: string }).result, "IN_REVIEW");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
