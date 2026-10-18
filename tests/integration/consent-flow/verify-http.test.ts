// Gobierna: UX-CNS-002 (handoff /verify, scratchpad verify-handoff.md), autorización de Carlos
// 2026-09-27 opción (a). specs/state-machines/otp-challenge.spec.yaml V1/V2/V2r/V3/V4/V5;
// contracts/openapi/consent-it0.openapi.yaml API-CNS-120/121/122. GET /verify exige la sesión
// con el OTP ya solicitado (session.verificationRef); sin ella sirve el estado de error
// uniforme de la propia pantalla (INV-CM-05), nunca un 404 crudo. GET /decision es, por ahora,
// un placeholder mínimo (Carlos 2026-09-27), igual patrón que lo fue /verify.
// TEST-CNS-553..TEST-CNS-56x (traceability/test-matrix.csv).

import { SYNTHETIC_SPA_DIST_DIR } from "../../helpers/synthetic-spa-dist.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY, TEST_GUEST_CHANNEL } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+verify@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
// SEC-CNS-021 PR-4: P-06 aprobado (3 envios/h, el inicial incluido) rige; solo se anula la separacion de 60 s (LOCAL_ONLY) para poder reenviar de inmediato.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, minResendIntervalMs: 0 };
// LOCAL-only sintetico (GRD-CD-04, decision-relationship.config.ts): estos tests no ejercen
// pasos de decision, pero createDefaultConsentFlowPorts exige la config igual que otpPolicy.
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const server: Server = createConsentFlowHttpServer({ spaDistDir: SYNTHETIC_SPA_DIST_DIR, guestMessageChannel: TEST_GUEST_CHANNEL, sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
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

/** SEC-CNS-014 (Carlos, 2026-09-28): GET /i/{token} ya no fija la sesión directamente, solo el
 * handle INVITATION_LANDING; la sesión real la fija GET /welcome al resolverlo. */
async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const first = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  const handleCookie = parseAllSetCookies(first)[INVITATION_HANDLE_COOKIE_NAME];
  if (!handleCookie) return undefined;
  const second = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  return parseAllSetCookies(second)[SESSION_COOKIE_NAME];
}

/** invitación -> canje -> open -> otp/request; devuelve la sesión con verificationRef ya
 * fijado (la que GET /verify exige) y el sink para leer el código emitido. */
async function bringToOtpRequested(
  harness: Harness,
  invitationRef: string,
  subjectRef: string,
): Promise<{ session: string; sink: InMemoryOtpChannelSink }> {
  const token = await seedSentInvitation(harness.ports, invitationRef, subjectRef);
  const landingSession = await redeem(harness.baseUrl, token);
  const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
  const sessionAfterOpen = parseAllSetCookies(opened)[SESSION_COOKIE_NAME] ?? landingSession;
  const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
  const session = parseAllSetCookies(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;
  if (!session) throw new Error("no se obtuvo sesión con verificationRef");
  return { session, sink: harness.ports.otp.channel as InMemoryOtpChannelSink };
}

test("TEST-CNS-553: GET /verify con sesión válida (OTP ya solicitado) responde 200 con el shell de la SPA y las cabeceras de seguridad", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, fixtureUuid("inv-553"), fixtureUuid("subject-553"));
    const res = await fetch(`${harness.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("content-security-policy"), "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff"); // F-E2E-02
    const html = await res.text();
    assert.match(html, /<html lang="es">/);
    assert.match(html, /<div id="root"><\/div>/); // el contenido lo pinta la SPA (TEST-CNS-1906 / E2E-CNS-010)
    assert.match(html, /<meta name="cns-page-state" content="ready">/);
    assert.doesNotMatch(html, /<script>/);
    assert.ok(parseAllSetCookies(res)[CSRF_COOKIE_NAME], "fija la cookie CSRF del double-submit");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-556: GET /decision sin sesión verificada responde 404 con el shell uniform-error de la SPA (UX-CNS-003), no un 404 JSON crudo", async () => {
  const harness = await startServer();
  try {
    const res = await fetch(`${harness.baseUrl}/decision`);
    assert.equal(res.status, 404);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const html = await res.text();
    assert.match(html, /<meta name="cns-page-state" content="uniform-error">/); // E2E-CNS-032 / TEST-CNS-1997
    assert.doesNotMatch(html, /"status":404/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-558: flujo completo GET /i/{token} -> /welcome -> open -> request -> /verify -> submit con el código correcto del sink -> /decision", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-558"), fixtureUuid("subject-558"));
    const landingSession = await redeem(harness.baseUrl, token);
    const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    const sessionAfterOpen = parseAllSetCookies(opened)[SESSION_COOKIE_NAME] ?? landingSession;
    const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    const sessionAfterRequest = parseAllSetCookies(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;

    const verifyPage = await fetch(`${harness.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionAfterRequest}` } });
    assert.equal(verifyPage.status, 200);

    const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[sink.sent.length - 1]?.code ?? "";
    assert.ok(code, "el sink debe tener el código emitido por /otp/request");

    const submitted = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code },
    });
    assert.equal(submitted.status, 200);
    assert.deepEqual(await submitted.json(), { result: "VERIFIED", scope: "DECISION" });
    const sessionVerified = parseAllSetCookies(submitted)[SESSION_COOKIE_NAME] ?? sessionAfterRequest;

    const decision = await fetch(`${harness.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionVerified}` } });
    assert.equal(decision.status, 200);
    assert.match(await decision.text(), /<meta name="cns-page-state" content="ready">/); // shell de la SPA (E2E-CNS-012 / TEST-CNS-1977)
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-559: código incorrecto en /verify no expone intentos restantes en la respuesta de /otp/submit", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, fixtureUuid("inv-559"), fixtureUuid("subject-559"));
    const rejected = await post(harness.baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: session,
      body: { code: "000000" },
    });
    assert.equal(rejected.status, 422);
    const body = (await rejected.json()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), ["code", "correlationId", "status"]);
    assert.equal(body.code, "OTP_CODE_REJECTED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-560: reenviar el código (POST /otp/resend) desde /verify reemplaza el código; el código viejo ya no verifica y el nuevo sí", async () => {
  const harness = await startServer();
  try {
    const { session, sink } = await bringToOtpRequested(harness, fixtureUuid("inv-560"), fixtureUuid("subject-560"));
    const oldCode = sink.sent[sink.sent.length - 1]?.code ?? "";

    const resent = await post(harness.baseUrl, { path: "/otp/resend", ...VALID_CSRF, sessionCookie: session });
    assert.equal(resent.status, 202);
    const newCode = sink.sent[sink.sent.length - 1]?.code ?? "";
    assert.notEqual(newCode, oldCode);

    const oldRejected = await post(harness.baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie: session, body: { code: oldCode } });
    assert.equal(oldRejected.status, 422);

    const verified = await post(harness.baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie: session, body: { code: newCode } });
    assert.equal(verified.status, 200);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-561: frontend/src/styles/app.css fija min-height 48px (tap target, D-05 Carlos 2026-10-14) para .lp-verify-tap-target, .lp-verify-cta y .lp-verify-code-input (fix Carlos, probado en navegador)", () => {
  const css = readFileSync(new URL("../../../frontend/src/styles/app.css", import.meta.url), "utf8"); // el CSS del invitado vive en frontend/ (SSR retirado)
  assert.match(css, /\.lp-verify-tap-target\s*\{[^}]*min-height:\s*48px/);
  assert.match(css, /\.lp-verify-cta[^{]*\{[^}]*min-height:\s*48px/);
  assert.match(css, /\.lp-verify-code-input\s*\{[^}]*min-height:\s*52px/);
});
