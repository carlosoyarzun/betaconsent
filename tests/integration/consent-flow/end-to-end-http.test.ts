// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}, P-12),
// API-CNS-115, API-CNS-120, API-CNS-121, API-CNS-127; specs/state-machines/invitation.spec.yaml
// (I1..I7), otp-challenge.spec.yaml (V1, V3), consent-decision.spec.yaml (C1, C2, C3);
// common.spec.yaml ledgerEnvelope, tenancy.isolationKey, INV-CM-08. Recorre el camino feliz
// completo por HTTP real (node:http en un puerto efímero de localhost): canje del enlace (GET)
// -> invitación -> OTP (leído del sink en memoria) -> decisión, y verifica la cadena del
// ledger (sequence consecutivo por agregado, tenant_id en cada evento).
// TEST-CNS-507.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
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
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+e2e-http@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));
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

test("TEST-CNS-507: HTTP end-to-end invitación -> OTP (sink) -> decisión; cadena del ledger consecutiva y tenant_id en cada evento", async () => {
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });

  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });

  try {
    await createInvitation(ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
      invitationRef: fixtureUuid("inv-507"),
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef: fixtureUuid("subject-507"),
    });
    await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-507"), {
      consentVersion: "v1",
      expiresAt: new Date(Date.now() + 60_000),
      recipientChannelRef: CHANNEL_REF,
    });
    const { token } = await sendInvitation(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-507"), { deliveryChannel: "CONSENT_APP_EMAIL" });

    // GET /i/{token} (API-CNS-101, P-12, SEC-CNS-014): canje uniforme sin transición
    // (INV-CM-08 reforzado), fija solo el handle INVITATION_LANDING (Carlos, 2026-09-28).
    const redeemed = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const handleCookie = parseSetCookie(redeemed)[INVITATION_HANDLE_COOKIE_NAME];
    // GET /welcome resuelve el handle y crea recién ahí la sesión LANDING real.
    const welcome = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
    const landingSession = parseAllSetCookies(welcome)[SESSION_COOKIE_NAME];

    // I4 vía HTTP.
    const opened = await post(baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
    assert.equal(opened.status, 200);
    const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];

    // V1 vía HTTP; el código se lee del sink en memoria (nunca del ledger ni de un log).
    const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
    assert.equal(requested.status, 202);
    const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[0]?.code ?? "";
    assert.ok(code.length > 0);

    // V3 vía HTTP: crea la sesión con decisionMakerRef derivado del canal.
    const submitted = await post(baseUrl, {
      path: "/otp/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterRequest,
      body: { code },
    });
    assert.equal(submitted.status, 200);
    const sessionVerified = parseSetCookie(submitted)[SESSION_COOKIE_NAME];

    // C1 perezoso + C2 vía HTTP: un POST /decision/steps por paso (x-scope-note).
    const stepBodies: unknown[] = [
      { stepKind: "CONTEXT_INFORMATION_VIEWED" },
      { stepKind: "CONSENT_VERSION_VIEWED" },
      { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
      { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
    ];
    let sessionAfterSteps = sessionVerified;
    for (const stepBody of stepBodies) {
      const stepRes = await post(baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: sessionAfterSteps, body: stepBody });
      assert.equal(stepRes.status, 200);
      const nextCookie = parseSetCookie(stepRes)[SESSION_COOKIE_NAME];
      if (nextCookie) sessionAfterSteps = nextCookie;
    }

    // C3 vía HTTP.
    const decided = await post(baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(decided.status, 200);
    const decidedBody = (await decided.json()) as { consentId: string; state: string };
    assert.equal(decidedBody.state, "GRANTED");

    assert.equal((await ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-507")))?.state, "COMPLETED");

    for (const [aggregateType, aggregateId] of [
      ["Invitation", fixtureUuid("inv-507")],
      ["ConsentDecision", decidedBody.consentId],
    ] as const) {
      const events = await ports.decision.ledger.listByAggregate(TENANT_ID, aggregateType, aggregateId);
      assert.ok(events.length > 0, `${aggregateType} debía tener eventos en el ledger`);
      for (const event of events) {
        assert.equal(event.tenantId, TENANT_ID);
      }
      const sequences = events.map((e) => e.sequence).sort((a, b) => a - b);
      assert.deepEqual(sequences, Array.from({ length: sequences.length }, (_, i) => i + 1));
    }
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
