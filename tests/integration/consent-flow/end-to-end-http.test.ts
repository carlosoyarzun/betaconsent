// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-115, API-CNS-120, API-CNS-121,
// API-CNS-127; specs/state-machines/invitation.spec.yaml (I1..I7), otp-challenge.spec.yaml
// (V1, V3), consent-decision.spec.yaml (C1, C2, C3); common.spec.yaml ledgerEnvelope,
// tenancy.isolationKey. Recorre el camino feliz completo por HTTP real (node:http en un
// puerto efímero de localhost): invitación -> OTP (leído del sink en memoria) -> decisión, y
// verifica la cadena del ledger (sequence consecutivo por agregado, tenant_id en cada evento).
// TEST-CNS-507.

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
const CHANNEL_REF = "test+e2e-http@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
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
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });

  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });

  try {
    createInvitation(ports.invitation, TENANT_ID, "INVITER", {
      invitationRef: "inv-507",
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef: "subject-507@example.invalid",
    });
    markInvitationReady(ports.invitation, TENANT_ID, "INVITER", "inv-507", {
      consentVersion: "v1",
      expiresAt: new Date(Date.now() + 60_000),
      recipientChannelRef: CHANNEL_REF,
    });
    const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", "inv-507");

    // I4 vía HTTP.
    const opened = await post(baseUrl, { path: "/invitation/open", ...VALID_CSRF, body: { token } });
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

    // C1/C2/C3 vía HTTP en un solo POST (x-scope-note).
    const decided = await post(baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionVerified,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(decided.status, 200);
    const decidedBody = (await decided.json()) as { consentId: string; state: string };
    assert.equal(decidedBody.state, "GRANTED");

    assert.equal(ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-507")?.state, "COMPLETED");

    for (const [aggregateType, aggregateId] of [
      ["Invitation", "inv-507"],
      ["ConsentDecision", decidedBody.consentId],
    ] as const) {
      const events = ports.decision.ledger.listByAggregate(TENANT_ID, aggregateType, aggregateId);
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
