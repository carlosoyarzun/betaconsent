// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-103 (GET /r/{token}),
// API-CNS-134 (POST /manage/recovery-link, RV0 BEARER), API-CNS-135 (POST /recovery/revoke);
// specs/state-machines/revocation.spec.yaml RV0, R1r, R2r, R3r, R10, R11, GRD-RV-06, ERR-RV-05.
// CA-116 (UX-CNS-004, PR 2 recuperación). Recorre por HTTP real (node:http en un puerto
// efímero de localhost): /m/{token} -> POST /manage/recovery-link -> leer el enlace real del
// sink -> GET /r/{token} -> GET /recovery/confirm -> POST /recovery/revoke -> comprobante
// (CONFIRMED). Agrega reutilización de token (ERR-RV-05 uniforme), token inválido (200
// UniformAccepted) y R11 NOOP (revocación ya CONFIRMED).
// TEST-CNS-592..597 (unidad complementaria del dominio: TEST-CNS-589..591 en
// tests/unit/revocation/revocation-self-service.test.ts).

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const TENANT_ID = "tenant-recovery";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };
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
}

async function setUp(chainRef: string, consentId: string, mgmtToken: string): Promise<Fixture> {
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: "subject-recovery@example.invalid",
    decisionMakerRef: "dm:recovery-seed",
    invitationRef: "inv-recovery-seed",
    verificationRef: "ver-recovery-seed",
    chainRef,
    state: "GRANTED",
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: `receipt-${consentId}`,
  });
  const revocationPorts = createDefaultRevocationFlowPorts(LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY, ports.decision.ledger);
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
  return { ports, revocationPorts, server, baseUrl };
}

/** Pulsa "Enviar enlace de recuperación" (RV0 BEARER) desde la sesión MANAGE_ENTRY de
 * GET /m/{token} y devuelve el token en claro leído del sink LOCAL (nunca de la respuesta
 * HTTP: mismo criterio Cero PII que dev.ts /__dev/recovery-sink). */
async function issueRecoveryLink(baseUrl: string, revocationPorts: RevocationFlowPorts, mgmtToken: string): Promise<string> {
  const redeemed = await fetch(`${baseUrl}/m/${mgmtToken}`, { redirect: "manual" });
  const sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];
  const rv0 = await post(baseUrl, { path: "/manage/recovery-link", ...VALID_CSRF, sessionCookie });
  assert.equal(rv0.status, 202);
  const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
  const message = sink.sent[sink.sent.length - 1];
  assert.ok(message, "debe existir un mensaje en el sink de recuperación");
  const match = message.recoveryPath.match(/^\/r\/(.+)$/);
  assert.ok(match, "recoveryPath debe tener la forma /r/<token>");
  return match![1]!;
}

function stripHtmlComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

test("TEST-CNS-592: /m -> RV0 BEARER -> leer el enlace del sink -> GET /r/{token} -> /recovery/confirm -> POST /recovery/revoke llega a CONFIRMED (R1r+R2r+R3r)", async () => {
  const { revocationPorts, server, baseUrl } = await setUp("chain-589", "consent-589", "mgmt-token-589");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-589");

    const redeemed = await fetch(`${baseUrl}/r/${token}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    assert.equal(redeemed.headers.get("location"), "/recovery/confirm");
    assert.equal(redeemed.headers.get("referrer-policy"), "no-referrer");
    assert.equal(redeemed.headers.get("cache-control"), "no-store");
    const sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const confirmPage = await fetch(`${baseUrl}/recovery/confirm`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    assert.equal(confirmPage.status, 200);
    assert.match(await confirmPage.text(), /confirm-recovery-btn/);

    const revoke = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF, sessionCookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(revoke.status, 200);
    const body = (await revoke.json()) as { revocationRef: string; state: string; receiptDelivery: string };
    assert.equal(body.state, "CONFIRMED");
    assert.equal(body.receiptDelivery, "BOUND_CHANNEL");

    const events = revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", body.revocationRef);
    assert.deepEqual(
      events.map((e) => e.eventType),
      ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED"],
    );
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-593: reutilizar el mismo token de recuperación tras confirmarlo responde la uniforme de ERR-RV-05 (202), sin duplicar el evento", async () => {
  const { revocationPorts, server, baseUrl } = await setUp("chain-590", "consent-590", "mgmt-token-590");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-590");
    const redeemed = await fetch(`${baseUrl}/r/${token}`, { redirect: "manual" });
    const sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const first = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF, sessionCookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { revocationRef: string };

    const second = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF, sessionCookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(second.status, 202);
    assert.deepEqual(await second.json(), { result: "RECEIVED" });

    const events = revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", firstBody.revocationRef);
    assert.equal(events.filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 1);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-594: GET /r/{token} con un token inválido responde 200 UniformAccepted (ERR-RV-05, distinto del 404 de /i/ y /m/), sin fijar sesión", async () => {
  const { server, baseUrl } = await setUp("chain-591", "consent-591", "mgmt-token-591");
  try {
    const res = await fetch(`${baseUrl}/r/no-existe-este-token`, { redirect: "manual" });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { result: "RECEIVED" });
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("set-cookie"), null);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-595: un segundo enlace de recuperación sobre una Revocation ya APPLIED responde la uniforme de ERR-RV-05 (GRD-RV-27, 'más allá de APPLIED'), sin duplicar eventos", async () => {
  // R3r reutiliza confirmRevocation (mismo criterio que R3 self-service, PR1): en IT0, sin
  // worker/cola real, CONFIRMED -> APPLIED ocurre síncrono en la misma tx (revocation.ts nota
  // en confirmRevocation), así que un segundo enlace tras completar el primero siempre encuentra
  // la Revocation ya APPLIED, no CONFIRMED: GRD-RV-27 ("desde APPLIED+ respuesta uniforme"), no
  // R11. R11 (CONFIRMED sin APPLIED) se prueba a nivel de dominio en revocation-self-service.test.ts
  // (TEST-CNS-591), donde sí es observable construir ese estado intermedio directamente.
  const { revocationPorts, server, baseUrl } = await setUp("chain-592", "consent-592", "mgmt-token-592");
  try {
    const firstToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-592");
    const firstRedeemed = await fetch(`${baseUrl}/r/${firstToken}`, { redirect: "manual" });
    const firstSession = parseSetCookie(firstRedeemed)[SESSION_COOKIE_NAME];
    const firstRevoke = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF, sessionCookie: firstSession, body: { confirmTotalWithdrawal: true } });
    const firstBody = (await firstRevoke.json()) as { revocationRef: string };

    const secondToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-592");
    const secondRedeemed = await fetch(`${baseUrl}/r/${secondToken}`, { redirect: "manual" });
    const secondSession = parseSetCookie(secondRedeemed)[SESSION_COOKIE_NAME];
    const secondRevoke = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF, sessionCookie: secondSession, body: { confirmTotalWithdrawal: true } });
    assert.equal(secondRevoke.status, 202);
    assert.deepEqual(await secondRevoke.json(), { result: "RECEIVED" });

    const events = revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", firstBody.revocationRef);
    assert.equal(events.filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 1);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-596: GET /recovery/confirm sin sesión RECOVERY (sin canjear /r/{token} antes) muestra el error uniforme (33:106), nunca un 404 JSON crudo", async () => {
  const { server, baseUrl } = await setUp("chain-593", "consent-593", "mgmt-token-593");
  try {
    const res = await fetch(`${baseUrl}/recovery/confirm`, { redirect: "manual" });
    assert.equal(res.status, 404);
    const html = await res.text();
    assert.match(html, /error-uniform/);
    assert.match(html, /No pudimos continuar con este retiro\./);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-597: GET /recovery/confirm muestra visibles los dos marcadores [LEGAL DECISION] (efecto sobre los datos, y alcance/irreversibilidad), nunca solo dentro de un comentario HTML", async () => {
  const { revocationPorts, server, baseUrl } = await setUp("chain-594", "consent-594", "mgmt-token-594");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-594");
    const redeemed = await fetch(`${baseUrl}/r/${token}`, { redirect: "manual" });
    const sessionCookie = parseSetCookie(redeemed)[SESSION_COOKIE_NAME];

    const confirmPage = await fetch(`${baseUrl}/recovery/confirm`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    const visible = stripHtmlComments(await confirmPage.text());
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar \(supresión\/plazos\), protocolo l\.522\]/);
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro \(total, sin retiro parcial\) e irreversibilidad desde esta pantalla \(protocolo l\.423\)\]/);
    assert.match(visible, /class="lp-btn lp-btn-danger lp-revocation-cta lp-verify-tap-target" id="confirm-recovery-btn"/);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
