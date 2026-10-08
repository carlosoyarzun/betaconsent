// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-103 (GET /r/{token}, ahora
// RecoveryRedeemSeeOther: 303 uniforme, sin BD), API-CNS-134 (POST /manage/recovery-link, RV0
// BEARER), API-CNS-135 (POST /recovery/revoke); specs/state-machines/revocation.spec.yaml RV0,
// R1r, R2r, R3r, R10, R11, GRD-RV-06, ERR-RV-05; specs/state-machines/common.spec.yaml
// INV-CM-08. CA-116 (UX-CNS-004, PR 2 recuperación) + SEC-CNS-014 (revisión APROBADA CON
// CAMBIOS, Carlos 2026-09-28 opción (a)): GET /r/{token} deja de leer la BD; solo fija la
// cookie firmada `__Host-cns-recovery` (recovery-handle.ts) con el hash del token, y responde
// SIEMPRE el mismo 303 a /recovery/confirm. GRD-RV-06/ERR-RV-05 se evalúan en GET
// /recovery/confirm (render, solo lectura) y en POST /recovery/revoke (consumo). Recorre por
// HTTP real (node:http en un puerto efímero de localhost): /m/{token} -> POST
// /manage/recovery-link -> leer el enlace real del sink -> GET /r/{token} -> GET
// /recovery/confirm -> POST /recovery/revoke -> comprobante (CONFIRMED). Agrega reutilización
// de token (ERR-RV-05 uniforme), token inválido (303 uniforme), R11 NOOP (revocación ya
// CONFIRMED), comparación byte a byte entre clases de token/handle, aislamiento de cookies y
// fijación del CSRF ligado al handle.
// TEST-CNS-592..600,604,605 (unidad complementaria del dominio: TEST-CNS-589..591,598 en
// tests/unit/revocation/revocation-self-service.test.ts).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { RecoveryTokenRepositoryPort } from "../../../src/server/ports/recovery-token.port.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const RECOVERY_COOKIE_NAME = "__Host-cns-recovery";
const MANAGE_ENTRY_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
const TENANT_ID = "5ab701b7-c97e-4715-8e69-45b9fc1d7123";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };
const LOCAL_ONLY_TEST_RECOVERY_HANDLE_POLICY = { ttlMs: 60_000 };

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

/** GET /manage puede fijar sesión + CSRF en la misma respuesta; getSetCookie() (undici) los
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
  readonly recoveryCookie?: string;
  readonly body?: unknown;
}

function post(baseUrl: string, opts: PostOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);
  if (opts.sessionCookie !== undefined) cookieParts.push(`${SESSION_COOKIE_NAME}=${opts.sessionCookie}`);
  if (opts.recoveryCookie !== undefined) cookieParts.push(`${RECOVERY_COOKIE_NAME}=${opts.recoveryCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}${opts.path}`, { method: "POST", headers, body: JSON.stringify(opts.body ?? {}) });
}

const VALID_CSRF_ORIGIN = { origin: ALLOWED_ORIGIN };

interface Fixture {
  readonly ports: ConsentFlowPorts;
  readonly revocationPorts: RevocationFlowPorts;
  readonly server: Server;
  readonly baseUrl: string;
}

async function setUp(chainRef: string, consentId: string, mgmtToken: string): Promise<Fixture> {
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  await ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-recovery"),
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
  const revocationPorts = createDefaultRevocationFlowPorts(LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY, ports.decision.ledger, ports.decision.repo);
  (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({
    handle: mgmtToken,
    tenantId: TENANT_ID,
    chainRef,
    revokedDecisionRef: consentId,
  });

  const server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    revocationPorts,
    recoveryHandlePolicy: LOCAL_ONLY_TEST_RECOVERY_HANDLE_POLICY,
  });
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
  // SEC-CNS-014 (Carlos, 2026-09-28): GET /m/{token} ya no fija la sesión directamente, solo el
  // handle MANAGE_ENTRY; la sesión real la fija GET /manage al resolverlo.
  const redeemed = await fetch(`${baseUrl}/m/${mgmtToken}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(redeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME];
  const manage = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const sessionCookie = parseAllSetCookies(manage)[SESSION_COOKIE_NAME];
  const rv0 = await post(baseUrl, { path: "/manage/recovery-link", ...VALID_CSRF_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh", sessionCookie });
  assert.equal(rv0.status, 202);
  const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
  const message = sink.sent[sink.sent.length - 1];
  assert.ok(message, "debe existir un mensaje en el sink de recuperación");
  const match = message.recoveryPath.match(/^\/r\/(.+)$/);
  assert.ok(match, "recoveryPath debe tener la forma /r/<token>");
  return match![1]!;
}

/** GET /r/{token} -> 303 -> devuelve la cookie __Host-cns-recovery fijada. */
async function redeemRecoveryToken(baseUrl: string, token: string): Promise<{ res: Response; recoveryCookie: string }> {
  const res = await fetch(`${baseUrl}/r/${token}`, { redirect: "manual" });
  const recoveryCookie = parseSetCookie(res)[RECOVERY_COOKIE_NAME]!;
  return { res, recoveryCookie };
}

/** GET /recovery/confirm con la cookie de recuperación -> devuelve la respuesta y, si 200, el
 * token CSRF ligado al handle (Set-Cookie __Host-cns-csrf). */
async function renderRecoveryConfirm(baseUrl: string, recoveryCookie: string): Promise<{ res: Response; csrfToken?: string }> {
  const res = await fetch(`${baseUrl}/recovery/confirm`, { headers: { cookie: `${RECOVERY_COOKIE_NAME}=${recoveryCookie}` } });
  const csrfToken = parseSetCookie(res)[CSRF_COOKIE_NAME];
  return { res, csrfToken };
}

function stripHtmlComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

const CONSENT_592 = "592a3c52-8d4e-4a7b-9c21-0e5a7d3b9f92";

test("TEST-CNS-592: /m -> RV0 BEARER -> leer el enlace del sink -> GET /r/{token} -> /recovery/confirm -> POST /recovery/revoke llega a CONFIRMED (R1r+R2r+R3r)", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-589"), CONSENT_592, "mgmt-token-589");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-589");

    const { res: redeemed, recoveryCookie } = await redeemRecoveryToken(baseUrl, token);
    assert.equal(redeemed.status, 303);
    assert.equal(redeemed.headers.get("location"), "/recovery/confirm");
    assert.equal(redeemed.headers.get("referrer-policy"), "no-referrer");
    assert.equal(redeemed.headers.get("cache-control"), "no-store");
    assert.ok(recoveryCookie, "GET /r/{token} debe fijar __Host-cns-recovery");

    const { res: confirmPage, csrfToken } = await renderRecoveryConfirm(baseUrl, recoveryCookie);
    assert.equal(confirmPage.status, 200);
    assert.match(await confirmPage.text(), /confirm-recovery-btn/);
    assert.ok(csrfToken, "GET /recovery/confirm debe fijar el CSRF ligado al handle");

    const revoke = await post(baseUrl, {
      path: "/recovery/revoke",
      ...VALID_CSRF_ORIGIN,
      csrfHeader: csrfToken,
      csrfCookie: csrfToken,
      recoveryCookie,
      body: { confirmTotalWithdrawal: true },
    });
    assert.equal(revoke.status, 200);
    const body = (await revoke.json()) as { revocationRef: string; state: string; receiptDelivery: string };
    assert.equal(body.state, "CONFIRMED");
    assert.equal(body.receiptDelivery, "BOUND_CHANNEL");

    const events = await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", body.revocationRef);
    assert.deepEqual(
      events.map((e) => e.eventType),
      ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"],
    );
    // CA-127: evidencia válida contra el schema; RECOVERY/CHANNEL_LINK; receiptRef == comprobante mostrado.
    assertRevocationEvidence(events, { revocationRef: body.revocationRef, authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", revokedDecisionRef: CONSENT_592 });
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-593: reutilizar el mismo token de recuperación tras confirmarlo responde la uniforme de ERR-RV-05 (202), sin duplicar el evento", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-590"), fixtureUuid("consent-590"), "mgmt-token-590");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-590");
    const { recoveryCookie } = await redeemRecoveryToken(baseUrl, token);
    const { csrfToken } = await renderRecoveryConfirm(baseUrl, recoveryCookie);

    const first = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF_ORIGIN, csrfHeader: csrfToken, csrfCookie: csrfToken, recoveryCookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { revocationRef: string };

    const second = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF_ORIGIN, csrfHeader: csrfToken, csrfCookie: csrfToken, recoveryCookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(second.status, 202);
    assert.deepEqual(await second.json(), { result: "RECEIVED" });

    const events = await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", firstBody.revocationRef);
    assert.equal(events.filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 1);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-594: GET /r/{token} con un token inválido responde 303 uniforme (Location /recovery/confirm, Set-Cookie presente), nunca 404 ni 200 con cuerpo", async () => {
  const { server, baseUrl } = await setUp(fixtureUuid("chain-591"), fixtureUuid("consent-591"), "mgmt-token-591");
  try {
    const res = await fetch(`${baseUrl}/r/no-existe-este-token`, { redirect: "manual" });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "/recovery/confirm");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.ok(res.headers.get("set-cookie"), "debe fijar __Host-cns-recovery aunque el token sea inválido (SEC-CNS-014)");
    assert.match(res.headers.get("set-cookie") ?? "", new RegExp(`^${RECOVERY_COOKIE_NAME}=`));
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
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-592"), fixtureUuid("consent-592"), "mgmt-token-592");
  try {
    const firstToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-592");
    const { recoveryCookie: firstCookie } = await redeemRecoveryToken(baseUrl, firstToken);
    const { csrfToken: firstCsrf } = await renderRecoveryConfirm(baseUrl, firstCookie);
    const firstRevoke = await post(baseUrl, {
      path: "/recovery/revoke",
      ...VALID_CSRF_ORIGIN,
      csrfHeader: firstCsrf,
      csrfCookie: firstCsrf,
      recoveryCookie: firstCookie,
      body: { confirmTotalWithdrawal: true },
    });
    const firstBody = (await firstRevoke.json()) as { revocationRef: string };

    const secondToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-592");
    const { recoveryCookie: secondCookie } = await redeemRecoveryToken(baseUrl, secondToken);
    // C6 (GRD-RV-06): con la decisión ya REVOKED el render de /recovery/confirm da el error
    // uniforme (404, sin CSRF); el POST directo (mismo par CSRF del primero) sigue uniforme.
    const { res: secondRender, csrfToken: noCsrf } = await renderRecoveryConfirm(baseUrl, secondCookie);
    assert.equal(secondRender.status, 404);
    assert.equal(noCsrf, undefined);
    const secondCsrf = firstCsrf;
    const secondRevoke = await post(baseUrl, {
      path: "/recovery/revoke",
      ...VALID_CSRF_ORIGIN,
      csrfHeader: secondCsrf,
      csrfCookie: secondCsrf,
      recoveryCookie: secondCookie,
      body: { confirmTotalWithdrawal: true },
    });
    assert.equal(secondRevoke.status, 202);
    assert.deepEqual(await secondRevoke.json(), { result: "RECEIVED" });

    const events = await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", firstBody.revocationRef);
    assert.equal(events.filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 1);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-596: GET /recovery/confirm sin cookie de recuperación (sin canjear /r/{token} antes) muestra el error uniforme (33:106), nunca un 404 JSON crudo", async () => {
  const { server, baseUrl } = await setUp(fixtureUuid("chain-593"), fixtureUuid("consent-593"), "mgmt-token-593");
  try {
    const res = await fetch(`${baseUrl}/recovery/confirm`, { redirect: "manual" });
    assert.equal(res.status, 404);
    const html = await res.text();
    assert.match(html, /error-uniform/);
    assert.match(html, /No pudimos continuar con este retiro\./);
    assert.equal(res.headers.get("content-security-policy"), "default-src 'self'; frame-ancestors 'none'");
    assert.equal(res.headers.get("cross-origin-opener-policy"), "same-origin");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-597: GET /recovery/confirm muestra visibles los dos marcadores [LEGAL DECISION] (efecto sobre los datos, y alcance/irreversibilidad), nunca solo dentro de un comentario HTML", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-594"), fixtureUuid("consent-594"), "mgmt-token-594");
  try {
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-594");
    const { recoveryCookie } = await redeemRecoveryToken(baseUrl, token);

    const { res: confirmPage } = await renderRecoveryConfirm(baseUrl, recoveryCookie);
    const visible = stripHtmlComments(await confirmPage.text());
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar \(supresión\/plazos\), protocolo l\.522\]/);
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro \(total, sin retiro parcial\) e irreversibilidad desde esta pantalla \(protocolo l\.423\)\]/);
    assert.match(visible, /class="lp-btn lp-btn-danger lp-revocation-cta lp-verify-tap-target" id="confirm-recovery-btn"/);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-600: GET /r/{token} responde idéntico (status, headers, Location, atributos y largo del Set-Cookie) para un token válido, inexistente, consumido, expirado y demasiado largo; findByTokenHash nunca se llama en este GET", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-600"), fixtureUuid("consent-600"), "mgmt-token-600");
  try {
    // CA-124: la resolución por hash ya no es `recoveryTokenRepo.findByTokenHash` sino
    // `tenantResolver.byRecoveryTokenHash` (+ `recoveryTokenRepo.findByRef`); GET /r/{token} no
    // debe tocar ninguna de las dos.
    let findByTokenHashCalls = 0;
    const realResolver = revocationPorts.revocation.tenantResolver;
    const realRepo: RecoveryTokenRepositoryPort = revocationPorts.revocation.recoveryTokenRepo;
    (revocationPorts.revocation as { tenantResolver: typeof realResolver }).tenantResolver = {
      ...realResolver,
      byRecoveryTokenHash: (hash) => {
        findByTokenHashCalls += 1;
        return realResolver.byRecoveryTokenHash(hash);
      },
    };
    (revocationPorts.revocation as { recoveryTokenRepo: RecoveryTokenRepositoryPort }).recoveryTokenRepo = {
      ...realRepo,
      findByRef: (tenantId, recoveryRef) => {
        findByTokenHashCalls += 1;
        return realRepo.findByRef(tenantId, recoveryRef);
      },
    };

    const validToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-600");

    // Token consumido: lo canjeamos y confirmamos primero, con un token/mgmt distinto para no
    // interferir con el token "válido" de arriba (que debe seguir sin consumir para esta prueba).
    const consumedToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-600");
    const { recoveryCookie: consumedCookie } = await redeemRecoveryToken(baseUrl, consumedToken);
    const { csrfToken: consumedCsrf } = await renderRecoveryConfirm(baseUrl, consumedCookie);
    await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF_ORIGIN, csrfHeader: consumedCsrf, csrfCookie: consumedCsrf, recoveryCookie: consumedCookie, body: { confirmTotalWithdrawal: true } });

    findByTokenHashCalls = 0; // solo nos interesan las llamadas de los GET /r/ de abajo.

    const tooLongToken = "x".repeat(5_000);
    const candidates = [validToken, "token-inexistente-cualquiera", consumedToken, tooLongToken];

    const responses: { status: number; location: string | null; referrer: string | null; cache: string | null; setCookieLength: number }[] = [];
    for (const candidate of candidates) {
      const res = await fetch(`${baseUrl}/r/${encodeURIComponent(candidate)}`, { redirect: "manual" });
      const setCookie = res.headers.get("set-cookie") ?? "";
      responses.push({
        status: res.status,
        location: res.headers.get("location"),
        referrer: res.headers.get("referrer-policy"),
        cache: res.headers.get("cache-control"),
        setCookieLength: setCookie.length,
      });
    }

    assert.equal(findByTokenHashCalls, 0, "GET /r/{token} nunca debe leer recoveryTokenRepo (SEC-CNS-014 P1)");
    const [first, ...rest] = responses;
    for (const other of rest) {
      assert.deepEqual(other, first);
    }
    assert.equal(first!.status, 303);
    assert.equal(first!.location, "/recovery/confirm");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-601: GET /recovery/confirm responde 404 byte-idéntico (33:106) para un token inválido, uno consumido y uno expirado; ningún GET emite eventos ni consume el token", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-601"), fixtureUuid("consent-601"), "mgmt-token-601");
  try {
    // Inválido: nunca existió.
    const { recoveryCookie: invalidCookie } = await redeemRecoveryToken(baseUrl, "token-que-nunca-existio-601");
    const invalidRes = await fetch(`${baseUrl}/recovery/confirm`, { headers: { cookie: `${RECOVERY_COOKIE_NAME}=${invalidCookie}` } });

    // Consumido: se canjea, confirma y se reutiliza la MISMA cookie de recuperación (ya
    // consumida por el POST) para pedir /recovery/confirm de nuevo.
    const consumedToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-601");
    const { recoveryCookie: consumedCookie } = await redeemRecoveryToken(baseUrl, consumedToken);
    const { csrfToken: consumedCsrf } = await renderRecoveryConfirm(baseUrl, consumedCookie);
    const consumedRevoke = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF_ORIGIN, csrfHeader: consumedCsrf, csrfCookie: consumedCsrf, recoveryCookie: consumedCookie, body: { confirmTotalWithdrawal: true } });
    const { revocationRef: consumedRevocationRef } = (await consumedRevoke.json()) as { revocationRef: string };
    const eventsBefore = (await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", consumedRevocationRef)).length;
    const consumedRes = await fetch(`${baseUrl}/recovery/confirm`, { headers: { cookie: `${RECOVERY_COOKIE_NAME}=${consumedCookie}` } });

    // Expirado: TTL del handle (P-18) vencido -> decodeRecoveryHandle ya lo trata como ausente.
    const expiringServer = await setUp(fixtureUuid("chain-601b"), fixtureUuid("consent-601b"), "mgmt-token-601b");
    try {
      const almostExpiredServer = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
        config: { allowedOrigin: ALLOWED_ORIGIN },
        ports: expiringServer.ports,
        revocationPorts: expiringServer.revocationPorts,
        recoveryHandlePolicy: { ttlMs: 1 },
      });
      const addr = await new Promise<string>((resolve) => {
        almostExpiredServer.listen(0, "127.0.0.1", () => {
          const address = almostExpiredServer.address() as AddressInfo;
          resolve(`http://127.0.0.1:${address.port}`);
        });
      });
      try {
        const expiredToken = await issueRecoveryLink(addr, expiringServer.revocationPorts, "mgmt-token-601b");
        const { recoveryCookie: expiredCookie } = await redeemRecoveryToken(addr, expiredToken);
        await new Promise((resolve) => setTimeout(resolve, 20));
        const expiredRes = await fetch(`${addr}/recovery/confirm`, { headers: { cookie: `${RECOVERY_COOKIE_NAME}=${expiredCookie}` } });

        const invalidHtml = await invalidRes.text();
        const consumedHtml = await consumedRes.text();
        const expiredHtml = await expiredRes.text();
        assert.equal(invalidRes.status, 404);
        assert.equal(consumedRes.status, 404);
        assert.equal(expiredRes.status, 404);
        assert.equal(invalidHtml, consumedHtml);
        assert.equal(consumedHtml, expiredHtml);
      } finally {
        await new Promise((resolve) => almostExpiredServer.close(() => resolve(undefined)));
        await new Promise((resolve) => expiringServer.server.close(() => resolve(undefined)));
      }
    } finally {
      // no-op: expiringServer.server ya se cerró arriba.
    }

    const eventsAfter = (await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", consumedRevocationRef)).length;
    assert.equal(eventsAfter, eventsBefore, "ningún GET /recovery/confirm debe emitir eventos");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-604: fijación de la cookie de recuperación entre el render de 33:87 y el POST — si __Host-cns-recovery cambia, el POST /recovery/revoke se rechaza (CSRF ligado al hash, P2)", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-604"), fixtureUuid("consent-604"), "mgmt-token-604");
  try {
    const victimToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-604");
    const { recoveryCookie: victimCookie } = await redeemRecoveryToken(baseUrl, victimToken);
    const { csrfToken: victimCsrf } = await renderRecoveryConfirm(baseUrl, victimCookie);

    // El atacante fija una cookie de recuperación distinta (otro token, aunque inválido) justo
    // antes del POST: el CSRF de la víctima quedó ligado al hash de victimCookie, no al de la
    // cookie que efectivamente viaja en este POST.
    const { recoveryCookie: attackerCookie } = await redeemRecoveryToken(baseUrl, "token-atacante-604");

    const revoke = await post(baseUrl, {
      path: "/recovery/revoke",
      ...VALID_CSRF_ORIGIN,
      csrfHeader: victimCsrf,
      csrfCookie: victimCsrf,
      recoveryCookie: attackerCookie,
      body: { confirmTotalWithdrawal: true },
    });
    assert.equal(revoke.status, 403);
    const body = (await revoke.json()) as { code: string };
    assert.equal(body.code, "CSRF_REJECTED");
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-605: aislamiento de cookies — una sesión MANAGE/DECISION no sirve para POST /recovery/revoke, y la cookie de recuperación no sirve para /manage ni /decision", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-605"), fixtureUuid("consent-605"), "mgmt-token-605");
  try {
    // Sesión MANAGE (GET /m/{token}) usada donde se espera la cookie de recuperación: 404, no
    // consume ningún token de recuperación real.
    const managed = await fetch(`${baseUrl}/m/mgmt-token-605`, { redirect: "manual" });
    const manageSessionCookie = parseSetCookie(managed)[SESSION_COOKIE_NAME]!;
    const revokeWithManageCookie = await post(baseUrl, {
      path: "/recovery/revoke",
      ...VALID_CSRF_ORIGIN,
      csrfHeader: "csrf-token-abcdefgh",
      csrfCookie: "csrf-token-abcdefgh",
      recoveryCookie: manageSessionCookie, // valor de la cookie de sesión, puesto bajo el nombre de la cookie de recuperación
      body: { confirmTotalWithdrawal: true },
    });
    assert.equal(revokeWithManageCookie.status, 404);

    // Cookie de recuperación real usada como cookie de sesión (__Host-cns-session) en /manage:
    // no trae chainRef de sesión MANAGE, así que /manage sigue mostrando el error uniforme.
    const token = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-605");
    const { recoveryCookie } = await redeemRecoveryToken(baseUrl, token);
    const manageWithRecoveryCookie = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${recoveryCookie}` } });
    assert.equal(manageWithRecoveryCookie.status, 404);
    const manageHtml = await manageWithRecoveryCookie.text();
    assert.match(manageHtml, /error-uniform/);

    const decisionWithRecoveryCookie = await fetch(`${baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${recoveryCookie}` } });
    assert.equal(decisionWithRecoveryCookie.status, 404);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

const CONSENT_704 = "704a3c52-8d4e-4a7b-9c21-0e5a7d3b9f04";

test("TEST-CNS-704: tras revocar por enlace (C6/REVOKED), el enlace viejo da el error uniforme (render 404 sin CSRF) y pedir otro enlace (RV0) responde 202 sin emitir token nuevo", async () => {
  const { revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-704"), CONSENT_704, "mgmt-token-704");
  try {
    const oldToken = await issueRecoveryLink(baseUrl, revocationPorts, "mgmt-token-704");
    const { recoveryCookie: cookie } = await redeemRecoveryToken(baseUrl, oldToken);
    const { csrfToken } = await renderRecoveryConfirm(baseUrl, cookie);
    const revoked = await post(baseUrl, { path: "/recovery/revoke", ...VALID_CSRF_ORIGIN, csrfHeader: csrfToken, csrfCookie: csrfToken, recoveryCookie: cookie, body: { confirmTotalWithdrawal: true } });
    assert.equal(revoked.status, 200);
    assert.equal((await revocationPorts.revocation.consentDecisionRepo.findByConsentId(TENANT_ID, CONSENT_704))?.state, "REVOKED");

    // Enlace viejo (misma cookie de recuperación): error uniforme, sin CSRF.
    const { res: oldRender, csrfToken: noCsrf } = await renderRecoveryConfirm(baseUrl, cookie);
    assert.equal(oldRender.status, 404);
    assert.equal(noCsrf, undefined);

    // RV0 sobre la cadena ya revocada: 202 uniforme, sin token nuevo en el sink.
    const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
    const sentBefore = sink.sent.length;
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-704`, { redirect: "manual" });
    const handleCookie = parseSetCookie(redeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME];
    const manage = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleCookie}` } });
    const sessionCookie = parseAllSetCookies(manage)[SESSION_COOKIE_NAME];
    const rv0 = await post(baseUrl, { path: "/manage/recovery-link", ...VALID_CSRF_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh", sessionCookie });
    assert.equal(rv0.status, 202);
    assert.equal(sink.sent.length, sentBefore);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
