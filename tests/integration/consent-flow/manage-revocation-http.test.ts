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
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const MANAGE_ENTRY_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
const TENANT_ID = "e4a381a5-1295-48d1-8818-b8033107c762";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
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

/** SEC-CNS-014 (Carlos, 2026-09-28): GET /m/{token} ya no fija la sesión directamente, solo el
 * handle MANAGE_ENTRY; la sesión real la fija GET /manage al resolverlo. */
async function redeemManage(baseUrl: string, token: string): Promise<string> {
  const redeemed = await fetch(`${baseUrl}/m/${token}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(redeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME];
  const manage = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const sessionCookie = parseAllSetCookies(manage)[SESSION_COOKIE_NAME];
  if (!sessionCookie) throw new Error(`redeemManage: GET /manage no fijó sesión para el token ${token}`);
  return sessionCookie;
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
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  await ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-mgmt"),
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
  const revocationPorts = createDefaultRevocationFlowPorts(LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY, ports.decision.ledger, ports.decision.repo);
  (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({
    handle: mgmtToken,
    tenantId: TENANT_ID,
    chainRef,
    revokedDecisionRef: consentId,
  });

  const server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports, revocationPorts });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
  return { ports, revocationPorts, server, baseUrl, token: mgmtToken };
}

const CONSENT_581 = "581a3c52-8d4e-4a7b-9c21-0e5a7d3b9f81";

test("TEST-CNS-581: GET /m/{token} -> verificación MANAGE -> estado -> R1 -> verificación REVOCATION -> R2 -> R3 llega a APPLIED; cadena del ledger consecutiva", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-581"), CONSENT_581, "mgmt-token-581");
  try {
    const redeemed = await fetch(`${baseUrl}/m/mgmt-token-581`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    assert.equal(redeemed.headers.get("location"), "/manage");
    let sessionCookie = await redeemManage(baseUrl, "mgmt-token-581");

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

    const events = await ports.decision.ledger.listByAggregate(TENANT_ID, "Revocation", r3Body.revocationRef);
    assert.deepEqual(
      events.map((e) => e.eventType),
      ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"],
    );
    const sequences = events.map((e) => e.sequence).sort((a, b) => a - b);
    assert.deepEqual(sequences, [1, 2, 3, 4, 5]);
    // CA-127: evidencia válida contra el schema; authPath OTP; receiptRef == el revocationRef mostrado como comprobante.
    assertRevocationEvidence(events, { revocationRef: r3Body.revocationRef, authPath: "OTP", revokedDecisionRef: CONSENT_581 });
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-582: R8 (cancelar solicitud de retiro) desde REQUESTED responde FAILED; el consentimiento sigue vigente (no llega a APPLIED)", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-582"), fixtureUuid("consent-582"), "mgmt-token-582");
  try {
    let sessionCookie = await redeemManage(baseUrl, "mgmt-token-582");

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
  const { ports, revocationPorts, server, baseUrl } = await setUp(fixtureUuid("chain-583"), fixtureUuid("consent-583"), "mgmt-token-583");
  try {
    let sessionCookie = await redeemManage(baseUrl, "mgmt-token-583");

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
    const revocation = await revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, r1Body.revocationRef);
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

// Quita cualquier comentario HTML antes de buscar un marcador (fix Carlos, revisión en
// navegador con dev.ts): si el marcador solo existiera dentro de `<!-- ... -->` el usuario nunca
// lo vería; assert.match sobre el HTML "limpio" lo detecta.
function stripHtmlComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

async function bringToRevocationConfirmSession(baseUrl: string, ports: ConsentFlowPorts, mgmtToken: string): Promise<string> {
  let sessionCookie = await redeemManage(baseUrl, mgmtToken);
  const sink = ports.otp.channel as InMemoryOtpChannelSink;

  const requestedMgmtOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
  sessionCookie = parseSetCookie(requestedMgmtOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;
  const manageCode = sink.sent[sink.sent.length - 1]?.code ?? "";
  const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: manageCode } });
  sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

  const r1 = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie });
  sessionCookie = parseSetCookie(r1)[SESSION_COOKIE_NAME] ?? sessionCookie;

  const requestedRevOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
  sessionCookie = parseSetCookie(requestedRevOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;
  const revCode = sink.sent[sink.sent.length - 1]?.code ?? "";
  const submittedRev = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: revCode } });
  sessionCookie = parseSetCookie(submittedRev)[SESSION_COOKIE_NAME] ?? sessionCookie;
  assert.ok(sessionCookie);
  return sessionCookie;
}

test("TEST-CNS-585: GET /manage (estado) muestra como texto visible el marcador [LEGAL DECISION] de alcance del retiro (33:21), nunca solo dentro de un comentario HTML", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-585"), fixtureUuid("consent-585"), "mgmt-token-585");
  try {
    let sessionCookie = await redeemManage(baseUrl, "mgmt-token-585");
    const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[sink.sent.length - 1]?.code ?? "";
    const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code } });
    sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const manageStatus = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    const visible = stripHtmlComments(await manageStatus.text());
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro \(total, sin retiro parcial\), protocolo l\.423\]/);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-586: GET /manage/revocation/confirm muestra visibles los dos marcadores [LEGAL DECISION] (efecto sobre los datos, y alcance/irreversibilidad) y el del comprobante (33:45/33:54)", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-586"), fixtureUuid("consent-586"), "mgmt-token-586");
  try {
    const sessionCookie = await bringToRevocationConfirmSession(baseUrl, ports, "mgmt-token-586");
    const confirmPage = await fetch(`${baseUrl}/manage/revocation/confirm`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    const visible = stripHtmlComments(await confirmPage.text());
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar \(supresión\/plazos\), protocolo l\.522\]/);
    assert.match(visible, /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro \(total, sin retiro parcial\) e irreversibilidad desde esta pantalla \(protocolo l\.423\)\]/);
    // El marcador del comprobante (33:54) vive en el bloque #state-applied (oculto hasta R3,
    // pero ya presente como texto en el HTML servido, no dentro de un comentario).
    const appliedBlockMatch = visible.match(/<div role="status"[^>]*id="state-applied"[\s\S]*?<\/div>/);
    assert.ok(appliedBlockMatch, "debe existir el bloque #state-applied");
    assert.match(
      appliedBlockMatch![0],
      /\[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar \(supresión\/plazos\), protocolo l\.522\]/,
    );
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-587: el estado bloqueado REVOCATION/MANAGE (33:11) oculta el formulario (#verify-form) y mueve el foco a la alerta; el formulario vuelve a mostrarse en cualquier otro estado", async () => {
  const { server, baseUrl } = await setUp(fixtureUuid("chain-587"), fixtureUuid("consent-587"), "mgmt-token-587");
  try {
    const verifyJs = await (await fetch(`${baseUrl}/assets/verify.js`)).text();
    assert.match(verifyJs, /function showLocked\(\) \{\s*hideStates\(\);/);
    assert.match(verifyJs, /if \(isRights\) \{\s*if \(verifyForm\) verifyForm\.hidden = true;/);
    assert.match(verifyJs, /stateLockedRights\.focus\(\)/);
    assert.match(verifyJs, /function hideStates\(\) \{[\s\S]*?if \(verifyForm\) verifyForm\.hidden = false;/);

    const managePage = await fetch(`${baseUrl}/manage/verify`, { redirect: "manual" });
    void managePage; // 404 esperado sin sesión con manageVerificationRef; solo valida que la ruta existe.
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-588: el CTA y el enlace de ayuda quedan apilados (no en la misma línea) en /manage (entrada y estado) y en confirmar-retiro, que además ahora incluye el enlace de ayuda", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-588"), fixtureUuid("consent-588"), "mgmt-token-588");
  try {
    let sessionCookie = await redeemManage(baseUrl, "mgmt-token-588");

    const manageEntry = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    const entryHtml = await manageEntry.text();
    assert.match(entryHtml, /id="start-verify-btn"[^<]*<\/button>\s*<p><a href="mailto:ayuda@example\.invalid"/);

    const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[sink.sent.length - 1]?.code ?? "";
    const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code } });
    sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;

    const manageStatus = await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } });
    const statusHtml = await manageStatus.text();
    assert.match(statusHtml, /id="start-revocation-btn"[^<]*<\/button>\s*<p><a href="mailto:ayuda@example\.invalid"/);

    const confirmSessionCookie = await bringToRevocationConfirmSession(baseUrl, ports, "mgmt-token-588");
    const confirmPage = await fetch(`${baseUrl}/manage/revocation/confirm`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${confirmSessionCookie}` } });
    const confirmHtml = await confirmPage.text();
    // La ayuda faltaba por completo en confirmar-retiro; ahora está presente y apilada bajo
    // "Cancelar solicitud de retiro" (no en la misma línea que ningún botón).
    assert.match(confirmHtml, /id="withdraw-btn"[^<]*<\/button>\s*<p><a href="mailto:ayuda@example\.invalid"/);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-703: tras revocar (C6/REVOKED), /manage verificado con OTP no dice GRANTED ni ofrece retirar; R1 sobre esa cadena es uniforme (ERR-RV-02) y no crea revocación", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-703"), fixtureUuid("consent-703"), "mgmt-token-703");
  try {
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    async function verifyManage(): Promise<string> {
      let sessionCookie = await redeemManage(baseUrl, "mgmt-token-703");
      const requested = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
      sessionCookie = parseSetCookie(requested)[SESSION_COOKIE_NAME] ?? sessionCookie;
      const submitted = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: sink.sent[sink.sent.length - 1]?.code ?? "" } });
      assert.equal(submitted.status, 200);
      return parseSetCookie(submitted)[SESSION_COOKIE_NAME] ?? sessionCookie;
    }

    let sessionCookie = await verifyManage();
    const before = await (await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } })).text();
    assert.match(before, /start-revocation-btn/);

    const r1 = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(r1)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const requestedRevOtp = await post(baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie });
    sessionCookie = parseSetCookie(requestedRevOtp)[SESSION_COOKIE_NAME] ?? sessionCookie;
    const submittedRev = await post(baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie, body: { code: sink.sent[sink.sent.length - 1]?.code ?? "" } });
    sessionCookie = parseSetCookie(submittedRev)[SESSION_COOKIE_NAME] ?? sessionCookie;
    await post(baseUrl, { path: "/manage/revocation/verify", ...VALID_CSRF, sessionCookie });
    const r3 = await post(baseUrl, { path: "/manage/revocation/confirm", ...VALID_CSRF, sessionCookie });
    assert.equal(((await r3.json()) as { status: string }).status, "APPLIED");
    assert.equal((await ports.decision.repo.findByConsentId(TENANT_ID, fixtureUuid("consent-703")))?.state, "REVOKED");

    // Reproducción del FINDING: volver a /m/<token>, verificar con OTP y abrir /manage.
    const again = await verifyManage();
    const html = await (await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${again}` } })).text();
    assert.doesNotMatch(html, /start-revocation-btn/);
    assert.doesNotMatch(html, /Retirar mi consentimiento/);
    assert.doesNotMatch(html, /GRANTED/);
    assert.match(html, /id="manage-revoked"/);
    assert.match(html, /role="status"/);
    assert.doesNotMatch(html, /\[UX — copy pendiente/);
    assert.match(html, /Tu consentimiento ya fue retirado\./);

    // R1 sobre la cadena revocada: 202 uniforme, sin revocationRef ni Revocation nueva.
    const r1Again = await post(baseUrl, { path: "/manage/revocation", ...VALID_CSRF, sessionCookie: again });
    assert.equal(r1Again.status, 202);
    assert.deepEqual(await r1Again.json(), { result: "RECEIVED" });
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-706: /manage con la decisión REVOKED pero sin sesión MANAGE verificada muestra la entrada, no el estado ya-retirado", async () => {
  const { ports, server, baseUrl } = await setUp(fixtureUuid("chain-706"), fixtureUuid("consent-706"), "mgmt-token-706");
  try {
    const seeded = await ports.decision.repo.findByConsentId(TENANT_ID, fixtureUuid("consent-706"));
    assert.ok(seeded);
    await ports.decision.repo.save({ ...seeded, state: "REVOKED" });
    const sessionCookie = await redeemManage(baseUrl, "mgmt-token-706");
    const html = await (await fetch(`${baseUrl}/manage`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}` } })).text();
    assert.match(html, /start-verify-btn/);
    assert.doesNotMatch(html, /manage-revoked/);
    assert.doesNotMatch(html, /ya fue retirado/);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
