// Gobierna: flujo del invitado v2 (UX-CNS-001/002/003/004/006/006b, Carlos 2026-10-14):
// D-02 (etiqueta sintética del estudiante), D-03 (dos mensajes al canal verificado: comprobante
// SIN enlace + mensaje aparte con el enlace de gestión), D-04 (comprobante §21 con marca de agua
// IT0), D-06 (POST /decision/subject-mismatch, API-CNS-128, I9), D-07 (consent-decision.spec C5:
// DECLINED no emite enlace de gestión), D-01/F-STITCH-17 (sin recursos remotos), F-STITCH-03
// (nada preseleccionado), sin descarga del comprobante. Datos sintéticos, example.invalid.
// TEST-CNS-1401..TEST-CNS-1407, 1412..1416 (traceability/test-matrix.csv).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  createConsentFlowHttpServer,
  createDefaultConsentFlowPorts,
  createDefaultRevocationFlowPorts,
} from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryGuestMessageSink } from "../../../src/infra/adapters/in-memory-guest-message-sink.adapter.ts";
import { createInMemorySubjectDirectory } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import { validateApiPayload, type ValidationResult } from "../../contract/schema-lite.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const MANAGE_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+guest-v2@example.invalid";
const OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
const REL = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));
const DECLINE_ONE = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose, i) => ({ purpose, choice: i === 0 ? ("DECLINE" as const) : ("GRANT" as const) }));
const VALID_CSRF = { origin: ALLOWED_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh" };

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  readonly sink: ReturnType<typeof createInMemoryGuestMessageSink>;
  readonly failures: string[];
  close(): Promise<void>;
}

/** Cablea el flujo del invitado v2 con un sink propio, el directorio sintético "Alumno de prueba 3" y
 * el mismo TenantHandle in-memory que resuelve GET /m/{token}. */
function startServer(subjectRef: string, channelOverride?: { send(m: unknown): Promise<void> }): Promise<Harness> {
  const failures: string[] = [];
  const base = createDefaultConsentFlowPorts(OTP_POLICY, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  // El TenantHandle donde C3 registra el handle (misma tx) es el que resuelve GET /m/{token}.
  const revocationPorts = createDefaultRevocationFlowPorts(undefined, base.decision.ledger, base.decision.repo, base.managementHandleStore);
  const sink = createInMemoryGuestMessageSink();
  const directory = createInMemorySubjectDirectory("LOCAL", [{ tenantId: TENANT_ID, subjectRef, label: "Alumno de prueba 3", participationRef: null }]);
  const ports: ConsentFlowPorts = {
    ...base,
    guest: {
      messageChannel: (channelOverride as never) ?? sink,
      subjectDirectory: directory,
      publicBaseUrl: "https://consent.example.invalid",
      recordDeliveryFailure: (kind) => void failures.push(kind),
    },
  };
  const server: Server = createConsentFlowHttpServer({
    sessionSecret: TEST_SESSION_SECRET,
    staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    revocationPorts,
    environment: "LOCAL",
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({ baseUrl: `http://127.0.0.1:${address.port}`, ports, sink, failures, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function allSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of res.headers.getSetCookie()) {
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

interface Verified {
  readonly session: string;
  readonly handleCookie: string;
}

async function bringToVerified(h: Harness, invitationRef: string, subjectRef: string): Promise<Verified> {
  await createInvitation(h.ports.invitation, TENANT_ID, "INVITER", {
    enrollmentRef: fixtureUuid("enr-fixture"),
    participationRef: fixtureUuid("part-fixture"),
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  await markInvitationReady(h.ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(h.ports.invitation, TENANT_ID, "INVITER", invitationRef, { deliveryChannel: "CONSENT_APP_EMAIL" });
  const redeemed = await fetch(`${h.baseUrl}/i/${token}`, { redirect: "manual" });
  const handleCookie = allSetCookies(redeemed)[INVITATION_HANDLE_COOKIE_NAME] as string;
  const welcome = await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const landing = allSetCookies(welcome)[SESSION_COOKIE_NAME];
  const opened = await post(h.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landing });
  const afterOpen = allSetCookies(opened)[SESSION_COOKIE_NAME];
  const requested = await post(h.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: afterOpen });
  const afterRequest = allSetCookies(requested)[SESSION_COOKIE_NAME];
  const sink = h.ports.otp.channel as InMemoryOtpChannelSink;
  const code = sink.sent[sink.sent.length - 1]?.code ?? "";
  const submitted = await post(h.baseUrl, { path: "/otp/submit", ...VALID_CSRF, sessionCookie: afterRequest, body: { code } });
  const session = allSetCookies(submitted)[SESSION_COOKIE_NAME];
  assert.ok(session, "V3 debe fijar la sesión verificada");
  return { session, handleCookie };
}

async function completeSteps(h: Harness, sessionCookie: string): Promise<string> {
  const steps: unknown[] = [
    { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    { stepKind: "CONSENT_VERSION_VIEWED" },
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
    { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
  ];
  let cookie = sessionCookie;
  for (const body of steps) {
    const res = await post(h.baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: cookie, body });
    assert.equal(res.status, 200);
    cookie = allSetCookies(res)[SESSION_COOKIE_NAME] ?? cookie;
  }
  return cookie;
}

test("TEST-CNS-1401: GET /decision no preselecciona nada (chips, casilla ni select), muestra Paso 2 de 3 y la etiqueta sintética del estudiante (D-02) y los botones Acepto/No acepto tienen el mismo tratamiento", async () => {
  const subjectRef = fixtureUuid("subject-1401");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1401"), subjectRef);
    const html = await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    assert.doesNotMatch(html, /aria-checked="true"/);
    assert.doesNotMatch(html, /<input[^>]*\bchecked\b/);
    assert.match(html, /<option value="" selected disabled>/);
    assert.doesNotMatch(html, /<option[^>]*value="SYNTHETIC_GUARDIAN"[^>]*selected/);
    assert.match(html, /Paso 2 de 3 · Revisa y decide/);
    assert.match(html, /Alumno de prueba 3 · Colegio Ejemplo/);
    assert.equal((html.match(/data-choice="GRANT"/g) ?? []).length, 4);
    assert.equal((html.match(/data-choice="DECLINE"/g) ?? []).length, 4);
    // Mismo componente y mismas clases para ambas opciones (sin variante verde/roja).
    const grant = html.match(/<button[^>]*data-choice="GRANT"[^>]*>/)?.[0] ?? "";
    const decline = html.match(/<button[^>]*data-choice="DECLINE"[^>]*>/)?.[0] ?? "";
    assert.equal(grant.match(/class="[^"]*"/)?.[0], decline.match(/class="[^"]*"/)?.[0]);
    const css = await (await fetch(`${h.baseUrl}/assets/app.css`)).text();
    assert.doesNotMatch(css, /lp-decision-chip\[aria-checked="true"\]\[data-choice="(GRANT|DECLINE)"\]\s*,?\s*\{/);
    // Sin PII del estudiante ni RUT.
    assert.doesNotMatch(html, /RUT|\d{1,2}\.\d{3}\.\d{3}-[\dkK]/);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1451: la casilla de autoridad de /decision tiene como nombre accesible el texto de la declaracion (label for/id y aria-labelledby al mismo texto), no 'on' (UX-CNS-003, accesibilidad)", async () => {
  const subjectRef = fixtureUuid("subject-1451");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1451"), subjectRef);
    const html = await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    const input = html.match(/<input[^>]*id="authority-declared"[^>]*>/)?.[0] ?? "";
    assert.match(input, /type="checkbox"/);
    assert.doesNotMatch(input, /\bvalue=/, "sin value: el arbol de accesibilidad no debe caer en 'on'");
    assert.match(input, /aria-labelledby="authority-declared-label"/);
    assert.match(html, /<label[^>]*for="authority-declared"/);
    const label = html.match(/<span id="authority-declared-label">([^<]*)<\/span>/)?.[1] ?? "";
    assert.match(label, /Declaro que tengo la autoridad/);
    assert.equal((html.match(/id="authority-declared-label"/g) ?? []).length, 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1402: las páginas del invitado (welcome, verify, decision, manage) no cargan recursos remotos, ni <style> ni style= inline, y app.css no importa nada remoto (D-01, F-STITCH-17)", async () => {
  const subjectRef = fixtureUuid("subject-1402");
  const h = await startServer(subjectRef);
  try {
    const { session, handleCookie } = await bringToVerified(h, fixtureUuid("inv-1402"), subjectRef);
    const pages: string[] = [];
    pages.push(await (await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } })).text());
    pages.push(await (await fetch(`${h.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text());
    pages.push(await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text());
    assert.equal(pages.length, 3);
    for (const html of pages) {
      assert.doesNotMatch(html, /(src|href)="https?:\/\//i);
      assert.doesNotMatch(html, /<style[\s>]/i);
      assert.doesNotMatch(html, /\sstyle="/i);
      assert.doesNotMatch(html, /fonts\.googleapis|cdn\.|googleusercontent|tailwind/i);
      for (const m of html.matchAll(/<(?:link|script|img)\b[^>]*(?:src|href)="([^"]+)"/g)) {
        assert.match(m[1] as string, /^\/assets\//, `recurso no local: ${m[1]}`);
      }
    }
    const css = await (await fetch(`${h.baseUrl}/assets/app.css`)).text();
    assert.doesNotMatch(css, /@import\s+(url\()?["']?https?:/i);
    assert.doesNotMatch(css, /url\(\s*["']?https?:/i);
    const ds = await (await fetch(`${h.baseUrl}/assets/design-system/index.css`)).text();
    assert.doesNotMatch(ds, /https?:\/\//);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1403: decisión GRANTED deja dos mensajes aparte en el sink: comprobante SIN enlace y mensaje con el enlace de gestión; el enlace nunca sale en la respuesta HTTP ni en las pantallas (D-03)", async () => {
  const subjectRef = fixtureUuid("subject-1403");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1403"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const decisionHtml = await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${afterSteps}` } })).text();
    assert.match(decisionHtml, /id="state-granted"/);
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 200);
    const raw = await res.text();
    const body = JSON.parse(raw) as { state: string; receiptRef: string; subjectLabel?: string };
    assert.equal(body.state, "GRANTED");
    assert.equal(body.subjectLabel, "Alumno de prueba 3"); // D-02
    assertValid(validateApiPayload("DecisionRecorded", body));
    assert.doesNotMatch(raw, /\/m\/|management/i);

    assert.equal(h.sink.sent.length, 2);
    const [receipt, mgmt] = h.sink.sent;
    assert.equal(receipt?.kind, "RECEIPT");
    assert.equal(mgmt?.kind, "MANAGEMENT_LINK");
    assert.equal(receipt?.recipientChannelRef, CHANNEL_REF);
    assert.equal(mgmt?.recipientChannelRef, CHANNEL_REF);
    // El comprobante no lleva ningún enlace ni la ruta de gestión.
    assert.doesNotMatch(receipt?.html ?? "", /href=|https?:\/\/|\/m\//i);
    assert.doesNotMatch(receipt?.text ?? "", /https?:\/\/|\/m\//i);
    // El mensaje aparte lleva el enlace de gestión (sintético) y nada más que el enlace.
    const link = (mgmt?.text ?? "").match(/https:\/\/consent\.example\.invalid(\/m\/[A-Za-z0-9_-]{20,})/);
    assert.ok(link, "el mensaje de gestión debe contener /m/<token>");
    assert.match(mgmt?.html ?? "", /href="https:\/\/consent\.example\.invalid\/m\//);
    assert.doesNotMatch(mgmt?.html ?? "", /<img|https?:\/\/(?!consent\.example\.invalid)/i);

    // El enlace emitido resuelve (GET /m/{token} -> 303 /manage con handle -> estado con sesión).
    const redeemed = await fetch(`${h.baseUrl}${link?.[1]}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const mHandle = allSetCookies(redeemed)[MANAGE_HANDLE_COOKIE_NAME];
    assert.ok(mHandle);
    const manage = await fetch(`${h.baseUrl}/manage`, { headers: { cookie: `${MANAGE_HANDLE_COOKIE_NAME}=${mHandle}` } });
    assert.equal(manage.status, 200);

    // La página /decision tras registrar no vuelca ni el token ni la ruta de gestión.
    assert.doesNotMatch(decisionHtml, /\/m\/[A-Za-z0-9_-]{20,}/);
    assert.doesNotMatch(decisionHtml, /Descargar|\.pdf|download|Copiar código/i);
    const decisionJs = await (await fetch(`${h.baseUrl}/assets/decision.js`)).text();
    assert.doesNotMatch(decisionJs, /\/m\//);

    // Comprobante visible por /__dev/message-sink solo en LOCAL (este harness lo es).
    const dev = await (await fetch(`${h.baseUrl}/__dev/message-sink`)).json();
    assert.equal(h.sink.sent.length, 2);
    assert.ok(typeof dev === "object");
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1404: decisión DECLINED emite solo el comprobante (sin mensaje ni handle de gestión, consent-decision.spec C5, D-07) y las pantallas de rechazo no prometen enlace de gestión", async () => {
  const subjectRef = fixtureUuid("subject-1404");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1404"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const html = await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${afterSteps}` } })).text();
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: DECLINE_ONE } });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { state: string };
    assert.equal(body.state, "DECLINED");
    assert.equal(h.sink.sent.length, 1);
    assert.equal(h.sink.sent[0]?.kind, "RECEIPT");
    assert.doesNotMatch(h.sink.sent[0]?.html ?? "", /href=|\/m\//i);
    assert.match(h.sink.sent[0]?.html ?? "", /✕ No acepto/);

    const declined = html.match(/id="state-declined"[\s\S]*?id="state-mismatch"/)?.[0] ?? "";
    assert.ok(declined.length > 0);
    assert.doesNotMatch(declined, /enlace para gestionar|gestionarla o retirarla/);
    assert.match(declined, /Te enviaremos el comprobante de tu decisión/);
    const granted = html.match(/id="state-granted"[\s\S]*?id="state-declined"/)?.[0] ?? "";
    assert.match(granted, /Te enviaremos aparte el enlace para gestionarla o retirarla/);
    assert.match(granted, /Marca de agua IT0 · comprobante de prueba/);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1405: POST /decision/subject-mismatch cancela la invitación (I9 SUBJECT_MISMATCH_REPORTED, D-06): 200 INVITATION_CANCELLED, ya no se puede decidir ni reabrir el enlace, sin mensajes, y exige CSRF y sesión verificada", async () => {
  const subjectRef = fixtureUuid("subject-1405");
  const h = await startServer(subjectRef);
  try {
    // Sin CSRF -> 403; sin sesión -> 404 uniforme.
    const noCsrf = await post(h.baseUrl, { path: "/decision/subject-mismatch" });
    assert.equal(noCsrf.status, 403);
    const noSession = await post(h.baseUrl, { path: "/decision/subject-mismatch", ...VALID_CSRF });
    assert.equal(noSession.status, 404);

    const { session, handleCookie } = await bringToVerified(h, fixtureUuid("inv-1405"), subjectRef);
    const res = await post(h.baseUrl, { path: "/decision/subject-mismatch", ...VALID_CSRF, sessionCookie: session });
    assert.equal(res.status, 200);
    const cancelledSession = allSetCookies(res)[SESSION_COOKIE_NAME] as string;
    const body = await res.json();
    assert.deepEqual(body, { result: "INVITATION_CANCELLED" });
    assertValid(validateApiPayload("SubjectMismatchAck", body));

    const record = await h.ports.invitation.uow.inTenant(TENANT_ID, (tx) => tx.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-1405")));
    assert.equal(record?.state, "CANCELLED");

    // Con la sesión devuelta ya no hay decisión posible ni /decision.
    const steps = await post(h.baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: cancelledSession, body: { stepKind: "CONTEXT_INFORMATION_VIEWED" } });
    assert.equal(steps.status, 404);
    const page = await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${cancelledSession}` } });
    assert.equal(page.status, 404);
    // El enlace deja de resolver (error uniforme de /welcome).
    const welcome = await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
    assert.equal(welcome.status, 404);
    // Idempotente por (invitationRef, reasonCode) y sin mensajes al canal.
    const again = await post(h.baseUrl, { path: "/decision/subject-mismatch", ...VALID_CSRF, sessionCookie: session });
    assert.equal(again.status, 200);
    assert.equal(h.sink.sent.length, 0);

    // El cableado de la UI: decision.js llama a la ruta solo desde el botón explícito.
    const js = await (await fetch(`${h.baseUrl}/assets/decision.js`)).text();
    assert.match(js, /postJson\("\/decision\/subject-mismatch"\)/);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1406: la pantalla incompleta ofrece resumen de errores con enlaces, errores inline por campo, aviso de rechazo y estado 'no es mi estudiante' (UX-CNS-003 106:189/295/568/706), sin temporizadores ni valores P-01/P-02/P-06", async () => {
  const subjectRef = fixtureUuid("subject-1406");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1406"), subjectRef);
    const html = await (await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    assert.match(html, /id="error-validation"[^>]*tabindex="-1"/);
    assert.match(html, /id="error-validation-list"/);
    for (const id of ["err-subject", "err-relationship", "err-authority", "err-STUDY_PARTICIPATION", "err-HUMAN_REVIEW"]) assert.match(html, new RegExp(`id="${id}"`));
    assert.match(html, /Elegiste no aceptar al menos una finalidad\./);
    assert.match(html, /Informar que no es mi estudiante/);
    assert.match(html, /Registramos tu aviso/);
    assert.match(html, /Cancelamos esta invitación\./);
    assert.match(html, /Nunca lo mostramos aquí\./);
    // P2-6: el copy de finalidades obligatorias lleva marcador [LEGAL DECISION] y ninguna pantalla presume "hija o hijo".
    assert.match(html, /\[LEGAL DECISION — carácter obligatorio de las 4 finalidades/);
    assert.doesNotMatch(html, /hija o hijo/);
    assert.doesNotMatch(await (await fetch(`${h.baseUrl}/assets/decision.js`)).text(), /hija o hijo/);
    // Todo copy legal conserva su marcador.
    assert.match(html, /\[LEGAL DECISION — enunciado de autoridad/);
    assert.match(html, /\[LEGAL DECISION — efecto de no aceptar una finalidad/);
    // Sin cifras de P-01/P-02/P-06 ni cuentas regresivas.
    const verify = await (await fetch(`${h.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    assert.match(verify, /\(P-01, valor pendiente de aprobación\)/);
    assert.match(verify, /\(P-06, valor pendiente de aprobación\)/);
    assert.doesNotMatch(verify, /\d{2}:\d{2}|\d+ minutos|\d+ segundos/);
    assert.match(verify, /Paso 1 de 3 · Verificación/);
    const js = await (await fetch(`${h.baseUrl}/assets/decision.js`)).text();
    assert.match(js, /function showIncompleteSummary\(\)/);
    assert.doesNotMatch(js, /setInterval/);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1407: GET /__dev/message-sink existe solo en LOCAL (404 fuera de LOCAL, GRD-CM-13)", async () => {
  const base = createDefaultConsentFlowPorts(OTP_POLICY, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  for (const [environment, expected] of [["LOCAL", 200], ["DEV", 404], [undefined, 404]] as const) {
    const server: Server = createConsentFlowHttpServer({
      sessionSecret: TEST_SESSION_SECRET,
      staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
      config: { allowedOrigin: ALLOWED_ORIGIN },
      ports: base,
      ...(environment ? { environment } : {}),
      guestMessageChannel: createInMemoryGuestMessageSink(),
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    try {
      const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/__dev/message-sink`);
      assert.equal(res.status, expected, String(environment));
    } finally {
      await new Promise((r) => server.close(() => r(undefined)));
    }
  }
});

const LEDGER_AGG = "ConsentDecision";

async function receiptEvents(h: Harness, consentId: string): Promise<Array<{ managementLinkIssued: boolean }>> {
  const events = await h.ports.decision.ledger.listByAggregate(TENANT_ID, LEDGER_AGG, consentId);
  return events.filter((e) => e.eventType === "RECEIPT_CREATED").map((e) => e.payload as { managementLinkIssued: boolean });
}

test("TEST-CNS-1412: el ledger dice la verdad: RECEIPT_CREATED.managementLinkIssued=true solo en GRANTED con el handle registrado en la misma tx (resuelve /m/{token}); false en DECLINED (P1-1, consent-decision C3/C5)", async () => {
  const subjectRef = fixtureUuid("subject-1411");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1411"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    const { consentId } = (await res.json()) as { consentId: string };
    const [granted] = await receiptEvents(h, consentId);
    assert.equal(granted?.managementLinkIssued, true);
    // Hay exactamente un mensaje de enlace y su handle ya estaba registrado (C3, misma tx): resuelve.
    const link = (h.sink.sent.find((m) => m.kind === "MANAGEMENT_LINK")?.text ?? "").match(/(\/m\/[A-Za-z0-9_-]{20,})/)?.[1];
    assert.ok(link);
    const redeemed = await fetch(`${h.baseUrl}${link}`, { redirect: "manual" });
    const mHandle = allSetCookies(redeemed)[MANAGE_HANDLE_COOKIE_NAME];
    assert.equal((await fetch(`${h.baseUrl}/manage`, { headers: { cookie: `${MANAGE_HANDLE_COOKIE_NAME}=${mHandle}` } })).status, 200);

    const h2 = await startServer(fixtureUuid("subject-1411b"));
    try {
      const v2 = await bringToVerified(h2, fixtureUuid("inv-1411b"), fixtureUuid("subject-1411b"));
      const steps2 = await completeSteps(h2, v2.session);
      const r2 = await post(h2.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: steps2, body: { purposes: DECLINE_ONE } });
      const { consentId: c2 } = (await r2.json()) as { consentId: string };
      assert.equal((await receiptEvents(h2, c2))[0]?.managementLinkIssued, false);
    } finally {
      await h2.close();
    }
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1413: si la entrega post-commit falla, la decisión sigue registrada y queda rastro explícito por tipo de mensaje (nunca silencio ni PII/token) (P1-1)", async () => {
  const subjectRef = fixtureUuid("subject-1412");
  const failing = { send: async (): Promise<void> => { throw new Error("SMTP_CAIDO a@b.test"); } };
  const h = await startServer(subjectRef, failing);
  const origError = console.error;
  const logs: string[] = [];
  console.error = (...a: unknown[]) => void logs.push(a.join(" "));
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1412"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { state: string }).state, "GRANTED");
    assert.deepEqual(h.failures, ["RECEIPT", "MANAGEMENT_LINK"]);
    assert.ok(!logs.some((l) => /SMTP_CAIDO|a@b\.test|\/m\//.test(l)));
  } finally {
    console.error = origError;
    await h.close();
  }
});

/** Espia las escrituras de `tx.securityEvents` que hace el handler (post-commit) sin tocar el resto de la unidad de trabajo. `failRecord` simula que ops.security_event no responde. */
function spyOnSecurityEvents(h: Harness, failRecord = false): unknown[] {
  const seen: unknown[] = [];
  const base = h.ports.invitation.uow;
  (h.ports as { invitation: unknown }).invitation = {
    ...h.ports.invitation,
    uow: {
      inTenant: <T>(tenantId: never, work: (tx: never) => Promise<T>) =>
        base.inTenant(tenantId, (tx) =>
          work({
            ...tx,
            securityEvents: {
              record: async (entry: unknown) => {
                if (failRecord) throw new Error("ops.security_event caido a@b.test");
                seen.push(entry);
                return tx.securityEvents.record(entry as never);
              },
            },
          } as never),
        ),
    },
  };
  return seen;
}

test("TEST-CNS-1446: el fallo de entrega post-commit deja un evento PERSISTENTE GUEST_MESSAGE_DELIVERY_FAILED por tipo de mensaje, con receiptRef opaca y sin PII ni token (SEC-CNS-PR94 P2-A)", async () => {
  const subjectRef = fixtureUuid("subject-1446");
  const failing = { send: async (): Promise<void> => { throw new Error("SMTP_CAIDO a@b.test"); } };
  const h = await startServer(subjectRef, failing);
  const origError = console.error;
  const logs: string[] = [];
  console.error = (...a: unknown[]) => void logs.push(a.join(" "));
  try {
    const events = spyOnSecurityEvents(h);
    const { session } = await bringToVerified(h, fixtureUuid("inv-1446"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { state: string; receiptRef: string };
    assert.equal(body.state, "GRANTED");
    assert.deepEqual(events, [
      { tenantId: TENANT_ID, eventType: "GUEST_MESSAGE_DELIVERY_FAILED", messageKind: "RECEIPT", receiptRef: body.receiptRef },
      { tenantId: TENANT_ID, eventType: "GUEST_MESSAGE_DELIVERY_FAILED", messageKind: "MANAGEMENT_LINK", receiptRef: body.receiptRef },
    ]);
    assert.deepEqual(h.failures, ["RECEIPT", "MANAGEMENT_LINK"], "la alerta inmediata sigue ocurriendo");
    assert.ok(!JSON.stringify(events).match(/SMTP_CAIDO|@|\/m\//), "el evento persistido no lleva PII ni token");
    assert.ok(!logs.some((l) => /SMTP_CAIDO|a@b\.test|\/m\//.test(l)));
  } finally {
    console.error = origError;
    await h.close();
  }
});

test("TEST-CNS-1447: si tampoco se puede persistir el evento de fallo de entrega, la decision sigue en 200 y queda la alerta inmediata (mejor esfuerzo, sin detalle) (SEC-CNS-PR94 P2-A)", async () => {
  const subjectRef = fixtureUuid("subject-1447");
  const failing = { send: async (): Promise<void> => { throw new Error("SMTP_CAIDO"); } };
  const h = await startServer(subjectRef, failing);
  const origError = console.error;
  const logs: string[] = [];
  console.error = (...a: unknown[]) => void logs.push(a.join(" "));
  try {
    spyOnSecurityEvents(h, true);
    const { session } = await bringToVerified(h, fixtureUuid("inv-1447"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { state: string }).state, "GRANTED");
    assert.deepEqual(h.failures, ["RECEIPT", "MANAGEMENT_LINK"]);
    assert.ok(logs.includes("guest_message_delivery_failure_not_persisted"));
    assert.ok(!logs.some((l) => /a@b\.test|ops\.security_event caido/.test(l)), "sin detalle del error");
  } finally {
    console.error = origError;
    await h.close();
  }
});

/** Tras confirmar C3 (la decision ya esta registrada), la lectura de la invitacion que hace la entrega post-commit falla (`throws`) o devuelve la invitacion sin canal ligado. */
function breakDeliveryLookup(h: Harness, mode: "throws" | "no-channel"): void {
  let armed = false;
  const decision = h.ports.decision;
  (h.ports as { decision: unknown }).decision = {
    ...decision,
    uow: { inTenant: async <T>(tenantId: never, work: (tx: never) => Promise<T>) => { const r = await decision.uow.inTenant(tenantId, work as never); armed = true; return r as T; } },
  };
  const base = h.ports.invitation.uow;
  (h.ports as { invitation: unknown }).invitation = {
    ...h.ports.invitation,
    uow: {
      inTenant: <T>(tenantId: never, work: (tx: never) => Promise<T>) =>
        base.inTenant(tenantId, (tx) =>
          work({
            ...tx,
            invitationRepo: {
              ...tx.invitationRepo,
              findByRef: async (t: never, ref: string) => {
                const found = await tx.invitationRepo.findByRef(t, ref);
                if (!armed) return found;
                if (mode === "throws") throw new Error("lectura caida");
                return found ? { ...found, recipientChannelRef: undefined } : found;
              },
            },
          } as never),
        ),
    },
  };
}

for (const mode of ["throws", "no-channel"] as const) {
  test(`TEST-CNS-${mode === "throws" ? "1453" : "1454"}: GRANTED con la entrega rota antes de enviar (${mode === "throws" ? "falla la lectura de la invitacion" : "invitacion sin canal ligado"}) registra RECEIPT y MANAGEMENT_LINK como no entregados (SEC-CNS-PR96 P2-1)`, async () => {
    const subjectRef = fixtureUuid(`subject-${mode}-1453`);
    const h = await startServer(subjectRef);
    const origError = console.error;
    console.error = () => undefined;
    try {
      const events = spyOnSecurityEvents(h);
      const { session } = await bringToVerified(h, fixtureUuid(`inv-${mode}-1453`), subjectRef);
      const afterSteps = await completeSteps(h, session);
      breakDeliveryLookup(h, mode);
      const res = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
      assert.equal(res.status, 200);
      const body = (await res.json()) as { state: string; receiptRef: string };
      assert.equal(body.state, "GRANTED");
      assert.deepEqual(h.failures, ["RECEIPT", "MANAGEMENT_LINK"]);
      assert.deepEqual(events, [
        { tenantId: TENANT_ID, eventType: "GUEST_MESSAGE_DELIVERY_FAILED", messageKind: "RECEIPT", receiptRef: body.receiptRef },
        { tenantId: TENANT_ID, eventType: "GUEST_MESSAGE_DELIVERY_FAILED", messageKind: "MANAGEMENT_LINK", receiptRef: body.receiptRef },
      ]);
      assert.equal(h.sink.sent.length, 0);
    } finally {
      console.error = origError;
      await h.close();
    }
  });
}

test("TEST-CNS-1448: rollback con inyeccion de fallo (en memoria): si el registro del handle de gestion falla dentro de C3, la decision sigue PENDING, el ledger no tiene RECEIPT_CREATED ni CONSENT_GRANTED ni INVITATION_COMPLETED, la invitacion sigue VERIFIED y no sale ningun mensaje; un reintento sano concluye (SEC-CNS-PR94 P2-B)", async () => {
  const subjectRef = fixtureUuid("subject-1448");
  const h = await startServer(subjectRef);
  const origError = console.error;
  const logs: string[] = [];
  console.error = (...a: unknown[]) => void logs.push(a.join(" "));
  try {
    const invitationRef = fixtureUuid("inv-1448");
    const { session } = await bringToVerified(h, invitationRef, subjectRef);
    const afterSteps = await completeSteps(h, session);

    // Inyeccion: el registro del handle de gestion (ultimo paso del lote C3) falla. Se captura el consentId que recibe (revokedDecisionRef).
    const healthyDecision = h.ports.decision;
    let consentId = "";
    let handleHash = "";
    (h.ports as { decision: unknown }).decision = {
      ...healthyDecision,
      uow: {
        inTenant: <T>(tenantId: never, work: (tx: never) => Promise<T>) =>
          healthyDecision.uow.inTenant(tenantId, (tx) =>
            work({
              ...tx,
              managementHandles: {
                register: async (input: { revokedDecisionRef: string; handleHash: string }) => {
                  consentId = input.revokedDecisionRef;
                  handleHash = input.handleHash;
                  await (tx as { managementHandles?: { register(i: unknown): Promise<void> } }).managementHandles?.register(input); // el registro REAL ocurre y luego falla
                  throw new Error("fallo inyectado tras el registro del handle");
                },
              },
            } as never),
          ),
      },
    };
    const ledgerBefore = (await healthyDecision.uow.inTenant(TENANT_ID as never, (tx) => tx.ledger.readChain(TENANT_ID as never))).length;
    const failed = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(failed.status, 500, "el fallo no se traga: el invitado no recibe un 200 de una decision no registrada");
    assert.ok(consentId, "el registro del handle se alcanzo (ultimo paso del lote C3)");

    const state = await healthyDecision.uow.inTenant(TENANT_ID as never, async (tx) => ({
      decision: await tx.consentDecisionRepo.findByConsentId(TENANT_ID as never, consentId),
      invitation: await tx.invitationRepo.findByRef(TENANT_ID as never, invitationRef),
      decisionEvents: (await tx.ledger.listByAggregate(TENANT_ID as never, "ConsentDecision", consentId)).map((e) => e.eventType),
      invitationEvents: (await tx.ledger.listByAggregate(TENANT_ID as never, "Invitation", invitationRef)).map((e) => e.eventType),
    }));
    assert.equal(state.decision?.state, "PENDING");
    assert.equal(state.decision?.receiptRef, undefined);
    assert.equal(state.invitation?.state, "VERIFIED");
    for (const type of ["CONSENT_GRANTED", "RECEIPT_CREATED", "CONSENT_DECLINED"]) assert.ok(!state.decisionEvents.includes(type), `no debe haber ${type}`);
    assert.ok(!state.invitationEvents.includes("INVITATION_COMPLETED"), "no debe haber INVITATION_COMPLETED");
    assert.equal(h.sink.sent.length, 0, "ningun mensaje salio");
    assert.deepEqual(h.failures, []);
    assert.equal((await healthyDecision.uow.inTenant(TENANT_ID as never, (tx) => tx.ledger.readChain(TENANT_ID as never))).length, ledgerBefore, "el ledger del tenant no cambio");
    // El handle que el registro REAL escribio antes del fallo se deshizo con la tx: no resuelve.
    assert.equal(await h.ports.managementHandleStore?.resolveByHash(handleHash), null, "ningun handle quedo registrado");

    // Sin residuo: restaurado el registro sano, el reintento de la misma decision concluye.
    (h.ports as { decision: unknown }).decision = healthyDecision;
    const retried = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(retried.status, 200);
    assert.equal(((await retried.json()) as { state: string }).state, "GRANTED");
  } finally {
    console.error = origError;
    await h.close();
  }
});

test("TEST-CNS-1414: con store Postgres o entorno distinto de LOCAL el servidor exige guestMessageChannel explícito y nunca cae al sink en memoria (P2-1, fail-closed)", () => {
  const base = createDefaultConsentFlowPorts(OTP_POLICY, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const common = { sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports: base };
  assert.throws(() => createConsentFlowHttpServer({ ...common, environment: "STAGING" }), /guestMessageChannel/);
  assert.throws(() => createConsentFlowHttpServer({ ...common, environment: "LOCAL", storeMode: "postgres", caseSessions: {} as never }), /guestMessageChannel/);
  // LOCAL en memoria conserva el sink por defecto.
  createConsentFlowHttpServer({ ...common, environment: "LOCAL" }).close();
});

test("TEST-CNS-1415: una cookie vieja no opera sobre una invitación que ya no está VERIFIED: tras cancelar (I9) o tras COMPLETED, /decision, /decision/steps y /decision/submit dan 404 uniforme (P2-2, P-30)", async () => {
  const subjectRef = fixtureUuid("subject-1414");
  const h = await startServer(subjectRef);
  try {
    const { session } = await bringToVerified(h, fixtureUuid("inv-1414"), subjectRef);
    const afterSteps = await completeSteps(h, session);
    // Copia de la cookie ANTES de cancelar.
    const cancelled = await post(h.baseUrl, { path: "/decision/subject-mismatch", ...VALID_CSRF, sessionCookie: afterSteps });
    assert.equal(cancelled.status, 200);
    assert.equal((await fetch(`${h.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${afterSteps}` } })).status, 404);
    const step = await post(h.baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: afterSteps, body: { stepKind: "CONTEXT_INFORMATION_VIEWED" } });
    assert.equal(step.status, 404);
    const submit = await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: afterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(submit.status, 404);
    // Sin decisión ni mensajes tras cancelar.
    assert.equal(h.sink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1416: I9 ramas negativas (GRD-IV-10, ERR-IV-09): estado no VERIFIED o terminal, otro decisionMakerRef (también sobre una ya CANCELLED) y exactamente un INVITATION_CANCELLED en el ledger tras repetir (P2-3, P2-4)", async () => {
  const { cancelInvitationSubjectMismatch } = await import("../../../src/server/modules/invitation/invitation.ts");
  const subjectRef = fixtureUuid("subject-1415");
  const h = await startServer(subjectRef);
  try {
    const invitationRef = fixtureUuid("inv-1415");
    await bringToVerified(h, invitationRef, subjectRef);
    const record = await h.ports.invitation.uow.inTenant(TENANT_ID, (tx) => tx.invitationRepo.findByRef(TENANT_ID, invitationRef));
    const dm = record?.boundDecisionMakerRef as string;
    assert.ok(dm);
    const expectCode = async (fn: () => Promise<unknown>, code: string): Promise<void> => {
      await assert.rejects(fn, (e: unknown) => (e as { code?: string }).code === code);
    };
    // Otro decisionMakerRef -> ERR-IV-09 (antes de cualquier rama), sin cancelar.
    await expectCode(() => cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, invitationRef, "otro-dm"), "ERR-IV-09");
    assert.equal((await h.ports.invitation.uow.inTenant(TENANT_ID, (tx) => tx.invitationRepo.findByRef(TENANT_ID, invitationRef)))?.state, "VERIFIED");
    // Cancela y repite: idempotente, exactamente un evento.
    await cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, invitationRef, dm);
    await cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, invitationRef, dm);
    const events = await h.ports.invitation.ledger.listByAggregate(TENANT_ID, "Invitation", invitationRef);
    assert.equal(events.filter((e) => e.eventType === "INVITATION_CANCELLED").length, 1);
    assert.deepEqual(events.find((e) => e.eventType === "INVITATION_CANCELLED")?.payload, { invitationRef, reasonCode: "SUBJECT_MISMATCH_REPORTED" });
    // Ya CANCELLED: otro decisionMakerRef sigue sin obtener el acuse.
    await expectCode(() => cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, invitationRef, "otro-dm"), "ERR-IV-09");

    // Estado no VERIFIED (SENT, nunca verificada) y terminal (COMPLETED) -> ERR-IV-09.
    const other = fixtureUuid("inv-1415b");
    await createInvitation(h.ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"), invitationRef: other, contextRef: LECTORPRO_BETA_CONFIG.contextRef, productRef: LECTORPRO_BETA_CONFIG.productRef, subjectRef: fixtureUuid("subject-1415b") });
    await expectCode(() => cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, other, dm), "ERR-IV-09");
    const done = fixtureUuid("inv-1415c");
    const doneSubject = fixtureUuid("subject-1415c");
    const v = await bringToVerified(h, done, doneSubject);
    const steps = await completeSteps(h, v.session);
    assert.equal((await post(h.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: steps, body: { purposes: GRANT_ALL } })).status, 200);
    const doneRec = await h.ports.invitation.uow.inTenant(TENANT_ID, (tx) => tx.invitationRepo.findByRef(TENANT_ID, done));
    assert.equal(doneRec?.state, "COMPLETED");
    await expectCode(() => cancelInvitationSubjectMismatch(h.ports.invitation, TENANT_ID, done, doneRec?.boundDecisionMakerRef as string), "ERR-IV-09");
  } finally {
    await h.close();
  }
});
