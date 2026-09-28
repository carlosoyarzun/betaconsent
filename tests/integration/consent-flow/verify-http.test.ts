// Gobierna: UX-CNS-002 (handoff /verify, scratchpad verify-handoff.md), autorización de Carlos
// 2026-09-27 opción (a). specs/state-machines/otp-challenge.spec.yaml V1/V2/V2r/V3/V4/V5;
// contracts/openapi/consent-it0.openapi.yaml API-CNS-120/121/122. GET /verify exige la sesión
// con el OTP ya solicitado (session.verificationRef); sin ella sirve el estado de error
// uniforme de la propia pantalla (INV-CM-05), nunca un 404 crudo. GET /decision es, por ahora,
// un placeholder mínimo (Carlos 2026-09-27), igual patrón que lo fue /verify.
// TEST-CNS-553..TEST-CNS-56x (traceability/test-matrix.csv).

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
const CHANNEL_REF = "test+verify@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 2 };

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY);
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

function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string): string {
  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
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

async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const res = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  return parseAllSetCookies(res)[SESSION_COOKIE_NAME];
}

/** invitación -> canje -> open -> otp/request; devuelve la sesión con verificationRef ya
 * fijado (la que GET /verify exige) y el sink para leer el código emitido. */
async function bringToOtpRequested(
  harness: Harness,
  invitationRef: string,
  subjectRef: string,
): Promise<{ session: string; sink: InMemoryOtpChannelSink }> {
  const token = seedSentInvitation(harness.ports, invitationRef, subjectRef);
  const landingSession = await redeem(harness.baseUrl, token);
  const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
  const sessionAfterOpen = parseAllSetCookies(opened)[SESSION_COOKIE_NAME] ?? landingSession;
  const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
  const session = parseAllSetCookies(requested)[SESSION_COOKIE_NAME] ?? sessionAfterOpen;
  if (!session) throw new Error("no se obtuvo sesión con verificationRef");
  return { session, sink: harness.ports.otp.channel as InMemoryOtpChannelSink };
}

test("TEST-CNS-553: GET /verify con sesión válida (OTP ya solicitado) responde 200, HTML con un h1, lang=es y las cabeceras de seguridad", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, "inv-553", "subject-553@example.invalid");
    const res = await fetch(`${harness.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("content-security-policy"), "default-src 'self'");
    const html = await res.text();
    assert.match(html, /<html lang="es">/);
    assert.match(html, /<h1[^>]*>Verifica el código<\/h1>/);
    assert.match(html, /<script src="\/assets\/verify\.js" defer><\/script>/);
    assert.doesNotMatch(html, /<script>/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-554: GET /verify contiene el copy exacto del handoff, incluidos los placeholders [N] y [tiempo pendiente de aprobación] (P-01/P-02 sin valor aprobado)", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, "inv-554", "subject-554@example.invalid");
    const html = await (await fetch(`${harness.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    assert.match(html, /Enviamos un código a la vía de contacto registrada para continuar\. No lo compartas con nadie\./);
    assert.match(html, /Código de verificación/);
    assert.match(html, /Ingresa el código de \[N\] caracteres que enviamos \(P-01, valor pendiente de aprobación\)\./);
    assert.match(html, /El código deja de funcionar después de \[tiempo pendiente de aprobación\] \(P-02\)\./);
    assert.match(html, /El código ingresado no es correcto\. Revísalo e inténtalo nuevamente\./);
    assert.match(html, /¿No recibiste el código\?/);
    assert.match(html, />Reenviar código<\/button>/);
    assert.match(html, /Puedes solicitarlo un número limitado de veces \(P-06, valor pendiente de aprobación\)\./);
    assert.match(html, />Verificar<\/button>/);
    assert.match(html, /Este código ya no es válido\./);
    assert.match(html, /Puede haber expirado o haberse usado antes\. Solicita uno nuevo para continuar\./);
    assert.match(html, /Bloqueamos este código por varios intentos incorrectos\./);
    assert.match(html, /Por seguridad, no podemos usarlo de nuevo\. Solicita un código nuevo para continuar\./);
    assert.match(html, />Solicitar nuevo código<\/button>/);
    assert.match(html, /No pudimos conectar\./);
    assert.match(html, /Revisa tu conexión e inténtalo nuevamente\./);
    assert.match(html, /No pudimos continuar con esta verificación\./);
    assert.match(html, /¿Necesitas ayuda\? Escríbenos a ayuda@example\.invalid/);
    // P-03 (intentos máximos) nunca aparece en el copy (V2, "sin revelar intentos restantes").
    assert.doesNotMatch(html, /intentos restantes/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-555: el campo de código tiene label visible, inputmode numeric y autocomplete one-time-code, asociado por aria-describedby al helper y al error", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, "inv-555", "subject-555@example.invalid");
    const html = await (await fetch(`${harness.baseUrl}/verify`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } })).text();
    assert.match(html, /<label class="lp-label" for="code-input">Código de verificación<\/label>/);
    assert.match(html, /id="code-input"/);
    assert.match(html, /inputmode="numeric"/);
    assert.match(html, /autocomplete="one-time-code"/);
    assert.match(html, /aria-describedby="code-help code-error"/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-556: GET /decision es un placeholder mínimo del servidor, no un 404", async () => {
  const harness = await startServer();
  try {
    const res = await fetch(`${harness.baseUrl}/decision`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const html = await res.text();
    assert.match(html, /<h1[^>]*>Decisión<\/h1>/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-557: /assets/verify.js responde 200 con content-type javascript y usa x-csrf-token (double-submit)", async () => {
  const harness = await startServer();
  try {
    const js = await fetch(`${harness.baseUrl}/assets/verify.js`);
    assert.equal(js.status, 200);
    assert.match(js.headers.get("content-type") ?? "", /javascript/);
    assert.match(await js.text(), /x-csrf-token/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-558: flujo completo GET /i/{token} -> /welcome -> open -> request -> /verify -> submit con el código correcto del sink -> /decision", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-558", "subject-558@example.invalid");
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

    const decision = await fetch(`${harness.baseUrl}/decision`);
    assert.equal(decision.status, 200);
    const html = await decision.text();
    assert.match(html, /<h1[^>]*>Decisión<\/h1>/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-559: código incorrecto en /verify no expone intentos restantes en la respuesta de /otp/submit", async () => {
  const harness = await startServer();
  try {
    const { session } = await bringToOtpRequested(harness, "inv-559", "subject-559@example.invalid");
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
    const { session, sink } = await bringToOtpRequested(harness, "inv-560", "subject-560@example.invalid");
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
