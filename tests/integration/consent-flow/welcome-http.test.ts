// Gobierna: CLAUDE.md (UX-CNS-001, Carlos 2026-09-27: /welcome). GET /welcome exige la sesión
// LANDING creada por GET /i/{token} (API-CNS-101, P-12) y nunca transiciona nada (INV-CM-08);
// sin sesión válida sirve el estado de error uniforme de la propia pantalla (INV-CM-05), nunca
// un 404 crudo. Estáticos bajo /assets/** solo desde una lista blanca cerrada
// (static-assets.ts). CSRF double-submit (GRD-CM-10): la cookie __Host-cns-csrf que fija
// GET /welcome (csrf.ts) es la misma que welcome.js copiaría al header x-csrf-token.
// TEST-CNS-538..TEST-CNS-544 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+welcome@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };

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

/** A diferencia de decision-http.test.ts, aquí puede haber MÁS de un Set-Cookie (sesión + CSRF)
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

async function redeem(baseUrl: string, token: string): Promise<string | undefined> {
  const res = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
  return parseAllSetCookies(res)[SESSION_COOKIE_NAME];
}

async function getWelcome(baseUrl: string, sessionCookie: string | undefined): Promise<Response> {
  const headers: Record<string, string> = {};
  if (sessionCookie !== undefined) headers.cookie = `${SESSION_COOKIE_NAME}=${sessionCookie}`;
  return fetch(`${baseUrl}/welcome`, { headers });
}

test("TEST-CNS-538: GET /welcome con sesión válida responde 200, HTML con un h1, lang=es y las cabeceras de seguridad (Cache-Control, Referrer-Policy, CSP)", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-538", "subject-538@example.invalid");
    const session = await redeem(harness.baseUrl, token);
    const res = await getWelcome(harness.baseUrl, session);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("content-security-policy"), "default-src 'self'");
    const html = await res.text();
    assert.match(html, /<html lang="es">/);
    assert.match(html, /<h1[^>]*>Bienvenida a la invitación<\/h1>/);
    assert.match(html, /<script src="\/assets\/welcome\.js" defer><\/script>/);
    assert.doesNotMatch(html, /<script>/); // sin inline scripts (CSP default-src 'self')
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-539: GET /welcome sin sesión (sin canjear /i/{token}) muestra el estado de error uniforme de la propia pantalla, nunca el 404 JSON crudo del framework", async () => {
  const harness = await startServer();
  try {
    const res = await getWelcome(harness.baseUrl, undefined);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const html = await res.text();
    assert.match(html, /No pudimos abrir esta invitación\./);
    assert.doesNotMatch(html, /"status":404/); // no es el {"status":404} JSON del resto del entrypoint
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-540: GET /welcome contiene el copy exacto del handoff (welcome-handoff.md §3)", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-540", "subject-540@example.invalid");
    const session = await redeem(harness.baseUrl, token);
    const html = await (await getWelcome(harness.baseUrl, session)).text();
    assert.match(html, /Colegio Ejemplo te invita a participar en el Estudio Beta de LectorPro\./);
    assert.match(
      html,
      /LectorPro es una aplicación que apoya la lectura de tu hija o hijo\. El colegio invita a las familias a sumarse a un estudio piloto\./,
    );
    assert.match(
      html,
      /A continuación te enviaremos un código de verificación\. Después de confirmarlo, podrás revisar la información y decidir si participar\./,
    );
    assert.match(html, />Continuar<\/button>/);
    assert.match(html, /¿Necesitas ayuda\? Escríbenos a ayuda@example\.invalid/);
    assert.match(html, /No pudimos conectar\./);
    assert.match(html, /Revisa tu conexión e inténtalo nuevamente\./);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-541: los estáticos de la lista blanca (design system, app.css, welcome.js) responden 200 con su content-type", async () => {
  const harness = await startServer();
  try {
    const dsIndex = await fetch(`${harness.baseUrl}/assets/design-system/index.css`);
    assert.equal(dsIndex.status, 200);
    assert.match(dsIndex.headers.get("content-type") ?? "", /text\/css/);
    assert.match(await dsIndex.text(), /@import/);

    const dsTokens = await fetch(`${harness.baseUrl}/assets/design-system/css/tokens.css`);
    assert.equal(dsTokens.status, 200);

    const appCss = await fetch(`${harness.baseUrl}/assets/app.css`);
    assert.equal(appCss.status, 200);
    assert.match(await appCss.text(), /min-height: 44px/);

    const js = await fetch(`${harness.baseUrl}/assets/welcome.js`);
    assert.equal(js.status, 200);
    assert.match(js.headers.get("content-type") ?? "", /javascript/);
    assert.match(await js.text(), /x-csrf-token/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-542: una ruta fuera de la lista blanca, incluido un intento de traversal con '../', responde 404 sin filtrar contenido del filesystem", async () => {
  const harness = await startServer();
  try {
    const unknown = await fetch(`${harness.baseUrl}/assets/does-not-exist.css`);
    assert.equal(unknown.status, 404);

    // Traversal literal sin normalizar (node:http.request, a diferencia de fetch/WHATWG URL,
    // envía el path tal cual, sin colapsar "..").
    const address = new URL(harness.baseUrl);
    const traversalBody = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpRequest(
        { host: address.hostname, port: address.port, path: "/assets/../../package.json", method: "GET" },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(traversalBody.status, 404);
    assert.doesNotMatch(traversalBody.body, /"name": ?"consent-app"/);

    // Traversal con puntos porcentaje-codificados hacia un archivo real del repo.
    const encoded = await fetch(`${harness.baseUrl}/assets/%2e%2e/server/entrypoints/http/config.ts`);
    assert.equal(encoded.status, 404);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-543: flujo GET /i/{token} -> GET /welcome -> POST /invitation/open -> POST /otp/request replica exactamente la secuencia y el CSRF double-submit que ejecuta welcome.js", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-543", "subject-543@example.invalid");

    // 1) GET /i/{token} (P-12): redirige a /welcome sin transicionar (INV-CM-08).
    const redeemed = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    assert.equal(redeemed.headers.get("location"), "/welcome");
    const cookiesAfterRedeem = parseAllSetCookies(redeemed);
    const sessionCookie = cookiesAfterRedeem[SESSION_COOKIE_NAME];
    assert.ok(sessionCookie);

    // 2) GET /welcome: fija la cookie CSRF que welcome.js leería con document.cookie.
    const welcome = await getWelcome(harness.baseUrl, sessionCookie);
    assert.equal(welcome.status, 200);
    const csrfToken = parseAllSetCookies(welcome)[CSRF_COOKIE_NAME];
    assert.ok(csrfToken, "GET /welcome debe fijar __Host-cns-csrf (csrf.ts)");

    // 3) POST /invitation/open (welcome.js: postJson en el click de "Continuar"), CSRF
    // double-submit: mismo valor en la cookie y en el header x-csrf-token (GRD-CM-10).
    const cookieHeader = `${SESSION_COOKIE_NAME}=${sessionCookie}; ${CSRF_COOKIE_NAME}=${csrfToken}`;
    const opened = await fetch(`${harness.baseUrl}/invitation/open`, {
      method: "POST",
      headers: { origin: ALLOWED_ORIGIN, cookie: cookieHeader, [CSRF_HEADER_NAME]: csrfToken, "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(opened.status, 200);
    assert.deepEqual(await opened.json(), { result: "OPENED" });
    const sessionAfterOpen = parseAllSetCookies(opened)[SESSION_COOKIE_NAME] ?? sessionCookie;

    // 4) POST /otp/request (welcome.js lo encadena automáticamente tras el open exitoso).
    const requested = await fetch(`${harness.baseUrl}/otp/request`, {
      method: "POST",
      headers: {
        origin: ALLOWED_ORIGIN,
        cookie: `${SESSION_COOKIE_NAME}=${sessionAfterOpen}; ${CSRF_COOKIE_NAME}=${csrfToken}`,
        [CSRF_HEADER_NAME]: csrfToken,
        "content-type": "application/json",
      },
      body: "{}",
    });
    assert.equal(requested.status, 202);
    assert.deepEqual(await requested.json(), { result: "RECEIVED" });

    assert.equal(harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-543")?.state, "OPENED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-544: GET /verify sirve un placeholder mínimo del servidor (siguiente pantalla pendiente), no un 404", async () => {
  const harness = await startServer();
  try {
    const res = await fetch(`${harness.baseUrl}/verify`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const html = await res.text();
    assert.match(html, /<h1[^>]*>Verificación<\/h1>/);
  } finally {
    await harness.close();
  }
});
