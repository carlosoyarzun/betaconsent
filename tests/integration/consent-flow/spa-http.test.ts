// Gobierna: ADR-001 rev. 8 F1 (React SPA servida por el backend, fase A) y §3 (CSP sin inline); decisión de Carlos 2026-10-18.
// CNS_UI_MODE=spa: las 8 rutas HTML del invitado devuelven dist/index.html conservando la lógica previa de cookie/sesión
// (200 con sesión + cookie CSRF; 404 uniforme sin ella, INV-CM-05), con la CSP única; los assets con hash se sirven por
// igualdad exacta (immutable); el resto sigue en 404 JSON. El dist es SINTÉTICO (directorio temporal), no depende del build.
// TEST-CNS-1889..TEST-CNS-1895 (traceability/test-matrix.csv).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { parseUiMode } from "../../../src/server/entrypoints/http/spa-assets.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY, TEST_GUEST_CHANNEL } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

const ADR_001_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const JS_NAME = "index-Ab12Cd34.js";
const CSS_NAME = "style-Ef56Gh78.css";
const INDEX_HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="cns-page-state" content="ready"><title>Consent App</title>
<script type="module" crossorigin src="/assets/${JS_NAME}"></script><link rel="stylesheet" crossorigin href="/assets/${CSS_NAME}"></head>
<body class="lp-guest-body"><div id="root"></div></body></html>
`;
const HTML_PAGES = ["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm"] as const;

function makeSyntheticDist(): string {
  const dir = mkdtempSync(join(tmpdir(), "cns-spa-dist-"));
  mkdirSync(join(dir, "assets"));
  mkdirSync(join(dir, ".vite"));
  writeFileSync(join(dir, "index.html"), INDEX_HTML);
  writeFileSync(join(dir, "assets", JS_NAME), "console.log('synthetic');\n");
  writeFileSync(join(dir, "assets", CSS_NAME), ".lp-guest-body{margin:0}\n");
  writeFileSync(join(dir, ".vite", "manifest.json"), "{}");
  return dir;
}

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(uiMode: "ssr" | "spa", spaDistDir?: string): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const server: Server = createConsentFlowHttpServer({
    guestMessageChannel: TEST_GUEST_CHANNEL,
    sessionSecret: TEST_SESSION_SECRET,
    staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    uiMode,
    ...(spaDistDir ? { spaDistDir } : {}),
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({ baseUrl: `http://127.0.0.1:${address.port}`, ports, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function parseAllSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of res.headers.getSetCookie()) {
    const first = raw.split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq !== -1 && !out[first.slice(0, eq).trim()]) out[first.slice(0, eq).trim()] = first.slice(eq + 1).trim();
  }
  return out;
}

async function seedSentInvitation(ports: ConsentFlowPorts): Promise<string> {
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    enrollmentRef: fixtureUuid("enr-spa"),
    participationRef: fixtureUuid("part-spa"),
    invitationRef: fixtureUuid("inv-spa"),
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-spa"),
  });
  await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-spa"), {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: "test+spa@example.invalid",
  });
  return (await sendInvitation(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-spa"), { deliveryChannel: "CONSENT_APP_EMAIL" })).token;
}

async function withSpa(fn: (h: Harness) => Promise<void>): Promise<void> {
  const dist = makeSyntheticDist();
  const h = await startServer("spa", dist);
  try {
    await fn(h);
  } finally {
    await h.close();
    rmSync(dist, { recursive: true, force: true });
  }
}

test("TEST-CNS-1889: spa — GET /welcome con sesión válida (canje /i/{token}) responde 200 con index.html, CSP ADR-001 §3, no-store y cookies de sesión + CSRF", async () => {
  await withSpa(async (h) => {
    const token = await seedSentInvitation(h.ports);
    const redeemed = await fetch(`${h.baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303); // el canje 303 no cambia
    const handle = parseAllSetCookies(redeemed)[INVITATION_HANDLE_COOKIE_NAME];
    assert.ok(handle);
    const res = await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handle}` } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /^text\/html; charset=utf-8/);
    assert.equal(res.headers.get("content-security-policy"), ADR_001_CSP);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff"); // F-E2E-02
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    const cookies = parseAllSetCookies(res);
    assert.ok(cookies[SESSION_COOKIE_NAME], "fija la sesión real como en ssr");
    assert.ok(cookies[CSRF_COOKIE_NAME], "fija la cookie CSRF como en ssr");
    const html = await res.text();
    assert.equal(html, INDEX_HTML);
    assert.match(html, /content="ready"/);
    assert.doesNotMatch(html, /<style|\sstyle=|<script>|welcome\.js/);
  });
});

test("TEST-CNS-1890: spa — las 8 rutas HTML sin sesión/handle responden 404 con index.html (cns-page-state=uniform-error), misma CSP y sin revelar la causa", async () => {
  await withSpa(async (h) => {
    const bodies = new Set<string>();
    for (const path of HTML_PAGES) {
      const res = await fetch(`${h.baseUrl}${path}`, { redirect: "manual" });
      assert.equal(res.status, 404, path);
      assert.match(res.headers.get("content-type") ?? "", /^text\/html; charset=utf-8/, path);
      assert.equal(res.headers.get("content-security-policy"), ADR_001_CSP, path);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff", path); // F-E2E-02
      assert.equal(res.headers.get("cache-control"), "no-store", path);
      const html = await res.text();
      assert.match(html, /<meta name="cns-page-state" content="uniform-error">/, path);
      assert.doesNotMatch(html, /content="ready"/, path);
      bodies.add(html);
    }
    assert.equal(bodies.size, 1, "cuerpo byte-idéntico en las 8 rutas (INV-CM-05)");
  });
});

test("TEST-CNS-1891: spa — /recovery/confirm conserva COOP same-origin y el resto de cabeceras de seguridad de la página", async () => {
  await withSpa(async (h) => {
    const res = await fetch(`${h.baseUrl}/recovery/confirm`);
    assert.equal(res.headers.get("cross-origin-opener-policy"), "same-origin");
    assert.equal(res.headers.get("content-security-policy"), ADR_001_CSP);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff"); // F-E2E-02
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });
});

test("TEST-CNS-1892: spa — assets con hash: 200, MIME correcto, immutable; fuera de la lista blanca (traversal, .vite, inexistente) 404 JSON", async () => {
  await withSpa(async (h) => {
    const js = await fetch(`${h.baseUrl}/assets/${JS_NAME}`);
    assert.equal(js.status, 200);
    assert.equal(js.headers.get("content-type"), "text/javascript; charset=utf-8");
    assert.equal(js.headers.get("cache-control"), "public, max-age=31536000, immutable");
    assert.equal(js.headers.get("x-content-type-options"), "nosniff");
    const css = await fetch(`${h.baseUrl}/assets/${CSS_NAME}`);
    assert.equal(css.status, 200);
    assert.equal(css.headers.get("content-type"), "text/css; charset=utf-8");
    assert.equal(css.headers.get("cache-control"), "public, max-age=31536000, immutable");
    for (const path of ["/assets/nope-12345678.js", "/assets/../index.html", "/assets/%2e%2e/index.html", "/assets/.vite/manifest.json", "/assets/", "/.vite/manifest.json", "/index.html"]) {
      const res = await fetch(`${h.baseUrl}${path}`, { redirect: "manual" });
      assert.equal(res.status, 404, path);
      assert.match(res.headers.get("content-type") ?? "", /application\/json/, path);
      assert.deepEqual(await res.json(), { status: 404 }, path);
    }
  });
});

test("TEST-CNS-1893: spa — los estáticos del SSR (app.css, DS) siguen sirviéndose no-store para las pantallas staff; rutas desconocidas siguen en 404 JSON", async () => {
  await withSpa(async (h) => {
    const css = await fetch(`${h.baseUrl}/assets/app.css`);
    assert.equal(css.status, 200);
    assert.equal(css.headers.get("cache-control"), "no-store");
    const unknown = await fetch(`${h.baseUrl}/no-existe`);
    assert.equal(unknown.status, 404);
    assert.match(unknown.headers.get("content-type") ?? "", /application\/json/);
    assert.deepEqual(await unknown.json(), { status: 404 });
  });
});

test("TEST-CNS-1894: ssr (default) — /welcome sin sesión sigue siendo el HTML SSR uniforme y los assets con hash de dist no se sirven", async () => {
  const dist = makeSyntheticDist();
  const h = await startServer("ssr", dist);
  try {
    const res = await fetch(`${h.baseUrl}/welcome`);
    assert.equal(res.status, 404);
    const html = await res.text();
    assert.match(html, /<h1[^>]*>Bienvenida a la invitación<\/h1>/);
    assert.match(html, /id="error-uniform"/);
    assert.doesNotMatch(html, /cns-page-state/);
    assert.equal(res.headers.get("content-security-policy"), ADR_001_CSP);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff"); // F-E2E-02
    assert.equal((await fetch(`${h.baseUrl}/assets/${JS_NAME}`)).status, 404);
  } finally {
    await h.close();
    rmSync(dist, { recursive: true, force: true });
  }
});

test("TEST-CNS-1895: CNS_UI_MODE — default ssr, valores inválidos abortan y spa sin build falla al arrancar (fail-closed)", async () => {
  assert.equal(parseUiMode(undefined), "ssr");
  assert.equal(parseUiMode(""), "ssr");
  assert.equal(parseUiMode("ssr"), "ssr");
  assert.equal(parseUiMode("spa"), "spa");
  assert.throws(() => parseUiMode("SPA"), /CNS_UI_MODE/);
  assert.throws(() => parseUiMode("react"), /CNS_UI_MODE/);
  const empty = mkdtempSync(join(tmpdir(), "cns-spa-empty-"));
  try {
    await assert.rejects(async () => startServer("spa", empty), /build:frontend/);
    // dist sin el marcador de estado de página: no es un build válido
    writeFileSync(join(empty, "index.html"), "<!doctype html><html></html>");
    await assert.rejects(async () => startServer("spa", empty), /cns-page-state/);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
});
