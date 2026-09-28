// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}), API-CNS-102
// (GET /m/{token}), SEC-CNS-014 (Carlos, 2026-09-28, opción a: mismo patrón que GET /r/{token},
// PR #23). specs/state-machines/invitation.spec.yaml I4 (rev. 4f), revocation.spec.yaml
// managementLink. Complementa invitation-redeem-http.test.ts (TEST-CNS-509..511, flujo feliz) y
// manage-revocation-http.test.ts (TEST-CNS-581, flujo feliz): aquí se cubre el contrato de canje
// uniforme en sí (headers idénticos, 0 lecturas de BD, 404 byte-idéntico, sin eventos, cookies
// aisladas y el botón de soporte de 59:3), plantilla tomada de recovery-http.test.ts
// TEST-CNS-600/601/605 (PR #23).
// TEST-CNS-610..619 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import type { InvitationRepositoryPort } from "../../../src/server/ports/invitation-repository.port.ts";
import type { TenantHandlePort } from "../../../src/server/ports/tenant-handle.port.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const MANAGE_ENTRY_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
const TENANT_ID = "tenant-uniform";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

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

interface Harness {
  readonly ports: ConsentFlowPorts;
  readonly revocationPorts: RevocationFlowPorts;
  readonly server: Server;
  readonly baseUrl: string;
}

function startHarness(): Promise<Harness> {
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports, revocationPorts });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({ ports, revocationPorts, server, baseUrl: `http://127.0.0.1:${address.port}` });
    });
  });
}

function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, expiresAt?: Date): string {
  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: `subject-${invitationRef}@example.invalid`,
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: expiresAt ?? new Date(Date.now() + 60_000),
    recipientChannelRef: `channel-${invitationRef}@example.invalid`,
  });
  const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
  return token;
}

interface RedeemHeaders {
  readonly status: number;
  readonly location: string | null;
  readonly referrer: string | null;
  readonly cache: string | null;
  readonly setCookieLength: number;
}

async function redeemHeaders(baseUrl: string, path: string): Promise<RedeemHeaders> {
  const res = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
  const setCookie = res.headers.get("set-cookie") ?? "";
  return {
    status: res.status,
    location: res.headers.get("location"),
    referrer: res.headers.get("referrer-policy"),
    cache: res.headers.get("cache-control"),
    setCookieLength: setCookie.length,
  };
}

// ---------------------------------------------------------------------------
// Headers 303 idénticos entre válido/inválido/usado/vencido (TEST-CNS-600 de recovery-http, PR #23).
// ---------------------------------------------------------------------------

test("TEST-CNS-610: GET /i/{token} responde idéntico (status, headers, Location, atributos y largo del Set-Cookie) para un token válido, inexistente, ya abierto (I4 ya corrida) y expirado", async () => {
  const harness = await startHarness();
  try {
    const validToken = seedSentInvitation(harness.ports, "inv-610-valid");
    const expiredToken = seedSentInvitation(harness.ports, "inv-610-expired", new Date(Date.now() - 1000));
    // "usado": I4 ya corrió (INVITATION_OPENED); el canje uniforme no distingue este estado tampoco.
    const usedToken = seedSentInvitation(harness.ports, "inv-610-used");

    const candidates = [validToken, "token-inexistente-610", expiredToken, usedToken];
    const responses: RedeemHeaders[] = [];
    for (const candidate of candidates) {
      responses.push(await redeemHeaders(harness.baseUrl, `/i/${encodeURIComponent(candidate)}`));
    }
    const [first, ...rest] = responses;
    for (const r of rest) {
      assert.deepEqual(r, first);
    }
    assert.equal(first!.status, 303);
    assert.equal(first!.location, "/welcome");
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-611: GET /m/{token} responde idéntico (status, headers, Location, atributos y largo del Set-Cookie) para un token válido, inexistente y rotado", async () => {
  const harness = await startHarness();
  try {
    const tenantHandle = harness.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter;
    tenantHandle.issue({ handle: "mgmt-610-valid", tenantId: TENANT_ID, chainRef: "chain-610", revokedDecisionRef: "consent-610" });
    tenantHandle.issue({ handle: "mgmt-610-rotated", tenantId: TENANT_ID, chainRef: "chain-610b", revokedDecisionRef: "consent-610b" });
    tenantHandle.rotate("mgmt-610-rotated");

    const candidates = ["mgmt-610-valid", "mgmt-inexistente-610", "mgmt-610-rotated"];
    const responses: RedeemHeaders[] = [];
    for (const candidate of candidates) {
      responses.push(await redeemHeaders(harness.baseUrl, `/m/${candidate}`));
    }
    const [first, ...rest] = responses;
    for (const r of rest) {
      assert.deepEqual(r, first);
    }
    assert.equal(first!.status, 303);
    assert.equal(first!.location, "/manage");
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

// ---------------------------------------------------------------------------
// 0 lecturas de BD en el GET de canje.
// ---------------------------------------------------------------------------

test("TEST-CNS-612: GET /i/{token} nunca llama invitationRepo.findByTokenHash ni findByRef (hashea sin leer la BD, SEC-CNS-014)", async () => {
  const harness = await startHarness();
  try {
    const token = seedSentInvitation(harness.ports, "inv-612");
    let findByTokenHashCalls = 0;
    let findByRefCalls = 0;
    const realRepo: InvitationRepositoryPort = harness.ports.invitation.invitationRepo;
    const spiedRepo: InvitationRepositoryPort = {
      ...realRepo,
      findByTokenHash: (hash) => {
        findByTokenHashCalls += 1;
        return realRepo.findByTokenHash(hash);
      },
      findByRef: (tenantId, ref) => {
        findByRefCalls += 1;
        return realRepo.findByRef(tenantId, ref);
      },
    };
    (harness.ports.invitation as { invitationRepo: InvitationRepositoryPort }).invitationRepo = spiedRepo;

    await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    await fetch(`${harness.baseUrl}/i/token-inexistente-612`, { redirect: "manual" });

    assert.equal(findByTokenHashCalls, 0, "GET /i/{token} no debe leer invitationRepo (INV-CM-08 reforzado)");
    assert.equal(findByRefCalls, 0);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-613: GET /m/{token} nunca llama tenantHandle.resolve ni resolveByHash (hashea sin leer la BD, SEC-CNS-014)", async () => {
  const harness = await startHarness();
  try {
    const tenantHandle = harness.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter;
    tenantHandle.issue({ handle: "mgmt-613", tenantId: TENANT_ID, chainRef: "chain-613", revokedDecisionRef: "consent-613" });

    let resolveCalls = 0;
    let resolveByHashCalls = 0;
    const realPort: TenantHandlePort = harness.revocationPorts.tenantHandle;
    const spiedPort: TenantHandlePort = {
      resolve: (h) => {
        resolveCalls += 1;
        return realPort.resolve(h);
      },
      resolveByHash: (h) => {
        resolveByHashCalls += 1;
        return realPort.resolveByHash(h);
      },
    };
    (harness.revocationPorts as { tenantHandle: TenantHandlePort }).tenantHandle = spiedPort;

    await fetch(`${harness.baseUrl}/m/mgmt-613`, { redirect: "manual" });
    await fetch(`${harness.baseUrl}/m/mgmt-inexistente-613`, { redirect: "manual" });

    assert.equal(resolveCalls, 0, "GET /m/{token} no debe leer tenantHandle (INV-CM-08 reforzado)");
    assert.equal(resolveByHashCalls, 0, "GET /m/{token} tampoco resuelve por hash: eso ocurre recién en GET /manage");
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

// ---------------------------------------------------------------------------
// 404 byte-idéntico en la página siguiente (frames 9:12 / 59:3), sin eventos en el caso inválido.
// ---------------------------------------------------------------------------

test("TEST-CNS-614: GET /welcome responde 404 byte-idéntico (9:12) para un handle inexistente, uno de una invitación expirada y uno con token demasiado largo; ningún GET emite INVITATION_OPENED", async () => {
  const harness = await startHarness();
  try {
    const expiredToken = seedSentInvitation(harness.ports, "inv-614-expired", new Date(Date.now() - 1000));
    const tooLongToken = "x".repeat(5_000);

    const htmls: string[] = [];
    for (const candidate of ["token-inexistente-614", expiredToken, tooLongToken]) {
      const redeemed = await fetch(`${harness.baseUrl}/i/${encodeURIComponent(candidate)}`, { redirect: "manual" });
      const handleCookie = parseSetCookie(redeemed)[INVITATION_HANDLE_COOKIE_NAME]!;
      const welcome = await fetch(`${harness.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
      assert.equal(welcome.status, 404);
      htmls.push(await welcome.text());
    }
    assert.equal(htmls[0], htmls[1]);
    assert.equal(htmls[1], htmls[2]);

    const events = harness.ports.invitation.ledger.listByAggregate(TENANT_ID, "Invitation", "inv-614-expired");
    assert.equal(events.some((e) => e.eventType === "INVITATION_OPENED"), false);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-615: GET /manage responde 404 byte-idéntico (59:3) para un handle inexistente y uno rotado; ningún GET emite eventos en el ledger de Revocation", async () => {
  const harness = await startHarness();
  try {
    const tenantHandle = harness.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter;
    tenantHandle.issue({ handle: "mgmt-615-rotated", tenantId: TENANT_ID, chainRef: "chain-615", revokedDecisionRef: "consent-615" });
    tenantHandle.rotate("mgmt-615-rotated");

    const htmls: string[] = [];
    for (const candidate of ["mgmt-inexistente-615", "mgmt-615-rotated"]) {
      const redeemed = await fetch(`${harness.baseUrl}/m/${candidate}`, { redirect: "manual" });
      const handleCookie = parseSetCookie(redeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME]!;
      const manage = await fetch(`${harness.baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleCookie}` } });
      assert.equal(manage.status, 404);
      const html = await manage.text();
      assert.match(html, /Este enlace ya no está disponible\./);
      htmls.push(html);
    }
    assert.equal(htmls[0], htmls[1]);

    const events = harness.revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", "chain-615");
    assert.equal(events.length, 0);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

// ---------------------------------------------------------------------------
// Cookies aisladas: los handles de /i y /m no sirven donde no corresponden.
// ---------------------------------------------------------------------------

test("TEST-CNS-616: el handle __Host-cns-i-handle no sirve como sesión en /welcome vía sessionCookieName, ni el handle __Host-cns-m-handle en /manage; solo bajo su propio nombre de cookie funcionan", async () => {
  const harness = await startHarness();
  try {
    const token = seedSentInvitation(harness.ports, "inv-616");
    const redeemedI = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    const iHandle = parseSetCookie(redeemedI)[INVITATION_HANDLE_COOKIE_NAME]!;

    // El valor del handle bajo el nombre de la cookie de sesión no resuelve nada (sesión inválida).
    const welcomeWrongCookieName = await fetch(`${harness.baseUrl}/welcome`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${iHandle}` } });
    assert.equal(welcomeWrongCookieName.status, 404);

    const tenantHandle = harness.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter;
    tenantHandle.issue({ handle: "mgmt-616", tenantId: TENANT_ID, chainRef: "chain-616", revokedDecisionRef: "consent-616" });
    const redeemedM = await fetch(`${harness.baseUrl}/m/mgmt-616`, { redirect: "manual" });
    const mHandle = parseSetCookie(redeemedM)[MANAGE_ENTRY_HANDLE_COOKIE_NAME]!;

    // El handle MANAGE_ENTRY bajo el nombre de la cookie INVITATION_LANDING tampoco resuelve
    // (typ distinto, clave HKDF distinta, link-handle.ts).
    const welcomeWithManageHandle = await fetch(`${harness.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${mHandle}` } });
    assert.equal(welcomeWithManageHandle.status, 404);

    // Y viceversa: el handle INVITATION_LANDING no sirve como MANAGE_ENTRY.
    const manageWithInvitationHandle = await fetch(`${harness.baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${iHandle}` } });
    assert.equal(manageWithInvitationHandle.status, 404);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

// ---------------------------------------------------------------------------
// El botón "Contactar a soporte" de 59:3 apunta al contacto de ayuda, no a /rights-case/open.
// ---------------------------------------------------------------------------

test("TEST-CNS-617: el botón 'Contactar a soporte' del error uniforme de /manage (59:3) es un enlace mailto al contacto de ayuda, nunca un POST a /rights-case/open", async () => {
  const harness = await startHarness();
  try {
    const manage = await fetch(`${harness.baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=handle-inexistente-617` } });
    assert.equal(manage.status, 404);
    const html = await manage.text();
    assert.match(html, /href="mailto:ayuda@example\.invalid"[^>]*id="contact-support-btn"/);
    assert.doesNotMatch(html, /rights-case\/open/);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});
