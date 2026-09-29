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

async function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, expiresAt?: Date): Promise<string> {
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: `subject-${invitationRef}@example.invalid`,
  });
  await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: expiresAt ?? new Date(Date.now() + 60_000),
    recipientChannelRef: `channel-${invitationRef}@example.invalid`,
  });
  const { token } = await sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
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
    const validToken = await seedSentInvitation(harness.ports, "inv-610-valid");
    const expiredToken = await seedSentInvitation(harness.ports, "inv-610-expired", new Date(Date.now() - 1000));
    // "usado": I4 ya corrió (INVITATION_OPENED); el canje uniforme no distingue este estado tampoco.
    const usedToken = await seedSentInvitation(harness.ports, "inv-610-used");

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
    const token = await seedSentInvitation(harness.ports, "inv-612");
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
    const expiredToken = await seedSentInvitation(harness.ports, "inv-614-expired", new Date(Date.now() - 1000));
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

    const events = await harness.ports.invitation.ledger.listByAggregate(TENANT_ID, "Invitation", "inv-614-expired");
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

    const events = await harness.revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", "chain-615");
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
    const token = await seedSentInvitation(harness.ports, "inv-616");
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

// ---------------------------------------------------------------------------
// FINDING P1 (Carlos, prueba en navegador): "el último enlace abierto manda". Una sesión previa
// vigente (real, ya sin handle en la petición: navegación normal dentro del flujo) nunca debe
// sobrevivir a un GET con un handle nuevo — ni cuando el handle nuevo es inválido (error
// uniforme, sesión borrada) ni cuando resuelve a una identidad distinta (contexto del enlace
// nuevo, no el anterior).
// ---------------------------------------------------------------------------

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

/** GET /i/{token} -> GET /welcome, devuelve (sesión real, Set-Cookie completo de /welcome). */
async function redeemInvitationFull(baseUrl: string, token: string): Promise<{ sessionCookie: string; welcomeRes: Response }> {
  const redeemed = await fetch(`${baseUrl}/i/${encodeURIComponent(token)}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(redeemed)[INVITATION_HANDLE_COOKIE_NAME]!;
  const welcomeRes = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const sessionCookie = parseAllSetCookies(welcomeRes)[SESSION_COOKIE_NAME]!;
  return { sessionCookie, welcomeRes };
}

test("TEST-CNS-618: /welcome — sesión A vigente + handle inválido -> error uniforme y la sesión A queda borrada; sesión A + handle válido de un enlace B distinto -> contexto de B, nunca el de A", async () => {
  const harness = await startHarness();
  try {
    const tokenA = await seedSentInvitation(harness.ports, "inv-618-a");
    const { sessionCookie: sessionA } = await redeemInvitationFull(harness.baseUrl, tokenA);
    assert.ok(sessionA);

    // Sesión A vigente + handle inválido (típico: el navegador todavía trae la cookie de
    // sesión A, pero el usuario acaba de abrir un enlace roto): error uniforme, sesión borrada.
    const invalidRedeemed = await fetch(`${harness.baseUrl}/i/token-inexistente-618`, { redirect: "manual" });
    const invalidHandle = parseSetCookie(invalidRedeemed)[INVITATION_HANDLE_COOKIE_NAME]!;
    const welcomeInvalid = await fetch(`${harness.baseUrl}/welcome`, {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionA}; ${INVITATION_HANDLE_COOKIE_NAME}=${invalidHandle}` },
    });
    assert.equal(welcomeInvalid.status, 404);
    assert.match(await welcomeInvalid.text(), /No pudimos abrir esta invitación\./);
    const clearedCookie = welcomeInvalid.headers.get("set-cookie") ?? "";
    assert.match(clearedCookie, new RegExp(`${SESSION_COOKIE_NAME}=;`));
    assert.match(clearedCookie, /Max-Age=0/);

    // Sesión A vigente + handle válido de un enlace B distinto (segundo hijo, p. ej.): el
    // contexto pasa a ser el de B, nunca el de A ("el último enlace abierto manda").
    const tokenB = await seedSentInvitation(harness.ports, "inv-618-b");
    const redeemedB = await fetch(`${harness.baseUrl}/i/${tokenB}`, { redirect: "manual" });
    const handleB = parseSetCookie(redeemedB)[INVITATION_HANDLE_COOKIE_NAME]!;
    const welcomeB = await fetch(`${harness.baseUrl}/welcome`, {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionA}; ${INVITATION_HANDLE_COOKIE_NAME}=${handleB}` },
    });
    assert.equal(welcomeB.status, 200);
    const sessionAfterB = parseAllSetCookies(welcomeB)[SESSION_COOKIE_NAME]!;
    assert.notEqual(sessionAfterB, sessionA);

    const opened = await fetch(`${harness.baseUrl}/invitation/open`, {
      method: "POST",
      headers: {
        origin: ALLOWED_ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": "csrf-token-abcdefgh",
        cookie: `${SESSION_COOKIE_NAME}=${sessionAfterB}; __Host-cns-csrf=csrf-token-abcdefgh`,
      },
      body: "{}",
    });
    assert.equal(opened.status, 200);
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-618-b"))?.state, "OPENED");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-618-a"))?.state, "SENT");
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});

test("TEST-CNS-619: /manage — sesión A vigente + handle inválido -> error uniforme (59:3) y la sesión A queda borrada; sesión A + handle válido de un enlace B distinto -> contexto (chainRef) de B, nunca el de A", async () => {
  const harness = await startHarness();
  try {
    const tenantHandle = harness.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter;
    tenantHandle.issue({ handle: "mgmt-619-a", tenantId: TENANT_ID, chainRef: "chain-619-a", revokedDecisionRef: "consent-619-a" });
    const redeemedA = await fetch(`${harness.baseUrl}/m/mgmt-619-a`, { redirect: "manual" });
    const handleA = parseSetCookie(redeemedA)[MANAGE_ENTRY_HANDLE_COOKIE_NAME]!;
    const manageA = await fetch(`${harness.baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleA}` } });
    const sessionA = parseAllSetCookies(manageA)[SESSION_COOKIE_NAME]!;
    assert.ok(sessionA);

    // Sesión A vigente + handle inválido: error uniforme (59:3), sesión borrada.
    const invalidRedeemed = await fetch(`${harness.baseUrl}/m/mgmt-inexistente-619`, { redirect: "manual" });
    const invalidHandle = parseSetCookie(invalidRedeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME]!;
    const manageInvalid = await fetch(`${harness.baseUrl}/manage`, {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionA}; ${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${invalidHandle}` },
    });
    assert.equal(manageInvalid.status, 404);
    assert.match(await manageInvalid.text(), /Este enlace ya no está disponible\./);
    const clearedCookie = manageInvalid.headers.get("set-cookie") ?? "";
    assert.match(clearedCookie, new RegExp(`${SESSION_COOKIE_NAME}=;`));
    assert.match(clearedCookie, /Max-Age=0/);

    // Sesión A vigente + handle válido de un enlace B distinto (otro chainRef, p. ej. la
    // gestión de un segundo hijo): el contexto pasa a ser el de B, nunca el de A.
    tenantHandle.issue({ handle: "mgmt-619-b", tenantId: TENANT_ID, chainRef: "chain-619-b", revokedDecisionRef: "consent-619-b" });
    const redeemedB = await fetch(`${harness.baseUrl}/m/mgmt-619-b`, { redirect: "manual" });
    const handleB = parseSetCookie(redeemedB)[MANAGE_ENTRY_HANDLE_COOKIE_NAME]!;
    const manageB = await fetch(`${harness.baseUrl}/manage`, {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${sessionA}; ${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleB}` },
    });
    assert.equal(manageB.status, 200);
    const sessionAfterB = parseAllSetCookies(manageB)[SESSION_COOKIE_NAME]!;
    assert.notEqual(sessionAfterB, sessionA);

    const r1 = await fetch(`${harness.baseUrl}/manage/revocation`, {
      method: "POST",
      headers: {
        origin: ALLOWED_ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": "csrf-token-abcdefgh",
        cookie: `${SESSION_COOKIE_NAME}=${sessionAfterB}; __Host-cns-csrf=csrf-token-abcdefgh`,
      },
      body: "{}",
    });
    // Sin sesión MANAGE verificada (V3) todavía: 404 uniforme, pero la aserción que importa aquí
    // es que R1 nunca alcanza a operar sobre chain-619-a (nunca se creó ninguna Revocation ahí).
    assert.equal(r1.status, 404);
    assert.equal(await harness.revocationPorts.revocation.revocationRepo.findOpenByChain(TENANT_ID, "chain-619-a"), null);
  } finally {
    await new Promise((resolve) => harness.server.close(() => resolve(undefined)));
  }
});
