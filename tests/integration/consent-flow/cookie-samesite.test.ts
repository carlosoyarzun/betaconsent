// Gobierna: API-CNS-103 SEC-CNS-014 (revisión APROBADA CON CAMBIOS), FINDING P1-02: la cookie
// de sesión (__Host-cns-session) y la cookie CSRF double-submit (__Host-cns-csrf) pasan de
// SameSite=Strict a SameSite=Lax (Carlos, 2026-09-28, opción b): el JS de /recovery/confirm y
// del resto de páginas de un solo uso necesita leer/usar estas cookies justo después de una
// redirección 303 cross-site (GET /r/{token} llega desde un enlace externo, p. ej. un cliente
// de correo). SameSite=Lax sigue bloqueando el envío de la cookie en un POST cross-site
// (solo la navegación GET de nivel superior la envía); GRD-CM-10 (csrf_and_origin,
// common.spec.yaml) sigue siendo la defensa real de los POST: token CSRF double-submit +
// comparación de Origin por igualdad exacta, sin debilitar. TEST-CNS-599.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const TENANT_ID = "tenant-samesite";

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

test("TEST-CNS-599: __Host-cns-session y __Host-cns-csrf se fijan con SameSite=Lax (Secure/HttpOnly/Path=/ intactos); un POST sin token CSRF o con Origin ajeno sigue rechazado (GRD-CM-10)", async () => {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: fixtureUuid("inv-599"),
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-599"),
  });
  await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-599"), {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: "channel-599@example.invalid",
  });
  const { token } = await sendInvitation(ports.invitation, TENANT_ID, "INVITER", fixtureUuid("inv-599"), { deliveryChannel: "CONSENT_APP_EMAIL" });

  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });

  try {
    const redeemed = await fetch(`${baseUrl}/i/${token}`, { redirect: "manual" });
    const handleSetCookie = redeemed.headers.get("set-cookie") ?? "";
    assert.match(handleSetCookie, /__Host-cns-i-handle=/);
    assert.match(handleSetCookie, /SameSite=Lax/);
    assert.match(handleSetCookie, /Secure/);
    assert.match(handleSetCookie, /HttpOnly/);
    assert.match(handleSetCookie, /Path=\//);
    const handleCookie = parseSetCookie(redeemed)[INVITATION_HANDLE_COOKIE_NAME]!;

    const welcome = await fetch(`${baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
    const welcomeSetCookies = welcome.headers.getSetCookie ? welcome.headers.getSetCookie() : [welcome.headers.get("set-cookie") ?? ""];
    const sessionSetCookie = welcomeSetCookies.find((c) => c.startsWith(`${SESSION_COOKIE_NAME}=`)) ?? "";
    assert.match(sessionSetCookie, /SameSite=Lax/);
    assert.match(sessionSetCookie, /Secure/);
    assert.match(sessionSetCookie, /HttpOnly/);
    assert.match(sessionSetCookie, /Path=\//);
    const csrfSetCookie = welcomeSetCookies.find((c) => c.startsWith(`${CSRF_COOKIE_NAME}=`)) ?? "";
    assert.match(csrfSetCookie, /SameSite=Lax/);
    assert.match(csrfSetCookie, /Secure/);
    assert.match(csrfSetCookie, /Path=\//);
    const sessionCookie = (() => {
      const out: Record<string, string> = {};
      for (const part of sessionSetCookie.split(";")) {
        const eq = part.indexOf("=");
        if (eq === -1) continue;
        out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
      }
      return out[SESSION_COOKIE_NAME]!;
    })();
    const csrfCookie = (() => {
      const out: Record<string, string> = {};
      for (const part of csrfSetCookie.split(";")) {
        const eq = part.indexOf("=");
        if (eq === -1) continue;
        out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
      }
      return out[CSRF_COOKIE_NAME]!;
    })();

    // GRD-CM-10 sigue vigente: sin token CSRF -> ERR-CM-09 (403), pese a SameSite=Lax.
    const withoutCsrf = await fetch(`${baseUrl}/invitation/open`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ALLOWED_ORIGIN, cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}; ${CSRF_COOKIE_NAME}=${csrfCookie}` },
      body: JSON.stringify({}),
    });
    assert.equal(withoutCsrf.status, 403);

    // Origin ajeno -> ERR-CM-09 (403), aun con CSRF header/cookie coincidentes.
    const wrongOrigin = await fetch(`${baseUrl}/invitation/open`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://ajeno.test.localhost",
        [CSRF_HEADER_NAME]: csrfCookie,
        cookie: `${SESSION_COOKIE_NAME}=${sessionCookie}; ${CSRF_COOKIE_NAME}=${csrfCookie}`,
      },
      body: JSON.stringify({}),
    });
    assert.equal(wrongOrigin.status, 403);
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
