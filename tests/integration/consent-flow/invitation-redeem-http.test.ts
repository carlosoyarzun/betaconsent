// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}, P-12);
// specs/state-machines/invitation.spec.yaml I4 (efecto de canje), GRD-IV-07;
// specs/state-machines/common.spec.yaml INV-CM-08 (un GET nunca transiciona).
// TEST-CNS-509..TEST-CNS-511 (traceability/test-matrix.csv).
//
// Levanta el servidor HTTP real (node:http) en un puerto efímero de localhost con adapters
// in-memory. Cero PII: subjectRef/channelRef con dominio example.invalid.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHANNEL_REF = "test+channel-redeem@example.invalid";

// LOCAL-only sintético (D4, no es default de producción): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintetico (GRD-CD-04, decision-relationship.config.ts): estos tests no ejercen
// pasos de decision, pero createDefaultConsentFlowPorts exige la config igual que otpPolicy.
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const server: Server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
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

async function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string, expiresAt?: Date): Promise<string> {
  await createInvitation(ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef,
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef,
  });
  await markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: expiresAt ?? new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef, { deliveryChannel: "CONSENT_APP_EMAIL" });
  return token;
}

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

test("TEST-CNS-509: GET /i/{token} con token válido -> 303 a ruta sin token, fija el handle INVITATION_LANDING (no la sesión final) y no transiciona (INV-CM-08 reforzado, SEC-CNS-014, Carlos 2026-09-28)", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-509"), fixtureUuid("subject-509"));
    const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });

    assert.equal(res.status, 303);
    const location = res.headers.get("location") ?? "";
    assert.match(location, /^\/[a-z-]+$/);
    assert.equal(location.includes(token), false, "la Location no debe llevar el token");

    const cookies = parseSetCookie(res);
    assert.ok(cookies[INVITATION_HANDLE_COOKIE_NAME], "debe fijar __Host-cns-i-handle (SEC-CNS-014, link-handle.ts)");
    assert.equal(cookies[SESSION_COOKIE_NAME], undefined, "GET /i/{token} ya no fija la sesión real directamente (Carlos 2026-09-28)");

    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("cache-control"), "no-store");

    // INV-CM-08: el GET no transiciona; la invitación sigue SENT hasta el POST /invitation/open.
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-509")))?.state, "SENT");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-510: GET /i/{token} con token inexistente, expirado o de otro tenant -> el mismo 303 uniforme que un token válido (Carlos 2026-09-28); GET /welcome subsiguiente es el que distingue (404 byte-idéntico, welcome-http.test.ts TEST-CNS-539)", async () => {
  const harness = await startServer();
  try {
    const expiredToken = await seedSentInvitation(harness.ports, fixtureUuid("inv-510-expired"), fixtureUuid("subject-510a"), new Date(Date.now() - 1000));

    for (const token of ["no-such-token", expiredToken]) {
      const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
      assert.equal(res.status, 303);
      assert.equal(res.headers.get("location"), "/welcome");
      assert.ok(parseSetCookie(res)[INVITATION_HANDLE_COOKIE_NAME], "debe fijar __Host-cns-i-handle igual que un token válido");

      const welcome = await fetch(`${harness.baseUrl}/welcome`, {
        headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${parseSetCookie(res)[INVITATION_HANDLE_COOKIE_NAME]}` },
      });
      assert.equal(welcome.status, 404);
      assert.match(await welcome.text(), /No pudimos abrir esta invitación\./);
    }
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-511: un segundo GET /i/{token} sigue sin transicionar; la invitación solo abre con el POST /invitation/open posterior", async () => {
  const harness = await startServer();
  try {
    const token = await seedSentInvitation(harness.ports, fixtureUuid("inv-511"), fixtureUuid("subject-511"));
    await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });

    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-511")))?.state, "SENT");
    const events = await harness.ports.invitation.ledger.listByAggregate(TENANT_ID, "Invitation", fixtureUuid("inv-511"));
    assert.equal(events.some((e) => e.eventType === "INVITATION_OPENED"), false, "GET no debe emitir INVITATION_OPENED");
  } finally {
    await harness.close();
  }
});
