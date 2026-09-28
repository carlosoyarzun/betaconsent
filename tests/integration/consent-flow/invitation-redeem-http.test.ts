// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}, P-12);
// specs/state-machines/invitation.spec.yaml I4 (efecto de canje), GRD-IV-07;
// specs/state-machines/common.spec.yaml INV-CM-08 (un GET nunca transiciona).
// TEST-CNS-509..TEST-CNS-511 (traceability/test-matrix.csv).
//
// Levanta el servidor HTTP real (node:http) en un puerto efímero de localhost con adapters
// in-memory. Cero PII: subjectRef/channelRef con dominio example.invalid.

import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+channel-redeem@example.invalid";

// LOCAL-only sintético (D4, no es default de producción): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };

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

function seedSentInvitation(ports: ConsentFlowPorts, invitationRef: string, subjectRef: string, expiresAt?: Date): string {
  createInvitation(ports.invitation, TENANT_ID, "INVITER", {
    invitationRef,
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef,
  });
  markInvitationReady(ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: expiresAt ?? new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", invitationRef);
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

test("TEST-CNS-509: GET /i/{token} con token válido -> 303 a ruta sin token, fija la cookie de sesión y no transiciona (INV-CM-08)", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-509", "subject-509@example.invalid");
    const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });

    assert.equal(res.status, 303);
    const location = res.headers.get("location") ?? "";
    assert.match(location, /^\/[a-z-]+$/);
    assert.equal(location.includes(token), false, "la Location no debe llevar el token");

    const cookies = parseSetCookie(res);
    assert.ok(cookies[SESSION_COOKIE_NAME], "debe fijar __Host-cns-session (D5, handle LANDING)");

    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("cache-control"), "no-store");

    // INV-CM-08: el GET no transiciona; la invitación sigue SENT hasta el POST /invitation/open.
    assert.equal(harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-509")?.state, "SENT");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-510: GET /i/{token} con token inexistente, expirado o de otro tenant -> 404 uniforme, sin cookie", async () => {
  const harness = await startServer();
  try {
    const expiredToken = seedSentInvitation(harness.ports, "inv-510-expired", "subject-510a@example.invalid", new Date(Date.now() - 1000));

    for (const token of ["no-such-token", expiredToken]) {
      const res = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
      assert.equal(res.status, 404);
      const body = (await res.json()) as { status: number };
      assert.equal(body.status, 404);
      assert.equal(res.headers.get("set-cookie"), null);
    }
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-511: un segundo GET /i/{token} sigue sin transicionar; la invitación solo abre con el POST /invitation/open posterior", async () => {
  const harness = await startServer();
  try {
    const token = seedSentInvitation(harness.ports, "inv-511", "subject-511@example.invalid");
    await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
    await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });

    assert.equal(harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, "inv-511")?.state, "SENT");
    const events = harness.ports.invitation.ledger.listByAggregate(TENANT_ID, "Invitation", "inv-511");
    assert.equal(events.some((e) => e.eventType === "INVITATION_OPENED"), false, "GET no debe emitir INVITATION_OPENED");
  } finally {
    await harness.close();
  }
});
