// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.d y §10 fila 6d, opcion A de Carlos (2026-10-15): `/platform/*` sale de `web` (404) y no hay dev-login CASE en web (GRD-CM-13, P6-4);
// contracts/openapi/consent-platform.openapi.yaml (las rutas de caso solo en el proceso platform). SYNTHETIC ONLY.
// TEST-CNS-1700: el servidor web (modo memoria, LOCAL) responde 404 uniforme a TODA ruta /platform/* (POST y GET, con y sin cookie/Origin/CSRF, las seis de caso, login, logout y step-up) sin tocar estado ni fijar
// cookies, y /__dev/staff-login con un principal CASE/PLATFORM tampoco abre sesion (404, sin Set-Cookie).

import { SYNTHETIC_SPA_DIST_DIR } from "../../helpers/synthetic-spa-dist.ts";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { LOCAL_ONLY_DEV_STAFF_ROSTER } from "../../../src/server/entrypoints/dev-local-config.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_GUEST_CHANNEL, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-consent.test.localhost";
const CASE = fixtureUuid("case-1700");
const PROPOSAL = fixtureUuid("proposal-1700");

test("TEST-CNS-1700: web responde 404 a toda ruta /platform/* (acciones de caso, sesiones, login, logout, step-up) y no abre sesion CASE/PLATFORM por dev-login; sin Set-Cookie", async () => {
  const ports = createDefaultConsentFlowPorts({ codeLength: 6, maxAttempts: 3, ttlMs: 60_000 }, { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] }, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const staffIdentity = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
  const server = createConsentFlowHttpServer({ spaDistDir: SYNTHETIC_SPA_DIST_DIR,
    guestMessageChannel: TEST_GUEST_CHANNEL, sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ORIGIN }, ports, environment: "LOCAL", staffIdentity,
  });
  const base = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  try {
    const paths = [
      `/platform/rights-cases/${CASE}/verification-proposals`,
      `/platform/rights-cases/${CASE}/verification-proposals/${PROPOSAL}/approval`,
      `/platform/rights-cases/${CASE}/verification-proposals/${PROPOSAL}/withdrawal`,
      `/platform/rights-cases/${CASE}/confirmation`,
      `/platform/rights-cases/${CASE}/confirmation/cosign`,
      `/platform/rights-cases/${CASE}/close`,
      `/platform/rights-cases/${CASE}/grant-requests`,
      "/platform/sessions/platform",
      "/platform/sessions/case",
      "/platform/logout",
      "/platform/case-session/logout",
      "/platform/step-up",
      "/platform/auth/login",
      "/platform/auth/callback",
    ];
    const cookie = "__Host-cns-case=" + "a".repeat(64) + "; __Host-cns-platform=" + "b".repeat(64) + "; __Host-cns-csrf=csrf-token-abcdefgh";
    for (const path of paths) {
      for (const method of ["POST", "GET"] as const) {
        for (const headers of [{}, { origin: ORIGIN, "content-type": "application/json", cookie, "x-csrf-token": "csrf-token-abcdefgh" }]) {
          const res = await fetch(`${base}${path}`, { method, headers, ...(method === "POST" ? { body: JSON.stringify({ proposalRef: PROPOSAL, verificationScriptVersion: "g", confirmationGivenOnCasePage: true, outcome: "RESOLVED" }) } : {}) });
          assert.equal(res.status, 404, `${method} ${path}`);
          assert.deepEqual(res.headers.getSetCookie(), [], `${method} ${path}: sin Set-Cookie`);
        }
      }
    }
    // dev-login: solo TENANT_ADMIN abre sesion STAFF; un RIGHTS_OPERATOR/APPROVER del roster (con o sin caseRef) = 404 sin cookies.
    for (const entry of LOCAL_ONLY_DEV_STAFF_ROSTER.filter((e) => e.role !== "TENANT_ADMIN")) {
      for (const body of [{ principalRef: entry.principalRef }, { principalRef: entry.principalRef, caseRef: CASE, tenantId: fixtureUuid("t-1700") }]) {
        const res = await fetch(`${base}/__dev/staff-login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
        assert.equal(res.status, 404, `${entry.role} dev-login`);
        assert.deepEqual(res.headers.getSetCookie(), []);
      }
    }
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
