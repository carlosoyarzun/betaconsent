// Gobierna: F-E2E-01 (hallazgo P1 LOCAL de la línea base E2E), common.schema.json Ref (UUIDv4 opaco, INV-CM-09),
// ADR-001 F1 (fase C, encargo de Carlos 2026-10-18). Protege la siembra del enlace de gestión de dev.ts
// (src/server/entrypoints/dev-mgmt-seed.ts): con refs UUIDv4 el POST /otp/submit del enlace sembrado responde 200 y no 500
// (LedgerPayloadViolationError). SYNTHETIC DATA ONLY.
// TEST-CNS-1931: las refs sembradas son UUIDv4 distintas y dev.ts no reintroduce literales no-UUID.
// TEST-CNS-1932: el enlace sembrado con esas refs recorre /m -> /manage -> POST /otp/request -> POST /otp/submit con 200 (MANAGE VERIFIED).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { DEV_MGMT_SEED_REFS } from "../../../src/server/entrypoints/dev-mgmt-seed.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_GUEST_CHANNEL, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const TENANT_ID = "e4a381a5-1295-48d1-8818-b8033107c762";
const TOKEN = "dev-mgmt-token-001";

test("TEST-CNS-1931: las refs de la siembra de gestión de dev.ts son UUIDv4 sintéticas y distintas; dev.ts las usa y no conserva literales no-UUID (F-E2E-01)", () => {
  const values = Object.values(DEV_MGMT_SEED_REFS);
  assert.equal(values.length, 6);
  for (const v of values) assert.match(v, UUID_V4);
  assert.equal(new Set(values).size, values.length);
  const dev = readFileSync(new URL("../../../src/server/entrypoints/dev.ts", import.meta.url), "utf8");
  assert.match(dev, /DEV_MGMT_SEED_REFS\.chainRef/);
  assert.match(dev, /DEV_MGMT_SEED_REFS\.consentId/);
  assert.doesNotMatch(dev, /"(chain|consent|dm|inv|ver|receipt)[-:]dev-mgmt/);
});

test("TEST-CNS-1932: el enlace de gestión sembrado como en dev.ts permite POST /otp/submit (MANAGE) con 200, sin LedgerPayloadViolationError (F-E2E-01)", async () => {
  const ports = createDefaultConsentFlowPorts({ codeLength: 6, maxAttempts: 3, ttlMs: 60_000 }, { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] }, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  await ports.decision.repo.save({
    consentId: DEV_MGMT_SEED_REFS.consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-dev-mgmt"),
    decisionMakerRef: DEV_MGMT_SEED_REFS.decisionMakerRef,
    invitationRef: DEV_MGMT_SEED_REFS.invitationRef,
    verificationRef: DEV_MGMT_SEED_REFS.verificationRef,
    chainRef: DEV_MGMT_SEED_REFS.chainRef,
    state: "GRANTED",
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: DEV_MGMT_SEED_REFS.receiptRef,
  });
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({ handle: TOKEN, tenantId: TENANT_ID, chainRef: DEV_MGMT_SEED_REFS.chainRef, revokedDecisionRef: DEV_MGMT_SEED_REFS.consentId });
  const server = createConsentFlowHttpServer({ guestMessageChannel: TEST_GUEST_CHANNEL, sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY, config: { allowedOrigin: ALLOWED_ORIGIN }, ports, revocationPorts });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  try {
    const redeemed = await fetch(`${baseUrl}/m/${TOKEN}`, { redirect: "manual" });
    const handle = redeemed.headers.getSetCookie().map((c) => c.split(";")[0] ?? "").find((c) => c.startsWith("__Host-cns-m-handle="));
    assert.ok(handle);
    const manage = await fetch(`${baseUrl}/manage`, { headers: { cookie: handle } });
    const session = manage.headers.getSetCookie().map((c) => c.split(";")[0] ?? "").find((c) => c.startsWith("__Host-cns-session="));
    assert.ok(session);
    const csrf = "csrf-token-abcdefgh";
    const post = (path: string, cookie: string, body: unknown = {}) =>
      fetch(`${baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ALLOWED_ORIGIN, "x-csrf-token": csrf, cookie: `__Host-cns-csrf=${csrf}; ${cookie}` }, body: JSON.stringify(body) });
    const requested = await post("/otp/request", session);
    assert.equal(requested.status, 202);
    const newSession = requested.headers.getSetCookie().map((c) => c.split(";")[0] ?? "").find((c) => c.startsWith("__Host-cns-session=")) ?? session;
    const sink = ports.otp.channel as InMemoryOtpChannelSink;
    const code = sink.sent[sink.sent.length - 1]?.code ?? "";
    const submitted = await post("/otp/submit", newSession, { code });
    assert.equal(submitted.status, 200);
    assert.deepEqual(await submitted.json(), { result: "VERIFIED", scope: "MANAGE" });
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
});
