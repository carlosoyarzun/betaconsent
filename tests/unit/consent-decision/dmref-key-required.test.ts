// Gobierna: INV-CM-09 rev. 4g / OPEN-CM-10, revision lampone-security P2-6.
// Sin default aleatorio para la clave del decisionMakerRef / chainRef: el servidor no arranca sin ella.

import test from "node:test";
import assert from "node:assert/strict";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { DecisionMakerRefKey } from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY } from "../../helpers/test-ref-keys.ts";

const OTP = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const REL = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const ORIGIN = "http://consola-consent.test.localhost";

test("TEST-CNS-1246: createDefaultConsentFlowPorts sin decisionMakerRefKey falla con error claro y sin filtrar secretos", () => {
  assert.throws(
    () => createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, undefined as unknown as DecisionMakerRefKey),
    (e: Error) => /decisionMakerRefKey es obligatoria/.test(e.message) && !e.message.includes(TEST_CHAIN_REF_KEY.toString("hex")),
  );
  assert.throws(() => createDefaultConsentFlowPorts(OTP, REL, undefined as unknown as Buffer, TEST_DECISION_MAKER_REF_KEY), /chainRefKey es obligatoria/);
});

test("TEST-CNS-1247: createConsentFlowHttpServer sin clave (ni ports) no arranca; con claves explicitas si", () => {
  assert.throws(
    () => createConsentFlowHttpServer({ config: { allowedOrigin: ORIGIN }, otpPolicy: OTP, relationshipConfig: REL, environment: "LOCAL" }),
    /obligatoria/,
  );
  const server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    otpPolicy: OTP,
    relationshipConfig: REL,
    environment: "LOCAL",
    chainRefKey: TEST_CHAIN_REF_KEY,
    decisionMakerRefKey: TEST_DECISION_MAKER_REF_KEY,
  });
  assert.ok(server);
  const ports = createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY);
  assert.equal(ports.decisionMakerRefKey, TEST_DECISION_MAKER_REF_KEY);
});

test("TEST-CNS-1248: ports inyectados sin decisionMakerRefKey hacen fallar el arranque del servidor", () => {
  const ports = { ...createDefaultConsentFlowPorts(OTP, REL, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY), decisionMakerRefKey: undefined as unknown as DecisionMakerRefKey };
  assert.throws(() => createConsentFlowHttpServer({ config: { allowedOrigin: ORIGIN }, ports, environment: "LOCAL" }), /decisionMakerRefKey es obligatoria/);
});
