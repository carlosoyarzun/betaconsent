// Gobierna: src/server/entrypoints/dev-rh3-seed.ts (seed RH3 de dev.ts), API-CNS-138/139,
// revocation.spec.yaml R4, CA-127. Regresión: la siembra de dev.ts dejó de pasar por el dominio
// que fija verifiedAuthPath/revokedDecisionRef y la co-firma respondía 409 INVALID_TRANSITION.
// Mismo patrón que dev-local-config.test.ts (TEST-CNS-566): usa los valores LOCAL_ONLY_DEV_*
// reales, sin ejecutar dev.ts como proceso. TEST-CNS-687.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";

import { createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, LOCAL_ONLY_DEV_STAFF_ROSTER, LOCAL_ONLY_DEV_TENANT_ID } from "../../../src/server/entrypoints/dev-local-config.ts";
import { RH3_DEV_CASE_REF, RH3_DEV_CONSENT_ID, RH3_DEV_REVOCATION_REF, seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { cosignCaseConfirmation, recordCaseConfirmationPendingCosign } from "../../../src/server/modules/revocation/revocation.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import { validateOutboxEvent } from "../../contract/schema-lite.ts";
import type { InMemoryOutbox } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET } from "../../helpers/test-ref-keys.ts";

const TENANT_ID = LOCAL_ONLY_DEV_TENANT_ID;

async function runSeededRh3Flow() {
  const ports = createDefaultConsentFlowPorts(loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY), loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG), TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const revocationPorts = createDefaultRevocationFlowPorts(loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY), ports.decision.ledger, ports.decision.repo);
  await seedRh3DevCase(ports, revocationPorts, TENANT_ID);
  // ADR-010 rev. 5 (6d parte 2): `web` ya no sirve /platform/* ni dev-login CASE; los pasos RH3 del caso sembrado se ejecutan sobre el DOMINIO en memoria (las rutas HTTP de platform, contra Postgres,
  // las cubre TEST-CNS-1711). Mismas aserciones de estado, evidencia y outbox que antes.
  const staff = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
  const ports3 = revocationPorts.revocation;
  await recordCaseConfirmationPendingCosign(ports3, staff, TENANT_ID, RH3_DEV_REVOCATION_REF, RH3_DEV_CASE_REF, { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
  const cosigned = await cosignCaseConfirmation(ports3, staff, TENANT_ID, RH3_DEV_REVOCATION_REF, RH3_DEV_CASE_REF, { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(cosigned.status, "APPLIED");
  assert.equal((await ports3.revocationRepo.findByRef(TENANT_ID, RH3_DEV_REVOCATION_REF))?.status, "APPLIED");
  assertRevocationEvidence(await ports3.ledger.listByAggregate(TENANT_ID, "Revocation", RH3_DEV_REVOCATION_REF), {
    revocationRef: RH3_DEV_REVOCATION_REF,
    authPath: "RECOVERY",
    recoveryMethod: "HUMAN_ASSISTED",
    revokedDecisionRef: RH3_DEV_CONSENT_ID,
  });
  return revocationPorts;
}

test("TEST-CNS-687: el caso RH3 sembrado con la config de dev completa confirmación + co-firma y llega a APPLIED con evidencia válida contra el schema", async () => {
  await runSeededRh3Flow();
});

test("TEST-CNS-697: el seed RH3 de dev queda APPLIED con exactamente un consent.revoked válido en el outbox (CA-127)", async () => {
  const revocationPorts = await runSeededRh3Flow();
  const outbox = revocationPorts.revocation.outbox as InMemoryOutbox;
  assert.equal(outbox.enqueued.length, 1);
  const record = outbox.enqueued[0]!;
  assert.equal(record.envelope.tenantRef, TENANT_ID);
  assert.ok(validateOutboxEvent(record.envelope).ok);
  assert.equal(record.envelope.payload.revocationRef, RH3_DEV_REVOCATION_REF);
  const revoked = (await revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", RH3_DEV_REVOCATION_REF)).find((e) => e.eventType === "CONSENT_REVOKED");
  assert.equal(record.envelope.occurredAt, (revoked!.payload as { effectiveAt: string }).effectiveAt);
  assert.equal(record.envelope.eventType, "consent.revoked");
});
