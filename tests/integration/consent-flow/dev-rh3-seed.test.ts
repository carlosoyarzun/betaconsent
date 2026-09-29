// Gobierna: src/server/entrypoints/dev-rh3-seed.ts (seed RH3 de dev.ts), API-CNS-138/139,
// revocation.spec.yaml R4, CA-127. Regresión: la siembra de dev.ts dejó de pasar por el dominio
// que fija verifiedAuthPath/revokedDecisionRef y la co-firma respondía 409 INVALID_TRANSITION.
// Mismo patrón que dev-local-config.test.ts (TEST-CNS-566): usa los valores LOCAL_ONLY_DEV_*
// reales, sin ejecutar dev.ts como proceso. TEST-CNS-687.

import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, LOCAL_ONLY_DEV_STAFF_ROSTER, LOCAL_ONLY_DEV_TENANT_ID } from "../../../src/server/entrypoints/dev-local-config.ts";
import { RH3_DEV_CASE_REF, RH3_DEV_CONSENT_ID, RH3_DEV_REVOCATION_REF, seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import { validateApiPayload, validateOutboxEvent } from "../../contract/schema-lite.ts";
import type { InMemoryOutbox } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";

const TENANT_ID = LOCAL_ONLY_DEV_TENANT_ID;
const ORIGIN = "http://127.0.0.1:3000";

function cookiesOf(res: Response): Record<string, string> {
  const withGetter = res.headers as Headers & { getSetCookie?: () => string[] };
  const lines = withGetter.getSetCookie ? withGetter.getSetCookie() : [res.headers.get("set-cookie") ?? ""];
  const out: Record<string, string> = {};
  for (const line of lines) {
    const first = line.split(";", 1)[0] ?? "";
    const eq = first.indexOf("=");
    if (eq > 0) out[first.slice(0, eq)] = first.slice(eq + 1);
  }
  return out;
}

async function runSeededRh3Flow() {
  const ports = createDefaultConsentFlowPorts(loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY), loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG));
  const revocationPorts = createDefaultRevocationFlowPorts(loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY), ports.decision.ledger, ports.decision.repo);
  seedRh3DevCase(ports, revocationPorts, TENANT_ID);
  const server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    revocationPorts,
    environment: "LOCAL",
    staffIdentity: createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER),
  });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
  });
  try {
    async function step(principalRef: string, path: string, body: unknown): Promise<Response> {
      const login = await fetch(`${baseUrl}/__dev/staff-login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tenantId: TENANT_ID, caseRef: RH3_DEV_CASE_REF, principalRef }),
      });
      assert.equal(login.status, 200);
      const c = cookiesOf(login);
      const session = c["__Host-cns-case"];
      const csrf = c["__Host-cns-case-csrf"];
      return fetch(`${baseUrl}/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrf!, cookie: `__Host-cns-case=${session}; __Host-cns-case-csrf=${csrf}` },
        body: JSON.stringify(body),
      });
    }

    const recorded = await step("staff-synthetic-01", "", { confirmationGivenOnCasePage: true });
    assert.equal(recorded.status, 200);
    const cosigned = await step("staff-synthetic-02", "/cosign", {});
    assert.equal(cosigned.status, 200);
    const ack = await cosigned.json();
    assert.deepEqual(ack, { cosign: "COSIGNED", revocationState: "APPLIED" });
    assert.ok(validateApiPayload("CaseConfirmationAck", ack).ok);

    assert.equal(revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, RH3_DEV_REVOCATION_REF)?.status, "APPLIED");
    assertRevocationEvidence(revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", RH3_DEV_REVOCATION_REF), {
      revocationRef: RH3_DEV_REVOCATION_REF,
      authPath: "RECOVERY",
      recoveryMethod: "HUMAN_ASSISTED",
      revokedDecisionRef: RH3_DEV_CONSENT_ID,
    });
    return revocationPorts;
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
  }
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
  const revoked = revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", RH3_DEV_REVOCATION_REF).find((e) => e.eventType === "CONSENT_REVOKED");
  assert.equal(record.envelope.occurredAt, (revoked!.payload as { effectiveAt: string }).effectiveAt);
  assert.equal(record.envelope.eventType, "consent.revoked");
});
