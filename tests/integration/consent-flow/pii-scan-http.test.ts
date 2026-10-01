// Gobierna: DEC-BR-014 rev. 8 §3 X5 (escaneo de PII, tokens, OTP y cookies en logs y URLs /i/*, /m/*, /r/*),
// SEC-CNS-014, INV-OT-02, DEC-BR-014 §4 (synthetic-only). Servidor HTTP real en memoria (mismo armado que
// dev.ts con CONSENT_STORE=memory): recorre /i -> OTP -> decision, /m -> retiro -> recibo, /r recuperacion,
// RH3 (cuatro ojos) y consola STAFF, captura TODO stdout/stderr y todas las URLs, y falla ante cualquier
// email (incluidos sinteticos), OTP, token en claro, valor de cookie __Host-*, secreto de entorno o hash dm:.
// TEST-CNS-952 (recorrido) y TEST-CNS-954 (el escaner no es vacuo: detecta fugas plantadas).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

import {
  createConsentFlowHttpServer,
  createDefaultConsentFlowPorts,
  createDefaultRevocationFlowPorts,
  createDefaultStaffConsolePorts,
} from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_PARTICIPATION_REF,
  LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_STAFF_SUBJECT_REF,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { InMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { SCAN_ORIGIN, assertNonVacuous, describeStats, newCorpus, runAllFlows, scanForLeaks, startCapture } from "./pii-scan-driver.ts";
import type { ScanEnv } from "./pii-scan-driver.ts";

const T = LOCAL_ONLY_DEV_TENANT_ID;
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

test("TEST-CNS-952 PII scan e2e (memoria): /i -> OTP -> decision, /m -> retiro, /r, RH3 y STAFF no dejan emails, OTP, tokens, cookies __Host-*, secretos ni dm: en logs ni URLs", async () => {
  const sessionSecret = randomBytes(32);
  const chainSecret = Buffer.alloc(32, 9);
  const ports = createDefaultConsentFlowPorts(loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY), loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG), deriveChainRefKey(chainSecret));
  const revocationPorts = createDefaultRevocationFlowPorts(loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY), ports.decision.ledger, ports.decision.repo);
  const staffIdentity = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
  const issuancePolicy = loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY);
  const staffConsole = createDefaultStaffConsolePorts(ports.invitation, staffIdentity, issuancePolicy, loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY));
  staffConsole.catalog.seedSubject(T, LOCAL_ONLY_DEV_STAFF_SUBJECT_REF);
  staffConsole.catalog.seedParticipation(T, {
    participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    status: "ACTIVE",
  });
  const server = createConsentFlowHttpServer({
    config: { allowedOrigin: SCAN_ORIGIN },
    ports,
    revocationPorts,
    sessionSecret,
    environment: "LOCAL",
    staffIdentity,
    staffConsole,
    storeMode: "memory",
  });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));

  const env: ScanEnv = {
    baseUrl,
    otpSink: ports.otp.channel as InMemoryOtpChannelSink,
    recoverySink: revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink,
    invitationSink: staffConsole.invitationLinkSink,
    envSecrets: [sessionSecret.toString("hex"), sessionSecret.toString("base64"), chainSecret.toString("hex"), chainSecret.toString("base64")],
    async seedInvitation(label) {
      const inv = fixtureUuid(`inv-${label}`);
      await createInvitation(ports.invitation, T, "INVITER", {
        invitationRef: inv,
        contextRef: LECTORPRO_BETA_CONFIG.contextRef,
        productRef: LECTORPRO_BETA_CONFIG.productRef,
        subjectRef: fixtureUuid(`subj-${label}`),
      });
      await markInvitationReady(ports.invitation, T, "INVITER", inv, {
        consentVersion: "v1-dev",
        expiresAt: new Date(Date.now() + 3_600_000),
        recipientChannelRef: `${label}@example.invalid`,
      });
      return sendInvitation(ports.invitation, T, "INVITER", inv);
    },
    async seedManage(label) {
      const consentId = fixtureUuid(`consent-${label}`);
      const chainRef = `chain-${label}`;
      const handleToken = `mgmt-token-${label}-${randomBytes(6).toString("hex")}`;
      await ports.decision.uow.inTenant(T, (tx) =>
        tx.consentDecisionRepo.save({
          consentId,
          tenantId: T,
          contextRef: LECTORPRO_BETA_CONFIG.contextRef,
          productRef: LECTORPRO_BETA_CONFIG.productRef,
          subjectRef: fixtureUuid(`subj-${label}`),
          decisionMakerRef: `dm:${label}`,
          invitationRef: `inv-${label}`,
          verificationRef: `ver-${label}`,
          chainRef,
          state: "GRANTED",
          purposes: GRANT_ALL,
          priorStepsComplete: true,
          stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
          receiptRef: `receipt-${label}`,
        }),
      );
      (revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({ handle: handleToken, tenantId: T, chainRef, revokedDecisionRef: consentId });
      return { handleToken };
    },
    seedRh3: async () => {
      await seedRh3DevCase(ports, revocationPorts, T);
    },
  };

  const corpus = newCorpus(env.envSecrets);
  const stop = startCapture();
  let logs = "";
  try {
    await runAllFlows(env, T, corpus);
  } finally {
    logs = stop();
    await new Promise((r) => server.close(() => r(undefined)));
  }
  corpus.logs = logs;
  const stats = describeStats(corpus);
  assertNonVacuous(corpus);
  assert.deepEqual(scanForLeaks(corpus), [], stats);
  // Evidencia de la corrida (solo conteos; cero valores).
  console.log(`TEST-CNS-952 scan-stats ${stats}`);
});

test("TEST-CNS-954 el escaner no es vacuo: detecta email, OTP, token, cookie, secreto de entorno, dm: y token reutilizado en una URL (fugas plantadas)", () => {
  const base = (): ReturnType<typeof newCorpus> => {
    const c = newCorpus(["SECRETO-DE-ENTORNO-0001"]);
    c.tokens.add("tok-abc-123456789");
    c.otpCodes.add("482913");
    c.cookieValues.add("cookie-valor-abcdefgh");
    c.emails.add("alguien@example.invalid");
    c.requestUrls.push("/i/tok-abc-123456789");
    return c;
  };
  assert.deepEqual(scanForLeaks(base()), [], "corpus limpio: 0 hallazgos");
  const plants: ReadonlyArray<readonly [string, (c: ReturnType<typeof newCorpus>) => void]> = [
    ["email en log", (c) => (c.logs = "user x@example.invalid failed")],
    ["destinatario del sink en URL", (c) => c.responseUrls.push("/x?to=alguien@example.invalid")],
    ["OTP en log", (c) => (c.logs = "code=482913")],
    ["token en log", (c) => (c.logs = "GET /i/tok-abc-123456789")],
    ["token en Location", (c) => c.responseUrls.push("/welcome?t=tok-abc-123456789")],
    ["token reutilizado en otro request", (c) => c.requestUrls.push("/i/tok-abc-123456789")],
    ["cookie en log", (c) => (c.logs = "cookie cookie-valor-abcdefgh")],
    ["secreto de entorno en log", (c) => (c.logs = "boot SECRETO-DE-ENTORNO-0001")],
    ["hash dm: en URL", (c) => c.responseUrls.push("/x?dm:abcdef")],
  ];
  // La captura de stdout/stderr no es vacua: console.log/error/process.stdout.write de texto quedan en el corpus.
  const stop = startCapture();
  console.log("probe-log");
  console.error("probe-error");
  process.stdout.write("probe-write\n");
  const captured = stop();
  assert.match(captured, /probe-log\nprobe-error\nprobe-write\n/);
  for (const [name, plant] of plants) {
    const c = base();
    plant(c);
    assert.notEqual(scanForLeaks(c).length, 0, `no detecto: ${name}`);
  }
});
