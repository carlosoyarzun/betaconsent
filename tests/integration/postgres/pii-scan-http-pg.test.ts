// Gobierna: DEC-BR-014 rev. 8 §3 X5 (escaneo de PII, tokens, OTP y cookies en logs y URLs /i/*, /m/*, /r/*),
// SEC-CNS-014, INV-OT-02, DEC-BR-014 §4. Variante Postgres REAL de TEST-CNS-952: mismo recorrido y mismo
// escaner (consent-flow/pii-scan-driver.ts), con el servidor armado igual que CONSENT_STORE=postgres
// (openPostgresStore + createPostgresFlowPorts, rol app_rw). Ademas del escaneo de logs/URLs, el
// password de la base y el secreto de sesion cuentan como secretos de entorno. TEST-CNS-953.
// Requiere Postgres real (harness.ts); SYNTHETIC DATA ONLY.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import { createConsentFlowHttpServer, createPostgresFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { InMemoryInvitationLinkChannelSink } from "../../../src/infra/adapters/in-memory-invitation-link-channel-sink.adapter.ts";
import { openPostgresStore } from "../../../src/infra/adapters/postgres/store.ts";
import { listOutboxEnvelopes } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
import { registerTenantHandle } from "../../../src/infra/adapters/postgres/tenant-handle.adapter.ts";
import { applyLocalFixtures, loadLocalFixtures } from "../../../src/infra/adapters/postgres/local-fixtures.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { SCAN_ORIGIN, assertNonVacuous, describeStats, newCorpus, runAllFlows, scanForLeaks, startCapture } from "../consent-flow/pii-scan-driver.ts";
import type { ScanEnv } from "../consent-flow/pii-scan-driver.ts";
import { deriveDecisionMakerRefKey } from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { pgTest } from "./harness.ts";

const T = LOCAL_ONLY_DEV_TENANT_ID;
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

pgTest("TEST-CNS-953 PII scan e2e (Postgres): /i -> OTP -> decision, /m -> retiro, /r, RH3 y STAFF no dejan emails, OTP, tokens, cookies __Host-*, secretos ni dm: en logs ni URLs", async (ctx) => {
  // Catalogo (SELECT-only para app_rw) provisionado como consent_migrator, igual que TEST-CNS-880.
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, loadLocalFixtures(new URL("../../../db/fixtures/local", import.meta.url).pathname), { environment: "LOCAL" });

  const appUrl = ctx.urlFor("app_rw");
  const dbPassword = decodeURIComponent(new URL(appUrl).password);
  const sessionSecret = randomBytes(32);
  const chainSecret = Buffer.alloc(32, 9);
  const store = await openPostgresStore({
    environment: "LOCAL",
    idempotencyPolicy: loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
    env: { CNS_DATABASE_URL: appUrl },
  });
  const staffIdentity = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
  const bundle = createPostgresFlowPorts(store, {
    otpPolicy: loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY),
    relationshipConfig: loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG),
    recoveryTokenPolicy: loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY),
    staffIdentity,
    chainRefKey: deriveChainRefKey(chainSecret),
    decisionMakerRefKey: deriveDecisionMakerRefKey(Buffer.alloc(32, 8)),
    invitationIssuancePolicy: loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
  });
  const { ports, revocationPorts, staffConsole, caseSessions } = bundle;
  const server = createConsentFlowHttpServer({
    config: { allowedOrigin: SCAN_ORIGIN },
    ports,
    revocationPorts,
    sessionSecret,
    environment: "LOCAL",
    staffIdentity,
    staffConsole,
    caseSessions,
    storeMode: "postgres",
    devOutboxSink: () => store.uow.withTenantTx(T, (tx) => listOutboxEnvelopes(tx)),
  });
  const baseUrl = await new Promise<string>((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));

  const env: ScanEnv = {
    baseUrl,
    otpSink: ports.otp.channel as InMemoryOtpChannelSink,
    recoverySink: revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink,
    invitationSink: staffConsole.issuance.invitationLinkChannel as InMemoryInvitationLinkChannelSink,
    envSecrets: [dbPassword, appUrl, sessionSecret.toString("hex"), sessionSecret.toString("base64"), chainSecret.toString("hex"), chainSecret.toString("base64")],
    async seedInvitation(label) {
      const inv = fixtureUuid(`inv-${label}`);
      await createInvitation(ports.invitation, T, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
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
      return sendInvitation(ports.invitation, T, "INVITER", inv, { deliveryChannel: "CONSENT_APP_EMAIL" });
    },
    async seedManage(label) {
      const consentId = fixtureUuid(`consent-${label}`);
      const chainRef = fixtureUuid(`chain-${label}`);
      const handleToken = `mgmt-token-${label}-${randomBytes(6).toString("hex")}`;
      await store.uow.inTenant(T, (tx) =>
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
      await store.uow.withTenantTx(T, (tx) => registerTenantHandle(tx, { handle: handleToken, chainRef, revokedDecisionRef: consentId }));
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
    await store.close();
  }
  corpus.logs = logs;
  const stats = describeStats(corpus);
  assertNonVacuous(corpus);
  assert.deepEqual(scanForLeaks(corpus), [], stats);
  console.log(`TEST-CNS-953 scan-stats ${stats}`);
});
