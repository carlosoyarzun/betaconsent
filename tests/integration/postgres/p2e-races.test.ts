// Gobierna: CA-124 (PR-D), SEC-CNS-015 P2-E (lock de fila FOR UPDATE + expectedSequence capturado antes del lock) y P2-D
// (consumo atomico del token de recuperacion), otp-challenge.spec V3, consent-decision.spec C3/C5, rights-case.spec RC2u,
// revocation.spec R1r. TEST-CNS-845..848: carreras reales entre dos conexiones, varias rondas. El UoW se crea con
// maxAttempts 1: el reintento ante LedgerSequenceConflictError taparia la falta del FOR UPDATE; con el lock, la
// perdedora espera, relee el estado ya cambiado y falla con el error de dominio del guard (nunca con un conflicto
// de secuencia). Requiere Postgres real (harness.ts). SYNTHETIC DATA ONLY.

import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, submitOtp, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { recordDecisionStep, startDecision, submitDecision, type ConsentDecisionPorts } from "../../../src/server/modules/consent-decision/consent-decision.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { confirmCaseReturnViaHandle, type RightsCasePorts } from "../../../src/server/modules/rights-case/rights-case.ts";
import {
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  revokeWithRecoveryLinkByHash,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { DEFAULT_UOW_MAX_ATTEMPTS, PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const CHANNEL = "test+channel-845@example.invalid";
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));
const isDomain = (r: PromiseSettledResult<unknown>, code: string): boolean =>
  r.status === "rejected" && r.reason instanceof DomainError && r.reason.code === code;

async function withEnv<T>(ctx: PgTestContext, body: (env: {
  uow: PgUnitOfWork;
  outside: ReturnType<typeof pgOutsideTxPorts>;
  invitation: InvitationPorts;
  otp: OtpChallengePorts;
  decision: ConsentDecisionPorts;
  count: (sql: string, values: unknown[]) => Promise<number>;
  pool: ReturnType<typeof createPool>;
}) => Promise<T>, maxAttempts = 1, policy: { codeLength: number; maxAttempts: number; ttlMs: number; maxResends: number } = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 }): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 16 });
  const admin = await ctx.connectAsSuperuser();
  try {
    const uow = new PgUnitOfWork(pool, { maxAttempts });
    const outside = pgOutsideTxPorts(uow);
    const invitation: InvitationPorts = {
      invitationRepo: outside.invitationRepo,
      eligibility: createInMemoryEligibilityAdapter(),
      ledger: outside.ledger,
      uow,
      tenantResolver: createPgTenantResolver(pool),
    };
    const otp: OtpChallengePorts = {
      otpRepo: outside.otpRepo,
      channel: createInMemoryOtpChannelSink(),
      ledger: outside.ledger,
      uow,
      invitation,
      policy,
      secret: randomBytes(32),
    };
    const decision: ConsentDecisionPorts = {
      repo: outside.consentDecisionRepo,
      ledger: outside.ledger,
      uow,
      invitation,
      config: LECTORPRO_BETA_CONFIG,
      relationships: { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] },
      chainRefKey: deriveChainRefKey(Buffer.alloc(32, 9)),
    };
    const count = async (sql: string, values: unknown[]): Promise<number> => (await admin.query<{ n: number }>(sql, values)).rows[0]?.n ?? -1;
    return await body({ uow, outside, invitation, otp, decision, count, pool });
  } finally {
    await pool.end();
  }
}

const eventCount = (count: (sql: string, values: unknown[]) => Promise<number>, tenant: string, aggregate: string, type: string): Promise<number> =>
  count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = $3", [tenant, aggregate, type]);

async function seedOpenedInvitation(outside: ReturnType<typeof pgOutsideTxPorts>, tenant: string, invitationRef: string, subject: string, state: "OPENED" | "VERIFIED" = "OPENED", dm?: string): Promise<void> {
  await outside.invitationRepo.save({
    invitationRef,
    tenantId: tenant,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: subject,
    state,
    recipientChannelRef: CHANNEL,
    ...(dm !== undefined ? { boundDecisionMakerRef: dm } : {}),
  });
}

pgTest("TEST-CNS-845 pg: OTP verify ∥ verify en dos conexiones: exactamente una verifica (un solo evento, una sola INVITATION_VERIFIED) y la otra falla con ERR-OT-03; sin conflicto de secuencia (FOR UPDATE + base previa)", async (ctx) => {
  const T = fixtureUuid("t845");
  await withEnv(ctx, async ({ outside, otp, count }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    for (let round = 0; round < 12; round += 1) {
      const inv = fixtureUuid(`inv845-${round}`);
      const ver = fixtureUuid(`ver845-${round}`);
      await seedOpenedInvitation(outside, T, inv, `test+s845-${round}@example.invalid`);
      await requestOtp(otp, T, ver, inv, CHANNEL);
      const code = sink.sent[sink.sent.length - 1]!.code;
      const results = await Promise.allSettled([submitOtp(otp, T, ver, code, "dm-845"), submitOtp(otp, T, ver, code, "dm-845")]);
      assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, `ronda ${round}: exactamente una gana`);
      assert.ok(results.some((r) => isDomain(r, "ERR-OT-03")), `ronda ${round}: la perdedora falla con ERR-OT-03 (no con conflicto de secuencia): ${JSON.stringify(results.map((r) => r.status === "rejected" ? String(r.reason) : "ok"))}`);
      assert.equal((await outside.otpRepo.findByRef(T, ver))?.state, "VERIFIED");
      assert.equal((await outside.invitationRepo.findByRef(T, inv))?.state, "VERIFIED");
      assert.equal(await eventCount(count, T, ver, "DECISION_MAKER_CHANNEL_VERIFIED"), 1);
      assert.equal(await eventCount(count, T, inv, "INVITATION_VERIFIED"), 1);
    }
  });
});

pgTest("TEST-CNS-846 pg: submit de decision ∥ submit: exactamente una decide (un CONSENT_GRANTED, un recibo, Invitation COMPLETED) y la otra falla con ERR-CD-08", async (ctx) => {
  const T = fixtureUuid("t846");
  await withEnv(ctx, async ({ outside, decision, count }) => {
    for (let round = 0; round < 12; round += 1) {
      const inv = fixtureUuid(`inv846-${round}`);
      const consent = fixtureUuid(`consent846-${round}`);
      await seedOpenedInvitation(outside, T, inv, `test+s846-${round}@example.invalid`, "VERIFIED", "dm-846");
      await startDecision(decision, T, "DECISION_MAKER", { consentId: consent, invitationRef: inv, verificationRef: fixtureUuid(`ver846-${round}`), decisionMakerRef: "dm-846" });
      await recordDecisionStep(decision, T, "DECISION_MAKER", "dm-846", consent, { stepKind: "CONSENT_VERSION_VIEWED" });
      await recordDecisionStep(decision, T, "DECISION_MAKER", "dm-846", consent, { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true });
      await recordDecisionStep(decision, T, "DECISION_MAKER", "dm-846", consent, { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true });
      const results = await Promise.allSettled([
        submitDecision(decision, T, "DECISION_MAKER", "dm-846", consent, GRANT_ALL),
        submitDecision(decision, T, "DECISION_MAKER", "dm-846", consent, GRANT_ALL),
      ]);
      assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, `ronda ${round}: exactamente una gana`);
      assert.ok(results.some((r) => isDomain(r, "ERR-CD-08")), `ronda ${round}: ${JSON.stringify(results.map((r) => r.status === "rejected" ? String(r.reason) : "ok"))}`);
      assert.equal((await outside.consentDecisionRepo.findByConsentId(T, consent))?.state, "GRANTED");
      assert.equal((await outside.invitationRepo.findByRef(T, inv))?.state, "COMPLETED");
      assert.equal(await eventCount(count, T, consent, "CONSENT_GRANTED"), 1);
      assert.equal(await eventCount(count, T, consent, "RECEIPT_CREATED"), 1);
      assert.equal(await eventCount(count, T, consent, "PURPOSE_DECISION_RECORDED"), GRANT_ALL.length);
      assert.equal(await eventCount(count, T, inv, "INVITATION_COMPLETED"), 1);
      assert.equal(await count("SELECT max(sequence)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, consent]), 3 + GRANT_ALL.length + 2, "secuencia contigua sin huecos");
    }
  });
});

pgTest("TEST-CNS-849 pg: N submits incorrectos concurrentes sobre el mismo challenge: attempts = N, LOCKED exactamente en maxAttempts y un solo OTP_LOCKED (GRD-OT-04)", async (ctx) => {
  const T = fixtureUuid("t849");
  await withEnv(ctx, async ({ outside, otp, count }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    for (let round = 0; round < 8; round += 1) {
      const inv = fixtureUuid(`inv849-${round}`);
      const ver = fixtureUuid(`ver849-${round}`);
      await seedOpenedInvitation(outside, T, inv, `test+s849-${round}@example.invalid`);
      await requestOtp(otp, T, ver, inv, CHANNEL);
      const good = sink.sent[sink.sent.length - 1]!.code;
      const wrong = good === "000000" ? "111111" : "000000";
      const N = otp.policy.maxAttempts; // 3 incorrectos concurrentes: el ultimo bloquea
      const results = await Promise.allSettled(Array.from({ length: N }, () => submitOtp(otp, T, ver, wrong, "dm-849")));
      const codes = results.map((r) => (r.status === "rejected" && r.reason instanceof DomainError ? r.reason.code : `?${r.status === "rejected" ? String(r.reason) : "ok"}`));
      assert.deepEqual([...codes].sort(), ["ERR-OT-02", "ERR-OT-02", "ERR-OT-04"], `ronda ${round}: ${codes.join(",")}`);
      const rec = await outside.otpRepo.findByRef(T, ver);
      assert.equal(rec?.attempts, N, "ningun intento se pierde");
      assert.equal(rec?.state, "LOCKED");
      assert.equal(await eventCount(count, T, ver, "OTP_LOCKED"), 1);
      assert.equal(await eventCount(count, T, ver, "OTP_FAILED"), N - 1);
      // Tras LOCKED, ni el codigo correcto verifica (GRD-OT-04).
      await assert.rejects(() => submitOtp(otp, T, ver, good, "dm-849"), (e: unknown) => e instanceof DomainError && e.code === "ERR-OT-04");
    }
  }, 8); // reintentos del UoW: la perdedora con base vieja relee y reintenta (el intento no se pierde)
});

// Nota de sensibilidad: RC2u es idempotente por idempotencyKey (caseRef), asi que sin FOR UPDATE el ledger deduplica y el
// resultado observable no cambia; el lock aqui evita la doble escritura del estado, no un conflicto visible. La
// sensibilidad al FOR UPDATE se comprueba en 845/846 (quitar FOR UPDATE de otp/decision las hace fallar).
pgTest("TEST-CNS-847 pg: RC2u ∥ RC2u: ambas ven CONTACTING pero se emite un solo RIGHTS_CASE_CONTACTING; sin conflicto de secuencia", async (ctx) => {
  const T = fixtureUuid("t847");
  await withEnv(ctx, async ({ uow, outside, count }) => {
    for (let round = 0; round < 12; round += 1) {
      const caseRef = fixtureUuid(`case847-${round}`);
      const chain = `chain-847-${round}`;
      const decisionRef = fixtureUuid(`dec847-${round}`);
      const tenantHandle = createInMemoryTenantHandleAdapter([{ handle: `h-847-${round}`, tenantId: T, chainRef: chain, revokedDecisionRef: decisionRef }]);
      const ports: RightsCasePorts = { tenantHandle, rightsCaseRepo: outside.rightsCaseRepo, revocationRepo: outside.revocationRepo, ledger: outside.ledger, uow };
      await outside.rightsCaseRepo.save({ caseRef, tenantId: T, chainRef: chain, revokedDecisionRef: decisionRef, status: "OPEN", origin: "CHANNEL_UNREACHABLE" });
      const results = await Promise.allSettled([confirmCaseReturnViaHandle(ports, `h-847-${round}`), confirmCaseReturnViaHandle(ports, `h-847-${round}`)]);
      assert.deepEqual(results.map((r) => (r.status === "fulfilled" ? r.value.status : String(r.reason))), ["CONTACTING", "CONTACTING"], `ronda ${round}`);
      assert.equal((await outside.rightsCaseRepo.findByRef(T, caseRef))?.status, "CONTACTING");
      assert.equal(await eventCount(count, T, caseRef, "RIGHTS_CASE_CONTACTING"), 1);
    }
  });
});

pgTest("TEST-CNS-848 pg: dos POST concurrentes con el mismo token de recuperacion (P2-D): uno gana (R1r..R4) y el otro responde UNIFORM sin efectos (una Revocation, un CONSENT_REVOKED, un outbox)", async (ctx) => {
  const T = fixtureUuid("t848");
  await withEnv(ctx, async ({ uow, outside, count, pool }) => {
    const sink = createInMemoryRecoveryLinkChannelSink();
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(pool),
    };
    for (let round = 0; round < 12; round += 1) {
      const D = fixtureUuid(`d848-${round}`);
      const chain = `chain-848-${round}`;
      await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
      await issueRecoveryLinkBearer(ports, T, chain, D, "REQUESTER_ASKED");
      const hash = hashRecoveryToken(sink.sent[sink.sent.length - 1]!.recoveryPath.replace("/r/", ""));
      const results = await Promise.allSettled([revokeWithRecoveryLinkByHash(ports, hash), revokeWithRecoveryLinkByHash(ports, hash)]);
      assert.ok(results.every((r) => r.status === "fulfilled"), `ronda ${round}: ${JSON.stringify(results.map((r) => r.status === "rejected" ? String(r.reason) : "ok"))}`);
      const kinds = results.map((r) => (r.status === "fulfilled" ? r.value.kind : "?"));
      assert.equal(kinds.filter((k) => k === "UNIFORM").length, 1, `ronda ${round}: una UNIFORM sin efectos (${kinds.join(",")})`);
      const open = await count("SELECT count(*)::int AS n FROM app.revocation WHERE tenant_id = $1 AND revoked_decision_ref = $2 AND status <> 'FAILED'", [T, D]);
      assert.equal(open, 1);
      const rev = await outside.revocationRepo.findOpenByChain(T, chain);
      assert.equal(rev?.status, "APPLIED");
      assert.equal(await eventCount(count, T, rev!.revocationRef, "CONSENT_REVOKED"), 1);
      assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${rev!.revocationRef}:consent.revoked`]), 1);
    }
  });
});

// SEC-CNS-016 P2 (reintentos del UoW): con la base de secuencia capturada ANTES del lock, N submits concurrentes sobre el
// mismo challenge se pisan entre si; sin espera, los reintentos van en lockstep y se agotan. Con backoff con jitter y el
// maxAttempts por defecto del UoW, ningun intento incorrecto se pierde ni falla con LedgerSequenceConflictError.
pgTest("TEST-CNS-861 pg: 10 submits incorrectos concurrentes sobre el mismo challenge con el maxAttempts por defecto no agotan reintentos: attempts = 10, ninguno falla con conflicto de secuencia", async (ctx) => {
  const T = fixtureUuid("t861");
  await withEnv(ctx, async ({ outside, otp, count }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    const N = 10;
    for (let round = 0; round < 5; round += 1) {
      const inv = fixtureUuid(`inv861-${round}`);
      const ver = fixtureUuid(`ver861-${round}`);
      await seedOpenedInvitation(outside, T, inv, `test+s861-${round}@example.invalid`);
      await requestOtp(otp, T, ver, inv, CHANNEL);
      const good = sink.sent[sink.sent.length - 1]!.code;
      const wrong = good === "000000" ? "111111" : "000000";
      const results = await Promise.allSettled(Array.from({ length: N }, () => submitOtp(otp, T, ver, wrong, "dm-861")));
      const codes = results.map((r) => (r.status === "rejected" && r.reason instanceof DomainError ? r.reason.code : `?${r.status === "rejected" ? String(r.reason) : "ok"}`));
      assert.ok(codes.every((c) => c === "ERR-OT-02"), `ronda ${round}: todos rechazados por codigo incorrecto, ninguno por reintentos agotados: ${codes.join(",")}`);
      assert.equal((await outside.otpRepo.findByRef(T, ver))?.attempts, N, "ningun intento se pierde");
      assert.equal(await eventCount(count, T, ver, "OTP_FAILED"), N);
    }
  }, DEFAULT_UOW_MAX_ATTEMPTS, { codeLength: 6, maxAttempts: 1000, ttlMs: 60_000, maxResends: 3 });
});
