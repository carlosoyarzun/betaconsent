// Gobierna: SEC-CNS-021 PR-2 (aceptada por Carlos 2026-10-08; F-1, D1 a; CA-146 / P-34), db/migrations/0030_ledger_drop_transitional_security_events.sql,
// INV-21-01 / INV-21-02 / INV-21-03, otp-challenge.spec V1/V2/V3/V4/V2r, revocation.spec RV0, INV-CM-01.
// TEST-CNS-1300 (el ledger rechaza OTP_* / RECOVERY_TOKEN_ISSUED / MANAGEMENT_TOKEN_ROTATED con 23514), TEST-CNS-1301 (V1/V2/V4/V2r y RV0 completos dejan
// 0 filas OTP_*/RECOVERY en el ledger y exactamente 1 por emision en ops.security_event), TEST-CNS-1302 (misma tx: un rollback no deja ni estado ni
// evento), TEST-CNS-1303 (V3 deja DECISION_MAKER_CHANNEL_VERIFIED con sequence 1 y verifyLedgerChain ok).
// Todos los conteos filtran por tenant y refs propios (nunca globales) y no dependen del orden de los CHECK (se acepta la lista de constraints que
// pueden violarse). Contra Postgres real (harness.ts; skip fuera de CI sin entorno). Solo datos sinteticos. Estos tests NO se corrieron localmente
// (sin Docker/Postgres): los corre el CI.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { verifyLedgerChain } from "../../../src/server/modules/common/ledger-chain.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, resendOtp, submitOtp, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { issueRecoveryLinkBearer, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, type PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const CHANNEL = "test+channel-1300@example.invalid";
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const H = "a".repeat(64);
const Z = "0".repeat(64);

const MOVED_TYPES = ["OTP_ISSUED", "OTP_FAILED", "OTP_LOCKED", "OTP_EXPIRED", "OTP_BUDGET_EXHAUSTED", "MANAGEMENT_TOKEN_ROTATED", "RECOVERY_TOKEN_ISSUED"] as const;

type Count = (sql: string, values: unknown[]) => Promise<number>;

async function withEnv<T>(ctx: PgTestContext, body: (env: {
  uow: PgUnitOfWork;
  outside: ReturnType<typeof pgOutsideTxPorts>;
  invitation: InvitationPorts;
  otp: OtpChallengePorts;
  pool: ReturnType<typeof createPool>;
  count: Count;
}) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 8 });
  const admin = await ctx.connectAsSuperuser();
  try {
    const uow = new PgUnitOfWork(pool, { maxAttempts: 1 });
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
      policy: { codeLength: 6, maxAttempts: 2, ttlMs: 60_000, maxResends: 3 },
      secret: randomBytes(32),
    };
    const count: Count = async (sql, values) => (await admin.query<{ n: number }>(sql, values)).rows[0]?.n ?? -1;
    return await body({ uow, outside, invitation, otp, pool, count });
  } finally {
    await pool.end();
  }
}

/** Filas OTP_*, RECOVERY y MANAGEMENT del ledger para UN agregado propio. */
const ledgerMovedRows = (count: Count, tenant: string, aggregate: string): Promise<number> =>
  count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = ANY($3::text[])", [tenant, aggregate, [...MOVED_TYPES]]);
/** Filas de ops.security_event de UN challenge propio, por tipo. */
const secByVerification = (count: Count, tenant: string, verificationRef: string, type: string): Promise<number> =>
  count("SELECT count(*)::int AS n FROM ops.security_event WHERE tenant_id = $1 AND verification_ref = $2 AND event_type = $3", [tenant, verificationRef, type]);

async function seedOpenedInvitation(outside: ReturnType<typeof pgOutsideTxPorts>, tenant: string, invitationRef: string, subject: string): Promise<void> {
  await outside.invitationRepo.save({
    invitationRef,
    tenantId: tenant,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: subject,
    state: "OPENED",
    recipientChannelRef: CHANNEL,
  });
}

pgTest("TEST-CNS-1300 pg: integrity.audit_event rechaza OTP_* / RECOVERY_TOKEN_ISSUED / MANAGEMENT_TOKEN_ROTATED con 23514 (lista blanca sin los transitorios, 0030) y conserva los tipos del ledger (INV-21-01)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const T = fixtureUuid("t1300-ledger");
  const insert = (eventType: string): Promise<unknown> =>
    admin.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
       VALUES ($1, 'DecisionMakerVerification', $2, 1, $3, 'HUMAN', '{}'::jsonb, 1, $4, $5, $4)`,
      [T, fixtureUuid(`agg-1300-${eventType}`), eventType, H, Z],
    );
  // Con el resto de columnas validas, solo la lista blanca puede violarse; se acepta una lista de constraints por si otro CHECK de tipo la acompana.
  const typeConstraints = ["audit_event_event_type_allowlist"];
  for (const type of MOVED_TYPES) {
    await assert.rejects(() => insert(type), (e: unknown) => codeOf(e) === "23514" && typeConstraints.includes(constraintOf(e) ?? ""), `${type} debe rechazarse con 23514`);
  }
  // Un tipo del ledger sigue aceptandose (DECISION_MAKER_CHANNEL_VERIFIED se queda en el ledger, D1 a).
  await insert("DECISION_MAKER_CHANNEL_VERIFIED");
  // La lista vigente no menciona ya ninguno de los 7 tipos.
  const def = (await admin.query<{ d: string }>("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'integrity.audit_event'::regclass AND conname = 'audit_event_event_type_allowlist'")).rows[0]?.d ?? "";
  for (const type of MOVED_TYPES) assert.equal(def.includes(`'${type}'`), false, `${type} no debe figurar en el CHECK`);
  assert.ok(def.includes("'DECISION_MAKER_CHANNEL_VERIFIED'"));
});

pgTest("TEST-CNS-1301 pg: V1/V2/V4/V2r completos dejan 0 filas OTP_* en el ledger y exactamente 1 por emision en ops.security_event; RV0 deja 0 RECOVERY en el ledger y 1 en security_event (INV-21-02)", async (ctx) => {
  const T = fixtureUuid("t1301");
  await withEnv(ctx, async ({ uow, outside, otp, count, pool }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    const inv = fixtureUuid("inv1301");
    const ver = fixtureUuid("ver1301");
    await seedOpenedInvitation(outside, T, inv, fixtureUuid("s1301"));

    // V1
    await requestOtp(otp, T, ver, inv, CHANNEL);
    assert.equal(await secByVerification(count, T, ver, "OTP_ISSUED"), 1, "V1: 1 OTP_ISSUED");
    // V2r: un reenvio = una emision mas
    await resendOtp(otp, T, ver);
    assert.equal(await secByVerification(count, T, ver, "OTP_ISSUED"), 2, "V2r: +1 OTP_ISSUED");
    const good = sink.sent[sink.sent.length - 1]!.code;
    const wrong = good === "000000" ? "111111" : "000000";
    // V2 (maxAttempts 2): un incorrecto
    await assert.rejects(() => submitOtp(otp, T, ver, wrong, fixtureUuid("dm-1301"), 2), (e: unknown) => e instanceof DomainError && e.code === "ERR-OT-02");
    assert.equal(await secByVerification(count, T, ver, "OTP_FAILED"), 1, "V2: 1 OTP_FAILED");
    // V4: el segundo incorrecto bloquea
    await assert.rejects(() => submitOtp(otp, T, ver, wrong, fixtureUuid("dm-1301"), 2), (e: unknown) => e instanceof DomainError && e.code === "ERR-OT-04");
    assert.equal(await secByVerification(count, T, ver, "OTP_LOCKED"), 1, "V4: 1 OTP_LOCKED");
    assert.equal(await ledgerMovedRows(count, T, ver), 0, "0 filas OTP_* en el ledger para el challenge");
    assert.equal(await count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND event_type = ANY($2::text[])", [T, [...MOVED_TYPES]]), 0, "0 filas de los tipos movidos en el ledger del tenant propio");

    // RV0
    const D = fixtureUuid("d1301");
    const chain = fixtureUuid("chain1301");
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
    const rports: RevocationPorts = { ...outside, recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(), recoveryTokenPolicy: { ttlMs: 60_000 }, uow, tenantResolver: createPgTenantResolver(pool) };
    await issueRecoveryLinkBearer(rports, T, chain, D, "REQUESTER_ASKED");
    assert.equal(await count("SELECT count(*)::int AS n FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'RECOVERY_TOKEN_ISSUED' AND trigger_kind = 'REQUESTER_ASKED'", [T]), 1, "RV0: 1 RECOVERY_TOKEN_ISSUED en security_event");
    assert.equal(await count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, chain]), 0, "RV0: nada en el ledger");
  });
});

pgTest("TEST-CNS-1302 pg: el evento OTP y el estado del challenge van en la MISMA tx: un rollback no deja ni challenge ni evento; un commit deja ambos (INV-21-02)", async (ctx) => {
  const T = fixtureUuid("t1302");
  await withEnv(ctx, async ({ uow, outside, count }) => {
    const mk = (ver: string) => ({
      verificationRef: ver, tenantId: T, scope: "DECISION" as const, parentRef: fixtureUuid("inv1302"), channelRef: CHANNEL,
      codeHash: "0".repeat(64), attempts: 0, expiresAt: new Date(Date.now() + 60_000), state: "CODE_SENT" as const, resendCount: 0,
    });
    const rolled = fixtureUuid("ver1302-rollback");
    const kept = fixtureUuid("ver1302-commit");
    const emit = (ver: string) => ({ tenantId: T, eventType: "OTP_ISSUED" as const, verificationRef: ver, otpScope: "DECISION" as const, channelRef: fixtureUuid("chref1302") });
    await assert.rejects(
      () => uow.inTenant(T, async (tx) => {
        await tx.otpRepo.save(mk(rolled));
        await tx.securityEvents.record(emit(rolled));
        throw new Error("rollback-sintetico");
      }),
      /rollback-sintetico/,
    );
    assert.equal(await secByVerification(count, T, rolled, "OTP_ISSUED"), 0, "rollback: sin evento");
    assert.equal(await count("SELECT count(*)::int AS n FROM app.otp_verification WHERE tenant_id = $1 AND verification_ref = $2", [T, rolled]), 0, "rollback: sin challenge");
    await uow.inTenant(T, async (tx) => {
      await tx.otpRepo.save(mk(kept));
      await tx.securityEvents.record(emit(kept));
    });
    assert.equal(await secByVerification(count, T, kept, "OTP_ISSUED"), 1, "commit: evento");
    assert.equal((await outside.otpRepo.findByRef(T, kept))?.state, "CODE_SENT", "commit: challenge");
  });
});

pgTest("TEST-CNS-1303 pg: V3 deja DECISION_MAKER_CHANNEL_VERIFIED con sequence 1 en el ledger y verifyLedgerChain = ok; V3 ∥ V3 da exactamente un VERIFIED (INV-21-03)", async (ctx) => {
  const T = fixtureUuid("t1303");
  await withEnv(ctx, async ({ uow, outside, otp, count }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    for (let round = 0; round < 6; round += 1) {
      const inv = fixtureUuid(`inv1303-${round}`);
      const ver = fixtureUuid(`ver1303-${round}`);
      await seedOpenedInvitation(outside, T, inv, fixtureUuid(`s1303-${round}`));
      await requestOtp(otp, T, ver, inv, CHANNEL);
      const code = sink.sent[sink.sent.length - 1]!.code;
      const results = await Promise.allSettled([submitOtp(otp, T, ver, code, fixtureUuid("dm-1303"), 2), submitOtp(otp, T, ver, code, fixtureUuid("dm-1303"), 2)]);
      assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, `ronda ${round}: exactamente un VERIFIED`);
      assert.ok(results.some((r) => r.status === "rejected" && r.reason instanceof DomainError && r.reason.code === "ERR-OT-03"), `ronda ${round}: la otra sale por ERR-OT-03, no por conflicto de secuencia`);
      assert.equal(await count("SELECT max(sequence)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, ver]), 1, "sequence 1");
      assert.equal(await count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'DECISION_MAKER_CHANNEL_VERIFIED'", [T, ver]), 1);
      assert.equal(await ledgerMovedRows(count, T, ver), 0);
    }
    const report = await uow.inTenant(T, ({ ledger }) => verifyLedgerChain(ledger, T));
    assert.equal(report.ok, true, JSON.stringify(report));
  });
});

pgTest("TEST-CNS-1328 pg: V2r ∥ V3 en dos conexiones se serializan por el lock de fila: o gana V3 (VERIFIED, el reenvio sale por ERR-OT-03) o gana el reenvio (V3 con el codigo viejo sale por ERR-OT-02); nunca ambos (SEC-CNS-021 PR-2)", async (ctx) => {
  const T = fixtureUuid("t1328");
  await withEnv(ctx, async ({ outside, otp, count }) => {
    const sink = otp.channel as ReturnType<typeof createInMemoryOtpChannelSink>;
    const isDomain = (r: PromiseSettledResult<unknown>, code: string): boolean => r.status === "rejected" && r.reason instanceof DomainError && r.reason.code === code;
    for (let round = 0; round < 10; round += 1) {
      const inv = fixtureUuid(`inv1328-${round}`);
      const ver = fixtureUuid(`ver1328-${round}`);
      await seedOpenedInvitation(outside, T, inv, fixtureUuid(`s1328-${round}`));
      await requestOtp(otp, T, ver, inv, CHANNEL);
      const oldCode = sink.sent[sink.sent.length - 1]!.code;
      const [resend, verify] = await Promise.allSettled([resendOtp(otp, T, ver), submitOtp(otp, T, ver, oldCode, fixtureUuid("dm-1328"), 2)]);
      const rec = await outside.otpRepo.findByRef(T, ver);
      if (verify.status === "fulfilled") {
        assert.ok(isDomain(resend, "ERR-OT-03"), `ronda ${round}: V3 gano, el reenvio debe salir por ERR-OT-03`);
        assert.equal(rec?.state, "VERIFIED");
        assert.equal(await secByVerification(count, T, ver, "OTP_ISSUED"), 1);
      } else {
        assert.equal(resend.status, "fulfilled", `ronda ${round}: si V3 falla, el reenvio gano`);
        assert.ok(isDomain(verify, "ERR-OT-02"), `ronda ${round}: V3 con el codigo reemplazado sale por ERR-OT-02`);
        assert.equal(rec?.state, "CODE_SENT");
        assert.equal(rec?.attempts, 1);
        assert.equal(await secByVerification(count, T, ver, "OTP_ISSUED"), 2);
        assert.equal(await secByVerification(count, T, ver, "OTP_FAILED"), 1);
      }
      assert.equal(await ledgerMovedRows(count, T, ver), 0);
    }
  });
});
