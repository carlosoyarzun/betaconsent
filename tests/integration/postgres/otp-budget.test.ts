// Gobierna: SEC-CNS-021 PR-4 (aceptada por Carlos 2026-10-08; CA-146 / DF-10; D6, D8), db/migrations/0032_otp_budget_p06_v6a.sql, otp-challenge.spec V1/V2/V6/V6a/V2r,
// GRD-OT-03/06/09/14, INV-21-05/06/11/12/13/17, INV-CM-02. Contra Postgres real (harness.ts; skip fuera de CI sin entorno). Solo datos sinteticos.
// TEST-CNS-1314 (reserva atomica N=20), 1315 (ventana fija), 1316 (V1 ∥ 3.er LOCKED sin deadlock), 1324 (P-06 concurrente), 1318 (tenants + RLS directo),
// 1329 (marcas P-06 round-trip), 1330 (puerto otpBudget), 1331 (catalogo y grants de ops.otp_budget), 1332 (trigger monotonico), 1333 (CHECK otp_send_marks_shape).
// PgUnitOfWork con maxAttempts 1 y lockTimeoutMs alto: un deadlock (40P01) se VE, no se reintenta. Conteos filtrados por tenant/ref propios (sin globales); los
// CHECK se aceptan por lista (el orden de evaluacion no esta garantizado); los channelRef respetan otp_channel_reserved.
// Estos tests NO se corrieron localmente (sin Docker/Postgres): los corre el CI.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, requestRightsOtp, resendOtp, submitOtp, type OtpChallengePorts, type OtpPolicy } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import type { OtpBudgetKey } from "../../../src/server/ports/otp-budget.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, type PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const HOUR = 3_600_000;

interface Env {
  readonly outside: ReturnType<typeof pgOutsideTxPorts>;
  readonly otp: OtpChallengePorts;
  readonly sink: ReturnType<typeof createInMemoryOtpChannelSink>;
  readonly clock: { ms: number };
  readonly admin: Awaited<ReturnType<PgTestContext["connectAsSuperuser"]>>;
  readonly count: (sql: string, values: unknown[]) => Promise<number>;
}

async function withEnv<T>(ctx: PgTestContext, policy: Partial<OtpPolicy>, body: (env: Env) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 32 });
  const admin = await ctx.connectAsSuperuser();
  try {
    const uow = new PgUnitOfWork(pool, { maxAttempts: 1, lockTimeoutMs: 30_000, statementTimeoutMs: 60_000 });
    const outside = pgOutsideTxPorts(uow);
    const invitation: InvitationPorts = { invitationRepo: outside.invitationRepo, eligibility: createInMemoryEligibilityAdapter(), ledger: outside.ledger, uow, tenantResolver: createPgTenantResolver(pool) };
    const sink = createInMemoryOtpChannelSink();
    const clock = { ms: Date.now() };
    const otp: OtpChallengePorts = {
      otpRepo: outside.otpRepo, channel: sink, ledger: outside.ledger, uow, invitation, secret: randomBytes(32), now: () => clock.ms,
      policy: { codeLength: 6, maxAttempts: 1000, ttlMs: 72 * HOUR, ...policy },
    };
    const count = async (sql: string, values: unknown[]): Promise<number> => (await admin.query<{ n: number }>(sql, values)).rows[0]?.n ?? -1;
    return await body({ outside, otp, sink, clock, admin, count });
  } finally {
    await pool.end();
  }
}

async function seedInvitation(outside: Env["outside"], tenant: string, ref: string, channel: string): Promise<void> {
  await outside.invitationRepo.save({
    invitationRef: ref, tenantId: tenant, contextRef: LECTORPRO_BETA_CONFIG.contextRef, productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid(`subj-${ref}`), state: "OPENED", recipientChannelRef: channel,
  });
}

const dom = (r: PromiseSettledResult<unknown>): string => (r.status === "fulfilled" ? "ok" : r.reason instanceof DomainError ? r.reason.code : `?${codeOf(r.reason) ?? String(r.reason)}`);
const tally = (rs: PromiseSettledResult<unknown>[]): Record<string, number> => rs.reduce<Record<string, number>>((m, r) => ({ ...m, [dom(r)]: (m[dom(r)] ?? 0) + 1 }), {});
const wrongOf = (c: string): string => (c === "000000" ? "111111" : "000000");
const budgetRows = (env: Env, tenant: string): Promise<Array<{ key_kind: string; failures: number; window_start: Date }>> =>
  env.admin.query<{ key_kind: string; failures: number; window_start: Date }>("SELECT key_kind, failures, window_start FROM ops.otp_budget WHERE tenant_id = $1 ORDER BY key_kind", [tenant]).then((r) => r.rows);

/** Abre N invitaciones sobre el MISMO canal, emite su challenge y devuelve (ver, code) de cada una. */
async function challenges(env: Env, tenant: string, channel: string, n: number, tag: string): Promise<Array<{ inv: string; ver: string; code: string }>> {
  const out: Array<{ inv: string; ver: string; code: string }> = [];
  for (let i = 0; i < n; i += 1) {
    const inv = fixtureUuid(`inv-${tag}-${i}`);
    const ver = fixtureUuid(`ver-${tag}-${i}`);
    await seedInvitation(env.outside, tenant, inv, channel);
    await requestOtp(env.otp, tenant, ver, inv, channel);
    out.push({ inv, ver, code: env.sink.sent[env.sink.sent.length - 1]!.code });
  }
  return out;
}

pgTest("TEST-CNS-1314 pg: N=20 fallos en paralelo sobre un CHANNEL compartido -> exactamente LIMIT ERR-OT-02 y N-LIMIT ERR-OT-06; aciertos en paralelo no consumen; 20 V1 sobre la misma invitacion dejan un solo challenge (INV-21-11)", async (ctx) => {
  const T = fixtureUuid("t1314");
  const CH = "test+1314-a@example.invalid";
  await withEnv(ctx, {}, async (env) => {
    const LIMIT = 10;
    const cs = await challenges(env, T, CH, 20, "1314");
    const results = await Promise.allSettled(cs.map((c) => submitOtp(env.otp, T, c.ver, wrongOf(c.code), fixtureUuid("dm-1314"), 2)));
    assert.deepEqual(tally(results), { "ERR-OT-02": LIMIT, "ERR-OT-06": 20 - LIMIT }, JSON.stringify(tally(results)));
    const rows = await budgetRows(env, T);
    assert.equal(rows.find((r) => r.key_kind === "CHANNEL")?.failures, LIMIT, "la reserva nunca supera el limite");
    assert.equal(await env.count("SELECT count(*)::int AS n FROM app.otp_verification WHERE tenant_id = $1 AND state = 'FAILED'", [T]), 20 - LIMIT);

    // Aciertos en paralelo (otro canal, mismo tenant): todos VERIFIED y la reserva se revierte (failures = 0).
    const CH2 = "test+1314-b@example.invalid";
    const ok = await challenges(env, T, CH2, 20, "1314ok");
    const okResults = await Promise.allSettled(ok.map((c) => submitOtp(env.otp, T, c.ver, c.code, fixtureUuid("dm-1314"), 2)));
    assert.deepEqual(tally(okResults), { ok: 20 });
    // Filas con fallos: el CHANNEL agotado + una INVITATION por cada fallo reservado (10). Los 20 aciertos no agregan ni dejan fallos.
    assert.equal(await env.count("SELECT count(*)::int AS n FROM ops.otp_budget WHERE tenant_id = $1 AND failures > 0", [T]), 1 + LIMIT, "los aciertos no consumen presupuesto");

    // 20 V1 concurrentes sobre la MISMA invitacion: el lock de la invitacion serializa y queda un solo challenge activo.
    const inv = fixtureUuid("inv-1314-v1");
    await seedInvitation(env.outside, T, inv, "test+1314-c@example.invalid");
    const v1 = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => requestOtp(env.otp, T, fixtureUuid(`ver-1314-v1-${i}`), inv, "test+1314-c@example.invalid")));
    assert.deepEqual(tally(v1), { ok: 20 });
    assert.equal(await env.count("SELECT count(*)::int AS n FROM app.otp_verification WHERE tenant_id = $1 AND parent_ref = $2", [T, inv]), 1);
  });
});

pgTest("TEST-CNS-1315 pg: ventana fija desde el primer fallo (no se desliza) y reinicio al vencer 24 h (INV-21-11)", async (ctx) => {
  const T = fixtureUuid("t1315");
  const CH = "test+1315@example.invalid";
  await withEnv(ctx, {}, async (env) => {
    const [c] = await challenges(env, T, CH, 1, "1315");
    const t0 = env.clock.ms;
    await assert.rejects(() => submitOtp(env.otp, T, c!.ver, wrongOf(c!.code), fixtureUuid("dm"), 2), (e) => e instanceof DomainError && e.code === "ERR-OT-02");
    const first = (await budgetRows(env, T)).find((r) => r.key_kind === "CHANNEL")!;
    assert.equal(first.failures, 1);
    env.clock.ms = t0 + 23 * HOUR;
    await assert.rejects(() => submitOtp(env.otp, T, c!.ver, wrongOf(c!.code), fixtureUuid("dm"), 2), (e) => e instanceof DomainError && e.code === "ERR-OT-02");
    const second = (await budgetRows(env, T)).find((r) => r.key_kind === "CHANNEL")!;
    assert.equal(second.failures, 2);
    assert.equal(second.window_start.getTime(), first.window_start.getTime(), "la ventana no se desliza");
    env.clock.ms = t0 + 24 * HOUR + 1;
    await assert.rejects(() => submitOtp(env.otp, T, c!.ver, wrongOf(c!.code), fixtureUuid("dm"), 2), (e) => e instanceof DomainError && e.code === "ERR-OT-02");
    const third = (await budgetRows(env, T)).find((r) => r.key_kind === "CHANNEL")!;
    assert.equal(third.failures, 1, "ventana nueva");
    assert.equal(third.window_start.getTime(), t0 + 24 * HOUR + 1);
  });
});

pgTest("TEST-CNS-1316 pg: V1 ∥ 3.er LOCKED sin deadlock: nunca un 4.o challenge, otp_exhausted queda en true y se emite un solo OTP_BUDGET_EXHAUSTED (INV-21-12, F-4)", async (ctx) => {
  const T = fixtureUuid("t1316");
  const CH = "test+1316@example.invalid";
  await withEnv(ctx, { maxAttempts: 1, budgetMaxFailures: 1000 }, async (env) => {
    for (let round = 0; round < 8; round += 1) {
      const inv = fixtureUuid(`inv-1316-${round}`);
      await seedInvitation(env.outside, T, inv, CH);
      for (let i = 0; i < 2; i += 1) {
        const ver = fixtureUuid(`ver-1316-${round}-${i}`);
        await requestOtp(env.otp, T, ver, inv, CH);
        await assert.rejects(() => submitOtp(env.otp, T, ver, wrongOf(env.sink.sent[env.sink.sent.length - 1]!.code), fixtureUuid("dm"), 2), (e) => e instanceof DomainError && e.code === "ERR-OT-04");
      }
      const third = fixtureUuid(`ver-1316-${round}-2`);
      await requestOtp(env.otp, T, third, inv, CH);
      const wrong = wrongOf(env.sink.sent[env.sink.sent.length - 1]!.code);
      const [submit, v1] = await Promise.allSettled([
        submitOtp(env.otp, T, third, wrong, fixtureUuid("dm"), 2),
        requestOtp(env.otp, T, fixtureUuid(`ver-1316-${round}-new`), inv, CH),
      ]);
      for (const r of [submit, v1]) assert.notEqual(r.status === "rejected" ? codeOf(r.reason) : "", "40P01", `ronda ${round}: deadlock`);
      assert.equal(dom(submit), "ERR-OT-04", `ronda ${round}`);
      assert.ok(["ok", "ERR-OT-06"].includes(dom(v1)), `ronda ${round}: V1 = ${dom(v1)}`);
      assert.equal(await env.count("SELECT count(*)::int AS n FROM app.otp_verification WHERE tenant_id = $1 AND parent_ref = $2", [T, inv]), 3, `ronda ${round}: nunca un 4.o challenge`);
      assert.equal(await env.count("SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND otp_exhausted", [T, inv]), 1);
      assert.equal(await env.count("SELECT count(*)::int AS n FROM ops.security_event WHERE tenant_id = $1 AND verification_ref = $2 AND event_type = 'OTP_BUDGET_EXHAUSTED' AND key_kind = 'INVITATION'", [T, third]), 1);
    }
  });
});

pgTest("TEST-CNS-1324 pg: P-06: 20 reenvios concurrentes -> 2 OK y 18 ERR-OT-09 (D8, el inicial cuenta); intervalo de 60 s; reinicio a la hora; tambien en RIGHTS", async (ctx) => {
  const T = fixtureUuid("t1324");
  const CH = "test+1324@example.invalid";
  await withEnv(ctx, { minResendIntervalMs: 0 }, async (env) => {
    const [c] = await challenges(env, T, CH, 1, "1324");
    const res = await Promise.allSettled(Array.from({ length: 20 }, () => resendOtp(env.otp, T, c!.ver)));
    assert.deepEqual(tally(res), { ok: 2, "ERR-OT-09": 18 }, JSON.stringify(tally(res)));
    assert.equal((await env.outside.otpRepo.findByRef(T, c!.ver))?.sendsInWindow, 3);

    // RIGHTS: mismo limite.
    const chain = fixtureUuid("chain-1324");
    const rver = fixtureUuid("ver-1324-r");
    await requestRightsOtp(env.otp, T, rver, "MANAGE", chain, `mgmt:${chain}`);
    const rres = await Promise.allSettled(Array.from({ length: 20 }, () => resendOtp(env.otp, T, rver)));
    assert.deepEqual(tally(rres), { ok: 2, "ERR-OT-09": 18 }, JSON.stringify(tally(rres)));

    // Reinicio a la hora +1: la ventana arranca de nuevo.
    env.clock.ms += HOUR + 1;
    const again = await resendOtp(env.otp, T, c!.ver);
    assert.equal(again.sendsInWindow, 1);
  });
  await withEnv(ctx, {}, async (env) => {
    const [c] = await challenges(env, T, CH, 1, "1324i");
    env.clock.ms += 59_000;
    await assert.rejects(() => resendOtp(env.otp, T, c!.ver), (e) => e instanceof DomainError && e.code === "ERR-OT-09");
    env.clock.ms += 1_000;
    await resendOtp(env.otp, T, c!.ver);
  });
});

pgTest("TEST-CNS-1318 pg: mismo canal en dos tenants, 10+10 concurrentes, no se afectan; RLS directo como app_rw (SELECT 0 filas, UPDATE 0, INSERT cross-tenant 42501) (INV-21-13)", async (ctx) => {
  const A = fixtureUuid("t1318-a");
  const B = fixtureUuid("t1318-b");
  const CH = "test+1318@example.invalid";
  await withEnv(ctx, {}, async (env) => {
    const caAll = await challenges(env, A, CH, 11, "1318a"); // el 11.o se emite ANTES de agotar (V1 ya no emitiria con el canal agotado)
    const ca = caAll.slice(0, 10);
    const extraA = caAll[10]!;
    const cb = await challenges(env, B, CH, 10, "1318b");
    const res = await Promise.allSettled([...ca.map((c) => submitOtp(env.otp, A, c.ver, wrongOf(c.code), fixtureUuid("dm"), 2)), ...cb.map((c) => submitOtp(env.otp, B, c.ver, wrongOf(c.code), fixtureUuid("dm"), 2))]);
    assert.deepEqual(tally(res), { "ERR-OT-02": 20 }, "10 por tenant no agotan: cada tenant tiene su propia clave");
    for (const t of [A, B]) assert.equal((await budgetRows(env, t)).find((r) => r.key_kind === "CHANNEL")?.failures, 10);
    // La 11.a de A se rechaza (A llego a su limite; el contador de B es independiente).
    await assert.rejects(() => submitOtp(env.otp, A, extraA.ver, wrongOf(extraA.code), fixtureUuid("dm"), 2), (e) => e instanceof DomainError && e.code === "ERR-OT-06");
  });

  // RLS directo como app_rw con el contexto del tenant A.
  const c = await ctx.connectAs("app_rw");
  const asA = async (sql: string, values: unknown[] = []): Promise<{ rowCount: number | null }> => {
    await c.query("BEGIN");
    try {
      await c.query("SELECT set_config('app.tenant_id', $1, true)", [A]);
      return await c.query(sql, values);
    } finally {
      await c.query("ROLLBACK");
    }
  };
  assert.equal((await asA("SELECT 1 FROM ops.otp_budget WHERE tenant_id = $1", [B])).rowCount, 0, "SELECT ajeno: 0 filas");
  assert.equal((await asA("UPDATE ops.otp_budget SET failures = 0 WHERE tenant_id = $1", [B])).rowCount, 0, "UPDATE ajeno: 0 filas");
  await assert.rejects(
    () => asA(
      `INSERT INTO ops.otp_budget (tenant_id, scope_class, key_kind, key_hmac, key_version, window_kind, window_start, expires_at, failures)
       VALUES ($1, 'DECISION', 'CHANNEL', repeat('a', 64), 1, 'DAY_1', now(), now() + interval '1 day', 1)`, [B]),
    (e: unknown) => codeOf(e) === "42501",
  );
});

pgTest("TEST-CNS-1329 pg: round-trip de las marcas de envio P-06 (lastSentAt, sendsWindowStart, sendsInWindow) y countLockedByParent", async (ctx) => {
  const T = fixtureUuid("t1329");
  await withEnv(ctx, {}, async ({ outside }) => {
    const base = {
      verificationRef: fixtureUuid("ver-1329"), tenantId: T, scope: "DECISION" as const, parentRef: fixtureUuid("inv-1329"), channelRef: "test+1329@example.invalid",
      codeHash: "a".repeat(64), attempts: 0, expiresAt: new Date("2030-01-01T00:00:00.000Z"), state: "CODE_SENT" as const, resendCount: 0,
    };
    await outside.otpRepo.save(base);
    assert.deepEqual(await outside.otpRepo.findByRef(T, base.verificationRef), base, "sin marcas: como antes de 0032");
    const marked = { ...base, lastSentAt: new Date("2029-12-31T10:00:00.000Z"), sendsWindowStart: new Date("2029-12-31T09:30:00.000Z"), sendsInWindow: 2 };
    await outside.otpRepo.save(marked);
    assert.deepEqual(await outside.otpRepo.findByRef(T, base.verificationRef), marked);
    assert.equal(await outside.otpRepo.countLockedByParent(T, base.parentRef, "DECISION"), 0);
    await outside.otpRepo.save({ ...marked, state: "LOCKED" });
    assert.equal(await outside.otpRepo.countLockedByParent(T, base.parentRef, "DECISION"), 1);
    assert.equal(await outside.otpRepo.countLockedByParent(fixtureUuid("t1329-otro"), base.parentRef, "DECISION"), 0, "RLS: otro tenant no cuenta");
  });
});

pgTest("TEST-CNS-1330 pg: contract del puerto otpBudget sobre ops.otp_budget: reserva, tope, reversion parcial en la misma llamada, release y findExhausted", async (ctx) => {
  const T = fixtureUuid("t1330");
  await withEnv(ctx, {}, async ({ outside }) => {
    const key = (kind: "CHANNEL" | "INVITATION", ch: string): OtpBudgetKey => ({ scopeClass: "DECISION", keyKind: kind, keyHmac: ch.repeat(64), keyVersion: 1, windowKind: "DAY_1" });
    const ch = key("CHANNEL", "c");
    const iv = key("INVITATION", "d");
    const at = new Date();
    assert.equal(await outside.otpBudget.findExhausted(T, [ch, iv], at, 1), null);
    assert.equal(await outside.otpBudget.reserveFailure(T, [iv], at, HOUR, 1), null);
    assert.deepEqual(await outside.otpBudget.findExhausted(T, [ch, iv], at, 1), iv);
    // INVITATION sin cupo: la reserva de CHANNEL hecha en la misma llamada se revierte.
    assert.deepEqual(await outside.otpBudget.reserveFailure(T, [ch, iv], at, HOUR, 1), iv);
    assert.equal(await outside.otpBudget.findExhausted(T, [ch], at, 1), null, "CHANNEL quedo sin reservar");
    await outside.otpBudget.releaseFailure(T, [iv]);
    assert.equal(await outside.otpBudget.findExhausted(T, [iv], at, 1), null);
    // Ventana vencida: la clave vuelve a tener cupo.
    assert.equal(await outside.otpBudget.reserveFailure(T, [iv], at, HOUR, 1), null);
    assert.equal(await outside.otpBudget.findExhausted(T, [iv], new Date(at.getTime() + HOUR + 1), 1), null);
  });
});

pgTest("TEST-CNS-1331 pg: catalogo y grants de ops.otp_budget (dueno, FORCE RLS, policies, columnas, sin acceso de worker/platform_rw/consent_owner) e identidad inmutable (INV-21-05/06)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>("SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = 'ops.otp_budget'::regclass")).rows[0];
  assert.deepEqual(rel, { rls: true, force: true, owner: "security_event_owner" });
  const pol = (await admin.query<{ policyname: string; cmd: string; roles: string[] }>("SELECT policyname, cmd, roles::text[] AS roles FROM pg_policies WHERE schemaname = 'ops' AND tablename = 'otp_budget' ORDER BY policyname")).rows;
  assert.deepEqual(pol.map((p) => `${p.policyname}:${p.cmd}:${p.roles.join(",")}`), ["otp_budget_tenant_insert:INSERT:app_rw", "otp_budget_tenant_select:SELECT:app_rw", "otp_budget_tenant_update:UPDATE:app_rw"]);
  const cols = async (role: string, priv: string): Promise<string[]> =>
    (await admin.query<{ c: string }>("SELECT attname AS c FROM pg_attribute WHERE attrelid = 'ops.otp_budget'::regclass AND attnum > 0 AND NOT attisdropped AND has_column_privilege($1, attrelid, attnum, $2) ORDER BY 1", [role, priv])).rows.map((r) => r.c);
  assert.deepEqual(await cols("app_rw", "UPDATE"), ["expires_at", "failures", "window_start"]);
  assert.ok(!(await cols("app_rw", "INSERT")).includes("data_class"));
  for (const role of ["worker", "platform_rw", "consent_owner"]) {
    assert.deepEqual([await cols(role, "SELECT"), await cols(role, "INSERT"), await cols(role, "UPDATE")], [[], [], []], role);
  }
  for (const priv of ["DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege('app_rw', 'ops.otp_budget', $1) AS p", [priv])).rows[0]?.p, false, priv);
  }
  // Identidad inmutable de app.otp_verification y sin DELETE sobre app.invitation (aserciones de 0032).
  for (const col of ["scope", "parent_ref", "channel_ref"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', 'app.otp_verification', $1, 'UPDATE') AS p", [col])).rows[0]?.p, false, col);
  }
  assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege('app_rw', 'app.invitation', 'DELETE') AS p")).rows[0]?.p, false);
});

pgTest("TEST-CNS-1332 pg: app.invitation.otp_exhausted es monotona: trigger ENABLE ALWAYS y UPDATE a false -> 23000 (GRD-OT-09)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const T = fixtureUuid("t1332");
  const trg = (await admin.query<{ tgenabled: string }>("SELECT tgenabled FROM pg_trigger WHERE tgrelid = 'app.invitation'::regclass AND tgname = 'invitation_otp_exhausted_monotonic'")).rows[0];
  assert.equal(trg?.tgenabled, "A");
  await admin.query(
    "INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, 'inv-1332', 'c', 'p', 's', 'OPENED')", [T]);
  await admin.query("UPDATE app.invitation SET otp_exhausted = true WHERE tenant_id = $1 AND invitation_ref = 'inv-1332'", [T]);
  await assert.rejects(() => admin.query("UPDATE app.invitation SET otp_exhausted = false WHERE tenant_id = $1 AND invitation_ref = 'inv-1332'", [T]), (e: unknown) => codeOf(e) === "23000");
  await admin.query("UPDATE app.invitation SET otp_exhausted = true WHERE tenant_id = $1 AND invitation_ref = 'inv-1332'", [T]); // true -> true es no-op valido
});

pgTest("TEST-CNS-1333 pg: CHECK otp_send_marks_shape: marcas incoherentes se rechazan con 23514 (se acepta la lista de constraints: el orden de CHECK no esta garantizado)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const T = fixtureUuid("t1333");
  const insert = (n: string, lastSent: string | null, windowStart: string | null, sends: number): Promise<unknown> =>
    admin.query(
      `INSERT INTO app.otp_verification (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, state, last_sent_at, sends_window_start, sends_in_window)
       VALUES ($1, $2, 'DECISION', 'p', 'a@example.invalid', $3, 0, now() + interval '1 hour', 'CODE_SENT', $4::timestamptz, $5::timestamptz, $6)`,
      [T, `v1333-${n}`, "a".repeat(64), lastSent, windowStart, sends],
    );
  const accepted = ["otp_send_marks_shape", "otp_sends_in_window_nonneg"];
  await insert("legacy", null, null, 0); // fila anterior a 0032
  await insert("ok", "2030-01-01T10:00:00Z", "2030-01-01T09:00:00Z", 2);
  for (const [n, a, b, c] of [["sin-ventana", "2030-01-01T10:00:00Z", null, 1], ["sin-ultimo", null, "2030-01-01T09:00:00Z", 1], ["cero-envios", "2030-01-01T10:00:00Z", "2030-01-01T09:00:00Z", 0], ["ventana-posterior", "2030-01-01T09:00:00Z", "2030-01-01T10:00:00Z", 1], ["envios-sin-marcas", null, null, 1]] as const) {
    await assert.rejects(() => insert(n, a, b, c), (e: unknown) => codeOf(e) === "23514" && accepted.includes(constraintOf(e) ?? ""), n);
  }
});
