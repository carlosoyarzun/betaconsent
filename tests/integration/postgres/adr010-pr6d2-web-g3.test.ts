// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a puntos 4 y 5 (G-3, lectura (A)); decision de Carlos: nunca informar fallo de algo que si se aplico; commit ambiguo = leer estado y
// devolver el resultado real; agotamiento = alerta + caso pendiente sin APPLIED y sin acuse. src/server/modules/revocation/revocation.ts (confirmRevocation = R3 web; revokeWithRecoveryLinkByHash = R3r web);
// db/migrations/0066, 0067. SYNTHETIC ONLY. Requiere Postgres real (harness.ts). Proceso web = rol app_rw con guardia de R4 (createApplyGuardConfig + alerta en tx de tenant separada).
// TEST-CNS-1715 R3 reintento, 1716 R3 agotamiento con alerta, 1717 R3 commit ambiguo (incl. relectura fallida), 1718 R3r reintento, 1719 R3r agotamiento (token sin consumir), 1720 R3r commit ambiguo (incl. relectura fallida, P1-a).

import assert from "node:assert/strict";
import type { Pool, PoolClient } from "pg";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createApplyGuardConfig, createTenantAlertSink } from "../../../src/infra/adapters/postgres/apply-guard.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import type { PoolLike } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { RevocationApplyUnavailableError } from "../../../src/server/modules/revocation/apply-guard.ts";
import { confirmRevocation, hashRecoveryToken, issueRecoveryLinkBearer, requestRevocation, revokeWithRecoveryLinkByHash, verifyRevocationOtp } from "../../../src/server/modules/revocation/revocation.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { injectOutboxFailure } from "../../helpers/pg-case-world.ts";
import { enableLedgerMechanicsAppend, pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

/** Commit ambiguo del proceso web: el COMMIT de la tx que ejecuto `marker` SI se aplica, pero al cliente le llega 08006; con `poisonRead` el siguiente BEGIN (la relectura de estado) tambien falla una vez. */
function ambiguousWeb(marker: string): { wrap: (pool: Pool) => PoolLike; arm(poisonRead: boolean): void; fired(): number } {
  let armed = false;
  let poison = false;
  let poisonNext = false;
  let fired = 0;
  const PATCHED = Symbol.for("qa.ambiguousWeb");
  return {
    fired: () => fired,
    arm: (poisonRead) => { armed = true; poison = poisonRead; },
    wrap: (pool) => ({
      async connect(): Promise<PoolClient> {
        const client = await pool.connect();
        const tagged = client as PoolClient & { [PATCHED]?: boolean };
        if (tagged[PATCHED] !== true) {
          tagged[PATCHED] = true;
          const original = client.query.bind(client) as (...args: unknown[]) => Promise<unknown>;
          let sawMarker = false;
          (client as unknown as { query: unknown }).query = async (...args: unknown[]): Promise<unknown> => {
            if (typeof args[0] === "string" && args[0].includes(marker)) sawMarker = true;
            if (args[0] === "ROLLBACK") sawMarker = false;
            if (args[0] === "BEGIN" && poisonNext) {
              poisonNext = false;
              throw Object.assign(new Error("connection terminated unexpectedly"), { code: "08006" });
            }
            if (args[0] === "COMMIT" && sawMarker && armed) {
              sawMarker = false;
              armed = false;
              fired += 1;
              await original("COMMIT");
              poisonNext = poison;
              throw Object.assign(new Error("connection terminated unexpectedly"), { code: "08006" });
            }
            return original(...args);
          };
        }
        return client;
      },
    }),
  };
}

interface WebEnv {
  readonly ports: RevocationPorts;
  readonly outside: ReturnType<typeof pgOutsideTxPorts>;
  readonly sink: ReturnType<typeof createInMemoryRecoveryLinkChannelSink>;
  readonly logs: string[];
}

async function withWeb<R>(ctx: PgTestContext, marker: string, body: (env: WebEnv, amb: ReturnType<typeof ambiguousWeb>) => Promise<R>): Promise<R> {
  await enableLedgerMechanicsAppend(ctx);
  const raw = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  const amb = ambiguousWeb(marker);
  try {
    const uow = new PgUnitOfWork(amb.wrap(raw) as never);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const logs: string[] = [];
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(raw),
      downstreamStub: createInMemoryDownstreamStub(),
      applyGuard: createApplyGuardConfig(createTenantAlertSink(uow), { maxAttempts: 3, sleep: async () => {}, log: (l) => logs.push(l) }),
    };
    return await body({ ports, outside, sink, logs }, amb);
  } finally {
    await raw.end();
  }
}

const events = async (ctx: PgTestContext, tenantId: string, ref: string): Promise<string[]> =>
  (await (await ctx.fixtureAdmin()).query<{ event_type: string }>("SELECT event_type FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [tenantId, ref])).rows.map((r) => r.event_type);
const alertsOf = async (ctx: PgTestContext, tenantId: string, ref: string): Promise<string[]> =>
  (await (await ctx.fixtureAdmin()).query<{ alert_reason: string }>("SELECT alert_reason FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_APPLY_ALERT' AND revocation_ref = $2 ORDER BY event_seq", [tenantId, ref])).rows.map((r) => r.alert_reason);
const outboxCount = async (ctx: PgTestContext, tenantId: string): Promise<number> =>
  (await (await ctx.fixtureAdmin()).query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1", [tenantId])).rows[0]!.n;

/** R1 + R2 (OTP) sobre una GRANTED sembrada: la Revocation queda VERIFIED lista para R3. */
async function verifiedViaOtp(env: WebEnv, T: string, label: string): Promise<{ revocationRef: string; decisionRef: string }> {
  const D = fixtureUuid(`d-${label}`);
  const chain = `chain-${label}`;
  await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
  const revocationRef = fixtureUuid(`r-${label}`);
  await requestRevocation(env.ports, T, { revocationRef, chainRef: chain, revokedDecisionRef: D });
  await verifyRevocationOtp(env.ports, T, revocationRef, fixtureUuid(`v-${label}`));
  return { revocationRef, decisionRef: D };
}

/** Enlace de recuperacion emitido para una GRANTED sembrada; devuelve el hash del portador. */
async function linkBearer(env: WebEnv, T: string, label: string): Promise<{ tokenHash: string; decisionRef: string }> {
  const D = fixtureUuid(`d-${label}`);
  const chain = `chain-${label}`;
  await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
  await issueRecoveryLinkBearer(env.ports, T, chain, D, "REQUESTER_ASKED");
  const token = env.sink.sent[env.sink.sent.length - 1]!.recoveryPath.replace("/r/", "");
  return { tokenHash: hashRecoveryToken(token), decisionRef: D };
}

const decisionState = async (ctx: PgTestContext, T: string, D: string): Promise<string> =>
  (await (await ctx.fixtureAdmin()).query<{ state: string }>("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [T, D])).rows[0]!.state;

pgTest("TEST-CNS-1715 pg web (R3): un error transitorio (40001) reintenta la tx completa (acotado) y llega a APPLIED con un solo juego de eventos y un solo outbox; sin alerta", async (ctx) => {
  const T = fixtureUuid("t1715");
  await withWeb(ctx, "confirm_revocation", async (env) => {
    const { revocationRef } = await verifiedViaOtp(env, T, "1715");
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1715", tenantId: T, failures: 2, sqlstate: "40001" });
    const done = await confirmRevocation(env.ports, T, revocationRef);
    assert.equal(done.status, "APPLIED");
    assert.equal(await failure.attempts(), 3);
    assert.equal((await events(ctx, T, revocationRef)).filter((e) => e === "CONSENT_REVOKED").length, 1);
    assert.equal(await outboxCount(ctx, T), 1);
    assert.deepEqual(await alertsOf(ctx, T, revocationRef), []);
    await failure.remove();
  });
});

pgTest("TEST-CNS-1716 pg web (R3): agotados los reintentos = alerta R4_RETRIES_EXHAUSTED (tx separada, una sola), error uniforme SIN acuse, Revocation VERIFIED sin APPLIED, decision GRANTED; luego el reintento llega a APPLIED", async (ctx) => {
  const T = fixtureUuid("t1716");
  await withWeb(ctx, "confirm_revocation", async (env) => {
    const { revocationRef, decisionRef } = await verifiedViaOtp(env, T, "1716");
    const before = await events(ctx, T, revocationRef);
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1716", tenantId: T, failures: 1_000, sqlstate: "40001" });
    await assert.rejects(confirmRevocation(env.ports, T, revocationRef), (e: unknown) => e instanceof RevocationApplyUnavailableError);
    const n1716 = await failure.attempts();
    assert.ok(n1716 >= 3 && n1716 <= 3 * 8, `acotado: maxAttempts del guardia x reintentos 40001 de la unidad de trabajo (8); fueron ${n1716}`);
    assert.equal((await env.outside.revocationRepo.findByRef(T, revocationRef))?.status, "VERIFIED");
    assert.deepEqual(await events(ctx, T, revocationRef), before);
    assert.equal(await decisionState(ctx, T, decisionRef), "GRANTED");
    assert.equal(await outboxCount(ctx, T), 0);
    assert.deepEqual(await alertsOf(ctx, T, revocationRef), ["R4_RETRIES_EXHAUSTED"]);
    assert.ok(env.logs.every((l) => !l.includes(decisionRef)), "el log de respaldo no lleva refs de decision");
    await failure.remove();
    assert.equal((await confirmRevocation(env.ports, T, revocationRef)).status, "APPLIED");
    assert.deepEqual(await alertsOf(ctx, T, revocationRef), ["R4_RETRIES_EXHAUSTED"], "sin alerta duplicada");
  });
});

for (const poisonRead of [false, true]) {
  pgTest(`TEST-CNS-1717 pg web (R3): commit ambiguo${poisonRead ? " y relectura de estado fallida" : ""} devuelve el resultado REAL (APPLIED), sin reaplicar ni duplicar eventos/outbox y sin alerta`, async (ctx) => {
    const T = fixtureUuid(`t1717-${poisonRead}`);
    await withWeb(ctx, "confirm_revocation", async (env, amb) => {
      const { revocationRef } = await verifiedViaOtp(env, T, `1717-${poisonRead}`);
      amb.arm(poisonRead);
      const done = await confirmRevocation(env.ports, T, revocationRef);
      assert.equal(amb.fired(), 1);
      assert.equal(done.status, "APPLIED", "nunca informar fallo de algo que se aplico");
      assert.equal((await events(ctx, T, revocationRef)).filter((e) => e === "CONSENT_REVOKED").length, 1);
      assert.equal(await outboxCount(ctx, T), 1);
      assert.deepEqual(await alertsOf(ctx, T, revocationRef), []);
    });
  });
}

pgTest("TEST-CNS-1718 pg web (R3r): un error transitorio (40001) reintenta la tx completa (token sin consumir hasta el exito) y responde CONFIRMED con la Revocation APPLIED, un solo outbox y sin alerta", async (ctx) => {
  const T = fixtureUuid("t1718");
  await withWeb(ctx, "revoke_with_recovery_link", async (env) => {
    const { tokenHash, decisionRef } = await linkBearer(env, T, "1718");
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1718", tenantId: T, failures: 2, sqlstate: "40001" });
    const out = await revokeWithRecoveryLinkByHash(env.ports, tokenHash);
    assert.equal(out.kind, "CONFIRMED");
    const ref = (out as { revocationRef: string }).revocationRef;
    assert.equal((await env.outside.revocationRepo.findByRef(T, ref))?.status, "APPLIED");
    assert.equal(await failure.attempts(), 3);
    assert.equal(await decisionState(ctx, T, decisionRef), "REVOKED");
    assert.equal(await outboxCount(ctx, T), 1);
    assert.deepEqual(await alertsOf(ctx, T, ref), []);
    await failure.remove();
  });
});

pgTest("TEST-CNS-1719 pg web (R3r): agotados los reintentos = alerta R4_RETRIES_EXHAUSTED con la ref generada, error uniforme SIN acuse, sin Revocation ni evento, token SIN consumir; el mismo enlace sirve despues y no se duplica la alerta", async (ctx) => {
  const T = fixtureUuid("t1719");
  await withWeb(ctx, "revoke_with_recovery_link", async (env) => {
    const { tokenHash, decisionRef } = await linkBearer(env, T, "1719");
    const failure = await injectOutboxFailure(await ctx.fixtureAdmin(), { name: "f1719", tenantId: T, failures: 1_000, sqlstate: "40001" });
    await assert.rejects(revokeWithRecoveryLinkByHash(env.ports, tokenHash), (e: unknown) => e instanceof RevocationApplyUnavailableError);
    const n1719 = await failure.attempts();
    assert.ok(n1719 >= 3 && n1719 <= 3 * 8, `acotado (guardia x unidad de trabajo); fueron ${n1719}`);
    assert.equal(await decisionState(ctx, T, decisionRef), "GRANTED");
    assert.equal(await outboxCount(ctx, T), 0);
    const admin = await ctx.fixtureAdmin();
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM case_state.revocation WHERE tenant_id = $1 AND revoked_decision_ref = $2", [T, decisionRef])).rows[0]!.n, 0, "la tx completa se revirtio: sin Revocation");
    const alerts = (await admin.query<{ alert_reason: string }>("SELECT alert_reason FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_APPLY_ALERT' ORDER BY event_seq", [T])).rows.map((r) => r.alert_reason);
    assert.deepEqual(alerts, ["R4_RETRIES_EXHAUSTED"]);
    await failure.remove();
    const retried = await revokeWithRecoveryLinkByHash(env.ports, tokenHash);
    assert.equal(retried.kind, "CONFIRMED", "el token no se consumio con el fallo");
    assert.equal(await decisionState(ctx, T, decisionRef), "REVOKED");
  });
});

for (const poisonRead of [false, true]) {
  pgTest(`TEST-CNS-1720 pg web (R3r): commit ambiguo${poisonRead ? " y relectura de estado fallida (P1-a: el intento siguiente ve APPLIED)" : ""} responde CONFIRMED con la ref real, nunca UNIFORM/fallo de algo aplicado; sin duplicar eventos ni outbox, sin alerta`, async (ctx) => {
    const T = fixtureUuid(`t1720-${poisonRead}`);
    await withWeb(ctx, "revoke_with_recovery_link", async (env, amb) => {
      const { tokenHash, decisionRef } = await linkBearer(env, T, `1720-${poisonRead}`);
      amb.arm(poisonRead);
      const out = await revokeWithRecoveryLinkByHash(env.ports, tokenHash);
      assert.equal(amb.fired(), 1);
      assert.equal(out.kind, "CONFIRMED", JSON.stringify(out));
      const ref = (out as { revocationRef: string }).revocationRef;
      assert.equal((await env.outside.revocationRepo.findByRef(T, ref))?.status, "APPLIED");
      assert.equal(await decisionState(ctx, T, decisionRef), "REVOKED");
      assert.equal((await events(ctx, T, ref)).filter((e) => e === "CONSENT_REVOKED").length, 1);
      assert.equal(await outboxCount(ctx, T), 1);
      assert.deepEqual(await alertsOf(ctx, T, ref), []);
    });
  });
}
