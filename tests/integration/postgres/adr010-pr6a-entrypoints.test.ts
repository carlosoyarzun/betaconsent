// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (6a: "Entrypoints web/platform/worker/verifier; unidades en infra/ (ADR-003); pools por rol"), INV-DBR-02, §4.2 (SYSTEM solo `worker`, GRD-CM-15);
// specs/state-machines/revocation.spec.yaml R5-R7 (FN-RV-13..15); db/migrations/0042_adr010_worker_downstream_only.sql; plan PR-6 sub-PR 6a; F-A10-23, F-PR6-06, F-PR6-20.
// TEST-CNS-1395: cada proceso (web/platform/worker/verifier) arranca con SU rol y los chequeos de arranque rechazan el rol equivocado (expectedRole por proceso); platform sirve solo /healthz.
// TEST-CNS-1398: 0042 - app_rw/platform_rw/integrity_verifier sin EXECUTE de R5-R7 (42501 real), worker si; R4 intacta; el worker solo LEE app.revocation e integrity.audit_event bajo RLS.
// TEST-CNS-1399: el worker ejecuta R5-R7 hasta COMPLETED (stub interno, LOCAL); el web ya no (42501, el estado no cambia); fuera de LOCAL el worker no ejecuta R5-R7.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo datos sinteticos.

import assert from "node:assert/strict";
import pg from "pg";
import type { Client } from "pg";

import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { openProcessPool, RUNTIME_PROCESS_ROLES } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import type { RuntimeProcess } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { assertStartupChecks, runStartupChecks, StartupCheckError } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { startPlatformProcess } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { startVerifierProcess } from "../../../src/server/entrypoints/verifier/verifier-process.ts";
import { runWorkerCycle, startWorkerProcess } from "../../../src/server/entrypoints/worker/worker-process.ts";
import { emitRevocationDownstream } from "../../../src/server/modules/revocation/downstream.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { invitationRefPayload } from "../../contract/ledger-payload-fixtures.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { revokeVia } from "../../contract/x6-revocation-scenarios.ts";
import type { X6Env } from "../../contract/x6-revocation-scenarios.ts";
import { pgTest, enableLedgerMechanicsAppend } from "./harness.ts";
import type { PgRole, PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const PROCESSES = Object.keys(RUNTIME_PROCESS_ROLES) as RuntimeProcess[];
const R5_R7 = ["mark_downstream_emitted", "record_downstream_ack", "record_erasure_attestation"] as const;

const envFor = (ctx: PgTestContext, role: PgRole) => ({ CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor(role) });

pgTest("TEST-CNS-1395 pg: cada proceso abre SU pool con SU rol (chequeos de arranque OK) y el rol equivocado se rechaza (expectedRole por proceso, INV-DBR-02)", async (ctx) => {
  for (const p of PROCESSES) {
    const role = RUNTIME_PROCESS_ROLES[p];
    const pool = await openProcessPool({ process: p, environment: "LOCAL", env: envFor(ctx, role) });
    try {
      const c = await pool.connect();
      try {
        assert.equal((await c.query<{ u: string }>("SELECT current_user AS u")).rows[0]?.u, role, `${p} conecta como ${role}`);
      } finally {
        c.release();
      }
    } finally {
      await pool.end();
    }
    // Con la URL de otro rol, el proceso no abre pool (ProcessRoleError antes de conectar).
    for (const other of Object.values(RUNTIME_PROCESS_ROLES)) {
      if (other === role) continue;
      await assert.rejects(() => openProcessPool({ process: p, environment: "LOCAL", env: envFor(ctx, other as PgRole) }), (e: unknown) => (e as { code?: string }).code === "PROCESS_ROLE_MISMATCH", `${p} con ${other}`);
    }
  }
  // Defensa en profundidad: aunque la URL fuera correcta, una conexion que ASUME otro rol falla los chequeos de arranque con expectedRole.
  for (const p of PROCESSES) {
    for (const actual of Object.values(RUNTIME_PROCESS_ROLES)) {
      if (actual === RUNTIME_PROCESS_ROLES[p]) continue;
      const client = await ctx.connectAs(actual as PgRole);
      const r = await runStartupChecks(client, { expectedEnvironment: "LOCAL", expectedRole: RUNTIME_PROCESS_ROLES[p] });
      assert.ok(r.failures.some((f) => f.includes(`no es ${RUNTIME_PROCESS_ROLES[p]}`)), `${p} acepto la conexion de ${actual}`);
    }
  }
});

pgTest("TEST-CNS-1395 pg: identidad disfrazada (P1-1 de #92): consent_migrator con options=-c role=consent_owner, o un rol con GUC app.* del cliente, no pasa los chequeos de arranque (StartupCheckError STARTUP_CHECK_FAILED)", async (ctx) => {
  const attempt = async (url: string, expectedRole: string): Promise<StartupCheckError> => {
    const c = new pg.Client({ connectionString: url });
    await c.connect();
    try {
      await assert.rejects(() => assertStartupChecks(c, { expectedEnvironment: "LOCAL", expectedRole }), (e: unknown) => e instanceof StartupCheckError && e.code === "STARTUP_CHECK_FAILED");
      try {
        await assertStartupChecks(c, { expectedEnvironment: "LOCAL", expectedRole });
      } catch (e) {
        return e as StartupCheckError;
      }
      throw new Error("debio fallar");
    } finally {
      await c.end();
    }
  };
  // session_user = consent_migrator pero current_user = consent_owner (SET ROLE por options).
  const disguised = await attempt(`${ctx.urlFor("consent_migrator")}?options=${encodeURIComponent("-c role=consent_owner")}`, "worker");
  assert.ok(disguised.failures.some((f) => f.includes("session_user difiere de current_user")), disguised.failures.join("|"));
  assert.ok(disguised.failures.some((f) => f.includes("session_user no es worker")));
  // GUC app.* fijado por el cliente con el rol correcto.
  const guc = await attempt(`${ctx.urlFor("worker")}?options=${encodeURIComponent("-c app.tenant_id=00000000-0000-4000-8000-000000000001")}`, "worker");
  assert.ok(guc.failures.some((f) => f.includes("el GUC app.tenant_id desde el cliente")), guc.failures.join("|"));
  // Y el proceso no abre pool con esa URL (query fuera de allowlist) ni con PGOPTIONS.
  await assert.rejects(() => openProcessPool({ process: "worker", environment: "LOCAL", env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: `${ctx.urlFor("worker")}?options=${encodeURIComponent("-c role=worker")}` } }), (e: unknown) => (e as { code?: string }).code === "PROCESS_ROLE_MISMATCH");
});

pgTest("TEST-CNS-1395 pg: platform arranca como platform_rw y sirve solo GET /healthz (404 uniforme en el resto: sin rutas de login en 6a); verifier y worker arrancan con su rol", async (ctx) => {
  const platform = await startPlatformProcess({ env: envFor(ctx, "platform_rw"), port: 0 });
  try {
    const health = await fetch(`http://127.0.0.1:${platform.port}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: "ok", process: "platform" });
    for (const [method, path] of [["GET", "/platform/auth/login"], ["POST", "/platform/step-up"], ["GET", "/healthz/x"], ["POST", "/healthz"]] as const) {
      const r = await fetch(`http://127.0.0.1:${platform.port}${path}`, { method });
      assert.equal(r.status, 404, `${method} ${path}`);
    }
  } finally {
    await platform.stop();
  }

  const worker = await startWorkerProcess({ env: envFor(ctx, "worker") });
  try {
    assert.equal((await worker.cycle()).failed, 0);
  } finally {
    await worker.stop();
  }

  const verifier = await startVerifierProcess({
    env: {
      ...envFor(ctx, "integrity_verifier"),
      CNS_VERIFIER_ISSUER: "https://idp.synthetic.invalid",
      CNS_VERIFIER_AUDIENCE: "consent-app-synthetic",
      CNS_VERIFIER_MAX_AUTH_AGE_SECONDS: "300",
      CNS_VERIFIER_SUB_HMAC_KEY_HEX: "ef".repeat(32),
    },
  });
  try {
    assert.equal(await verifier.cycle(), "IDLE");
  } finally {
    await verifier.stop();
  }
});

async function execFor(admin: Client, role: string, fn: string): Promise<boolean> {
  return (await admin.query<{ x: boolean }>("SELECT has_function_privilege($1, p.oid, 'EXECUTE') AS x FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = $2", [role, fn])).rows[0]?.x ?? false;
}

pgTest("TEST-CNS-1398 pg: 0042 - R5-R7 solo worker (app_rw recibe 42501), R4 intacta, y el worker solo LEE app.revocation e integrity.audit_event bajo RLS por tenant", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const fn of R5_R7) {
    assert.equal(await execFor(admin, "worker", fn), true, `worker ${fn}`);
    for (const role of ["app_rw", "platform_rw", "integrity_verifier"]) assert.equal(await execFor(admin, role, fn), false, `${role} ${fn}`);
  }
  // 6d parte 2 (0070, cierre de F-A10-26 por privilegio): apply_revocation ya no es de app_rw (R4 corre dentro de R3 via r4_apply, interna); queda el worker como respaldo.
  assert.equal(await execFor(admin, "app_rw", "apply_revocation"), false, "R4: app_rw sin EXECUTE (0070)");
  assert.equal(await execFor(admin, "worker", "apply_revocation"), true, "R4 de respaldo: worker");

  // Ataque real: app_rw intenta ejecutar R5/R6/R7 -> 42501 (privilegio, no guard de dominio).
  const app = await ctx.connectAs("app_rw");
  const T = fixtureUuid("t1398");
  const calls: Record<(typeof R5_R7)[number], string> = {
    mark_downstream_emitted: "SELECT case_state.mark_downstream_emitted('r1398', ARRAY['5717b0b5-0000-4000-8000-000000000001'], 0)",
    record_downstream_ack: "SELECT case_state.record_downstream_ack('r1398', 'ack1398', 0)",
    record_erasure_attestation: "SELECT case_state.record_erasure_attestation('r1398', 'att1398', 0)",
  };
  for (const fn of R5_R7) {
    await app.query("BEGIN");
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    await assert.rejects(() => app.query(calls[fn]), (e: unknown) => codeOf(e) === "42501", `app_rw ${fn}`);
    await app.query("ROLLBACK");
  }

  // Lectura minima del worker bajo RLS: ve las filas de SU tenant y ninguna sin tenant; ninguna escritura directa.
  const A = fixtureUuid("t1398-a");
  const B = fixtureUuid("t1398-b");
  await admin.query("SELECT set_config('case_state.effect', 'seed_local_revocation', false)");
  for (const [t, ref] of [[A, "r1398-a"], [B, "r1398-b"]] as const) {
    await admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, verified_auth_path) VALUES ($1, $2, $3, $4, 'APPLIED', 'OTP')", [t, ref, `c-${ref}`, `d-${ref}`]);
  }
  const worker = await ctx.connectAs("worker");
  const refsAs = async (tenant: string | null): Promise<string[]> => {
    await worker.query("BEGIN");
    try {
      if (tenant !== null) await worker.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
      return (await worker.query<{ revocation_ref: string }>("SELECT revocation_ref FROM app.revocation WHERE revocation_ref LIKE 'r1398-%' ORDER BY 1")).rows.map((r) => r.revocation_ref);
    } finally {
      await worker.query("ROLLBACK");
    }
  };
  assert.deepEqual(await refsAs(A), ["r1398-a"]);
  assert.deepEqual(await refsAs(B), ["r1398-b"]);
  assert.deepEqual(await refsAs(null), []);
  // Ledger: siembra eventos en A y B (por el adaptador del ledger como app_rw) y el worker solo ve los del tenant fijado.
  await enableLedgerMechanicsAppend(ctx); // ADR-010 rev. 5 PR-b: siembra de eventos arbitrarios (mecanica del ledger)
  const seedPool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const seedUow = new PgUnitOfWork(seedPool);
    for (const [t, agg] of [[A, "agg1398-a"], [B, "agg1398-b"]] as const) {
      await seedUow.inTenant(t, ({ ledger }) => ledger.append({ eventType: "INVITATION_OPENED", tenantId: t, aggregateType: "Invitation", aggregateId: agg, actorType: "HUMAN", expectedSequence: 0, payload: invitationRefPayload(agg) }));
    }
  } finally {
    await seedPool.end();
  }
  const ledgerAs = async (tenant: string | null): Promise<string[]> => {
    await worker.query("BEGIN");
    try {
      if (tenant !== null) await worker.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
      return (await worker.query<{ aggregate_id: string }>("SELECT aggregate_id FROM integrity.audit_event WHERE aggregate_id LIKE 'agg1398-%' ORDER BY 1")).rows.map((r) => r.aggregate_id);
    } finally {
      await worker.query("ROLLBACK");
    }
  };
  assert.deepEqual(await ledgerAs(A), ["agg1398-a"], "el worker solo ve el ledger de A");
  assert.deepEqual(await ledgerAs(B), ["agg1398-b"], "el worker solo ve el ledger de B");
  assert.deepEqual(await ledgerAs(null), [], "sin tenant no ve nada");
  for (const sql of [
    "UPDATE app.revocation SET status = 'COMPLETED' WHERE revocation_ref = 'r1398-a'",
    "DELETE FROM app.revocation WHERE revocation_ref = 'r1398-a'",
    "INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES ('00000000-0000-4000-8000-000000000000', 'Revocation', 'x', 1, 'REVOCATION_REQUESTED', 'SYSTEM_GUARD', '{}')",
  ]) {
    await assert.rejects(() => worker.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
  }
  // platform_rw e integrity_verifier siguen sin ninguna lectura de esas tablas.
  for (const role of ["platform_rw", "integrity_verifier"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(() => c.query("SELECT 1 FROM app.revocation LIMIT 1"), (e: unknown) => codeOf(e) === "42501", `${role} app.revocation`);
    await assert.rejects(() => c.query("SELECT 1 FROM integrity.audit_event LIMIT 1"), (e: unknown) => codeOf(e) === "42501", `${role} audit_event`);
  }
});

async function withAppEnv<R>(ctx: PgTestContext, body: (env: X6Env, outside: ReturnType<typeof pgOutsideTxPorts>) => Promise<R>): Promise<R> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const stub = createInMemoryDownstreamStub();
    const ports: RevocationPorts = { ...outside, recoveryLinkChannel: sink, recoveryTokenPolicy: { ttlMs: 60_000 }, uow, tenantResolver: createPgTenantResolver(pool), downstreamStub: stub };
    return await body({ ports, stub, sink }, outside);
  } finally {
    await pool.end();
  }
}

pgTest("TEST-CNS-1399 pg: el worker ejecuta R5-R7 hasta COMPLETED (stub interno, LOCAL) y el web ya no (42501, estado intacto); fuera de LOCAL el worker no ejecuta R5-R7", async (ctx) => {
  const T = fixtureUuid("t1399");
  const refs: string[] = [];
  await withAppEnv(ctx, async (env, outside) => {
    // R1-R4 siguen en el web (app_rw): llegan a APPLIED y R4 encola consent.revoked en el outbox.
    for (const path of ["OTP", "LINK"] as const) // la via CASE (RH2/RH3) solo corre en platform: TEST-CNS-1711
    refs.push((await revokeVia(env, T, `1399-${path}`, path)).revocationRef);
    for (const ref of refs) assert.equal((await outside.revocationRepo.findByRef(T, ref))?.status, "APPLIED");

    // El web intenta R5: la base lo niega por privilegio y el estado no cambia.
    await assert.rejects(() => emitRevocationDownstream(env.ports, T, refs[0]!), (e: unknown) => codeOf(e) === "42501");
    assert.equal((await outside.revocationRepo.findByRef(T, refs[0]!))?.status, "APPLIED");
    assert.equal((await outside.ledger.listByAggregate(T, "Revocation", refs[0]!)).some((e) => e.eventType === "REVOCATION_DOWNSTREAM_EMITTED"), false);

    // El worker (rol worker, LOCAL) toma los eventos del outbox y lleva las tres hasta COMPLETED.
    const pool = await openProcessPool({ process: "worker", environment: "LOCAL", env: envFor(ctx, "worker") });
    try {
      const result = await runWorkerCycle({ pool, environment: "LOCAL" });
      assert.equal(result.failed, 0);
      assert.equal(result.completed, 2); // OTP y LINK; la via CASE corre en platform (TEST-CNS-1711)
    } finally {
      await pool.end();
    }
    for (const ref of refs) {
      assert.equal((await outside.revocationRepo.findByRef(T, ref))?.status, "COMPLETED", ref);
      const types = (await outside.ledger.listByAggregate(T, "Revocation", ref)).map((e) => e.eventType);
      for (const t of ["REVOCATION_DOWNSTREAM_EMITTED", "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED"]) assert.equal(types.filter((x) => x === t).length, 1, `${ref} ${t}`);
    }

    // Re-claim (at-least-once sin acuse, F-PR6-20): vencido el lease, un segundo ciclo reclama de nuevo los eventos y NO agrega eventos al ledger (R5-R7 idempotentes).
    const ledgerCounts = async (): Promise<number[]> => Promise.all(refs.map(async (r) => (await outside.ledger.listByAggregate(T, "Revocation", r)).length));
    const before = await ledgerCounts();
    const adminRc = await ctx.connectAsSuperuser();
    await adminRc.query("UPDATE app.outbox SET claimed_at = now() - interval '5 minutes' WHERE status = 'CLAIMED'");
    const poolRc = await openProcessPool({ process: "worker", environment: "LOCAL", env: envFor(ctx, "worker") });
    try {
      const again = await runWorkerCycle({ pool: poolRc, environment: "LOCAL" });
      assert.ok(again.claimed >= 2, "reclama de nuevo"); // OTP y LINK (la via CASE corre en platform)
      assert.equal(again.failed, 0);
    } finally {
      await poolRc.end();
    }
    assert.deepEqual(await ledgerCounts(), before, "el re-claim no agrega eventos al ledger");

    // Fuera de LOCAL no hay consumidor downstream: el worker NO reclama el outbox ni ejecuta R5-R7 (la Revocation sigue APPLIED y el evento PENDING).
    const dev = (await revokeVia(env, T, "1399-DEV", "OTP")).revocationRef;
    const pool2 = await openProcessPool({ process: "worker", environment: "LOCAL", env: envFor(ctx, "worker") });
    try {
      const result = await runWorkerCycle({ pool: pool2, environment: "DEV" });
      assert.equal(result.completed, 0);
      assert.equal(result.claimed, 0);
    } finally {
      await pool2.end();
    }
    assert.equal((await outside.revocationRepo.findByRef(T, dev))?.status, "APPLIED");
    const st = await adminRc.query<{ status: string; attempts: number }>("SELECT status, attempts FROM app.outbox WHERE tenant_id = $1 AND payload->>'revocationRef' = $2", [T, dev]);
    assert.deepEqual(st.rows, [{ status: "PENDING", attempts: 0 }], "el evento no se reclamo fuera de LOCAL");
    await adminRc.end();
  });
});
