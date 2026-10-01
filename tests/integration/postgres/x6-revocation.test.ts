// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128), revocation.spec R5/R6/R7 + GRD-RV-04 ("UNIQUE parcial ... WHERE
// state NOT IN ('COMPLETED','FAILED')") + INV-6, db/migrations/0015_revocation_completed.sql.
// TEST-CNS-969 (ciclo hasta COMPLETED en Postgres real, tres vías), TEST-CNS-970 (CHECK de estados e índice
// GRD-RV-04 con COMPLETED), TEST-CNS-971 (INV-6 con participación SUSPENDED/CLOSED y enrollment/OTP en BD). SYNTHETIC ONLY.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { completeDownstream, REVOCATION_PATHS, revokeVia, type X6Env } from "../../contract/x6-revocation-scenarios.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

async function withEnv<R>(ctx: PgTestContext, body: (env: X6Env, outside: ReturnType<typeof pgOutsideTxPorts>) => Promise<R>): Promise<R> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const stub = createInMemoryDownstreamStub();
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(pool),
      downstreamStub: stub,
    };
    return await body({ ports, stub, sink }, outside);
  } finally {
    await pool.end();
  }
}

for (const path of REVOCATION_PATHS) {
  pgTest(`TEST-CNS-969 pg (${path}): la revocación llega hasta COMPLETED con el stub interno; ledger sin huecos y un solo consent.revoked`, async (ctx) => {
    const T = fixtureUuid(`t969-${path}`);
    await withEnv(ctx, async (env, outside) => {
      const { revocationRef } = await revokeVia(env, T, `969-${path}`, path);
      await completeDownstream(env, T, revocationRef, `969-${path}`);
      assert.equal((await outside.revocationRepo.findByRef(T, revocationRef))?.status, "COMPLETED");
      const events = await outside.ledger.listByAggregate(T, "Revocation", revocationRef);
      assert.deepEqual(events.map((e) => e.sequence), events.map((_, i) => i + 1));
      const types = events.map((e) => e.eventType);
      for (const t of ["REVOCATION_DOWNSTREAM_EMITTED", "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED", "CONSENT_REVOKED"]) {
        assert.equal(types.filter((x) => x === t).length, 1, t);
      }
      assert.equal(types.filter((x) => x === "RECEIPT_CREATED").length, 2);
      // COMPLETED es terminal para GRD-RV-04: ya no cuenta como abierta.
      assert.equal(await outside.revocationRepo.findOpenByChain(T, `chain-969-${path}`), null);
    });
  });
}

pgTest("TEST-CNS-970 pg: 0015 admite los estados DOWNSTREAM_PENDING/DELIVERED/COMPLETED, rechaza otros y el UNIQUE de GRD-RV-04 excluye COMPLETED (no DELIVERED)", async (ctx) => {
  const T = fixtureUuid("t970");
  const admin = await ctx.connectAsSuperuser();
  try {
    const D = fixtureUuid("d970");
    const ins = (ref: string, status: string) =>
      admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status) VALUES ($1, $2, 'c970', $3, $4)", [T, ref, D, status]);
    await assert.rejects(() => ins("r970-x", "EXPIRED"), (e: unknown) => (e as { code?: string }).code === "23514");
    await ins("r970-1", "DELIVERED");
    await assert.rejects(() => ins("r970-2", "REQUESTED"), (e: unknown) => (e as { constraint?: string }).constraint === "revocation_open_per_decision_uq");
    await admin.query("UPDATE app.revocation SET status = 'COMPLETED' WHERE tenant_id = $1 AND revocation_ref = 'r970-1'", [T]);
    await ins("r970-2", "REQUESTED"); // COMPLETED libera la decisión en el índice
    await ins("r970-3", "DOWNSTREAM_PENDING").then(
      () => assert.fail("no debería admitir dos abiertas"),
      (e: unknown) => assert.equal((e as { constraint?: string }).constraint, "revocation_open_per_decision_uq"),
    );
  } finally {
    await admin.end();
  }
});

pgTest("TEST-CNS-971 pg (INV-6): con SchoolParticipation SUSPENDED/CLOSED, Enrollment CLOSED y OTP LOCKED en la BD, la revocación llega a APPLIED y encola consent.revoked en las tres vías", async (ctx) => {
  const T = fixtureUuid("t971");
  const admin = await ctx.connectAsSuperuser();
  try {
    for (const [ref, status] of [["p971-s", "SUSPENDED"], ["p971-c", "CLOSED"]] as const) {
      await admin.query("INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, $2, 'BETA_2026_01', 'LECTORPRO_BETA', $3)", [T, ref, status]);
    }
    await withEnv(ctx, async (env, outside) => {
      await outside.enrollmentRepo.save({ enrollmentRef: fixtureUuid("e971"), tenantId: T, subjectRef: fixtureUuid("s971"), participationRef: "p971-s", state: "CLOSED" });
      await outside.otpRepo.save({
        verificationRef: fixtureUuid("otp971"), tenantId: T, scope: "REVOCATION", parentRef: fixtureUuid("chain-971-OTP"), channelRef: "x6+971@example.invalid",
        codeHash: "0".repeat(64), attempts: 99, expiresAt: new Date("2000-01-01T00:00:00Z"), state: "LOCKED", resendCount: 5,
      });
      for (const path of REVOCATION_PATHS) {
        const { revocationRef } = await revokeVia(env, T, `971-${path}`, path);
        assert.equal((await outside.revocationRepo.findByRef(T, revocationRef))?.status, "APPLIED", path);
        const n = (await admin.query("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${revocationRef}:consent.revoked`])).rows[0]?.n;
        assert.equal(n, 1, `${path}: consent.revoked encolado`);
      }
      assert.equal((await outside.otpRepo.findByRef(T, fixtureUuid("otp971")))?.state, "LOCKED");
    });
  } finally {
    await admin.end();
  }
});

pgTest("TEST-CNS-973 pg: el append del ledger rechaza (ERR-RV-13) un campo extra con PII sintética y NO persiste evento ni avanza la cadena", async (ctx) => {
  const T = fixtureUuid("t973");
  const admin = await ctx.connectAsSuperuser();
  try {
    await withEnv(ctx, async (env, outside) => {
      const agg = fixtureUuid("inv973");
      const valid = { invitationRef: agg, participationRef: fixtureUuid("p973"), enrollmentRef: fixtureUuid("e973"), subjectRef: fixtureUuid("s973"), reissueOfRef: null };
      const ev = (payload: Record<string, unknown>) => ({
        eventType: "INVITATION_CREATED", tenantId: T, aggregateType: "Invitation", aggregateId: agg, actorType: "HUMAN" as const, expectedSequence: 0, payload,
      });
      await assert.rejects(
        () => env.ports.uow.inTenant(T, (tx) => tx.ledger.append(ev({ ...valid, guardianEmail: "padre.sintetico@example.invalid" }))),
        (e: unknown) => e instanceof LedgerPayloadViolationError,
      );
      const n = (await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, agg])).rows[0]?.n;
      assert.equal(n, 0, "sin fila en el ledger");
      assert.equal((await outside.ledger.listByAggregate(T, "Invitation", agg)).length, 0);
      await env.ports.uow.inTenant(T, (tx) => tx.ledger.append(ev(valid)));
      assert.equal((await outside.ledger.listByAggregate(T, "Invitation", agg)).length, 1, "el válido procede con sequence 1");
    });
  } finally {
    await admin.end();
  }
});
