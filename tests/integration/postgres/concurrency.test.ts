// Gobierna: CA-124 (PR-C), SEC-CNS-015 P1-1 (R4 "una tx con lock": R4 vs R8 con FOR UPDATE y
// expectedSequence capturado antes de decidir) y P1-2 (GRD-CD-08 y GRD-RV-04 impuestos por UNIQUE
// parcial, migracion 0009), revocation.spec R1/R1r/R4/R8, consent-decision.spec GRD-CD-08.
// TEST-CNS-822..825: carreras reales entre dos conexiones. Requiere Postgres real (harness.ts).

import assert from "node:assert/strict";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import {
  applyRevocation,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  withdrawRevocation,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;

async function withEnv<T>(
  ctx: PgTestContext,
  body: (env: {
    ports: RevocationPorts;
    uow: PgUnitOfWork;
    outside: ReturnType<typeof pgOutsideTxPorts>;
    sink: ReturnType<typeof createInMemoryRecoveryLinkChannelSink>;
    count: (sql: string, values: unknown[]) => Promise<number>;
  }) => Promise<T>,
): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 8 });
  const admin = await ctx.connectAsSuperuser();
  try {
    const uow = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(pool),
    };
    const count = async (sql: string, values: unknown[]): Promise<number> => (await admin.query<{ n: number }>(sql, values)).rows[0]?.n ?? -1;
    return await body({ ports, uow, outside, sink, count });
  } finally {
    await pool.end();
  }
}

pgTest("TEST-CNS-822 pg: R4 concurrente con R8 (retiro) en dos conexiones: exactamente una gana y nunca queda APPLIED tras FAILED (FOR UPDATE + expectedSequence)", async (ctx) => {
  const T = fixtureUuid("t822");
  await withEnv(ctx, async ({ ports, outside, count }) => {
    for (let round = 0; round < 12; round += 1) {
      const D = fixtureUuid(`d822-${round}`);
      const REV = fixtureUuid(`rev822-${round}`);
      await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: `chain-822-${round}` });
      await outside.revocationRepo.save({
        revocationRef: REV, tenantId: T, chainRef: `chain-822-${round}`, revokedDecisionRef: D, status: "CONFIRMED", verifiedAuthPath: "OTP",
      });
      const results = await Promise.allSettled([applyRevocation(ports, T, REV), withdrawRevocation(ports, T, REV)]);
      const [r4, r8] = results;
      assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, `ronda ${round}: exactamente una gana`);
      const final = await outside.revocationRepo.findByRef(T, REV);
      const events = (await outside.ledger.listByAggregate(T, "Revocation", REV)).map((e) => e.eventType);
      const outboxRows = await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${REV}:consent.revoked`]);
      const decision = await outside.consentDecisionRepo.findByConsentId(T, D);
      if (r4?.status === "fulfilled") {
        assert.equal(final?.status, "APPLIED");
        assert.deepEqual(events.sort(), ["CONSENT_REVOKED", "RECEIPT_CREATED"], "R4 aplico y R8 no dejo REVOCATION_FAILED");
        assert.equal(outboxRows, 1);
        assert.equal(decision?.state, "REVOKED");
        assert.ok(r8?.status === "rejected" && r8.reason instanceof DomainError && r8.reason.code === "ERR-CM-06");
      } else {
        assert.equal(final?.status, "FAILED");
        assert.deepEqual(events, ["REVOCATION_FAILED"], "R8 gano: R4 no escribio nada");
        assert.equal(outboxRows, 0);
        assert.equal(decision?.state, "GRANTED", "la decision no se revoco");
        assert.ok(r4?.status === "rejected" && r4.reason instanceof DomainError && r4.reason.code === "ERR-CM-06");
      }
    }
  });
});

pgTest("TEST-CNS-823 pg: GRD-CD-08: dos GRANTED concurrentes en la misma cadena => una gana y la otra falla con ERR-CD-01; REVOKED libera la cadena", async (ctx) => {
  const T = fixtureUuid("t823");
  await withEnv(ctx, async ({ uow, outside }) => {
    const chain = "chain-823";
    const a = { ...syntheticDecision(T, fixtureUuid("d823-a")), chainRef: chain };
    const b = { ...syntheticDecision(T, fixtureUuid("d823-b")), chainRef: chain };
    const results = await Promise.allSettled([
      uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(a)),
      uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(b)),
    ]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    const loser = results.find((r) => r.status === "rejected");
    assert.ok(loser?.status === "rejected" && loser.reason instanceof DomainError && loser.reason.code === "ERR-CD-01");
    const winner = results[0]?.status === "fulfilled" ? a : b;
    const other = winner === a ? b : a;
    assert.equal((await outside.consentDecisionRepo.findActiveGrantByChain(T, chain))?.consentId, winner.consentId);
    assert.equal(await outside.consentDecisionRepo.findByConsentId(T, other.consentId), null, "la perdedora no dejo fila");
    // Otra cadena no se ve afectada; DECLINED/PENDING no cuentan; tras C6 (REVOKED) la cadena admite una GRANTED nueva.
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T, fixtureUuid("d823-c")), chainRef: "chain-823-otra" });
    await outside.consentDecisionRepo.save({ ...other, state: "DECLINED" });
    await outside.consentDecisionRepo.save({ ...winner, state: "REVOKED" });
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T, fixtureUuid("d823-d")), chainRef: chain });
    assert.equal((await outside.consentDecisionRepo.findActiveGrantByChain(T, chain))?.consentId, fixtureUuid("d823-d"));
    // Misma cadena en otro tenant: independiente (tenant_id es parte de la clave).
    const T2 = fixtureUuid("t823-2");
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T2, fixtureUuid("d823-e")), chainRef: chain });
  });
});

pgTest("TEST-CNS-824 pg: GRD-RV-04: una sola Revocation no terminal por decision (UNIQUE parcial); FAILED libera; revoked_decision_ref NOT NULL; el perdedor concurrente falla con ERR-CM-06", async (ctx) => {
  const T = fixtureUuid("t824");
  const admin = await ctx.connectAsSuperuser();
  await withEnv(ctx, async ({ ports, uow, outside }) => {
    const D = fixtureUuid("d824");
    const chain = "chain-824";
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
    const base = { tenantId: T, chainRef: chain, revokedDecisionRef: D, status: "REQUESTED" as const };
    await outside.revocationRepo.save({ ...base, revocationRef: fixtureUuid("r824-1") });
    // Segunda abierta sobre la misma decision: violacion del UNIQUE parcial (nombre exacto).
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, status, revoked_decision_ref) VALUES ($1, 'r824-2', 'c', 'APPLIED', $2)", [T, D])),
      (e: unknown) => codeOf(e) === "23505" && (e as { constraint?: string }).constraint === "revocation_open_per_decision_uq",
    );
    // Sin decision: NOT NULL.
    await assert.rejects(
      () => admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, status) VALUES ($1, 'r824-3', 'c', 'REQUESTED')", [T]),
      (e: unknown) => codeOf(e) === "23502",
    );
    // Otra decision u otro tenant con la misma decision: permitido. FAILED libera la decision.
    await outside.revocationRepo.save({ ...base, revocationRef: fixtureUuid("r824-4"), revokedDecisionRef: fixtureUuid("d824-otra") });
    await outside.revocationRepo.save({ ...base, revocationRef: fixtureUuid("r824-1"), status: "FAILED", reasonCode: "WITHDRAWN_BY_REQUESTER" });
    await outside.revocationRepo.save({ ...base, revocationRef: fixtureUuid("r824-5") });

    // Dos R1 concurrentes (refs distintas, misma decision): una crea; la otra reintenta, sigue en conflicto y
    // termina con ERR-CM-06 (transicion invalida), sin dejar ni fila ni evento.
    const D2 = fixtureUuid("d824-2");
    await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D2), chainRef: "chain-824-2" });
    const results = await Promise.allSettled([
      requestRevocation(ports, T, { revocationRef: fixtureUuid("r824-a"), chainRef: "chain-824-2", revokedDecisionRef: D2 }),
      requestRevocation(ports, T, { revocationRef: fixtureUuid("r824-b"), chainRef: "chain-824-2", revokedDecisionRef: D2 }),
    ]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    const loser = results.find((r) => r.status === "rejected");
    assert.ok(loser?.status === "rejected" && loser.reason instanceof DomainError && loser.reason.code === "ERR-CM-06");
    const open = (await admin.query("SELECT 1 FROM app.revocation WHERE tenant_id = $1 AND revoked_decision_ref = $2 AND status <> 'FAILED'", [T, D2])).rows;
    assert.equal(open.length, 1);
    const events = (await admin.query("SELECT 1 FROM integrity.audit_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_REQUESTED' AND aggregate_id = ANY($2)", [T, [fixtureUuid("r824-a"), fixtureUuid("r824-b")]])).rows;
    assert.equal(events.length, 1, "un solo REVOCATION_REQUESTED");
  });
});

pgTest("TEST-CNS-825 pg: R1 concurrente con R1r sobre la misma decision => una sola revocacion abierta y un solo CONSENT_REVOKED/RECEIPT_CREATED/outbox", async (ctx) => {
  const T = fixtureUuid("t825");
  await withEnv(ctx, async ({ ports, outside, sink, count }) => {
    for (let round = 0; round < 10; round += 1) {
      const D = fixtureUuid(`d825-${round}`);
      const chain = `chain-825-${round}`;
      await outside.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
      await issueRecoveryLinkBearer(ports, T, chain, D, "REQUESTER_ASKED");
      const token = sink.sent[sink.sent.length - 1]!.recoveryPath.replace("/r/", "");
      const R1 = fixtureUuid(`r825-${round}`);
      const results = await Promise.allSettled([
        requestRevocation(ports, T, { revocationRef: R1, chainRef: chain, revokedDecisionRef: D }),
        revokeWithRecoveryLinkByHash(ports, hashRecoveryToken(token)),
      ]);
      // Ningun resultado inesperado: R1 gana, o pierde con un error de dominio (ERR-RV-02: decision ya revocada).
      for (const r of results) {
        if (r.status === "rejected") assert.ok(r.reason instanceof DomainError && (r.reason.code === "ERR-RV-02" || r.reason.code === "ERR-CM-06"), String(r.reason));
      }
      assert.equal(results[1]?.status, "fulfilled", `ronda ${round}: R1r no falla`);
      const open = await count("SELECT count(*)::int AS n FROM app.revocation WHERE tenant_id = $1 AND revoked_decision_ref = $2 AND status <> 'FAILED'", [T, D]);
      assert.equal(open, 1, `ronda ${round}: una sola revocacion abierta`);
      const revs = (await outside.revocationRepo.findOpenByChain(T, chain));
      assert.equal(revs?.status, "APPLIED", "la unica revocacion llego a APPLIED (R1r adjunta o crea)");
      const evt = (type: string): Promise<number> =>
        count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = $3", [T, revs!.revocationRef, type]);
      assert.equal(await evt("CONSENT_REVOKED"), 1);
      assert.equal(await evt("RECEIPT_CREATED"), 1);
      assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${revs!.revocationRef}:consent.revoked`]), 1);
      assert.equal((await outside.consentDecisionRepo.findByConsentId(T, D))?.state, "REVOKED");
    }
  });
});
