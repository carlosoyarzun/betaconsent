// Gobierna: CA-124 (PR-C), postgres-design.md rev. 2 §5 ("Cierra el P2 de R4"), INV-CM-01
// (append + proyeccion + outbox en una tx), revocation.spec R3/R3r/R4/RH3, SEC-CNS-013 P2-3.
// TEST-CNS-815..817: los mismos tres flujos que TEST-CNS-773..775 (R3+R4, recuperacion+R4,
// cosign+R4) contra PgUnitOfWork: un fallo inyectado en el ULTIMO paso de R4 (guardar APPLIED)
// revierte TODO (revocation, ledger, outbox, decision y consumo del token) y el reintento llega a
// APPLIED. TEST-CNS-818: la numeracion del ledger la fija R4 con expectedSequence. SYNTHETIC ONLY.

import { injectOutboxFailure, recordRh3, seedCaseWorld, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import assert from "node:assert/strict";

import { confirmRevocation, evaluateRecoveryTokenEligibilityByHash, hashRecoveryToken, issueRecoveryLinkBearer, requestRevocation, revokeWithRecoveryLinkByHash, verifyRevocationOtp, type RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

/** uow que falla al guardar la Revocation en APPLIED (ultimo paso de R4) mientras `fail.on`. */
function flakyUow(real: UnitOfWorkPort, fail: { on: boolean }): UnitOfWorkPort {
  return {
    inTenant: (tenantId, work) =>
      real.inTenant(tenantId, (tx) =>
        work({
          ...tx,
          revocationRepo: {
            ...tx.revocationRepo,
            async save(record) {
              if (record.status === "APPLIED" && fail.on) throw new Error("R4 falló (simulado)");
              return tx.revocationRepo.save(record);
            },
          },
          // ADR-010 PR-5a: en Postgres R4 la escribe case_state.apply_revocation; el fallo se inyecta tras la funcion (misma tx: todo revierte).
          ...(tx.revocationTransitions
            ? {
                revocationTransitions: {
                  ...tx.revocationTransitions,
                  async confirm(input: { readonly revocationRef: string; readonly expectedSequence: number }) {
                    // ADR-010 rev. 5 (0066): R3 + R4 + C6 son UNA funcion; el fallo se inyecta tras ella (misma tx: todo revierte).
                    const confirmed = await tx.revocationTransitions!.confirm(input);
                    if (fail.on) throw new Error("R4 falló (simulado)");
                    return confirmed;
                  },
                },
              }
            : {}),
        }),
      ),
  };
}

async function withPorts<T>(
  ctx: PgTestContext,
  tenantId: string,
  decisionId: string,
  chainRef: string,
  body: (env: {
    ports: RevocationPorts;
    fail: { on: boolean };
    outside: ReturnType<typeof pgOutsideTxPorts>;
    sink: ReturnType<typeof createInMemoryRecoveryLinkChannelSink>;
    count: (sql: string) => Promise<number>;
  }) => Promise<T>,
): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  const admin = await ctx.connectAsSuperuser();
  try {
    const real = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(real);
    await outside.consentDecisionRepo.save({ ...syntheticDecision(tenantId, decisionId), chainRef });
    const fail = { on: true };
    const sink = createInMemoryRecoveryLinkChannelSink();
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: sink,
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow: flakyUow(real, fail),
      tenantResolver: createPgTenantResolver(pool),
    };
    const count = async (sql: string): Promise<number> => (await admin.query<{ n: number }>(sql, [tenantId])).rows[0]?.n ?? -1;
    return await body({ ports, fail, outside, sink, count });
  } finally {
    await pool.end();
  }
}

const events = async (ports: RevocationPorts, tenantId: string, ref: string): Promise<string[]> =>
  (await ports.ledger.listByAggregate(tenantId, "Revocation", ref)).map((e) => e.eventType);

pgTest("TEST-CNS-815 pg E2E: R3+R4 con fallo inyectado en R4 dejan la revocacion VERIFIED (sin CONFIRMED, ledger, outbox ni C6) y el reintento llega a APPLIED", async (ctx) => {
  const T = fixtureUuid("tenant-815");
  const D = fixtureUuid("decision-815");
  const REV = fixtureUuid("rev-815");
  await withPorts(ctx, T, D, fixtureUuid("chain-815"), async ({ ports, fail, outside, count }) => {
    await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-815"), revokedDecisionRef: D });
    await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-815"));
    const before = await events(ports, T, REV);

    await assert.rejects(() => confirmRevocation(ports, T, REV), /R4 falló/);
    assert.equal((await outside.revocationRepo.findByRef(T, REV))?.status, "VERIFIED");
    assert.deepEqual(await events(ports, T, REV), before, "ni REVOCATION_CONFIRMED ni CONSENT_REVOKED ni RECEIPT_CREATED");
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 0);
    assert.equal((await outside.consentDecisionRepo.findByConsentId(T, D))?.state, "GRANTED");

    fail.on = false;
    assert.equal((await confirmRevocation(ports, T, REV)).status, "APPLIED");
    const types = await events(ports, T, REV);
    for (const t of ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]) assert.equal(types.filter((x) => x === t).length, 1, t);
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 1);
    assert.equal((await outside.consentDecisionRepo.findByConsentId(T, D))?.state, "REVOKED");
    // Sin huecos ni duplicados en la numeracion del agregado.
    const seqs = (await outside.ledger.listByAggregate(T, "Revocation", REV)).map((e) => e.sequence);
    assert.deepEqual(seqs, seqs.map((_, i) => i + 1));
  });
});

pgTest("TEST-CNS-816 pg E2E: recuperacion con fallo inyectado en R4 no consume el token ni deja Revocation; el mismo enlace reintenta hasta APPLIED", async (ctx) => {
  const T = fixtureUuid("tenant-816");
  const D = fixtureUuid("decision-816");
  const CHAIN = fixtureUuid("chain-816");
  await withPorts(ctx, T, D, CHAIN, async ({ ports, fail, outside, sink, count }) => {
    await issueRecoveryLinkBearer(ports, T, CHAIN, D, "REQUESTER_ASKED");
    const token = sink.sent[0]!.recoveryPath.replace("/r/", "");
    const tokenHash = hashRecoveryToken(token);
    // El hash se resuelve sin tenant via tenant_resolve (registrado en la misma tx que el token).
    assert.equal((await ports.tenantResolver.byRecoveryTokenHash(tokenHash))?.tenantId, T);
    const ledgerBefore = await count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1");

    await assert.rejects(() => revokeWithRecoveryLinkByHash(ports, tokenHash), /R4 falló/);
    assert.equal(await outside.revocationRepo.findOpenByChain(T, CHAIN), null, "sin Revocation huerfana (ni REQUESTED/VERIFIED/CONFIRMED)");
    assert.ok(await evaluateRecoveryTokenEligibilityByHash(ports, tokenHash), "el token NO quedo consumido");
    assert.equal(await count("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1"), ledgerBefore, "ni un evento de ledger");
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 0);
    assert.equal((await outside.consentDecisionRepo.findByConsentId(T, D))?.state, "GRANTED");

    fail.on = false;
    const outcome = await revokeWithRecoveryLinkByHash(ports, tokenHash);
    assert.equal(outcome.kind, "CONFIRMED");
    const ref = (outcome as { revocationRef: string }).revocationRef;
    assert.equal((await outside.revocationRepo.findByRef(T, ref))?.status, "APPLIED");
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 1);
    assert.equal(await evaluateRecoveryTokenEligibilityByHash(ports, tokenHash), null, "ahora si consumido (un solo uso)");
  });
});

pgTest("TEST-CNS-817 pg platform E2E: RH3 cosign+R4 con fallo inyectado en R4 (ultimo paso: outbox) deja VERIFIED con el paso 1 registrado, sin CONFIRMED/CONSENT_REVOKED/RECEIPT_CREATED ni outbox, y el reintento de cosign llega a APPLIED", async (ctx) => {
  // ADR-010 rev. 5 (6d parte 2): RH3 solo corre por platform (sesion CASE, actor desde la sesion, R4 atomica en cosign_case_confirmation). El fallo se inyecta DENTRO de la base (trigger en app.outbox, paso final de R4):
  // todo revierte; un error NO transitorio (XX000) no se reintenta y llega al llamador tal cual.
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "817");
  const http = await startPlatformHttp(ctx);
  try {
    await recordRh3(admin, http, w);
    const events = async (): Promise<string[]> => (await admin.query<{ event_type: string }>("SELECT event_type FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [w.tenantId, w.revocationRef])).rows.map((r) => r.event_type);
    const outbox = async (): Promise<number> => (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1", [w.tenantId])).rows[0]!.n;
    const before = await events();
    const failure = await injectOutboxFailure(admin, { name: "f817", tenantId: w.tenantId, failures: 1_000, sqlstate: "XX000" });
    await assert.rejects(() => http.cases.cosign({ sid: w.op2.caseSession.sid, caseRef: w.caseRef }), /fallo inyectado/);
    assert.equal(await failure.attempts(), 1, "un error no transitorio no se reintenta");
    const rolled = (await admin.query("SELECT status, recorded_by_ref, cosigned_by_ref FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0];
    assert.deepEqual(rolled, { status: "VERIFIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: null }, "el paso 1 (anterior a la tx de la co-firma) se conserva; sin co-firma");
    assert.deepEqual(await events(), before, "R3, R4 y C6 revierten juntos");
    assert.equal(await outbox(), 0);
    assert.equal((await admin.query("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [w.tenantId, w.consentId])).rows[0]?.state, "GRANTED");

    await failure.remove();
    const retried = await http.cases.cosign({ sid: w.op2.caseSession.sid, caseRef: w.caseRef });
    assert.equal(retried.ok, true, JSON.stringify(retried));
    const row = (await admin.query("SELECT status, cosigned_by_ref FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0];
    assert.deepEqual(row, { status: "APPLIED", cosigned_by_ref: w.op2.principal });
    const types = await events();
    for (const t of ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]) assert.equal(types.filter((x) => x === t).length, 1, t);
    assert.equal(await outbox(), 1);
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-818 pg: R4 registra CONSENT_REVOKED y RECEIPT_CREATED con sequence = expectedSequence + 1 en el ledger real (R1..R4 numerados 1..5 sin huecos)", async (ctx) => {
  const T = fixtureUuid("tenant-818");
  const D = fixtureUuid("decision-818");
  const REV = fixtureUuid("rev-818");
  await withPorts(ctx, T, D, fixtureUuid("chain-818"), async ({ ports, fail, outside }) => {
    fail.on = false;
    await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-818"), revokedDecisionRef: D });
    await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-818"));
    await confirmRevocation(ports, T, REV);
    const listed = await outside.ledger.listByAggregate(T, "Revocation", REV);
    assert.deepEqual(
      listed.map((e) => [e.sequence, e.eventType]),
      [[1, "REVOCATION_REQUESTED"], [2, "REVOCATION_VERIFIED"], [3, "REVOCATION_CONFIRMED"], [4, "CONSENT_REVOKED"], [5, "RECEIPT_CREATED"]],
    );
  });
});
