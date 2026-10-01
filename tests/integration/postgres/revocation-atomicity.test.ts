// Gobierna: CA-124 (PR-C), postgres-design.md rev. 2 §5 ("Cierra el P2 de R4"), INV-CM-01
// (append + proyeccion + outbox en una tx), revocation.spec R3/R3r/R4/RH3, SEC-CNS-013 P2-3.
// TEST-CNS-815..817: los mismos tres flujos que TEST-CNS-773..775 (R3+R4, recuperacion+R4,
// cosign+R4) contra PgUnitOfWork: un fallo inyectado en el ULTIMO paso de R4 (guardar APPLIED)
// revierte TODO (revocation, ledger, outbox, decision y consumo del token) y el reintento llega a
// APPLIED. TEST-CNS-818: la numeracion del ledger la fija R4 con expectedSequence. SYNTHETIC ONLY.

import assert from "node:assert/strict";

import {
  attestHumanAssistedVerification,
  confirmRevocation,
  cosignCaseConfirmation,
  evaluateRecoveryTokenEligibilityByHash,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-03", role: "APPROVER" },
  { principalRef: "staff-synthetic-04", role: "APPROVER" },
]);

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
  await withPorts(ctx, T, D, "chain-815", async ({ ports, fail, outside, count }) => {
    await requestRevocation(ports, T, { revocationRef: REV, chainRef: "chain-815", revokedDecisionRef: D });
    await verifyRevocationOtp(ports, T, REV, "ver-815");
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
  const CHAIN = "chain-816";
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

pgTest("TEST-CNS-817 pg E2E: RH3 cosign+R4 con fallo inyectado en R4 deja VERIFIED con el paso 1 registrado y el reintento de cosign llega a APPLIED", async (ctx) => {
  const T = fixtureUuid("tenant-817");
  const D = fixtureUuid("decision-817");
  const REV = fixtureUuid("rev-817");
  const CASE = `case-${REV}`;
  await withPorts(ctx, T, D, "chain-817", async ({ ports, fail, outside, count }) => {
    await outside.revocationRepo.save({ revocationRef: REV, tenantId: T, chainRef: "chain-817", caseRef: CASE, revokedDecisionRef: D, status: "REQUESTED" });
    await attestHumanAssistedVerification(ports, T, REV, CASE);
    await recordCaseConfirmationPendingCosign(ports, staff, T, REV, CASE, { recordedByPrincipalRef: "staff-synthetic-01" });
    const before = await events(ports, T, REV);

    await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, CASE, { cosignedByPrincipalRef: "staff-synthetic-02" }), /R4 falló/);
    const rolled = await outside.revocationRepo.findByRef(T, REV);
    assert.equal(rolled?.status, "VERIFIED");
    assert.equal(rolled?.recordedByRef, "staff-synthetic-01", "el paso 1 (anterior a la unidad de trabajo) se conserva");
    assert.equal(rolled?.cosignedByRef, undefined);
    assert.deepEqual(await events(ports, T, REV), before);
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 0);

    fail.on = false;
    const retried = await cosignCaseConfirmation(ports, staff, T, REV, CASE, { cosignedByPrincipalRef: "staff-synthetic-02" });
    assert.equal(retried.status, "APPLIED");
    assert.equal(retried.cosignedByRef, "staff-synthetic-02");
    const types = await events(ports, T, REV);
    for (const t of ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]) assert.equal(types.filter((x) => x === t).length, 1, t);
    assert.equal(await count("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1"), 1);
  });
});

pgTest("TEST-CNS-818 pg: R4 registra CONSENT_REVOKED y RECEIPT_CREATED con sequence = expectedSequence + 1 en el ledger real (R1..R4 numerados 1..5 sin huecos)", async (ctx) => {
  const T = fixtureUuid("tenant-818");
  const D = fixtureUuid("decision-818");
  const REV = fixtureUuid("rev-818");
  await withPorts(ctx, T, D, "chain-818", async ({ ports, fail, outside }) => {
    fail.on = false;
    await requestRevocation(ports, T, { revocationRef: REV, chainRef: "chain-818", revokedDecisionRef: D });
    await verifyRevocationOtp(ports, T, REV, "ver-818");
    await confirmRevocation(ports, T, REV);
    const listed = await outside.ledger.listByAggregate(T, "Revocation", REV);
    assert.deepEqual(
      listed.map((e) => [e.sequence, e.eventType]),
      [[1, "REVOCATION_REQUESTED"], [2, "REVOCATION_VERIFIED"], [3, "REVOCATION_CONFIRMED"], [4, "CONSENT_REVOKED"], [5, "RECEIPT_CREATED"]],
    );
  });
});
