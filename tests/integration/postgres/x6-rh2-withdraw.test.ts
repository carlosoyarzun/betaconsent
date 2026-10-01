// Gobierna: CA-128 X6 P2 (Carlos 2026-10-01), API-CNS-140 withdraw_case_verification_proposal, db/migrations/0016 (RLS FORCE por
// tenant de app.revocation) y 0017 (REVOCATION_PROPOSAL_WITHDRAWN en la lista blanca del ledger), INV-6. SYNTHETIC ONLY.
// TEST-CNS-1019 (retiro/propuesta nueva/aprobacion en Postgres real, ledger y CHECK), TEST-CNS-1020 (aislamiento cross-tenant).
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import {
  approveCaseVerification,
  proposeCaseVerification,
  withdrawCaseVerificationProposal,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { RH2_APPROVER, RH2_OPERATOR, RH2_ROSTER } from "../../contract/rh2-helper.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

async function withPorts<R>(ctx: PgTestContext, body: (ports: RevocationPorts) => Promise<R>): Promise<R> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const ports: RevocationPorts = {
      ...pgOutsideTxPorts(uow),
      recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(pool),
      downstreamStub: createInMemoryDownstreamStub(),
    };
    return await body(ports);
  } finally {
    await pool.end();
  }
}

async function seed(ports: RevocationPorts, tenantId: string, label: string) {
  const revocationRef = fixtureUuid(`r-${label}`);
  const caseRef = fixtureUuid(`c-${label}`);
  await ports.revocationRepo.save({ revocationRef, tenantId, chainRef: fixtureUuid(`chain-${label}`), caseRef, revokedDecisionRef: fixtureUuid(`d-${label}`), status: "REQUESTED" });
  const proposalRef = fixtureUuid(`p-${label}`);
  await proposeCaseVerification(ports, RH2_ROSTER, tenantId, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" });
  return { revocationRef, caseRef, proposalRef };
}

pgTest("TEST-CNS-1019 y 1022 pg: retiro RH2 limpia la propuesta (columnas NULL), registra REVOCATION_PROPOSAL_WITHDRAWN (CHECK de 0017), no cambia el estado; aprobar tras retiro falla y una propuesta nueva se aprueba hasta VERIFIED", async (ctx) => {
  const T = fixtureUuid("t1019");
  const admin = await ctx.connectAsSuperuser();
  try {
    await withPorts(ctx, async (ports) => {
      const { revocationRef, caseRef, proposalRef } = await seed(ports, T, "1019");
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: fixtureUuid("rh2-operator-2") }), code("ERR-RV-07"));
      assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.proposal?.proposalRef, proposalRef);

      const record = await withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR });
      assert.equal(record.status, "REQUESTED");
      const row = (await admin.query("SELECT status, proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [T, revocationRef])).rows[0];
      assert.deepEqual(row, { status: "REQUESTED", proposal_ref: null, proposed_by_ref: null, verification_script_version: null, second_approver_ref: null });
      const events = await ports.ledger.listByAggregate(T, "Revocation", revocationRef);
      assert.deepEqual(events.map((e) => e.eventType), ["REVOCATION_PROPOSAL_WITHDRAWN"]);
      assert.deepEqual(events[0]!.payload, { revocationRef, caseRef, proposalRef, verificationScriptVersion: "guion-1", withdrawnByRef: RH2_OPERATOR });

      await assert.rejects(() => approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true), code("ERR-CM-01"));
      // TEST-CNS-1022: repetir el retiro por el mismo proponente es idempotente (sin evento nuevo); otro principal ERR-CM-01.
      const replay = await withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: RH2_OPERATOR });
      assert.equal(replay.status, "REQUESTED");
      assert.equal((await ports.ledger.listByAggregate(T, "Revocation", revocationRef)).length, 1, "sin segundo evento");
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, proposalRef, { principalRef: fixtureUuid("rh2-operator-2") }), code("ERR-CM-01"));
      await assert.rejects(() => proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "guion-1" }), code("ERR-CM-06"));

      const next = fixtureUuid("p-1019-nueva");
      await proposeCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef: next, verificationScriptVersion: "guion-2" });
      const approved = await approveCaseVerification(ports, RH2_ROSTER, T, revocationRef, caseRef, next, { principalRef: RH2_APPROVER }, true);
      assert.equal(approved.record.status, "VERIFIED");
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, T, revocationRef, caseRef, next, { principalRef: RH2_OPERATOR }), code("ERR-CM-06"), "VERIFIED: ya no PENDING");
      const types = (await ports.ledger.listByAggregate(T, "Revocation", revocationRef)).map((e) => e.eventType);
      assert.deepEqual(types, ["REVOCATION_PROPOSAL_WITHDRAWN", "REVOCATION_VERIFIED"]);
    });
    // 0017: el tipo nuevo esta en el CHECK; uno fuera de lista sigue rechazado (23514).
    const def = (await admin.query("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'integrity.audit_event'::regclass AND conname = 'audit_event_event_type_allowlist'")).rows[0]?.d as string;
    assert.ok(def.includes("REVOCATION_PROPOSAL_WITHDRAWN") && def.includes("REVOCATION_VERIFIED") && !def.includes("NOT_IN_VOCABULARY"));
  } finally {
    await admin.end();
  }
});

pgTest("TEST-CNS-1020 pg: aislamiento cross-tenant del retiro RH2 (RLS FORCE): el tenant B no ve ni retira la propuesta del tenant A (ERR-CM-01) y la fila de A queda intacta", async (ctx) => {
  const A = fixtureUuid("t1020-a");
  const B = fixtureUuid("t1020-b");
  const admin = await ctx.connectAsSuperuser();
  try {
    await withPorts(ctx, async (ports) => {
      const a = await seed(ports, A, "1020a");
      const b = await seed(ports, B, "1020b");
      // B intenta retirar la propuesta de A con los refs de A: invisible bajo RLS.
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, B, a.revocationRef, a.caseRef, a.proposalRef, { principalRef: RH2_OPERATOR }), code("ERR-CM-01"));
      // Refs mezclados dentro del tenant B (caso/propuesta de A sobre revocacion de B): uniforme ERR-CM-01.
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, B, b.revocationRef, a.caseRef, a.proposalRef, { principalRef: RH2_OPERATOR }), code("ERR-CM-01"));
      await assert.rejects(() => withdrawCaseVerificationProposal(ports, RH2_ROSTER, B, b.revocationRef, b.caseRef, a.proposalRef, { principalRef: RH2_OPERATOR }), code("ERR-CM-01"));
      const intactA = (await admin.query("SELECT proposal_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [A, a.revocationRef])).rows[0];
      assert.equal(intactA?.proposal_ref, a.proposalRef, "la propuesta de A sigue PENDING");
      const intactB = (await admin.query("SELECT proposal_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [B, b.revocationRef])).rows[0];
      assert.equal(intactB?.proposal_ref, b.proposalRef, "la propuesta de B sigue PENDING");
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE event_type = 'REVOCATION_PROPOSAL_WITHDRAWN' AND tenant_id = ANY($1)", [[A, B]])).rows[0]?.n, 0, "ningun retiro cruzado registrado");
      // El retiro legitimo en A sigue funcionando y no toca a B.
      await withdrawCaseVerificationProposal(ports, RH2_ROSTER, A, a.revocationRef, a.caseRef, a.proposalRef, { principalRef: RH2_OPERATOR });
      assert.equal((await ports.revocationRepo.findByRef(B, b.revocationRef))?.proposal?.proposalRef, b.proposalRef);
      assert.equal((await ports.ledger.listByAggregate(B, "Revocation", b.revocationRef)).length, 0);
    });
  } finally {
    await admin.end();
  }
});
