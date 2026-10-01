// Gobierna: CA-124 (PR-B0, D3), postgres-design.md rev. 2 §5 ("Cierra el P2 de R4"), INV-CM-01,
// revocation.spec R3/R4/R3r/RH3. TEST-CNS-773..776: con UnitOfWork, un fallo inyectado en R4 deja
// TODO como estaba antes de la operación y el reintento llega a APPLIED. SYNTHETIC DATA ONLY.

import { revocationRequestedPayload, revocationVerifiedPayload } from "../../contract/ledger-payload-fixtures.ts";
import test from "node:test";
import assert from "node:assert/strict";

import {
  confirmRevocation,
  cosignCaseConfirmation,
  evaluateRecoveryTokenEligibilityByHash,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  attestHumanAssistedVerification,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { LedgerSequenceConflictError } from "../../../src/server/ports/ledger.port.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = fixtureUuid("tenant-773");
const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
]);

/** Ports con un revocationRepo que falla al guardar APPLIED (fallo inyectado en R4) mientras `fail.on`. */
async function makePorts(decisionId: string, chainRef = fixtureUuid("chain-773")) {
  const inner = createInMemoryRevocationRepository();
  const fail = { on: true };
  const flaky: RevocationRepositoryPort = {
    ...inner,
    async save(record) {
      if (record.status === "APPLIED" && fail.on) throw new Error("R4 falló (simulado)");
      await inner.save(record);
    },
  };
  const consentDecisionRepo = createInMemoryConsentDecisionRepository();
  await consentDecisionRepo.save({ ...syntheticDecision(T, decisionId), chainRef });
  const ports: RevocationPorts = withInMemoryTenancy({
    revocationRepo: flaky,
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  });
  return { ports, inner, fail, outbox: (ports as unknown as { outbox: { enqueued: unknown[] } }).outbox, sink: ports.recoveryLinkChannel as ReturnType<typeof createInMemoryRecoveryLinkChannelSink> };
}

const eventTypes = async (ports: RevocationPorts, ref: string) => (await ports.ledger.listByAggregate(T, "Revocation", ref)).map((e) => e.eventType);

test("TEST-CNS-773: R3+R4 con fallo inyectado en R4 dejan la revocación como estaba antes de R3 (VERIFIED, sin REVOCATION_CONFIRMED ni outbox) y el reintento llega a APPLIED", async () => {
  const D = fixtureUuid("decision-773");
  const REV = fixtureUuid("rev-773");
  const { ports, inner, fail, outbox } = await makePorts(D);
  await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-773"), revokedDecisionRef: D });
  await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-773"));
  const before = await eventTypes(ports, REV);

  await assert.rejects(() => confirmRevocation(ports, T, REV), /R4 falló/);
  assert.equal((await inner.findByRef(T, REV))?.status, "VERIFIED");
  assert.deepEqual(await eventTypes(ports, REV), before, "ni REVOCATION_CONFIRMED ni CONSENT_REVOKED ni RECEIPT_CREATED");
  assert.equal(outbox.enqueued.length, 0);
  assert.equal((await ports.consentDecisionRepo.findByConsentId(T, D))?.state, "GRANTED");

  fail.on = false;
  const retried = await confirmRevocation(ports, T, REV);
  assert.equal(retried.status, "APPLIED");
  const types = await eventTypes(ports, REV);
  for (const t of ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]) assert.equal(types.filter((x) => x === t).length, 1, t);
  assert.equal(outbox.enqueued.length, 1);
  assert.equal((await ports.consentDecisionRepo.findByConsentId(T, D))?.state, "REVOKED");
});

test("TEST-CNS-774: recuperación con fallo inyectado en R4 no consume el token ni deja Revocation; el mismo enlace reintenta hasta APPLIED", async () => {
  const D = fixtureUuid("decision-774");
  const CHAIN = fixtureUuid("chain-774");
  const { ports, inner, fail, outbox, sink } = await makePorts(D, CHAIN);
  await issueRecoveryLinkBearer(ports, T, CHAIN, D, "REQUESTER_ASKED");
  const token = sink.sent[0]!.recoveryPath.replace("/r/", "");
  const tokenHash = hashRecoveryToken(token);
  const ledgerBefore = (await ports.ledger.listByAggregate(T, "Revocation", CHAIN)).length;

  await assert.rejects(() => revokeWithRecoveryLinkByHash(ports, tokenHash), /R4 falló/);
  assert.equal(await inner.findOpenByChain(T, CHAIN), null, "sin Revocation huérfana (ni REQUESTED/VERIFIED/CONFIRMED)");
  assert.ok(await evaluateRecoveryTokenEligibilityByHash(ports, tokenHash), "el token NO quedó consumido");
  assert.equal((await ports.ledger.listByAggregate(T, "Revocation", CHAIN)).length, ledgerBefore);
  assert.equal(outbox.enqueued.length, 0);
  assert.equal((await ports.consentDecisionRepo.findByConsentId(T, D))?.state, "GRANTED");

  fail.on = false;
  const outcome = await revokeWithRecoveryLinkByHash(ports, tokenHash);
  assert.equal(outcome.kind, "CONFIRMED");
  const ref = (outcome as { revocationRef: string }).revocationRef;
  assert.equal((await inner.findByRef(T, ref))?.status, "APPLIED");
  assert.equal(outbox.enqueued.length, 1);
  assert.equal(await evaluateRecoveryTokenEligibilityByHash(ports, tokenHash), null, "ahora sí consumido (un solo uso)");
});

test("TEST-CNS-775: RH3 cosign+R4 con fallo inyectado en R4 deja la revocación VERIFIED con el paso 1 registrado y el reintento de cosign llega a APPLIED", async () => {
  const D = fixtureUuid("decision-775");
  const REV = fixtureUuid("rev-775");
  const CASE = fixtureUuid(`case-${REV}`);
  const { ports, inner, fail, outbox } = await makePorts(D);
  await inner.save({ revocationRef: REV, tenantId: T, chainRef: fixtureUuid("chain-775"), caseRef: CASE, revokedDecisionRef: D, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, T, REV, CASE);
  await recordCaseConfirmationPendingCosign(ports, staff, T, REV, CASE, { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
  const before = await eventTypes(ports, REV);

  await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, CASE, { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") }), /R4 falló/);
  const rolled = await inner.findByRef(T, REV);
  assert.equal(rolled?.status, "VERIFIED");
  assert.equal(rolled?.recordedByRef, fixtureUuid("staff-synthetic-01"), "el paso 1 (anterior a la unidad de trabajo) se conserva");
  assert.equal(rolled?.cosignedByRef, undefined);
  assert.deepEqual(await eventTypes(ports, REV), before);
  assert.equal(outbox.enqueued.length, 0);

  fail.on = false;
  const retried = await cosignCaseConfirmation(ports, staff, T, REV, CASE, { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") });
  assert.equal(retried.status, "APPLIED");
  const types = await eventTypes(ports, REV);
  for (const t of ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]) assert.equal(types.filter((x) => x === t).length, 1, t);
  assert.equal(outbox.enqueued.length, 1);
});

test("TEST-CNS-776: LedgerPort.expectedSequence: procede solo si la última sequence del agregado coincide; conflicto no escribe y la dedupe por idempotencyKey se evalúa antes", async () => {
  const ledger = createInMemoryLedgerAdapter();
  const base = { eventType: "REVOCATION_REQUESTED", tenantId: T, aggregateType: "Revocation", aggregateId: fixtureUuid("agg-776"), actorType: "HUMAN" as const, payload: revocationRequestedPayload("base") };
  const first = await ledger.append({ ...base, expectedSequence: 0, idempotencyKey: "k1" });
  assert.equal(first.sequence, 1);
  assert.ok(!("expectedSequence" in first), "expectedSequence no se persiste en el registro");
  await assert.rejects(() => ledger.append({ ...base, expectedSequence: 0, idempotencyKey: "k2" }), (e: unknown) => e instanceof LedgerSequenceConflictError && e.actualSequence === 1);
  assert.equal((await ledger.listByAggregate(T, "Revocation", base.aggregateId)).length, 1);
  assert.equal((await ledger.append({ ...base, expectedSequence: 0, idempotencyKey: "k1" })).sequence, 1, "dedupe devuelve el existente");
  assert.equal((await ledger.append({ ...base, expectedSequence: 1, idempotencyKey: "k2" })).sequence, 2);
});
