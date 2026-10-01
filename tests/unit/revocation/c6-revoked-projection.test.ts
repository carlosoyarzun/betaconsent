// Gobierna: specs/state-machines/consent-decision.spec.yaml C6 (GRANTED -> REVOKED en el mismo
// lote que R4, GRD-CD-09, INV-5, GRD-CD-08), revocation.spec.yaml R4 (idempotente por
// revocationRef) y GRD-RV-02 / GRD-RV-06. CA-127 (FINDING P1 proyección C6/REVOKED).
// Datos SINTÉTICOS. TEST-CNS-698..702.

import test from "node:test";
import assert from "node:assert/strict";

import {
  applyRevocation,
  attestHumanAssistedVerification,
  confirmRevocation,
  cosignCaseConfirmation,
  evaluateRecoveryTokenEligibilityByHash,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  requestRevocation,
  resolveRecoveryTokenForRedeem,
  revokeWithRecoveryLink,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter, type InMemoryOutbox } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink, type InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import type { ConsentDecisionRecord, ConsentDecisionRepositoryPort } from "../../../src/server/ports/consent-decision-repository.port.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const T = fixtureUuid("tenant-698");
const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
]);
const COSIGN = { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") };

type Ports = RevocationPorts & { readonly outbox: InMemoryOutbox; readonly recoveryLinkChannel: InMemoryRecoveryLinkChannelSink };

async function makePorts(decision: ConsentDecisionRecord, opts: { revocationRepo?: RevocationRepositoryPort; decisionRepo?: ConsentDecisionRepositoryPort } = {}): Promise<Ports> {
  const consentDecisionRepo = opts.decisionRepo ?? createInMemoryConsentDecisionRepository();
  await consentDecisionRepo.save(decision);
  return withInMemoryTenancy({
    revocationRepo: opts.revocationRepo ?? createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  });
}

async function stateOf(ports: Ports, id: string) {
  return (await ports.consentDecisionRepo.findByConsentId(T, id))?.state;
}

async function seedRh3(ports: Ports, ref: string, decisionId: string) {
  await ports.revocationRepo.save({ revocationRef: ref, tenantId: T, chainRef: `chain-${ref}`, caseRef: fixtureUuid(`case-${ref}`), revokedDecisionRef: decisionId, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, T, ref, fixtureUuid(`case-${ref}`));
  await recordCaseConfirmationPendingCosign(ports, staff, T, ref, fixtureUuid(`case-${ref}`), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
}

test("TEST-CNS-698: R4 deja la decisión en REVOKED en las tres vías (autoservicio OTP, recuperación y RH3)", async () => {
  // Autoservicio.
  const D1 = fixtureUuid("decision-698a");
  const REV1 = fixtureUuid("rev-698a");
  const p1 = await makePorts(syntheticDecision(T, D1));
  assert.equal(await stateOf(p1, D1), "GRANTED");
  await requestRevocation(p1, T, { revocationRef: REV1, chainRef: fixtureUuid("chain-698a"), revokedDecisionRef: D1 });
  await verifyRevocationOtp(p1, T, REV1, fixtureUuid("ver-698a"));
  assert.equal(await stateOf(p1, D1), "GRANTED", "antes de R3/R4 sigue GRANTED");
  await confirmRevocation(p1, T, REV1);
  assert.equal(await stateOf(p1, D1), "REVOKED");

  // Recuperación.
  const D2 = fixtureUuid("decision-698b");
  const d2 = { ...syntheticDecision(T, D2), chainRef: fixtureUuid("chain-698b") };
  const p2 = await makePorts(d2);
  await issueRecoveryLinkBearer(p2, T, fixtureUuid("chain-698b"), D2, "REQUESTER_ASKED");
  const token = p2.recoveryLinkChannel.sent[p2.recoveryLinkChannel.sent.length - 1]!.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(p2, token);
  assert.ok(resolved);
  assert.equal((await revokeWithRecoveryLink(p2, T, fixtureUuid("chain-698b"), D2, resolved.tokenHash)).kind, "CONFIRMED");
  assert.equal(await stateOf(p2, D2), "REVOKED");

  // RH3.
  const D3 = fixtureUuid("decision-698c");
  const REV3 = fixtureUuid("rev-698c");
  const p3 = await makePorts(syntheticDecision(T, D3));
  await seedRh3(p3, REV3, D3);
  assert.equal(await stateOf(p3, D3), "GRANTED", "antes del cosign sigue GRANTED");
  await cosignCaseConfirmation(p3, staff, T, REV3, fixtureUuid(`case-${REV3}`), COSIGN);
  assert.equal(await stateOf(p3, D3), "REVOKED");
});

test("TEST-CNS-699: findActiveGrantByChain no devuelve la decisión revocada (INV-5, GRD-CD-08) y una GRANTED nueva de la misma cadena sí", async () => {
  const D = fixtureUuid("decision-699");
  const REV = fixtureUuid("rev-699");
  const decision = syntheticDecision(T, D);
  const ports = await makePorts(decision);
  assert.equal((await ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef))?.consentId, D);
  await seedRh3(ports, REV, D);
  await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN);
  assert.equal(await ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef), null);
  // Re-consentir = consentId nuevo (no revive la revocada); GRD-CD-08 lo permite.
  const D2 = fixtureUuid("decision-699-new");
  await ports.consentDecisionRepo.save({ ...decision, consentId: D2 });
  assert.equal((await ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef))?.consentId, D2);
  assert.equal(await stateOf(ports, D), "REVOKED");
});

test("TEST-CNS-700: reintentar R4 no reproyecta ni duplica: un solo guardado REVOKED, 1 CONSENT_REVOKED, 1 outbox; APPLIED converge tras fallo", async () => {
  const D = fixtureUuid("decision-700");
  const REV = fixtureUuid("rev-700");
  const inner = createInMemoryRevocationRepository();
  let failApply = true;
  const flaky: RevocationRepositoryPort = {
    ...inner,
    async save(record) {
      if (record.status === "APPLIED" && failApply) throw new Error("save falló (simulado)");
      await inner.save(record);
    },
  };
  const innerDecisions = createInMemoryConsentDecisionRepository();
  let revokedSaves = 0;
  const countingDecisions: ConsentDecisionRepositoryPort = {
    ...innerDecisions,
    async save(record) {
      if (record.state === "REVOKED") revokedSaves += 1;
      await innerDecisions.save(record);
    },
  };
  const ports = await makePorts(syntheticDecision(T, D), { revocationRepo: flaky, decisionRepo: countingDecisions });
  await seedRh3(ports, REV, D);
  await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN), /save falló/);
  // CA-124 (P2 de lampone-security): RH3 cosign + R4 son UNA unidad de trabajo; el fallo deja todo
  // como estaba antes del cosign (antes: C6 proyectada y Revocation CONFIRMED huérfana).
  assert.equal(revokedSaves, 1, "R4 intentó proyectar C6 antes de fallar");
  assert.equal(await stateOf(ports, D), "GRANTED", "C6 revertida junto con el resto de la unidad de trabajo");
  assert.equal((await inner.findByRef(T, REV))?.status, "VERIFIED");

  failApply = false;
  const retried = await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN);
  assert.equal(retried.status, "APPLIED");
  assert.equal(revokedSaves, 2, "la proyección REVOKED confirmada ocurre una sola vez (la del primer intento se revirtió)");
  const events = await ports.ledger.listByAggregate(T, "Revocation", REV);
  assert.equal(events.filter((e) => e.eventType === "CONSENT_REVOKED").length, 1);
  assert.equal(ports.outbox.enqueued.length, 1);
  await assert.rejects(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06");
  assert.equal(revokedSaves, 2);
});

test("TEST-CNS-701: sobre una cadena ya REVOKED, R1 (ERR-RV-02) y RV0 no crean revocación ni emiten token; el token de recuperación previo deja de ser elegible (GRD-RV-06)", async () => {
  const D = fixtureUuid("decision-701");
  const REV = fixtureUuid("rev-701");
  const decision = { ...syntheticDecision(T, D), chainRef: fixtureUuid("chain-701") };
  const ports = await makePorts(decision);
  // Token emitido ANTES de la revocación (aún elegible).
  await issueRecoveryLinkBearer(ports, T, fixtureUuid("chain-701"), D, "REQUESTER_ASKED");
  const token = ports.recoveryLinkChannel.sent[0]!.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);
  assert.ok(await evaluateRecoveryTokenEligibilityByHash(ports, resolved.tokenHash));

  await seedRh3(ports, REV, D);
  await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN);
  assert.equal(await stateOf(ports, D), "REVOKED");

  assert.equal(await evaluateRecoveryTokenEligibilityByHash(ports, resolved.tokenHash), null, "GRD-RV-06: uniforme");
  assert.equal((await revokeWithRecoveryLink(ports, T, fixtureUuid("chain-701"), D, resolved.tokenHash)).kind, "UNIFORM");

  const sentBefore = ports.recoveryLinkChannel.sent.length;
  assert.equal((await issueRecoveryLinkBearer(ports, T, fixtureUuid("chain-701"), D, "REQUESTER_ASKED")).sent, false);
  assert.equal(ports.recoveryLinkChannel.sent.length, sentBefore);

  const NEW = fixtureUuid("rev-701-new");
  await assert.rejects(
    () => requestRevocation(ports, T, { revocationRef: NEW, chainRef: fixtureUuid("chain-701"), revokedDecisionRef: D }),
    (e: unknown) => e instanceof DomainError && e.code === "ERR-RV-02",
  );
  assert.equal(await ports.revocationRepo.findByRef(T, NEW), null);
  assert.equal((await ports.ledger.listByAggregate(T, "Revocation", NEW)).length, 0);
});

test("TEST-CNS-702: C6 solo revoca una decisión GRANTED (GRD-CD-09): PENDING/DECLINED -> ERR-CM-06 sin CONSENT_REVOKED, sin outbox y sin cambiar el estado", async () => {
  for (const state of ["PENDING", "DECLINED"] as const) {
    const D = fixtureUuid(`decision-702-${state}`);
    const REV = fixtureUuid(`rev-702-${state}`);
    const ports = await makePorts({ ...syntheticDecision(T, D), state });
    await seedRh3(ports, REV, D);
    await assert.rejects(
      () => cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN),
      (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06",
    );
    assert.equal(await stateOf(ports, D), state);
    assert.equal(ports.outbox.enqueued.length, 0);
    assert.equal((await ports.ledger.listByAggregate(T, "Revocation", REV)).filter((e) => e.eventType === "CONSENT_REVOKED").length, 0);
  }
});
