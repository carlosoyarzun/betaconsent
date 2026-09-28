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

const T = fixtureUuid("tenant-698");
const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-03", role: "APPROVER" },
  { principalRef: "staff-synthetic-04", role: "APPROVER" },
]);
const COSIGN = { cosignedByPrincipalRef: "staff-synthetic-02" };

type Ports = RevocationPorts & { readonly outbox: InMemoryOutbox; readonly recoveryLinkChannel: InMemoryRecoveryLinkChannelSink };

function makePorts(decision: ConsentDecisionRecord, opts: { revocationRepo?: RevocationRepositoryPort; decisionRepo?: ConsentDecisionRepositoryPort } = {}): Ports {
  const consentDecisionRepo = opts.decisionRepo ?? createInMemoryConsentDecisionRepository();
  consentDecisionRepo.save(decision);
  return {
    revocationRepo: opts.revocationRepo ?? createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  };
}

function stateOf(ports: Ports, id: string) {
  return ports.consentDecisionRepo.findByConsentId(T, id)?.state;
}

function seedRh3(ports: Ports, ref: string, decisionId: string) {
  ports.revocationRepo.save({ revocationRef: ref, tenantId: T, chainRef: `chain-${ref}`, caseRef: `case-${ref}`, revokedDecisionRef: decisionId, status: "REQUESTED" });
  attestHumanAssistedVerification(ports, T, ref, `case-${ref}`);
  recordCaseConfirmationPendingCosign(ports, staff, T, ref, `case-${ref}`, { recordedByPrincipalRef: "staff-synthetic-01" });
}

test("TEST-CNS-698: R4 deja la decisión en REVOKED en las tres vías (autoservicio OTP, recuperación y RH3)", () => {
  // Autoservicio.
  const D1 = fixtureUuid("decision-698a");
  const REV1 = fixtureUuid("rev-698a");
  const p1 = makePorts(syntheticDecision(T, D1));
  assert.equal(stateOf(p1, D1), "GRANTED");
  requestRevocation(p1, T, { revocationRef: REV1, chainRef: "chain-698a", revokedDecisionRef: D1 });
  verifyRevocationOtp(p1, T, REV1, "ver-698a");
  assert.equal(stateOf(p1, D1), "GRANTED", "antes de R3/R4 sigue GRANTED");
  confirmRevocation(p1, T, REV1);
  assert.equal(stateOf(p1, D1), "REVOKED");

  // Recuperación.
  const D2 = fixtureUuid("decision-698b");
  const d2 = { ...syntheticDecision(T, D2), chainRef: "chain-698b" };
  const p2 = makePorts(d2);
  issueRecoveryLinkBearer(p2, T, "chain-698b", D2, "REQUESTER_ASKED");
  const token = p2.recoveryLinkChannel.sent[p2.recoveryLinkChannel.sent.length - 1]!.recoveryPath.replace("/r/", "");
  const resolved = resolveRecoveryTokenForRedeem(p2, token);
  assert.ok(resolved);
  assert.equal(revokeWithRecoveryLink(p2, T, "chain-698b", D2, resolved.tokenHash).kind, "CONFIRMED");
  assert.equal(stateOf(p2, D2), "REVOKED");

  // RH3.
  const D3 = fixtureUuid("decision-698c");
  const REV3 = fixtureUuid("rev-698c");
  const p3 = makePorts(syntheticDecision(T, D3));
  seedRh3(p3, REV3, D3);
  assert.equal(stateOf(p3, D3), "GRANTED", "antes del cosign sigue GRANTED");
  cosignCaseConfirmation(p3, staff, T, REV3, `case-${REV3}`, COSIGN);
  assert.equal(stateOf(p3, D3), "REVOKED");
});

test("TEST-CNS-699: findActiveGrantByChain no devuelve la decisión revocada (INV-5, GRD-CD-08) y una GRANTED nueva de la misma cadena sí", () => {
  const D = fixtureUuid("decision-699");
  const REV = fixtureUuid("rev-699");
  const decision = syntheticDecision(T, D);
  const ports = makePorts(decision);
  assert.equal(ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef)?.consentId, D);
  seedRh3(ports, REV, D);
  cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, COSIGN);
  assert.equal(ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef), null);
  // Re-consentir = consentId nuevo (no revive la revocada); GRD-CD-08 lo permite.
  const D2 = fixtureUuid("decision-699-new");
  ports.consentDecisionRepo.save({ ...decision, consentId: D2 });
  assert.equal(ports.consentDecisionRepo.findActiveGrantByChain(T, decision.chainRef)?.consentId, D2);
  assert.equal(stateOf(ports, D), "REVOKED");
});

test("TEST-CNS-700: reintentar R4 no reproyecta ni duplica: un solo guardado REVOKED, 1 CONSENT_REVOKED, 1 outbox; APPLIED converge tras fallo", () => {
  const D = fixtureUuid("decision-700");
  const REV = fixtureUuid("rev-700");
  const inner = createInMemoryRevocationRepository();
  let failApply = true;
  const flaky: RevocationRepositoryPort = {
    ...inner,
    save(record) {
      if (record.status === "APPLIED" && failApply) throw new Error("save falló (simulado)");
      inner.save(record);
    },
  };
  const innerDecisions = createInMemoryConsentDecisionRepository();
  let revokedSaves = 0;
  const countingDecisions: ConsentDecisionRepositoryPort = {
    ...innerDecisions,
    save(record) {
      if (record.state === "REVOKED") revokedSaves += 1;
      innerDecisions.save(record);
    },
  };
  const ports = makePorts(syntheticDecision(T, D), { revocationRepo: flaky, decisionRepo: countingDecisions });
  seedRh3(ports, REV, D);
  assert.throws(() => cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, COSIGN), /save falló/);
  assert.equal(stateOf(ports, D), "REVOKED", "C6 ya proyectada aunque APPLIED falló");
  assert.equal(inner.findByRef(T, REV)?.status, "CONFIRMED");

  failApply = false;
  const retried = cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, COSIGN);
  assert.equal(retried.status, "APPLIED");
  assert.equal(revokedSaves, 1, "el reintento no reproyecta la decisión");
  const events = ports.ledger.listByAggregate(T, "Revocation", REV);
  assert.equal(events.filter((e) => e.eventType === "CONSENT_REVOKED").length, 1);
  assert.equal(ports.outbox.enqueued.length, 1);
  assert.throws(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06");
  assert.equal(revokedSaves, 1);
});

test("TEST-CNS-701: sobre una cadena ya REVOKED, R1 (ERR-RV-02) y RV0 no crean revocación ni emiten token; el token de recuperación previo deja de ser elegible (GRD-RV-06)", () => {
  const D = fixtureUuid("decision-701");
  const REV = fixtureUuid("rev-701");
  const decision = { ...syntheticDecision(T, D), chainRef: "chain-701" };
  const ports = makePorts(decision);
  // Token emitido ANTES de la revocación (aún elegible).
  issueRecoveryLinkBearer(ports, T, "chain-701", D, "REQUESTER_ASKED");
  const token = ports.recoveryLinkChannel.sent[0]!.recoveryPath.replace("/r/", "");
  const resolved = resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);
  assert.ok(evaluateRecoveryTokenEligibilityByHash(ports, resolved.tokenHash));

  seedRh3(ports, REV, D);
  cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, COSIGN);
  assert.equal(stateOf(ports, D), "REVOKED");

  assert.equal(evaluateRecoveryTokenEligibilityByHash(ports, resolved.tokenHash), null, "GRD-RV-06: uniforme");
  assert.equal(revokeWithRecoveryLink(ports, T, "chain-701", D, resolved.tokenHash).kind, "UNIFORM");

  const sentBefore = ports.recoveryLinkChannel.sent.length;
  assert.equal(issueRecoveryLinkBearer(ports, T, "chain-701", D, "REQUESTER_ASKED").sent, false);
  assert.equal(ports.recoveryLinkChannel.sent.length, sentBefore);

  const NEW = fixtureUuid("rev-701-new");
  assert.throws(
    () => requestRevocation(ports, T, { revocationRef: NEW, chainRef: "chain-701", revokedDecisionRef: D }),
    (e: unknown) => e instanceof DomainError && e.code === "ERR-RV-02",
  );
  assert.equal(ports.revocationRepo.findByRef(T, NEW), null);
  assert.equal(ports.ledger.listByAggregate(T, "Revocation", NEW).length, 0);
});

test("TEST-CNS-702: C6 solo revoca una decisión GRANTED (GRD-CD-09): PENDING/DECLINED -> ERR-CM-06 sin CONSENT_REVOKED, sin outbox y sin cambiar el estado", () => {
  for (const state of ["PENDING", "DECLINED"] as const) {
    const D = fixtureUuid(`decision-702-${state}`);
    const REV = fixtureUuid(`rev-702-${state}`);
    const ports = makePorts({ ...syntheticDecision(T, D), state });
    seedRh3(ports, REV, D);
    assert.throws(
      () => cosignCaseConfirmation(ports, staff, T, REV, `case-${REV}`, COSIGN),
      (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06",
    );
    assert.equal(stateOf(ports, D), state);
    assert.equal(ports.outbox.enqueued.length, 0);
    assert.equal(ports.ledger.listByAggregate(T, "Revocation", REV).filter((e) => e.eventType === "CONSENT_REVOKED").length, 0);
  }
});
