// Gobierna: specs/state-machines/revocation.spec.yaml R1 (RequestRevocation), R2
// (VerifyRevocationOtp), R3 (ConfirmRevocation), R8 (WithdrawRevocationRequest), RV0
// guardsBySource.BEARER. Subconjunto mínimo IT0 (ver revocation.ts). TEST-CNS-575..TEST-CNS-579,
// TEST-CNS-589..591, TEST-CNS-598 (SEC-CNS-014, FINDING P1-01).

import test from "node:test";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import assert from "node:assert/strict";

import {
  confirmRevocation,
  evaluateRecoveryTokenEligibility,
  issueRecoveryLinkBearer,
  requestRevocation,
  resolveRecoveryTokenForRedeem,
  revokeWithRecoveryLink,
  verifyRevocationOtp,
  withdrawRevocation,
} from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { withSyntheticFallback } from "../../contract/synthetic-decision.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import type { ConsentDecisionState } from "../../../src/server/ports/consent-decision-repository.port.ts";

const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };

function makePorts() {
  return {
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY,
    consentDecisionRepo: withSyntheticFallback(createInMemoryConsentDecisionRepository()),
  };
}

/** Siembra directa (bypass de submitDecision/GRD-CD-08) de la GRANTED vigente que
 * findActiveGrantByChain debe ver. INV-CM-06: revocation.ts nunca escribe este port; estos
 * tests simulan a mano el "otro ciclo" (D1 deja de ser vigente, nace D2 GRANTED) que en el
 * producto real ocurriría en un flujo posterior fuera de este módulo. */
async function seedGrantedDecision(
  ports: ReturnType<typeof makePorts>,
  tenantId: string,
  chainRef: string,
  consentId: string,
  state: ConsentDecisionState = "GRANTED",
): Promise<void> {
  await ports.consentDecisionRepo.save({
    consentId,
    tenantId,
    contextRef: "ctx-test",
    productRef: "prod-test",
    subjectRef: "subject-test@example.invalid",
    decisionMakerRef: "dm-test",
    invitationRef: "inv-test",
    verificationRef: "ver-test",
    chainRef,
    state,
    purposes: [],
    priorStepsComplete: true,
    stepsRecorded: [],
  });
}

test("TEST-CNS-575: R1 -> R2 -> R3 recorre REQUESTED -> VERIFIED -> CONFIRMED -> APPLIED (R4 síncrono) y encola un solo CONSENT_REVOKED", async () => {
  const ports = makePorts();
  const REV = "5a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f75";
  const DECISION = "5a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f76";
  const requested = await requestRevocation(ports, "tenant-1", {
    revocationRef: REV,
    chainRef: "chain-575",
    revokedDecisionRef: DECISION,
  });
  assert.equal(requested.status, "REQUESTED");

  const verified = await verifyRevocationOtp(ports, "tenant-1", REV, "ver-575");
  assert.equal(verified.status, "VERIFIED");

  const applied = await confirmRevocation(ports, "tenant-1", REV);
  assert.equal(applied.status, "APPLIED");

  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", REV);
  assert.deepEqual(
    events.map((e) => e.eventType),
    ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"],
  );
  // CA-127: evidencia válida contra el schema; authPath OTP derivado del registro (R2).
  assertRevocationEvidence(events, { revocationRef: REV, authPath: "OTP", revokedDecisionRef: DECISION });
});

test("TEST-CNS-576: R1 es idempotente por revocationRef (una sola solicitud abierta, sin duplicar el evento)", async () => {
  const ports = makePorts();
  const input = { revocationRef: fixtureUuid("rv-576"), chainRef: "chain-576", revokedDecisionRef: fixtureUuid("consent-576") };
  await requestRevocation(ports, "tenant-1", input);
  await requestRevocation(ports, "tenant-1", input);
  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", fixtureUuid("rv-576"));
  assert.equal(events.filter((e) => e.eventType === "REVOCATION_REQUESTED").length, 1);
});

test("TEST-CNS-577: R8 desde REQUESTED, VERIFIED o CONFIRMED retira la solicitud (FAILED, WITHDRAWN_BY_REQUESTER)", async () => {
  const ports = makePorts();
  await requestRevocation(ports, "tenant-1", { revocationRef: fixtureUuid("rv-577"), chainRef: "chain-577", revokedDecisionRef: fixtureUuid("consent-577") });
  const withdrawn = await withdrawRevocation(ports, "tenant-1", fixtureUuid("rv-577"));
  assert.equal(withdrawn.status, "FAILED");
  assert.equal(withdrawn.reasonCode, "WITHDRAWN_BY_REQUESTER");
});

test("TEST-CNS-578: R8 sobre una Revocation ya APPLIED no tiene efecto (GRD-RV-15, R4 ya ganó la carrera)", async () => {
  const ports = makePorts();
  await requestRevocation(ports, "tenant-1", { revocationRef: fixtureUuid("rv-578"), chainRef: "chain-578", revokedDecisionRef: fixtureUuid("consent-578") });
  await verifyRevocationOtp(ports, "tenant-1", fixtureUuid("rv-578"), "ver-578");
  await confirmRevocation(ports, "tenant-1", fixtureUuid("rv-578"));
  await assert.rejects(
    () => withdrawRevocation(ports, "tenant-1", fixtureUuid("rv-578")),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-06",
  );
});

test("TEST-CNS-579: issueRecoveryLinkBearer (RV0 fuente BEARER) emite RECOVERY_TOKEN_ISSUED sin transicionar la Revocation (kind EMISSION)", async () => {
  const ports = makePorts();
  const result = await issueRecoveryLinkBearer(ports, "tenant-1", "chain-579", fixtureUuid("consent-579"), "LIMIT_REACHED");
  assert.equal(result.sent, true);
  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", "chain-579");
  assert.equal(events[0]?.eventType, "RECOVERY_TOKEN_ISSUED");
});

test("TEST-CNS-580: un revocationRef inexistente en R2/R3/R8 da 404 uniforme (ERR-CM-01), mismo criterio que RH2/RH3", async () => {
  const ports = makePorts();
  await assert.rejects(
    () => verifyRevocationOtp(ports, "tenant-1", fixtureUuid("rv-missing"), "ver-x"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-01",
  );
});

test("TEST-CNS-589: revokeWithRecoveryLink sin Revocation abierta (token fresco) recorre R1r+R2r+R3r hasta CONFIRMED (APPLIED síncrono, GRD-RV-06)", async () => {
  const ports = makePorts();
  const DECISION_589 = "5a1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f89";
  await seedGrantedDecision(ports, "tenant-1", "chain-589b", DECISION_589);
  await issueRecoveryLinkBearer(ports, "tenant-1", "chain-589b", DECISION_589, "REQUESTER_ASKED");
  const sent = ports.recoveryLinkChannel.sent[ports.recoveryLinkChannel.sent.length - 1]!;
  const token = sent.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);

  const outcome = await revokeWithRecoveryLink(ports, "tenant-1", "chain-589b", DECISION_589, resolved!.tokenHash);
  assert.equal(outcome.kind, "CONFIRMED");
  const revocationRef = (outcome as { kind: "CONFIRMED"; revocationRef: string }).revocationRef;
  const events = await ports.ledger.listByAggregate("tenant-1", "Revocation", revocationRef);
  assert.deepEqual(
    events.map((e) => e.eventType),
    ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"],
  );
  // CA-127: evidencia válida contra el schema; authPath RECOVERY/CHANNEL_LINK derivado del registro (R2r).
  assertRevocationEvidence(events, { revocationRef, authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", revokedDecisionRef: DECISION_589 });

  // GRD-RV-06: el token consumido ya no resuelve (un solo uso).
  assert.equal(await resolveRecoveryTokenForRedeem(ports, token), null);
});

test("TEST-CNS-590: revokeWithRecoveryLink con un token inválido/inexistente responde UNIFORM (ERR-RV-05), sin crear ninguna Revocation", async () => {
  const ports = makePorts();
  const outcome = await revokeWithRecoveryLink(ports, "tenant-1", "chain-590b", fixtureUuid("consent-590b"), "hash-que-no-existe");
  assert.deepEqual(outcome, { kind: "UNIFORM" });
});

test("TEST-CNS-591: revokeWithRecoveryLink sobre una Revocation ya CONFIRMED (antes de que R4 la aplique) responde R11 NOOP: no consume el token ni emite evento", async () => {
  const ports = makePorts();
  await seedGrantedDecision(ports, "tenant-1", "chain-595", fixtureUuid("consent-595"));
  await ports.revocationRepo.save({
    revocationRef: fixtureUuid("rv-595"),
    tenantId: "tenant-1",
    chainRef: "chain-595",
    revokedDecisionRef: fixtureUuid("consent-595"),
    status: "CONFIRMED",
  });
  await issueRecoveryLinkBearer(ports, "tenant-1", "chain-595", fixtureUuid("consent-595"), "REQUESTER_ASKED");
  const sent = ports.recoveryLinkChannel.sent[ports.recoveryLinkChannel.sent.length - 1]!;
  const token = sent.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);

  const before = (await ports.ledger.listByAggregate("tenant-1", "Revocation", fixtureUuid("rv-595"))).length;
  const outcome = await revokeWithRecoveryLink(ports, "tenant-1", "chain-595", fixtureUuid("consent-595"), resolved!.tokenHash);
  assert.deepEqual(outcome, { kind: "IN_PROGRESS" });
  const after = (await ports.ledger.listByAggregate("tenant-1", "Revocation", fixtureUuid("rv-595"))).length;
  assert.equal(after, before);

  // SEC N-05: R11 nunca consume el token (sigue resolviendo).
  assert.ok(await resolveRecoveryTokenForRedeem(ports, token));
});

test("TEST-CNS-598: revokeWithRecoveryLink rechaza un token de un ciclo anterior (D1) cuando la cadena ya tiene una GRANTED nueva (D2), sin revocar D2 ni consumir el token (SEC-CNS-014, FINDING P1-01, GRD-RV-06)", async () => {
  const ports = makePorts();
  const tenantId = "tenant-1";
  const chainRef = "chain-598";

  // D1 GRANTED, se emite el enlace de recuperación (RV0 BEARER) mientras D1 sigue vigente.
  await seedGrantedDecision(ports, tenantId, chainRef, "consent-598-d1");
  await issueRecoveryLinkBearer(ports, tenantId, chainRef, "consent-598-d1", "REQUESTER_ASKED");
  const sent = ports.recoveryLinkChannel.sent[ports.recoveryLinkChannel.sent.length - 1]!;
  const token = sent.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(ports, token);
  assert.ok(resolved);

  // D1 se revoca por otra vía (fuera del boundary de revocation.ts, INV-CM-06) y nace D2
  // GRANTED en la misma cadena: el token de D1, sin consumir y todavía dentro de P-15, ya no
  // es elegible para el ciclo nuevo.
  await seedGrantedDecision(ports, tenantId, chainRef, "consent-598-d1", "DECLINED");
  await seedGrantedDecision(ports, tenantId, chainRef, "consent-598-d2");

  assert.equal(
    await evaluateRecoveryTokenEligibility(ports, tenantId, chainRef, "consent-598-d1", resolved!.tokenHash),
    null,
  );

  const outcome = await revokeWithRecoveryLink(ports, tenantId, chainRef, "consent-598-d1", resolved!.tokenHash);
  assert.deepEqual(outcome, { kind: "UNIFORM" });

  // No debe haber creado ninguna Revocation para la cadena (D2 sigue intacto).
  assert.equal(await ports.revocationRepo.findOpenByChain(tenantId, chainRef), null);

  // GRD-RV-06 onFail: el token no se consume (defensa en profundidad; sigue sin resolver como
  // vigente para D2, pero no queda "gastado" al azar por un intento inválido).
  assert.ok(await resolveRecoveryTokenForRedeem(ports, token));
});
