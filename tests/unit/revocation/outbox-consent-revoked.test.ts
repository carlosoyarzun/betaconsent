// Gobierna: specs/state-machines/revocation.spec.yaml R4 (emits [CONSENT_REVOKED, RECEIPT_CREATED,
// consent.revoked], GRD-RV-11, idempotencia por revocationRef), contracts/schemas/
// outbox-events.schema.json (API-CNS-185, DRAFT), common.spec.yaml (INV-CM-01, payloadPolicy sin
// PII). CA-127 (diseño aprobado por Carlos 2026-09-28). TEST-CNS-688..693.
// Datos SINTÉTICOS. Fuera de alcance: proyección C6/REVOKED (F2), consent.granted, R5/R6/R7, C8.

import test from "node:test";
import assert from "node:assert/strict";

import {
  applyRevocation,
  attestHumanAssistedVerification,
  confirmRevocation,
  cosignCaseConfirmation,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  requestRevocation,
  resolveRecoveryTokenForRedeem,
  revokeWithRecoveryLink,
  verifyRevocationOtp,
  withdrawRevocation,
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
import { assertConsentRevokedOutbox, OUTBOX_FORBIDDEN_KEYS } from "../../contract/outbox-evidence.ts";
import { validateOutboxEvent } from "../../contract/schema-lite.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

const T = fixtureUuid("tenant-688");
const staff = createInMemoryStaffIdentityAdapter([
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
]);

type Ports = RevocationPorts & { readonly outbox: InMemoryOutbox; readonly recoveryLinkChannel: InMemoryRecoveryLinkChannelSink };

async function makePorts(opts: { revocationRepo?: RevocationRepositoryPort; seedDecisionId?: string } = {}): Promise<Ports> {
  const consentDecisionRepo = createInMemoryConsentDecisionRepository();
  if (opts.seedDecisionId) await consentDecisionRepo.save(syntheticDecision(T, opts.seedDecisionId));
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

function ledgerOf(ports: Ports, ref: string) {
  return ports.ledger.listByAggregate(T, "Revocation", ref);
}

async function seedRh3(ports: Ports, ref: string, decisionId: string) {
  await ports.revocationRepo.save({ revocationRef: ref, tenantId: T, chainRef: `chain-${ref}`, caseRef: fixtureUuid(`case-${ref}`), revokedDecisionRef: decisionId, status: "REQUESTED" });
  await attestHumanAssistedVerification(ports, T, ref, fixtureUuid(`case-${ref}`));
  await recordCaseConfirmationPendingCosign(ports, staff, T, ref, fixtureUuid(`case-${ref}`), { recordedByPrincipalRef: fixtureUuid("staff-synthetic-01") });
}

const COSIGN = { cosignedByPrincipalRef: fixtureUuid("staff-synthetic-02") };

test("TEST-CNS-688: R4 por OTP (autoservicio) encola exactamente un consent.revoked válido; effectiveAt = CONSENT_REVOKED.effectiveAt = occurredAt", async () => {
  const D = fixtureUuid("decision-688");
  const REV = fixtureUuid("rev-688");
  const ports = await makePorts({ seedDecisionId: D });
  await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-688"), revokedDecisionRef: D });
  await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-688"));
  await confirmRevocation(ports, T, REV);
  assert.equal(ports.outbox.enqueued.length, 1);
  assertConsentRevokedOutbox(ports.outbox.enqueued, await ledgerOf(ports, REV), { tenantId: T, revocationRef: REV, decision: syntheticDecision(T, D) });
  assert.equal((await ports.revocationRepo.findByRef(T, REV))?.status, "APPLIED");
});

test("TEST-CNS-689: R4 por RECOVERY/CHANNEL_LINK y por RH3 cosign encolan exactamente un consent.revoked cada una", async () => {
  // Enlace de recuperación.
  const D1 = fixtureUuid("decision-689a");
  const p1 = await makePorts();
  const d1 = { ...syntheticDecision(T, D1), chainRef: fixtureUuid("chain-689") }; // GRD-RV-06: la GRANTED vigente de la cadena
  await p1.consentDecisionRepo.save(d1);
  await issueRecoveryLinkBearer(p1, T, fixtureUuid("chain-689"), D1, "REQUESTER_ASKED");
  const token = p1.recoveryLinkChannel.sent[p1.recoveryLinkChannel.sent.length - 1]!.recoveryPath.replace("/r/", "");
  const resolved = await resolveRecoveryTokenForRedeem(p1, token);
  assert.ok(resolved);
  const outcome = await revokeWithRecoveryLink(p1, T, fixtureUuid("chain-689"), D1, resolved.tokenHash);
  assert.equal(outcome.kind, "CONFIRMED");
  const ref1 = (outcome as { revocationRef: string }).revocationRef;
  assert.equal(p1.outbox.enqueued.length, 1);
  assertConsentRevokedOutbox(p1.outbox.enqueued, await ledgerOf(p1, ref1), { tenantId: T, revocationRef: ref1, decision: d1 });

  // RH3 (caso humano).
  const D2 = fixtureUuid("decision-689b");
  const REV2 = fixtureUuid("rev-689b");
  const p2 = await makePorts({ seedDecisionId: D2 });
  await seedRh3(p2, REV2, D2);
  await cosignCaseConfirmation(p2, staff, T, REV2, fixtureUuid(`case-${REV2}`), COSIGN);
  assert.equal(p2.outbox.enqueued.length, 1);
  assertConsentRevokedOutbox(p2.outbox.enqueued, await ledgerOf(p2, REV2), { tenantId: T, revocationRef: REV2, decision: syntheticDecision(T, D2) });
});

test("TEST-CNS-690: fallo inyectado en revocationRepo.save y reintento: 1 CONSENT_REVOKED, 1 RECEIPT_CREATED, 1 outbox (mismo eventId), termina APPLIED", async () => {
  const D = fixtureUuid("decision-690");
  const REV = fixtureUuid("rev-690");
  const inner = createInMemoryRevocationRepository();
  let failApply = true;
  const flaky: RevocationRepositoryPort = {
    ...inner,
    findByRef: (t, r) => inner.findByRef(t, r),
    async save(record) {
      if (record.status === "APPLIED" && failApply) throw new Error("save falló (simulado)");
      await inner.save(record);
    },
  };
  const ports = await makePorts({ revocationRepo: flaky, seedDecisionId: D });
  await seedRh3(ports, REV, D);
  await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN), /save falló/);
  // CA-124 (P2 de lampone-security): cosign + R4 son UNA unidad de trabajo; el fallo de
  // `revocationRepo.save` deja todo como antes del cosign (antes: CONFIRMED huérfana + outbox).
  assert.equal((await inner.findByRef(T, REV))?.status, "VERIFIED");
  assert.equal((await ledgerOf(ports, REV)).filter((e) => e.eventType === "REVOCATION_CONFIRMED" || e.eventType === "CONSENT_REVOKED" || e.eventType === "RECEIPT_CREATED").length, 0);
  assert.equal(ports.outbox.enqueued.length, 0);

  failApply = false;
  const retried = await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN);
  assert.equal(retried.status, "APPLIED");
  const events = await ledgerOf(ports, REV);
  assert.equal(events.filter((e) => e.eventType === "CONSENT_REVOKED").length, 1);
  assert.equal(events.filter((e) => e.eventType === "RECEIPT_CREATED").length, 1);
  assert.equal(events.filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 1);
  assert.equal(ports.outbox.enqueued.length, 1);
  assertConsentRevokedOutbox(ports.outbox.enqueued, events, { tenantId: T, revocationRef: REV, decision: syntheticDecision(T, D) });

  // Reaplicar una vez APPLIED tampoco duplica (R4 exige CONFIRMED).
  await assert.rejects(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06");
  assert.equal(ports.outbox.enqueued.length, 1);
});

test("TEST-CNS-691: decisión revocada inexistente -> ERR-CM-06 sin CONSENT_REVOKED, sin RECEIPT_CREATED, sin outbox y estado VERIFIED (todo-o-nada, CA-124)", async () => {
  const D = fixtureUuid("decision-691");
  const REV = fixtureUuid("rev-691");
  const ports = await makePorts(); // sin decisión sembrada
  await seedRh3(ports, REV, D);
  await assert.rejects(() => cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06");
  assert.equal((await ledgerOf(ports, REV)).filter((e) => e.eventType === "CONSENT_REVOKED" || e.eventType === "RECEIPT_CREATED").length, 0);
  assert.equal(ports.outbox.enqueued.length, 0);
  assert.equal((await ledgerOf(ports, REV)).filter((e) => e.eventType === "REVOCATION_CONFIRMED").length, 0, "el cosign se revirtió completo");
  assert.equal((await ports.revocationRepo.findByRef(T, REV))?.status, "VERIFIED");
});

test("TEST-CNS-692: whitelist del sobre y del payload: 3 claves en el payload, ninguna clave prohibida, LOCAL/SYNTHETIC, eventId distinto de revocationRef", async () => {
  const D = fixtureUuid("decision-692");
  const REV = fixtureUuid("rev-692");
  const ports = await makePorts({ seedDecisionId: D });
  await seedRh3(ports, REV, D);
  await cosignCaseConfirmation(ports, staff, T, REV, fixtureUuid(`case-${REV}`), COSIGN);
  const env = ports.outbox.enqueued[0]!.envelope;
  assert.deepEqual(Object.keys(env.payload).sort(), ["effectiveAt", "revocationRef", "scope"]);
  assert.deepEqual(
    Object.keys(env).sort(),
    ["contextRef", "dataClass", "environment", "eventId", "eventType", "occurredAt", "payload", "schemaVersion", "subjectRef", "tenantRef"],
  );
  for (const key of OUTBOX_FORBIDDEN_KEYS) {
    assert.ok(!(key in env), `sobre sin ${key}`);
    assert.ok(!(key in env.payload), `payload sin ${key}`);
  }
  assert.equal(env.environment, "LOCAL");
  assert.equal(env.dataClass, "SYNTHETIC");
  assert.equal(env.schemaVersion, "1.0.0");
  assert.notEqual(env.eventId, REV);
  // Ningún valor del sobre filtra el decisionMakerRef ni la chainRef de la decisión.
  const decision = syntheticDecision(T, D);
  const serialized = JSON.stringify(env);
  assert.ok(!serialized.includes(decision.decisionMakerRef));
  assert.ok(!serialized.includes(decision.chainRef));
  assert.ok(!serialized.includes(D));
  // El validador rechaza un payload con una clave extra (additionalProperties: false vía allOf).
  assert.equal(validateOutboxEvent({ ...env, payload: { ...env.payload, authPath: "OTP" } }).ok, false);
  assert.equal(validateOutboxEvent({ ...env, payload: { revocationRef: REV } }).ok, false);
});

test("TEST-CNS-693: sin outbox en R8 (FAILED) ni en R4 sobre un estado distinto de CONFIRMED", async () => {
  const D = fixtureUuid("decision-693");
  const REV = fixtureUuid("rev-693");
  const ports = await makePorts({ seedDecisionId: D });
  await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-693"), revokedDecisionRef: D });
  await assert.rejects(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06"); // REQUESTED
  await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-693"));
  await assert.rejects(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06"); // VERIFIED
  const failed = await withdrawRevocation(ports, T, REV);
  assert.equal(failed.status, "FAILED");
  await assert.rejects(() => applyRevocation(ports, T, REV), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-06"); // FAILED
  assert.equal(ports.outbox.enqueued.length, 0);
});
