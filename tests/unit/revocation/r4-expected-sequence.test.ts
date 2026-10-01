// Gobierna: CA-124 (PR-C), SEC-CNS-013 P2-3 (expectedSequence obligatorio en LedgerPort), revocation.spec
// R4 (una tx con lock y expectedSequence), postgres-design.md rev. 2 §3 "P2 del ledger".
// TEST-CNS-819: R4 pasa expectedSequence explicito (CONSENT_REVOKED = ultima sequence del agregado,
// RECEIPT_CREATED = la de CONSENT_REVOKED). TEST-CNS-821: si el agregado avanzo por otro camino entre la lectura
// y el append, falla con LedgerSequenceConflictError y la unidad de trabajo no deja nada.
// TEST-CNS-820: appendNext (flujos sin decision de secuencia) lee la secuencia del agregado y la
// declara; el ledger rechaza un append cuya expectedSequence no sea la vigente. SYNTHETIC DATA ONLY.

import { revocationRequestedPayload, revocationVerifiedPayload } from "../../contract/ledger-payload-fixtures.ts";
import test from "node:test";
import assert from "node:assert/strict";

import { appendNext } from "../../../src/server/modules/common/ledger-append.ts";
import {
  confirmRevocation,
  evaluateRecoveryTokenEligibility,
  evaluateRecoveryTokenEligibilityByHash,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  requestRevocation,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { LedgerSequenceConflictError, type LedgerEventInput, type LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = fixtureUuid("tenant-819");

async function makePorts(decisionId: string, wrap: (inner: LedgerPort) => LedgerPort = (l) => l) {
  const inner = createInMemoryLedgerAdapter();
  const consentDecisionRepo = createInMemoryConsentDecisionRepository();
  await consentDecisionRepo.save({ ...syntheticDecision(T, decisionId), chainRef: fixtureUuid("chain-819") });
  const ledger = wrap(inner);
  // El wrapper conserva la participacion en el journal del UoW (spread de `inner`).
  const ports: RevocationPorts = withInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: ledger as typeof inner,
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  });
  return { ports, inner };
}

test("TEST-CNS-819: R4 pasa expectedSequence explicito: CONSENT_REVOKED con la ultima sequence del agregado y RECEIPT_CREATED con la de CONSENT_REVOKED", async () => {
  const D = fixtureUuid("decision-819");
  const REV = fixtureUuid("rev-819");
  const seen: LedgerEventInput[] = [];
  const { ports } = await makePorts(D, (inner) => ({
    ...inner,
    async append(event) {
      seen.push(event);
      return inner.append(event);
    },
  }));
  await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-819"), revokedDecisionRef: D });
  await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-819"));
  await confirmRevocation(ports, T, REV);
  const r4 = seen.filter((e) => e.eventType === "CONSENT_REVOKED" || e.eventType === "RECEIPT_CREATED");
  assert.deepEqual(r4.map((e) => [e.eventType, e.expectedSequence]), [["CONSENT_REVOKED", 3], ["RECEIPT_CREATED", 4]]);
  // Todo append del flujo declara su secuencia esperada (obligatoria en el puerto).
  assert.ok(seen.every((e) => typeof e.expectedSequence === "number"));
  assert.deepEqual(seen.map((e) => e.expectedSequence), [0, 1, 2, 3, 4]);
});

test("TEST-CNS-821: si el agregado avanza entre la lectura y el append de R4, falla con LedgerSequenceConflictError y no queda nada (ni CONFIRMED)", async () => {
  const D = fixtureUuid("decision-819b");
  const REV = fixtureUuid("rev-819b");
  let interfere = false;
  const { ports, inner } = await makePorts(D, (real) => ({
    ...real,
    async append(event) {
      if (interfere && event.eventType === "CONSENT_REVOKED") {
        // Otra unidad (simulada) avanza el agregado despues de que R4 leyo su secuencia.
        interfere = false;
        await real.append({ ...event, eventType: "REVOCATION_VERIFIED", payload: revocationVerifiedPayload("otra"), idempotencyKey: "otra-unidad", expectedSequence: event.expectedSequence });
      }
      return real.append(event);
    },
  }));
  await requestRevocation(ports, T, { revocationRef: REV, chainRef: fixtureUuid("chain-819"), revokedDecisionRef: D });
  await verifyRevocationOtp(ports, T, REV, fixtureUuid("ver-819b"));
  interfere = true;
  await assert.rejects(() => confirmRevocation(ports, T, REV), (e: unknown) => e instanceof LedgerSequenceConflictError);
  const types = (await inner.listByAggregate(T, "Revocation", REV)).map((e) => e.eventType);
  assert.equal(types.includes("REVOCATION_CONFIRMED"), false, "REVOCATION_CONFIRMED revertido");
  assert.equal(types.includes("CONSENT_REVOKED"), false);
  assert.equal(await ports.revocationRepo.findByRef(T, REV).then((r) => r?.status), "VERIFIED");
});

test("TEST-CNS-820: appendNext declara la secuencia vigente del agregado; el ledger rechaza una expectedSequence distinta (incluida una en el futuro: sin huecos)", async () => {
  const ledger = createInMemoryLedgerAdapter();
  const base = { eventType: "REVOCATION_REQUESTED", tenantId: T, aggregateType: "Revocation", aggregateId: fixtureUuid("agg-820"), actorType: "HUMAN" as const, payload: revocationRequestedPayload("base") };
  assert.equal((await appendNext(ledger, base)).sequence, 1);
  assert.equal((await appendNext(ledger, base)).sequence, 2);
  await assert.rejects(() => ledger.append({ ...base, expectedSequence: 5 }), (e: unknown) => e instanceof LedgerSequenceConflictError && e.actualSequence === 2);
  await assert.rejects(() => ledger.append({ ...base, expectedSequence: 1 }), (e: unknown) => e instanceof LedgerSequenceConflictError);
  assert.equal((await ledger.append({ ...base, expectedSequence: 2 })).sequence, 3);
  assert.deepEqual((await ledger.listByAggregate(T, "Revocation", base.aggregateId)).map((r) => r.sequence), [1, 2, 3]);
});

test("TEST-CNS-826: SEC-CNS-015 P2-A: un token cuyo hash no coincide con el hash pedido no es elegible aunque el resolver lo apunte (defensa en profundidad)", async () => {
  const D = fixtureUuid("decision-826");
  const { ports } = await makePorts(D);
  const sink = ports.recoveryLinkChannel as ReturnType<typeof createInMemoryRecoveryLinkChannelSink>;
  await issueRecoveryLinkBearer(ports, T, fixtureUuid("chain-819"), D, "REQUESTER_ASKED");
  const hash = hashRecoveryToken(sink.sent[0]!.recoveryPath.replace("/r/", ""));
  assert.ok(await evaluateRecoveryTokenEligibilityByHash(ports, hash), "control: el hash correcto es elegible");
  // Resolver erroneo: cualquier hash "resuelve" a la ref del token real.
  const real = await ports.tenantResolver.byRecoveryTokenHash(hash);
  assert.ok(real);
  const lying = { ...ports, tenantResolver: { ...ports.tenantResolver, byRecoveryTokenHash: async () => real } };
  const otherHash = hashRecoveryToken("otro-token");
  assert.equal(await evaluateRecoveryTokenEligibility(lying, T, fixtureUuid("chain-819"), D, otherHash), null);
  assert.equal(await evaluateRecoveryTokenEligibilityByHash(lying, otherHash), null);
});
