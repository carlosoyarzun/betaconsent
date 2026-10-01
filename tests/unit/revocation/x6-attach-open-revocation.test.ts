// Gobierna: revocation.spec.yaml GRD-RV-04 (single_open_revocation_per_chain, onFail null: "una
// crea, las demás se adjuntan"), INV-RV-01; DEC-BR-014 rev. 8 §3 X6 (CA-128); decisión de Carlos
// 2026-10-01 (opción a): una segunda R1 sobre una decisión con revocación abierta se ADJUNTA.
// TEST-CNS-960.

import test from "node:test";
import assert from "node:assert/strict";

import {
  confirmRevocation,
  requestRevocation,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../../src/server/modules/revocation/revocation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";

const T = "tenant-960";

async function makePorts(decisionId: string, chain: string): Promise<RevocationPorts> {
  const consentDecisionRepo = createInMemoryConsentDecisionRepository();
  await consentDecisionRepo.save({ ...syntheticDecision(T, decisionId), chainRef: chain });
  return withInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo,
  });
}

test("TEST-CNS-960: GRD-RV-04 R1 con otra revocationRef sobre la misma decisión se adjunta a la abierta (misma ref y estado, sin eventos duplicados), en cualquier estado no terminal", async () => {
  const D = fixtureUuid("d960");
  const A = fixtureUuid("r960-a");
  const B = fixtureUuid("r960-b");
  const C = fixtureUuid("r960-c");
  const ports = await makePorts(D, fixtureUuid("chain-960"));

  const first = await requestRevocation(ports, T, { revocationRef: A, chainRef: fixtureUuid("chain-960"), revokedDecisionRef: D });
  const attachedRequested = await requestRevocation(ports, T, { revocationRef: B, chainRef: fixtureUuid("chain-960"), revokedDecisionRef: D });
  assert.equal(attachedRequested.revocationRef, A);
  assert.equal(attachedRequested.status, "REQUESTED");
  assert.equal(await ports.revocationRepo.findByRef(T, B), null, "no se crea fila para la adjunta");
  assert.equal((await ports.ledger.listByAggregate(T, "Revocation", B)).length, 0, "sin eventos para la adjunta");

  await verifyRevocationOtp(ports, T, A, fixtureUuid("v960"));
  const attachedVerified = await requestRevocation(ports, T, { revocationRef: C, chainRef: fixtureUuid("chain-960"), revokedDecisionRef: D });
  assert.equal(attachedVerified.revocationRef, A);
  assert.equal(attachedVerified.status, "VERIFIED");

  const events = (await ports.ledger.listByAggregate(T, "Revocation", A)).map((e) => e.eventType);
  assert.equal(events.filter((e) => e === "REVOCATION_REQUESTED").length, 1);
  assert.equal(first.revocationRef, A);
});

test("TEST-CNS-961: GRD-RV-02 precede a GRD-RV-04: tras APPLIED (decisión REVOKED) una R1 nueva da ERR-RV-02, no se adjunta; otra decisión no se adjunta a la abierta", async () => {
  const D = fixtureUuid("d961");
  const ports = await makePorts(D, fixtureUuid("chain-961"));
  const A = fixtureUuid("r961-a");
  await requestRevocation(ports, T, { revocationRef: A, chainRef: fixtureUuid("chain-961"), revokedDecisionRef: D });
  await verifyRevocationOtp(ports, T, A, fixtureUuid("v961"));
  await confirmRevocation(ports, T, A);
  await assert.rejects(
    () => requestRevocation(ports, T, { revocationRef: fixtureUuid("r961-b"), chainRef: fixtureUuid("chain-961"), revokedDecisionRef: D }),
    (e: unknown) => e instanceof DomainError && e.code === "ERR-RV-02",
  );

  // Otra decisión GRANTED (ciclo nuevo) de otra cadena: crea, no se adjunta a la abierta de D.
  const D2 = fixtureUuid("d961-2");
  await ports.consentDecisionRepo.save({ ...syntheticDecision(T, D2), chainRef: fixtureUuid("chain-961-2") });
  const created = await requestRevocation(ports, T, { revocationRef: fixtureUuid("r961-c"), chainRef: fixtureUuid("chain-961-2"), revokedDecisionRef: D2 });
  assert.equal(created.revocationRef, fixtureUuid("r961-c"));
});
