// Gobierna: F-A10-29 (alineacion dominio<->spec, confirmada por Carlos 2026-10-13; no decide LD-03), revocation.spec R1/R3/R8, GRD-RV-02.
// TEST-CNS-1379: variante in-memory de los escenarios compartidos (tests/contract/f-a10-29-scenarios.ts). SYNTHETIC DATA ONLY.

import test from "node:test";

import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { withInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { runFA1029Scenarios } from "../../contract/f-a10-29-scenarios.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

test("TEST-CNS-1379 (in-memory): R8 solo desde REQUESTED/VERIFIED/CONFIRMED, R3 no confirma HUMAN_ASSISTED y R1 exige decision GRANTED de la misma cadena (F-A10-29)", async () => {
  const ports: RevocationPorts = withInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
  });
  const T = fixtureUuid("t1379");
  await runFA1029Scenarios({ ports, seedDecision: (d) => ports.uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(d)) }, T, "mem");
});
