// Gobierna: CA-124 (PR-B). Registra la suite de contrato Ledger/Outbox contra el adaptador in-memory.
// TEST-CNS-780..786. El registro contra Postgres vive en tests/integration/postgres/ledger-outbox-contract.test.ts.

import test from "node:test";

import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { runLedgerChainContract } from "./ledger-chain.contract.ts";
import { runLedgerOutboxContract } from "./ledger-outbox-tx.contract.ts";
import type { LedgerOutboxHarness } from "./ledger-outbox-tx.contract.ts";

function makeInMemoryHarness(): LedgerOutboxHarness {
  const { uow } = createInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
  });
  return { inTenant: (tenantId, work) => uow.inTenant(tenantId, (tx) => work({ ledger: tx.ledger, outbox: tx.outbox })) };
}

runLedgerOutboxContract("in-memory", (name, body) => {
  test(name, () => body(makeInMemoryHarness()));
});

runLedgerChainContract("in-memory", (name, body) => {
  test(name, () => body(makeInMemoryHarness()));
});
