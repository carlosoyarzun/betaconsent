// Gobierna: src/server/ports/unit-of-work.port.ts (CA-124). TEST-CNS-770..772.

import { runUnitOfWorkPortContract } from "./unit-of-work-port.contract.ts";
import { createInMemoryConsentDecisionRepository } from "../../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";

runUnitOfWorkPortContract("in-memory", async () => {
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  const outbox = createInMemoryOutboxAdapter();
  const { uow } = createInMemoryTenancy({
    revocationRepo,
    ledger,
    outbox,
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
  });
  return { uow, revocationRepo, ledger, outbox };
});

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-102 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
