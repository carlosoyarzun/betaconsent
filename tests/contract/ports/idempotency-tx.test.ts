// Gobierna: CA-124 (PR-E). Registra la suite de contrato de IdempotencyPort dentro de la unidad de
// trabajo contra el adaptador in-memory. TEST-CNS-862..864. El registro contra Postgres vive en
// tests/integration/postgres/idempotency-contract.test.ts.

import test from "node:test";

import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { runIdempotencyTxContract } from "./idempotency-tx.contract.ts";

runIdempotencyTxContract((name, body) => {
  test(name, () => body({ uow: createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter() }).uow }));
});
