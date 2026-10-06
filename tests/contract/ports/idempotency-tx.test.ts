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

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-102, TEST-CNS-863, TEST-CNS-864 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
