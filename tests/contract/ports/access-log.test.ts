// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6, rights-case.spec INV-RC-04. Registra la suite de
// contrato de AccessLogPort contra el adaptador in-memory (TEST-CNS-918). El registro contra
// Postgres vive en tests/integration/postgres/access-log.test.ts.

import test from "node:test";

import { createInMemoryAccessLogAdapter } from "../../../src/infra/adapters/in-memory-access-log.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { runAccessLogContract } from "./access-log.contract.ts";

runAccessLogContract("in-memory", (name, body) => {
  test(name, () => {
    const { uow } = createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter(), accessLog: createInMemoryAccessLogAdapter() });
    return body({ inTenant: (tenantId, work) => uow.inTenant(tenantId, (tx) => work({ accessLog: tx.accessLog })) });
  });
});
