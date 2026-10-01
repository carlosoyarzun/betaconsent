// Gobierna: CA-124 (PR-B), tests/contract/ports/ledger-outbox-tx.contract.ts (TEST-CNS-780..786),
// db/migrations/0002_ledger.sql, 0003_outbox.sql. Misma suite que el adaptador in-memory, contra
// los adaptadores Postgres dentro de PgUnitOfWork. Skip fuera de CI sin entorno (harness.ts).

import { runLedgerOutboxContract } from "../../contract/ports/ledger-outbox-tx.contract.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgLedgerAdapter } from "../../../src/infra/adapters/postgres/ledger.adapter.ts";
import { createPgOutboxAdapter } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { pgTest } from "./harness.ts";

runLedgerOutboxContract("postgres", (name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
    try {
      const uow = new PgUnitOfWork(pool);
      await body({
        inTenant: (tenantId, work) =>
          uow.inTenant(tenantId, (tx) => work({ ledger: createPgLedgerAdapter(tx), outbox: createPgOutboxAdapter(tx) })),
      });
    } finally {
      await pool.end();
    }
  });
});
