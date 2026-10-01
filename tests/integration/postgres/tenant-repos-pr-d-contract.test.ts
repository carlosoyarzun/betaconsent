// Gobierna: CA-124 (PR-D), tests/contract/ports/tenant-repos-pr-d.contract.ts (TEST-CNS-830..837),
// db/migrations/0010..0011. Misma suite que los adaptadores in-memory, contra los adaptadores
// Postgres dentro de PgUnitOfWork (app_rw, sin superusuario). Skip fuera de CI sin entorno.

import { runTenantReposPrDContract } from "../../contract/ports/tenant-repos-pr-d.contract.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantHandleAdapter, registerTenantHandle, rotateTenantHandle } from "../../../src/infra/adapters/postgres/tenant-handle.adapter.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { pgTest } from "./harness.ts";

runTenantReposPrDContract("postgres", (name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
    try {
      const uow = new PgUnitOfWork(pool);
      await body({
        uow,
        resolver: createPgTenantResolver(pool),
        handlePort: createPgTenantHandleAdapter(pool),
        issueHandle: (tenantId, seed) => uow.withTenantTx(tenantId, (tx) => registerTenantHandle(tx, seed)),
        rotateHandle: (tenantId, handle) => uow.withTenantTx(tenantId, (tx) => rotateTenantHandle(tx, handle)),
      });
    } finally {
      await pool.end();
    }
  });
});
