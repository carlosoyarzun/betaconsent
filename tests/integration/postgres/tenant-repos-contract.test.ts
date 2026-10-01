// Gobierna: CA-124 (PR-C), tests/contract/ports/tenant-repos-tx.contract.ts (TEST-CNS-800..806),
// db/migrations/0005..0007. Misma suite que los adaptadores in-memory, contra los adaptadores
// Postgres dentro de PgUnitOfWork (app_rw, sin superusuario). Skip fuera de CI sin entorno.

import { runTenantReposContract } from "../../contract/ports/tenant-repos-tx.contract.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantCatalogAdapter } from "../../../src/infra/adapters/postgres/tenant-catalog.adapter.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { pgTest } from "./harness.ts";

runTenantReposContract("postgres", (name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
    const admin = await ctx.connectAsSuperuser();
    try {
      const uow = new PgUnitOfWork(pool);
      await body({
        uow,
        resolver: createPgTenantResolver(pool),
        async seedSubject(tenantId, subjectRef) {
          await admin.query("INSERT INTO app.subject (tenant_id, subject_ref) VALUES ($1, $2)", [tenantId, subjectRef]);
        },
        async seedParticipation(tenantId, p) {
          await admin.query(
            "INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, $2, $3, $4, $5)",
            [tenantId, p.participationRef, p.contextRef, p.productRef, p.status],
          );
        },
        withCatalog: (tenantId, work) => uow.withTenantTx(tenantId, (tx) => work(createPgTenantCatalogAdapter(tx))),
      });
    } finally {
      await pool.end();
    }
  });
});
