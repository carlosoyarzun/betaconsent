// Gobierna: CA-124 (PR-E), tests/contract/ports/idempotency-tx.contract.ts (TEST-CNS-862..864),
// db/migrations/0012_idempotency.sql. Misma suite que el adaptador in-memory, contra el adaptador
// Postgres dentro de PgUnitOfWork (app_rw, sin superusuario). El pool es de UNA conexion: A -> B reusa
// la misma conexion fisica (X5, TEST-CNS-102). Skip fuera de CI sin entorno.

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { runIdempotencyTxContract } from "../../contract/ports/idempotency-tx.contract.ts";
import { pgTest } from "./harness.ts";

runIdempotencyTxContract((name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
    try {
      // TTL de prueba: P-33 no tiene valor aprobado (sin default de produccion).
      await body({ uow: new PgUnitOfWork(pool, { idempotencyPolicy: { ttlMs: 60_000 } }) });
    } finally {
      await pool.end();
    }
  });
});
