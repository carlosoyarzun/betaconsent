// Gobierna: ADR-010 rev. 4 §4.2 / §7 fila PR-6 (6a), GRD-CM-15: R5-R7 (mark_downstream_emitted, record_downstream_ack, record_erasure_attestation) solo las ejecuta el rol `worker`
// (db/migrations/0042). Helper de TESTS: lleva una Revocation APPLIED hasta COMPLETED con un pool del rol worker (el stub es el MISMO que firma la evidencia en el test).

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { createWorkerRevocationPorts } from "../../../src/server/entrypoints/worker/worker-process.ts";
import { completeDownstream } from "../../contract/x6-revocation-scenarios.ts";
import type { X6Env } from "../../contract/x6-revocation-scenarios.ts";
import type { PgTestContext } from "./harness.ts";

export async function completeDownstreamAsWorker(ctx: PgTestContext, env: X6Env, T: string, revocationRef: string, label: string): Promise<void> {
  const pool = createPool({ connectionString: ctx.urlFor("worker"), max: 2 });
  try {
    const ports = createWorkerRevocationPorts(new PgUnitOfWork(pool), env.stub);
    await completeDownstream({ ports, stub: env.stub, sink: env.sink }, T, revocationRef, label);
  } finally {
    await pool.end();
  }
}
