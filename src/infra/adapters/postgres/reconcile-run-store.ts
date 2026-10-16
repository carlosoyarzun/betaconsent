// Gobierna: ADR-010 rev. 5 §4.2.c y §7 ("persistencia de la conciliacion"), rev. 6 §3 (fila PR-7), plan PR-7 v3 (PR-7b, T-4); db/migrations/0077 (integrity.reconcile_run); specs/db-roles.spec.yaml (integrity_reconciler).
//
// ESCRITURA del proceso `reconciler`: una tx corta `BEGIN READ WRITE` aparte del snapshot de lectura. SOLO INSERT por columnas en integrity.reconcile_run (sin RETURNING: el rol no lee la tabla; el run_id lo genera
// el proceso). Persiste CONTEOS por codigo de divergencia: sin ids de agregado, sin tenant, sin detail, sin PII. El trigger de la base valida claves ([A-Z_]{1,40}) y suma; este codigo no es la barrera.
// ADAPTADOR (ADR-001 §11): el dominio no conoce Postgres.

import type { PoolClient } from "pg";

import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";

export interface ReconcileRunRecord {
  /** uuid v4 generado por el proceso (crypto.randomUUID). */
  readonly runId: string;
  readonly startedAt: Date;
  readonly environment: string;
  readonly tenants: number;
  readonly events: number;
  readonly divergences: number;
  /** Conteos por codigo (DivergenceKind). Sin ceros. */
  readonly byCode: Readonly<Record<string, number>>;
  readonly exitCode: 0 | 2;
}

const INSERT_RUN =
  "INSERT INTO integrity.reconcile_run (run_id, started_at, environment, tenants, events, divergences, divergences_by_code, exit_code) VALUES ($1::uuid, $2::timestamptz, $3, $4::int, $5::bigint, $6::int, $7::jsonb, $8::smallint)";

/** Persiste la corrida del reconciler (una fila). Lanza ante cualquier error (el llamador sale con exit 1). */
export async function persistReconcileRun(pool: PoolLike, run: ReconcileRunRecord): Promise<void> {
  const client: PoolClient = await acquireCleanClient(pool);
  try {
    await client.query("BEGIN READ WRITE");
    try {
      await client.query(INSERT_RUN, [run.runId, run.startedAt.toISOString(), run.environment, run.tenants, run.events, run.divergences, JSON.stringify(run.byCode), run.exitCode]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  } finally {
    client.release();
  }
}
