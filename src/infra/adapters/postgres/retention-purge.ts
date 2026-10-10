// Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.3), P-34 (placeholder; LD-15 abierta), INV-21-07/08/09/10/19.
//
// Nucleo del job de retencion (lo usa retention-purge-cli.ts, conectado como `worker`). Llama ops.purge_p34 por store, en orden
// (primero purge_run, luego los demas: la corrida actual nunca se borra a si misma) y devuelve SOLO run_id y conteos agregados:
// ni tenant_id, ni refs, ni filas (cero PII en la salida).

import type { RetentionConfig } from "../../../server/modules/common/retention.config.ts";
import type { Queryable } from "./pool.ts";

export type PurgeStore = "purge_run" | "security_event" | "otp_verification";

export interface PurgeStoreResult {
  readonly store: PurgeStore;
  readonly runId: string;
  readonly tenants: number;
  readonly eligible: number;
  readonly deleted: number;
  readonly remaining: number;
}

/** Orden de purga: purge_run primero. */
export const PURGE_ORDER: readonly PurgeStore[] = ["purge_run", "security_event", "otp_verification"];

export function retentionDaysFor(config: RetentionConfig, store: PurgeStore): number {
  switch (store) {
    case "security_event": return config.securityEventDays;
    case "otp_verification": return config.otpVerificationDays;
    case "purge_run": return config.purgeRunDays;
  }
}

/** Ejecuta la purga de todos los stores habilitados. Cualquier error (politica distinta, post-condicion) se propaga: fail-closed. */
export async function executeRetentionPurge(db: Queryable, config: RetentionConfig): Promise<PurgeStoreResult[]> {
  const results: PurgeStoreResult[] = [];
  for (const store of PURGE_ORDER) {
    const days = retentionDaysFor(config, store);
    const run = await db.query<{ run_id: string }>(
      "SELECT ops.purge_p34($1::text, pg_catalog.make_interval(days => $2::int)) AS run_id",
      [store, days],
    );
    const runId = run.rows[0]?.run_id;
    if (runId === undefined) throw new Error(`purge_p34 no devolvio run_id (${store})`);
    const summary = await db.query<{ tenants: string; eligible_before: string; deleted_count: string; remaining_older_than_cutoff: string }>(
      "SELECT tenants::text, eligible_before::text, deleted_count::text, remaining_older_than_cutoff::text FROM ops.purge_run_summary($1::uuid)",
      [runId],
    );
    const row = summary.rows[0];
    if (row === undefined) throw new Error(`purge_run sin fila resumen (${store})`);
    const result: PurgeStoreResult = {
      store,
      runId,
      tenants: Number(row.tenants),
      eligible: Number(row.eligible_before),
      deleted: Number(row.deleted_count),
      remaining: Number(row.remaining_older_than_cutoff),
    };
    if (result.remaining !== 0 || result.deleted !== result.eligible) throw new Error(`post-condicion de purga incumplida (${store})`);
    results.push(result);
  }
  return results;
}

/** Linea de salida del CLI: solo run_id y conteos. */
export function formatPurgeLine(r: PurgeStoreResult): string {
  return `store=${r.store} run_id=${r.runId} tenants=${r.tenants} eligible=${r.eligible} deleted=${r.deleted} remaining=${r.remaining}`;
}
