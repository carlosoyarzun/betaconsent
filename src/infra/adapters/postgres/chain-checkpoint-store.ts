// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: persistencia de checkpoints y cabeza por tenant por el chain-verifier; INSERT solo para integrity_chain_verifier), F-PR6E-05, plan PR-7 v3 (PR-7b, T-2, T-3, T-4);
// db/migrations/0076 (integrity.chain_run, integrity.chain_checkpoint); specs/db-roles.spec.yaml (integrity_chain_verifier).
//
// ESCRITURA del proceso `chain-verifier`: una tx corta `BEGIN READ WRITE` APARTE del snapshot RR READ ONLY (T-3: se conserva default_transaction_read_only=on del rol y la lectura consistente). Solo INSERT por
// columnas (sin RETURNING: el run_id lo genera el proceso y el rol no lee chain_run). El trigger de la base valida cada cabeza contra el ledger y contra el checkpoint anterior: este codigo no es la barrera.
// Todo valor va como parametro $n (arrays tipados para los checkpoints). Cero PII: tenant (uuid del colegio), hashes y conteos.
// ADAPTADOR (ADR-001 §11): el dominio no conoce Postgres.

import type { PoolClient } from "pg";

import type { ChainHead } from "../../../server/modules/integrity/chain-checkpoint.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";

export interface ChainRunRecord {
  /** uuid v4 generado por el proceso (crypto.randomUUID). */
  readonly runId: string;
  readonly startedAt: Date;
  readonly environment: string;
  readonly tenants: number;
  readonly events: number;
  /** 0 cadena integra; 2 rota o con anomalia. */
  readonly exitCode: 0 | 2;
  readonly leafCount: number;
  /** Solo con exitCode 0 (CHECK de la base). */
  readonly merkleRoot: string | null;
  readonly merkleFormat: string | null;
}

export interface CheckpointRecord extends ChainHead {
  readonly verifiedEvents: number;
}

const INSERT_RUN =
  "INSERT INTO integrity.chain_run (run_id, started_at, environment, tenants, events, exit_code, leaf_count, merkle_root, merkle_format) VALUES ($1::uuid, $2::timestamptz, $3, $4::int, $5::bigint, $6::smallint, $7::int, $8, $9)";
const INSERT_CHECKPOINTS =
  "INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) " +
  "SELECT $1::uuid, x.tenant_id, x.head_chain_seq, x.head_event_hash, x.verified_events FROM unnest($2::uuid[], $3::bigint[], $4::text[], $5::bigint[]) AS x(tenant_id, head_chain_seq, head_event_hash, verified_events)";

/**
 * Persiste la corrida y los checkpoints en una sola tx READ WRITE (todo o nada). Lanza ante cualquier error (el llamador sale con exit 1; sin mensaje de la base en el log). Si `checkpoints` es vacio solo se
 * inserta chain_run.
 */
export async function persistChainRun(pool: PoolLike, run: ChainRunRecord, checkpoints: readonly CheckpointRecord[]): Promise<void> {
  const client: PoolClient = await acquireCleanClient(pool);
  try {
    await client.query("BEGIN READ WRITE");
    try {
      await client.query(INSERT_RUN, [run.runId, run.startedAt.toISOString(), run.environment, run.tenants, run.events, run.exitCode, run.leafCount, run.merkleRoot, run.merkleFormat]);
      if (checkpoints.length > 0) {
        await client.query(INSERT_CHECKPOINTS, [
          run.runId,
          checkpoints.map((c) => c.tenantId),
          checkpoints.map((c) => c.chainSeq),
          checkpoints.map((c) => c.eventHash),
          checkpoints.map((c) => c.verifiedEvents),
        ]);
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  } finally {
    client.release();
  }
}
