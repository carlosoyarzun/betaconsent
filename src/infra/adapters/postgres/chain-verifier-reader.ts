// Gobierna: ADR-010 rev. 6 §1 (fila `integrity_chain_verifier`: SELECT por columnas de las 17 de la cadena; policy unica cross-tenant), §2 (una transaccion REPEATABLE READ READ ONLY con aserciones C6/C13 al
// arrancar; ROLLBACK siempre), §3 fila PR-6f, F-PR6E-06, SEC-06-3; db/migrations/0072-0073; specs/db-roles.spec.yaml.
//
// Lectura del proceso `chain-verifier`. Una sola transaccion READ ONLY / REPEATABLE READ (snapshot consistente de todo el ledger) sobre el pool del rol integrity_chain_verifier. NO fija app.tenant_id (el rol es
// NOBYPASSRLS y la lectura cross-tenant la da la policy explicita TO integrity_chain_verifier USING (true); el chequeo de arranque exige que el cliente no fije GUC app.*). Solo SELECT de las 17 columnas
// concedidas en 0073. Sin DML y sin funciones. Todo valor variable (tenant, cursor, tamano de lote) va como parametro $n: ninguna cadena de SQL se arma con datos.
// ADAPTADOR (ADR-001 §11): el dominio (modules/integrity/ledger-chain-audit.ts) no conoce Postgres.
//
// PR-7b (rev. 6, F-PR6E-05): dentro del MISMO snapshot lee tambien la ultima cabeza persistida por tenant (integrity.chain_checkpoint, SELECT concedido en 0076) y, por tenant, el hash del ledger en una secuencia dada
// (`hashAtSeq`, solo las columnas concedidas en 0073) para que el proceso detecte truncamiento de cola. La ESCRITURA de checkpoints/chain_run es de chain-checkpoint-store.ts (tx READ WRITE aparte, T-3).
//
// Aserciones al arrancar, DENTRO de la misma tx (SEC-06-3, C5/C6/C13): transaction_read_only = on; la policy exacta (unica que alcanza al rol, permisiva, SELECT, USING true, sin WITH CHECK; se cuentan las
// PUBLIC y las RESTRICTIVE); relrowsecurity y relforcerowsecurity; has_column_privilege de las 17 columnas. Si algo falta o difiere: ChainVerifierPreconditionError (el proceso sale con exit 1). Sin ellas, una
// policy borrada o una RESTRICTIVE dejaria al verifier viendo 0 filas y daria exit 0 en verde falso.

import type { PoolClient } from "pg";

import type { ChainRow } from "../../../server/modules/common/ledger-chain.ts";
import type { HeadRef } from "../../../server/modules/integrity/chain-checkpoint.ts";
import { assertCheckpointWritable, ChainVerifierPreconditionError } from "./chain-checkpoint-preconditions.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike, Queryable } from "./pool.ts";

/** Las 17 columnas de la cadena concedidas en 0073 (ChainLinkFields + payload + event_hash). Orden = orden del GRANT. */
export const CHAIN_COLUMNS: readonly string[] = [
  "tenant_id", "chain_seq", "aggregate_type", "aggregate_id", "sequence", "event_type", "actor_type", "actor_role", "recorded_by_ref", "cosigned_by_ref", "idempotency_key_hash",
  "occurred_at", "environment", "payload", "payload_hash", "previous_event_hash", "event_hash",
];
export const CHAIN_VERIFIER_POLICY = "audit_event_chain_verifier_select";
export const CHAIN_VERIFIER_APPLICATION_NAME = "consent-chain-verifier";

export { ChainVerifierPreconditionError } from "./chain-checkpoint-preconditions.ts";
export type { ChainPreconditionCode } from "./chain-checkpoint-preconditions.ts";

/** SQL fijo (sin interpolacion de datos): solo constantes de columnas. */
const EVENT_SELECT =
  "SELECT tenant_id::text AS tenant_id, chain_seq::float8 AS chain_seq, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, idempotency_key_hash, " +
  `to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at_txt, environment, payload, payload_hash, previous_event_hash, event_hash ` +
  "FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq > $2::bigint ORDER BY chain_seq LIMIT $3::int";
/** Toma el lock de lectura sobre el ledger sin leer filas ni columnas distintas de las concedidas (SEC-6F-01). */
const LOCK_SQL = "SELECT tenant_id FROM integrity.audit_event LIMIT 0";
/** Lock de lectura sobre la tabla de checkpoints (mismo motivo que LOCK_SQL: lo asertado no cambia durante la corrida). */
const LOCK_CHECKPOINT_SQL = "SELECT run_id FROM integrity.chain_checkpoint LIMIT 0";
/** Ultima cabeza persistida por tenant (la de mayor head_chain_seq). */
const CHECKPOINT_HEADS_SQL =
  "SELECT DISTINCT ON (tenant_id) tenant_id::text AS tenant_id, head_chain_seq::float8 AS head_chain_seq, head_event_hash FROM integrity.chain_checkpoint ORDER BY tenant_id, head_chain_seq DESC";
/** Hash del ledger en una secuencia de un tenant (solo columnas concedidas en 0073). */
const HASH_AT_SQL = "SELECT event_hash FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = $2::bigint";
const TENANTS_SQL = "SELECT DISTINCT tenant_id::text AS tenant_id FROM integrity.audit_event ORDER BY 1";
/** Filas sin eslabon (chain_seq NULL) posteriores al inicio de la cadena (primer eslabon del tenant): las anteriores a 0013 son legado fuera de la cadena. */
const UNCHAINED_SQL =
  "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq IS NULL " +
  "AND occurred_at > (SELECT min(occurred_at) FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = 1)";

interface EventRow {
  tenant_id: string;
  chain_seq: number;
  aggregate_type: string;
  aggregate_id: string;
  sequence: number;
  event_type: string;
  actor_type: string;
  actor_role: string | null;
  recorded_by_ref: string | null;
  cosigned_by_ref: string | null;
  idempotency_key_hash: string | null;
  occurred_at_txt: string;
  environment: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  previous_event_hash: string;
  event_hash: string;
}

function toChainRow(row: EventRow): ChainRow {
  return {
    tenantId: row.tenant_id,
    chainSeq: Number(row.chain_seq),
    aggregateType: row.aggregate_type,
    aggregateId: row.aggregate_id,
    sequence: row.sequence,
    eventType: row.event_type,
    actorType: row.actor_type,
    actorRole: row.actor_role,
    recordedByRef: row.recorded_by_ref,
    cosignedByRef: row.cosigned_by_ref,
    idempotencyKeyHash: row.idempotency_key_hash,
    occurredAt: row.occurred_at_txt,
    environment: row.environment,
    payload: row.payload,
    payloadHash: row.payload_hash,
    previousEventHash: row.previous_event_hash,
    eventHash: row.event_hash,
  };
}

/** Eslabones de UN tenant por lotes (keyset por chain_seq: `chain_seq > ultimo`); nunca acumula la cadena entera. */
async function* readTenantBatches(db: Queryable, tenantId: string, batchSize: number): AsyncGenerator<readonly ChainRow[]> {
  let last = 0;
  for (;;) {
    const r = await db.query<EventRow>(EVENT_SELECT, [tenantId, last, batchSize]);
    if (r.rows.length === 0) return;
    const rows = r.rows.map(toChainRow);
    last = rows[rows.length - 1]!.chainSeq;
    yield rows;
    if (rows.length < batchSize) return;
  }
}

/**
 * C13 + C5/C6: aserciones de la sesion y de la base antes de leer nada, dentro de la tx del snapshot. Devuelve el environment del catalogo (ops.db_catalog) para que el proceso contraste el flag solo-LOCAL.
 * `pg_policy`, `pg_class` y `pg_roles` son legibles por PUBLIC (no requieren grant).
 */
export async function assertChainReadable(db: Queryable): Promise<{ readonly catalogEnvironment: string }> {
  const ro = await db.query<{ ro: string }>("SELECT current_setting('transaction_read_only') AS ro");
  if (ro.rows[0]?.ro !== "on") throw new ChainVerifierPreconditionError("READ_ONLY_NOT_ENFORCED");

  const policies = await db.query<{ polname: string; polcmd: string; permissive: boolean; qual: string | null; has_check: boolean; roles: string[] }>(
    `SELECT p.polname::text AS polname, p.polcmd::text AS polcmd, p.polpermissive AS permissive, pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS qual, p.polwithcheck IS NOT NULL AS has_check,
            ARRAY(SELECT CASE WHEN r = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(r)::text END FROM pg_catalog.unnest(p.polroles) AS r) AS roles
       FROM pg_catalog.pg_policy p
      WHERE p.polrelid = 'integrity.audit_event'::pg_catalog.regclass
        AND (0::pg_catalog.oid = ANY (p.polroles) OR (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) = ANY (p.polroles))`,
  );
  const only = policies.rows[0];
  if (
    policies.rows.length !== 1 || only === undefined || only.polname !== CHAIN_VERIFIER_POLICY || only.polcmd !== "r" || !only.permissive || only.qual !== "true" || only.has_check ||
    only.roles.length !== 1 || only.roles[0] !== "integrity_chain_verifier"
  ) {
    throw new ChainVerifierPreconditionError("POLICY_MISSING_OR_ALTERED");
  }

  const rls = await db.query<{ enabled: boolean; forced: boolean }>(
    "SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced FROM pg_catalog.pg_class c WHERE c.oid = 'integrity.audit_event'::pg_catalog.regclass",
  );
  if (rls.rows[0]?.enabled !== true || rls.rows[0]?.forced !== true) throw new ChainVerifierPreconditionError("RLS_NOT_FORCED");

  const cols = await db.query<{ missing: number }>(
    `SELECT pg_catalog.count(*)::int AS missing FROM pg_catalog.unnest($1::text[]) AS c(name)
      WHERE NOT pg_catalog.has_column_privilege(current_user, 'integrity.audit_event'::pg_catalog.regclass, c.name, 'SELECT')`,
    [[...CHAIN_COLUMNS]],
  );
  if (cols.rows[0]?.missing !== 0) throw new ChainVerifierPreconditionError("COLUMN_PRIVILEGE_MISSING");

  await assertCheckpointWritable(db);

  const catalog = await db.query<{ environment: string }>("SELECT environment FROM ops.db_catalog");
  const env = catalog.rows[0]?.environment;
  if (catalog.rows.length !== 1 || typeof env !== "string") throw new ChainVerifierPreconditionError("CATALOG_UNREADABLE");
  return { catalogEnvironment: env };
}

/** Lo que el lector entrega por tenant: sus lotes de eslabones (en orden de chain_seq) y el conteo de filas sin eslabon. */
export interface TenantChainInput {
  readonly tenantId: string;
  readonly unchainedAfterStart: number;
  readonly batches: AsyncIterable<readonly ChainRow[]>;
  /** Ultima cabeza persistida en integrity.chain_checkpoint para el tenant (null si nunca hubo). */
  readonly previousHead: HeadRef | null;
  /** Hash del ledger en `chainSeq` (null si no existe esa secuencia), dentro del mismo snapshot. */
  hashAtSeq(chainSeq: number): Promise<string | null>;
}

/** Resultado del snapshot: tenants visitados y ultimas cabezas persistidas por tenant (todas, incluidas las de tenants sin eventos). */
export interface ChainSnapshotResult {
  readonly visited: number;
  readonly tenantIds: ReadonlySet<string>;
  readonly checkpointHeads: ReadonlyMap<string, HeadRef>;
}

export interface ChainSnapshotOptions {
  readonly batchSize: number;
  /** El proceso decide si 0 tenants/0 eventos es error (C7); el lector solo informa el environment del catalogo para el flag solo-LOCAL. */
  readonly onReadable?: (info: { catalogEnvironment: string; tenants: number }) => void;
}

/**
 * Lee TODOS los tenants en un snapshot y entrega cada uno al callback (sin acumular el ledger en memoria). Siempre READ ONLY; al terminar ROLLBACK (nada que confirmar). Si el cliente trae app.tenant_id
 * arrastrado de otra sesion, acquireCleanClient lo destruye y falla cerrado. Devuelve los tenants visitados y las ultimas cabezas persistidas.
 */
export async function forEachTenantChainInSnapshot(pool: PoolLike, visit: (input: TenantChainInput) => Promise<void>, options: ChainSnapshotOptions): Promise<ChainSnapshotResult> {
  const client: PoolClient = await acquireCleanClient(pool);
  try {
    await client.query("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY");
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    let result: ChainSnapshotResult;
    try {
      // SEC-6F-01: PRIMERA sentencia de la tx. Toma ACCESS SHARE sobre la tabla y bloquea CREATE/DROP/ALTER POLICY y NO FORCE RLS (ACCESS EXCLUSIVE) hasta el ROLLBACK:
      // lo asertado abajo no puede cambiar durante la corrida (sin esto, una policy alterada a mitad de camino daria exit 0 con filas filtradas).
      await client.query(LOCK_SQL);
      await client.query(LOCK_CHECKPOINT_SQL);
      const { catalogEnvironment } = await assertChainReadable(client);
      const checkpointHeads = new Map<string, HeadRef>();
      for (const h of (await client.query<{ tenant_id: string; head_chain_seq: number; head_event_hash: string }>(CHECKPOINT_HEADS_SQL)).rows) {
        checkpointHeads.set(h.tenant_id, { chainSeq: Number(h.head_chain_seq), eventHash: h.head_event_hash });
      }
      const tenants = (await client.query<{ tenant_id: string }>(TENANTS_SQL)).rows.map((r) => r.tenant_id);
      options.onReadable?.({ catalogEnvironment, tenants: tenants.length });
      for (const tenantId of tenants) {
        const unchained = (await client.query<{ n: number }>(UNCHAINED_SQL, [tenantId])).rows[0]?.n ?? 0;
        await visit({
          tenantId,
          unchainedAfterStart: unchained,
          batches: readTenantBatches(client, tenantId, options.batchSize),
          previousHead: checkpointHeads.get(tenantId) ?? null,
          hashAtSeq: async (chainSeq) => (await client.query<{ event_hash: string }>(HASH_AT_SQL, [tenantId, chainSeq])).rows[0]?.event_hash ?? null,
        });
      }
      result = { visited: tenants.length, tenantIds: new Set(tenants), checkpointHeads };
    } finally {
      await client.query("ROLLBACK");
    }
    // Defensa en profundidad: tras liberar el lock se repite la asercion en una tx nueva; si la policy, FORCE RLS o los privilegios cambiaron entre las dos, exit 1 (fail-closed).
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      await client.query(LOCK_SQL);
      await client.query(LOCK_CHECKPOINT_SQL);
      await assertChainReadable(client);
    } finally {
      await client.query("ROLLBACK");
    }
    return result;
  } finally {
    client.release();
  }
}
