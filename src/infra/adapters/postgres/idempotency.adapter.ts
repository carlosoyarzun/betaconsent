// Gobierna: CA-124 (H09), PR-E; src/server/ports/idempotency.port.ts,
// db/migrations/0012_idempotency_local_seed.sql (app.idempotency_key), common.spec.yaml GRD-CM-08 y
// ERR-CM-07, ADR-006. ADR-001 §11: solo este adaptador conoce el SQL de app.idempotency_key.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()): find +
// ejecutar + store son atomicos. `find` toma un advisory lock transaccional sobre la clave: dos
// requests con la misma Idempotency-Key se serializan (la segunda espera al COMMIT de la primera y
// ve su respuesta almacenada: replay, nunca doble ejecucion). El TTL P-33 NO esta aprobado: el
// adaptador lo recibe de la configuracion (idempotency-policy.config.ts, fail-closed); sin
// politica, cualquier uso falla cerrado.

import type { IdempotencyPort, StoredIdempotentResponse } from "../../../server/ports/idempotency.port.ts";
import type { IdempotencyPolicy } from "../../../server/modules/common/idempotency-policy.config.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface IdempotencyRow {
  payload_hash: string;
  status: number;
  body: Record<string, unknown>;
}

export class IdempotencyPolicyMissingError extends Error {
  constructor() {
    super("Politica de idempotencia (P-33) no configurada: no hay default de produccion (fail-closed).");
    this.name = "IdempotencyPolicyMissingError";
  }
}

export function createPgIdempotencyAdapter(tx: TenantTx, policy: IdempotencyPolicy | undefined): IdempotencyPort {
  const requirePolicy = (): IdempotencyPolicy => {
    if (policy === undefined) throw new IdempotencyPolicyMissingError();
    return policy;
  };
  return {
    async find(tenantId, scopeKeyHash) {
      requirePolicy();
      await tx.query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))", [`${tenantId}:${scopeKeyHash}`]);
      const r = await tx.query<IdempotencyRow>(
        `SELECT payload_hash, status, body FROM app.idempotency_key
          WHERE tenant_id = $1 AND scope_key_hash = $2 AND expires_at > pg_catalog.now()`,
        [tenantId, scopeKeyHash],
      );
      const row = r.rows[0];
      return row ? { payloadHash: row.payload_hash, status: row.status, body: row.body } : null;
    },
    async store(tenantId, scopeKeyHash, response: StoredIdempotentResponse) {
      const { ttlMs } = requirePolicy();
      // Una entrada vencida se reemplaza; una vigente nunca se pisa (la primera gana).
      await tx.query(
        `INSERT INTO app.idempotency_key (tenant_id, scope_key_hash, payload_hash, status, body, expires_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, pg_catalog.now() + ($6::bigint * interval '1 millisecond'))
         ON CONFLICT (tenant_id, scope_key_hash) DO UPDATE
            SET payload_hash = EXCLUDED.payload_hash, status = EXCLUDED.status, body = EXCLUDED.body, expires_at = EXCLUDED.expires_at
          WHERE app.idempotency_key.expires_at <= pg_catalog.now()`,
        [tenantId, scopeKeyHash, response.payloadHash, response.status, JSON.stringify(response.body), String(ttlMs)],
      );
    },
  };
}
