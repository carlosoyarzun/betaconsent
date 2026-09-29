// Gobierna: CA-124 (H09), ADR-002, ADR-006 §1/§4-§6, common.spec.yaml (INV-CM-01, INV-CM-02),
// TEST-CNS-741/742 (propuestos TEST-CNS-711/712 en el diseño de CA-124).
//
// Unidad de trabajo por tenant sobre PostgreSQL: BEGIN + `set_config('app.tenant_id', $1,
// true)` como PRIMER statement (solo local a la transacción; nunca sesión), trabajo, COMMIT.
// Error: ROLLBACK. Si el ROLLBACK falla, la conexión se destruye (release(true)). Reintenta
// 40001/40P01 hasta 3 intentos: `work` debe ser reejecutable (sin efectos fuera de la tx).
//
// El dominio nunca importa este archivo (ADR-001 §11): el puerto UnitOfWorkPort y su
// conexión con este adaptador llegan en PR-B0/PR-B.
//
// Este es el ÚNICO archivo de src/** autorizado a invocar set_config('app.tenant_id', ...);
// tests/unit/postgres/tenant-context-scan.test.ts lo hace cumplir.

import type { QueryResult } from "pg";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";

export interface TenantTx {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RETRYABLE_SQLSTATES = new Set(["40001", "40P01"]);

export interface UnitOfWorkOptions {
  maxAttempts?: number;
}

function sqlState(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

export class PgUnitOfWork {
  private readonly pool: PoolLike;
  private readonly maxAttempts: number;

  constructor(pool: PoolLike, options: UnitOfWorkOptions = {}) {
    this.pool = pool;
    this.maxAttempts = options.maxAttempts ?? 3;
  }

  async inTenant<T>(tenantId: string, work: (tx: TenantTx) => Promise<T>): Promise<T> {
    if (!UUID_RE.test(tenantId)) {
      throw new TypeError("tenantId debe ser un UUID.");
    }
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.runOnce(tenantId, work);
      } catch (error) {
        const state = sqlState(error);
        if (state !== undefined && RETRYABLE_SQLSTATES.has(state) && attempt < this.maxAttempts) continue;
        throw error;
      }
    }
  }

  private async runOnce<T>(tenantId: string, work: (tx: TenantTx) => Promise<T>): Promise<T> {
    const client = await acquireCleanClient(this.pool);
    let destroy = false;
    let open = true;
    const tx: TenantTx = {
      query: (text, values) => {
        if (!open) return Promise.reject(new Error("La transacción de tenant ya terminó."));
        return client.query(text, values);
      },
    };
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await work(tx);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
        destroy = true; // ROLLBACK o conexión rota: no se devuelve al pool (P1-1)
      }
      throw error;
    } finally {
      open = false;
      client.release(destroy);
    }
  }
}
