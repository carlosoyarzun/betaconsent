// Gobierna: plan v2 H1-04.
// origen: src/infra/adapters/postgres/unit-of-work.ts@9345b78 (runOnce, reintento de 40001/40P01 con backoff de jitter completo, ROLLBACK que destruye
// la conexión si falla). Se eliminan: GUC app.tenant_id, SET ROLE, puertos por tenant, carreras de UNIQUE de dominio y política de idempotencia.
//
// Unidad de trabajo: BEGIN, topes locales de lock/statement, trabajo, COMMIT. `work` debe ser reejecutable (se reintenta ante 40001/40P01).

import { guardBorrowedClient } from "./pool.ts";
import type { PoolLike, Queryable } from "./pool.ts";

export type Tx = Queryable;

export interface UnitOfWork {
  withTransaction<T>(work: (tx: Tx) => Promise<T>): Promise<T>;
}

export interface UnitOfWorkOptions {
  /** Intentos totales ante 40001/40P01. Default 3. */
  maxAttempts?: number;
  /** Un lock que no se obtiene falla (55P03) en vez de colgar la petición. Default 2 s. */
  lockTimeoutMs?: number;
  /** Tope por statement. Default 5 s. */
  statementTimeoutMs?: number;
  /** Inyectables para tests. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

export const DEFAULT_LOCK_TIMEOUT_MS = 2000;
export const DEFAULT_STATEMENT_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_ATTEMPTS = 3;
const BACKOFF_BASE_MS = 20;
const BACKOFF_CAP_MS = 200;
const RETRYABLE_SQLSTATES = new Set(["40001", "40P01"]);

function sqlState(error: unknown): string | undefined {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  return typeof code === "string" ? code : undefined;
}

export class PgUnitOfWork implements UnitOfWork {
  private readonly pool: PoolLike;
  private readonly maxAttempts: number;
  private readonly lockTimeoutMs: number;
  private readonly statementTimeoutMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  constructor(pool: PoolLike, options: UnitOfWorkOptions = {}) {
    this.pool = pool;
    this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.lockTimeoutMs = options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
    this.statementTimeoutMs = options.statementTimeoutMs ?? DEFAULT_STATEMENT_TIMEOUT_MS;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.random = options.random ?? Math.random;
    for (const v of [this.maxAttempts, this.lockTimeoutMs, this.statementTimeoutMs]) {
      if (!Number.isInteger(v) || v <= 0) throw new TypeError("maxAttempts, lockTimeoutMs y statementTimeoutMs deben ser enteros > 0 (fail-closed).");
    }
  }

  async withTransaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.runOnce(work);
      } catch (error) {
        const state = sqlState(error);
        if (state !== undefined && RETRYABLE_SQLSTATES.has(state) && attempt < this.maxAttempts) {
          const delay = Math.floor(this.random() * Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** (attempt - 1)));
          if (delay > 0) await this.sleep(delay);
          continue;
        }
        throw error;
      }
    }
  }

  private async runOnce<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    const client = guardBorrowedClient(await this.pool.connect());
    let destroy = false;
    let open = true;
    const tx: Tx = {
      query: (text, values) => (open ? client.query(text, values) : Promise.reject(new Error("La transacción ya terminó."))),
    };
    try {
      await client.query("BEGIN");
      // Enteros validados en el constructor: SET LOCAL no admite parámetros.
      await client.query(`SET LOCAL lock_timeout = ${this.lockTimeoutMs}`);
      await client.query(`SET LOCAL statement_timeout = ${this.statementTimeoutMs}`);
      const result = await work(tx);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
        destroy = true; // ROLLBACK fallido o conexión rota: no se devuelve al pool
      }
      throw error;
    } finally {
      open = false;
      client.release(destroy);
    }
  }
}
