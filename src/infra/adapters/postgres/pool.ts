// Gobierna: CA-124 (H09), ADR-002, ADR-006 §1/§4-§6 (tenant_id como única clave de
// aislamiento), TEST-CNS-740 (propuesto TEST-CNS-710 en el diseño de CA-124).
//
// Pool de PostgreSQL y adquisición "limpia" de conexiones (P1-1 de lampone-security).
// El contexto de tenant SOLO vive en la transacción (`set_config(..., true)` en
// unit-of-work.ts). Si al adquirir una conexión `app.tenant_id` no está vacío, la conexión
// arrastra contexto de una sesión anterior (fuga A->B): se destruye (release(true)) y se
// falla cerrado.

import pg from "pg";
import type { Pool, PoolClient, QueryResult } from "pg";

/** Superficie mínima para consultar; la implementan Client, PoolClient y los dobles de test. */
export interface Queryable {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

/** Superficie mínima del pool que necesitan pool.ts y unit-of-work.ts. */
export interface PoolLike {
  connect(): Promise<PoolClient>;
}

export interface CreatePoolOptions {
  /** URL de conexión del rol de runtime (app_rw / worker / platform_rw). Nunca el migrador. */
  connectionString: string;
  max?: number;
  applicationName?: string;
}

export class TenantContextLeakError extends Error {
  readonly code = "TENANT_CONTEXT_LEAK";
  constructor() {
    super("La conexión adquirida arrastra app.tenant_id de una sesión anterior; se destruye y se falla cerrado (ADR-006, P1-1).");
    this.name = "TenantContextLeakError";
  }
}

export function createPool(options: CreatePoolOptions): Pool {
  const pool = new pg.Pool({
    connectionString: options.connectionString,
    max: options.max ?? 10,
    application_name: options.applicationName ?? "consent-app",
    connectionTimeoutMillis: 5_000,
  });
  // Un error en una conexión ociosa no debe tumbar el proceso ni filtrar detalles.
  pool.on("error", () => {});
  return pool;
}

/**
 * Adquiere una conexión y verifica que `app.tenant_id` esté vacío o NULL. Si no, destruye la
 * conexión y lanza TenantContextLeakError. Devuelve la conexión limpia (el llamador debe
 * liberarla).
 */
export async function acquireCleanClient(pool: PoolLike): Promise<PoolClient> {
  const client = await pool.connect();
  let clean: boolean;
  try {
    const result = await client.query<{ tenant: string | null }>("SELECT current_setting('app.tenant_id', true) AS tenant");
    const tenant = result.rows[0]?.tenant;
    clean = tenant === null || tenant === undefined || tenant === "";
  } catch (error) {
    client.release(true);
    throw error;
  }
  if (!clean) {
    client.release(true);
    throw new TenantContextLeakError();
  }
  return client;
}
