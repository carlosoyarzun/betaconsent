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
  // Un error en una conexión ociosa no debe tumbar el proceso ni filtrar detalles (solo name/code, sin mensaje).
  pool.on("error", (error) => logClientError("pool_idle_client_error", error));
  return pool;
}

function logClientError(event: string, error: unknown): void {
  const e = error as { name?: unknown; code?: unknown } | null;
  const name = typeof e?.name === "string" ? e.name : "Error";
  const code = typeof e?.code === "string" ? ` code=${e.code}` : "";
  console.error(`${event} name=${name}${code}`);
}

/**
 * pg-pool quita su listener de 'error' al prestar un cliente (index.js: removeListener('error', idleListener)):
 * si Postgres cae o mata la sesión mientras está prestado y sin query en curso, 'error' se emite sin listener y el
 * proceso cae (SEC-CNS-017 P2). Registra un listener propio, marca el cliente como roto y envuelve `release` para
 * (a) quitar el listener (no acumularlos en conexiones reusadas) y (b) destruir la conexión rota (release(true)).
 * Idempotente por cliente préstamo; llamar una vez por adquisición.
 */
export function guardBorrowedClient(client: PoolClient): PoolClient {
  let broken = false;
  const onError = (error: Error): void => {
    broken = true;
    logClientError("pg_borrowed_client_error", error);
  };
  client.on("error", onError);
  const originalRelease = client.release.bind(client);
  client.release = (err?: Error | boolean): void => {
    client.removeListener("error", onError);
    originalRelease(broken ? true : err);
  };
  return client;
}

/**
 * Adquiere una conexión y verifica que `app.tenant_id` esté vacío o NULL. Si no, destruye la
 * conexión y lanza TenantContextLeakError. Devuelve la conexión limpia (el llamador debe
 * liberarla).
 */
export async function acquireCleanClient(pool: PoolLike): Promise<PoolClient> {
  const client = guardBorrowedClient(await pool.connect());
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
