// Gobierna: plan v2 H1-04.
// origen: src/infra/adapters/postgres/pool.ts@9345b78 (createPool, guardBorrowedClient, logClientError; se elimina acquireCleanClient/TenantContextLeakError:
// beta tiene un único tenant constante en la base y no usa GUC de sesión).
//
// Pool de PostgreSQL del proceso web: conecta como `consent_app` con CNS_DATABASE_URL (nunca el migrador).

import pg from "pg";
import type { Pool, PoolClient, QueryResult } from "pg";

/** Superficie mínima para consultar; la implementan Client, PoolClient y la transacción. */
export interface Queryable {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

export interface PoolLike {
  connect(): Promise<PoolClient>;
}

export interface CreatePoolOptions {
  /** CNS_DATABASE_URL (rol consent_app). */
  connectionString: string;
  max?: number;
  applicationName?: string;
}

export function createPool(options: CreatePoolOptions): Pool {
  const pool = new pg.Pool({
    connectionString: options.connectionString,
    max: options.max ?? 10,
    application_name: options.applicationName ?? "consent-beta",
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
 * pg-pool quita su listener de 'error' al prestar un cliente: si Postgres mata la sesión mientras está prestado y sin query en curso,
 * 'error' se emite sin listener y el proceso cae. Registra un listener propio, marca el cliente como roto y envuelve `release` para
 * quitar el listener y destruir la conexión rota. Llamar una vez por adquisición.
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
