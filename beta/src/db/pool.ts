// Gobierna: plan v2 H1-04.
// origen: src/infra/adapters/postgres/pool.ts@9345b78 (createPool, guardBorrowedClient, logClientError; se elimina acquireCleanClient/TenantContextLeakError:
// beta tiene un único tenant constante en la base y no usa GUC de sesión).
//
// Dos pools en el MISMO proceso Node (SEC-CNS-024-V1): `app` (consent_app, CNS_DATABASE_URL, 10 conexiones) atiende HTTP y NO puede emitir secretos;
// `mailer` (consent_mailer, CNS_MAILER_DATABASE_URL, 2 conexiones) solo emite OTP/tokens y lleva el outbox. Nunca el migrador. assertPoolRoles verifica cada pool contra su rol.

import pg from "pg";
import type { Pool, PoolClient, QueryResult } from "pg";

import { assertRuntimeRole, MAILER_ROLE, RUNTIME_ROLE } from "./assert-runtime-role.ts";

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

export const APP_POOL_MAX = 10;
export const MAILER_POOL_MAX = 2;

export interface RuntimePools {
  /** consent_app: peticiones HTTP. */
  readonly app: Pool;
  /** consent_mailer: issue_otp, arm_invitation_token y outbox. */
  readonly mailer: Pool;
}

export function createPools(urls: { readonly appUrl: string; readonly mailerUrl: string }): RuntimePools {
  return {
    app: createPool({ connectionString: urls.appUrl, max: APP_POOL_MAX, applicationName: "consent-beta-app" }),
    mailer: createPool({ connectionString: urls.mailerUrl, max: MAILER_POOL_MAX, applicationName: "consent-beta-mailer" }),
  };
}

/** Gate de arranque por pool: el pool app debe conectar como consent_app y el mailer como consent_mailer (F-SB-02). Lanza RuntimeRoleError. */
export async function assertPoolRoles(pools: RuntimePools): Promise<void> {
  await assertRuntimeRole(pools.app, RUNTIME_ROLE);
  await assertRuntimeRole(pools.mailer, MAILER_ROLE);
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
