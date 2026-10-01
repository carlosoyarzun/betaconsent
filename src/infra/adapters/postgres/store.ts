// Gobierna: CA-124 (H09), PR-E; postgres-design.md rev. 2 §7 (PR-E) y §4 (arranque, TEST-CNS-724/747),
// ADR-002, ADR-006 §1/§4-§6, ADR-001 §11 (solo entrypoints importan adaptadores), SEC-CNS-016.
//
// Almacen Postgres del proceso web (CONSENT_STORE=postgres): pool del rol app_rw, chequeos de arranque
// OBLIGATORIOS antes de escuchar (assertStartupChecks) y puertos "fuera de tx" que FALLAN CERRADO: todo
// acceso a repos/ledger/outbox/catalogo/idempotencia fuera de `uow.inTenant` lanza
// OutsideTransactionError (SEC-CNS-016). La credencial sale SOLO del entorno (CNS_DATABASE_URL); nunca se
// loguea y el proceso web nunca recibe la del migrador (se rechaza el rol consent_migrator y cualquier
// variable *MIGRATOR* en el entorno del proceso).

import type { Pool } from "pg";
import type { IdempotencyPolicy } from "../../../server/modules/common/idempotency-policy.config.ts";
import type { TenantHandlePort } from "../../../server/ports/tenant-handle.port.ts";
import type { TenantResolverPort } from "../../../server/ports/tenant-resolver.port.ts";
import type { TenantTxPorts } from "../../../server/ports/unit-of-work.port.ts";
import { createPool } from "./pool.ts";
import { assertStartupChecks } from "./startup-checks.ts";
import { createPgTenantHandleAdapter } from "./tenant-handle.adapter.ts";
import { createPgTenantResolver } from "./tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "./unit-of-work.ts";

export class OutsideTransactionError extends Error {
  readonly code = "OUTSIDE_TRANSACTION";
  constructor(operation: string) {
    super(`Acceso a ${operation} fuera de uow.inTenant: en Postgres todo acceso a datos del tenant corre dentro de una tx (SEC-CNS-016).`);
    this.name = "OutsideTransactionError";
  }
}

function forbidden<T extends object>(name: string): T {
  return new Proxy({}, {
    get: (_target, prop) => (typeof prop === "string" && prop !== "then" ? () => Promise.reject(new OutsideTransactionError(`${name}.${prop}`)) : undefined),
  }) as T;
}

/** Bolsa de puertos de la que el dominio NO debe leer fuera de `inTenant`: cada metodo rechaza. */
export function createForbiddenOutsideTxPorts(): TenantTxPorts {
  return {
    revocationRepo: forbidden("revocationRepo"),
    consentDecisionRepo: forbidden("consentDecisionRepo"),
    recoveryTokenRepo: forbidden("recoveryTokenRepo"),
    invitationRepo: forbidden("invitationRepo"),
    otpRepo: forbidden("otpRepo"),
    rightsCaseRepo: forbidden("rightsCaseRepo"),
    enrollmentRepo: forbidden("enrollmentRepo"),
    ledger: forbidden("ledger"),
    outbox: forbidden("outbox"),
    tenantCatalog: forbidden("tenantCatalog"),
    idempotency: forbidden("idempotency"),
  };
}

export interface PostgresStore {
  readonly pool: Pool;
  readonly uow: PgUnitOfWork;
  readonly tenantResolver: TenantResolverPort;
  readonly tenantHandle: TenantHandlePort;
  /** Puertos que rechazan cualquier uso fuera de `inTenant`. */
  readonly outsideTx: TenantTxPorts;
  close(): Promise<void>;
}

export interface OpenPostgresStoreOptions {
  /** Entorno declarado; debe coincidir con el catalogo de la base (SEC N2-06). */
  readonly environment: "LOCAL" | "DEV" | "STAGING";
  /** P-33: sin default de produccion (idempotency-policy.config.ts). */
  readonly idempotencyPolicy: IdempotencyPolicy;
  /** Por defecto process.env (inyectable en tests). */
  readonly env?: NodeJS.ProcessEnv;
}

/** Valida la credencial del entorno: solo el rol de runtime; nunca el migrador. */
export function readRuntimeDatabaseUrl(env: NodeJS.ProcessEnv): string {
  const migratorVars = Object.keys(env).filter((k) => /MIGRATOR/i.test(k) && (env[k] ?? "") !== "");
  if (migratorVars.length > 0) {
    throw new Error("El proceso web no debe recibir la credencial del migrador (variables *MIGRATOR* presentes). Abortando.");
  }
  const url = env.CNS_DATABASE_URL;
  if (url === undefined || url === "") {
    throw new Error("CONSENT_STORE=postgres requiere CNS_DATABASE_URL (credencial de app_rw, solo por entorno). Abortando.");
  }
  let user: string;
  try {
    user = decodeURIComponent(new URL(url).username);
  } catch {
    throw new Error("CNS_DATABASE_URL no es una URL valida. Abortando.");
  }
  if (user === "consent_migrator" || user === "postgres" || user === "consent_owner") {
    throw new Error(`CNS_DATABASE_URL usa el rol "${user}": el proceso web solo puede usar el rol de runtime (app_rw). Abortando.`);
  }
  return url;
}

/** Abre el pool y ejecuta los chequeos de arranque; si fallan, cierra el pool y lanza (no se escucha). */
export async function openPostgresStore(options: OpenPostgresStoreOptions): Promise<PostgresStore> {
  const url = readRuntimeDatabaseUrl(options.env ?? process.env);
  const pool = createPool({ connectionString: url, max: 10 });
  try {
    const client = await pool.connect();
    try {
      await assertStartupChecks(client, { expectedEnvironment: options.environment, expectedRole: "app_rw" });
    } finally {
      client.release();
    }
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
  const uow = new PgUnitOfWork(pool, { idempotencyPolicy: options.idempotencyPolicy });
  return {
    pool,
    uow,
    tenantResolver: createPgTenantResolver(pool),
    tenantHandle: createPgTenantHandleAdapter(pool),
    outsideTx: createForbiddenOutsideTxPorts(),
    close: () => pool.end(),
  };
}
