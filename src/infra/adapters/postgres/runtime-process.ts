// Gobierna: ADR-010 rev. 4 §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; ... pools por rol"), specs/db-roles.spec.yaml INV-DBR-02 ("cada proceso arranca solo con su rol
// exacto: web=app_rw, platform=platform_rw, worker=worker, verifier=integrity_verifier"), INV-DBR-01/03, SEC-CNS-017 F6; ADR-001 §11 (solo entrypoints importan adaptadores).
//
// Un proceso = un rol LOGIN = un pool. La credencial sale SOLO del entorno (CNS_DATABASE_URL); su usuario debe ser EXACTAMENTE el rol del proceso (no basta con "no ser el migrador"),
// y despues de conectar los chequeos de arranque (assertStartupChecks) exigen current_user = rol esperado, que el rol no sea miembro de un owner, que la membresia de los roles
// gobernados coincida con el modo declarado (role-membership.ts) y el resto de INV-DBR-01. Si algo falla, el pool se cierra y se lanza: el proceso NO escucha ni trabaja (fail-closed).

import type { Pool } from "pg";
import { loadRetentionConfig } from "../../../server/modules/common/retention.config.ts";
import type { RetentionConfig } from "../../../server/modules/common/retention.config.ts";
import { createPool, guardBorrowedClient } from "./pool.ts";
import { resolveDbRoleMode } from "./role-membership.ts";
import { assertStartupChecks } from "./startup-checks.ts";

/** INV-DBR-02: rol LOGIN de cada proceso de runtime. Nombres reales de specs/db-roles.spec.yaml. */
export const RUNTIME_PROCESS_ROLES = {
  web: "app_rw",
  platform: "platform_rw",
  worker: "worker",
  verifier: "integrity_verifier",
} as const;

/** Pool de un proceso de runtime (alias para que los entrypoints no importen `pg`, ADR-001 §11). */
export type ProcessPool = Pool;
export type RuntimeProcess = keyof typeof RUNTIME_PROCESS_ROLES;
export type RuntimeEnvironment = "LOCAL" | "DEV" | "STAGING";

export class ProcessRoleError extends Error {
  readonly code = "PROCESS_ROLE_MISMATCH";
  constructor(detail: string) {
    super(`${detail}. Abortando (INV-DBR-02, fail-closed).`);
    this.name = "ProcessRoleError";
  }
}

export function expectedRoleFor(runtimeProcess: RuntimeProcess): string {
  return RUNTIME_PROCESS_ROLES[runtimeProcess];
}

/** CNS_ENVIRONMENT: enum cerrado (F-PR6-08); cualquier otro valor aborta. */
export function parseRuntimeEnvironment(value: string | undefined): RuntimeEnvironment {
  if (value === "LOCAL" || value === "DEV" || value === "STAGING") return value;
  throw new ProcessRoleError(`CNS_ENVIRONMENT debe ser LOCAL, DEV o STAGING (recibido: "${value === undefined || value === "" ? "(vacio)" : "otro valor"}")`);
}

/**
 * Credencial del proceso: solo del entorno, nunca el migrador y el usuario de la URL debe ser exactamente el rol del proceso. Nunca incluye la URL ni la clave en el mensaje.
 */
export function readProcessDatabaseUrl(runtimeProcess: RuntimeProcess, env: Readonly<Record<string, string | undefined>>): string {
  const role = expectedRoleFor(runtimeProcess);
  const migratorVars = Object.keys(env).filter((k) => /MIGRATOR/i.test(k) && (env[k] ?? "") !== "");
  if (migratorVars.length > 0) throw new ProcessRoleError(`el proceso ${runtimeProcess} no debe recibir la credencial del migrador (variables *MIGRATOR* presentes)`);
  const url = env.CNS_DATABASE_URL;
  if (url === undefined || url === "") throw new ProcessRoleError(`el proceso ${runtimeProcess} requiere CNS_DATABASE_URL (credencial de ${role}, solo por entorno)`);
  let user: string;
  try {
    user = decodeURIComponent(new URL(url).username);
  } catch {
    throw new ProcessRoleError("CNS_DATABASE_URL no es una URL valida");
  }
  if (user !== role) throw new ProcessRoleError(`el proceso ${runtimeProcess} solo puede conectar como ${role} (la URL usa otro rol)`);
  return url;
}

export interface OpenProcessPoolOptions {
  readonly process: RuntimeProcess;
  readonly environment: RuntimeEnvironment;
  /** Por defecto process.env (inyectable en tests). */
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly max?: number;
  /** SEC-CNS-021 PR-3: si falta se carga de env (lanza en STAGING si no esta configurada). */
  readonly retention?: RetentionConfig;
}

/**
 * Abre el pool UNICO del rol del proceso y ejecuta los chequeos de arranque con expectedRole = rol del proceso. Si fallan cierra el pool y lanza (StartupCheckError).
 * Un proceso no puede abrir el pool de otro rol: el rol sale de RUNTIME_PROCESS_ROLES[process], no de un parametro libre.
 */
export async function openProcessPool(options: OpenProcessPoolOptions): Promise<Pool> {
  const env = options.env ?? process.env;
  const url = readProcessDatabaseUrl(options.process, env);
  let retention: RetentionConfig | undefined = options.retention;
  if (retention === undefined) {
    const loaded = loadRetentionConfig(env as NodeJS.ProcessEnv, options.environment);
    retention = loaded.status === "CONFIGURED" ? loaded.config : undefined;
  }
  const pool = createPool({ connectionString: url, max: options.max ?? 4, applicationName: `consent-${options.process}` });
  try {
    const client = guardBorrowedClient(await pool.connect());
    try {
      await assertStartupChecks(client, {
        expectedEnvironment: options.environment,
        expectedRole: expectedRoleFor(options.process),
        roleMode: resolveDbRoleMode(env, options.environment),
        ...(retention === undefined ? {} : { retention }),
      });
    } finally {
      client.release();
    }
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
  return pool;
}
