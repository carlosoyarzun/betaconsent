// Gobierna: ADR-010 rev. 6 §1 (septimo proceso y credencial: `chain-verifier` -> `integrity_chain_verifier`; D-1 (b), Carlos 2026-10-16), §2 (recomputo de la cadena SHA-256 por tenant: una tx REPEATABLE READ READ ONLY,
// asserts de arranque C5/C6, exit 0/2/1, tenants=0/events=0 = exit 1 salvo flag solo-LOCAL C7, aislamiento por tenant C8, log sin PII C9/C10), §3 fila PR-6f, F-PR6E-06, SEC-06-1/3/4/5/6; INV-DBR-02. specs/db-roles.spec.yaml.
//
// Logica del proceso chain-verifier (sin HTTP, sin egress, sin escrituras, SIN K_sub ni IdP: no importa ningun modulo OIDC ni del verifier). ENTRYPOINT (ADR-001 §11): puede importar adaptadores. Un pool UNICO del rol
// `integrity_chain_verifier` con chequeos de arranque (expectedRole, session_user = current_user, sin superusuario, sin GUC app.* ni role del cliente, URL saneada con assertSafeConnectionUrl, catalogo/environment):
// un rol equivocado NO arranca. El recomputo reutiliza el oraculo unico (modules/common/ledger-chain.ts) por la auditoria pura (modules/integrity/ledger-chain-audit.ts). No corrige ni escribe nada: la persistencia de
// checkpoints y de la cabeza por tenant llega en PR-7. Cero PII y cero secretos en logs: solo ids opacos, enums y conteos; nunca payloads, hashes ni refs de actor.

import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { forEachTenantChainInSnapshot } from "../../../infra/adapters/postgres/chain-verifier-reader.ts";
import { auditTenantChain, summarizeChainAudit } from "../../modules/integrity/ledger-chain-audit.ts";
import type { ChainAuditReport, TenantChainResult } from "../../modules/integrity/ledger-chain-audit.ts";

export { CHAIN_VERIFIER_EXIT, exitCodeFor, formatChainReport } from "../../modules/integrity/ledger-chain-audit.ts";

export const DEFAULT_BATCH = 500;
export const MIN_BATCH = 100;
export const MAX_BATCH = 5000;

/** Configuracion invalida (variable ajena al proceso, fuera de rango o combinacion prohibida). Mensajes sin valores. */
export class ChainVerifierConfigError extends Error {
  readonly code = "CHAIN_VERIFIER_CONFIG";
  constructor(detail: string) {
    super(`${detail}. Abortando (ADR-010 rev. 6, fail-closed).`);
    this.name = "ChainVerifierConfigError";
  }
}

/** La base esta vacia (0 tenants o 0 eventos) sin el flag solo-LOCAL: una base vacia nunca da verde (SEC-06-3, C7). */
export class ChainVerifierEmptyLedgerError extends Error {
  readonly code = "EMPTY_LEDGER";
  constructor() {
    super("el ledger no tiene tenants o eventos que verificar (una base vacia no es verde)");
    this.name = "ChainVerifierEmptyLedgerError";
  }
}

export interface ChainVerifierConfig {
  readonly batchSize: number;
  readonly allowEmpty: boolean;
}

const OWN_VARS = new Set(["CNS_CHAIN_VERIFIER_BATCH", "CNS_CHAIN_VERIFIER_ALLOW_EMPTY"]);

/**
 * Variables propias del proceso. Fail-closed (C7, C11): cualquier `CNS_VERIFIER_*` (credenciales y K_sub del verifier OIDC) en el entorno -inyectado o real- aborta; un `CNS_CHAIN_VERIFIER_*` desconocido o fuera de
 * rango aborta; `CNS_CHAIN_VERIFIER_ALLOW_EMPTY` solo existe en LOCAL (si aparece con otro CNS_ENVIRONMENT, aborta).
 */
export function parseChainVerifierConfig(env: Readonly<Record<string, string | undefined>>): ChainVerifierConfig {
  for (const source of [env, process.env as Readonly<Record<string, string | undefined>>]) {
    for (const key of Object.keys(source)) {
      if (key.startsWith("CNS_VERIFIER_")) throw new ChainVerifierConfigError("el entorno del chain-verifier no puede llevar variables CNS_VERIFIER_* (secretos del verifier OIDC)");
    }
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith("CNS_CHAIN_VERIFIER_") && !OWN_VARS.has(key)) throw new ChainVerifierConfigError("variable CNS_CHAIN_VERIFIER_* desconocida");
  }
  const rawBatch = env.CNS_CHAIN_VERIFIER_BATCH;
  let batchSize = DEFAULT_BATCH;
  if (rawBatch !== undefined) {
    if (!/^[0-9]{1,5}$/.test(rawBatch)) throw new ChainVerifierConfigError(`CNS_CHAIN_VERIFIER_BATCH debe ser un entero entre ${MIN_BATCH} y ${MAX_BATCH}`);
    batchSize = Number(rawBatch);
    if (batchSize < MIN_BATCH || batchSize > MAX_BATCH) throw new ChainVerifierConfigError(`CNS_CHAIN_VERIFIER_BATCH debe ser un entero entre ${MIN_BATCH} y ${MAX_BATCH}`);
  }
  const rawEmpty = env.CNS_CHAIN_VERIFIER_ALLOW_EMPTY;
  let allowEmpty = false;
  if (rawEmpty !== undefined) {
    if (rawEmpty !== "true" && rawEmpty !== "false") throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_ALLOW_EMPTY debe ser true o false");
    if (env.CNS_ENVIRONMENT !== "LOCAL") throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_ALLOW_EMPTY solo existe con CNS_ENVIRONMENT=LOCAL");
    allowEmpty = rawEmpty === "true";
  }
  return { batchSize, allowEmpty };
}

export interface ChainVerifierProcess {
  /** Una corrida completa. Lanza ante un error de arranque, de precondicion o de lectura (el llamador sale con ERROR). */
  run(): Promise<ChainAuditReport>;
  stop(): Promise<void>;
}

export interface StartChainVerifierProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** Arranque fail-closed: configuracion propia, environment (enum cerrado) y pool UNICO de `integrity_chain_verifier` con chequeos de arranque. Cualquier fallo lanza antes de leer nada. */
export async function startChainVerifierProcess(options: StartChainVerifierProcessOptions = {}): Promise<ChainVerifierProcess> {
  const env = options.env ?? process.env;
  const config = parseChainVerifierConfig(env);
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const pool = await openProcessPool({ process: "chain-verifier", environment, env, max: 1 });
  return {
    async run() {
      const results: TenantChainResult[] = [];
      const tenants = await forEachTenantChainInSnapshot(
        pool,
        async (input) => {
          results.push(await auditTenantChain(input.tenantId, input.batches, input.unchainedAfterStart));
        },
        {
          batchSize: config.batchSize,
          onReadable: ({ catalogEnvironment }) => {
            if (config.allowEmpty && catalogEnvironment !== "LOCAL") throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_ALLOW_EMPTY solo existe con un catalogo LOCAL");
          },
        },
      );
      const report = summarizeChainAudit(results);
      if ((tenants === 0 || report.events === 0) && !config.allowEmpty) throw new ChainVerifierEmptyLedgerError();
      return report;
    },
    stop: () => pool.end(),
  };
}
