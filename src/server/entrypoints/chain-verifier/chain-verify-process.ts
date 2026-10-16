// Gobierna: ADR-010 rev. 6 §1 (septimo proceso y credencial: `chain-verifier` -> `integrity_chain_verifier`; D-1 (b), Carlos 2026-10-16), §2 (recomputo de la cadena SHA-256 por tenant: una tx REPEATABLE READ READ ONLY,
// asserts de arranque C5/C6, exit 0/2/1, tenants=0/events=0 = exit 1 salvo flag solo-LOCAL C7, aislamiento por tenant C8, log sin PII C9/C10), §3 fila PR-6f, F-PR6E-06, SEC-06-1/3/4/5/6; INV-DBR-02. specs/db-roles.spec.yaml.
//
// PR-7b (rev. 6, F-PR6E-05): tras el snapshot RR READ ONLY (sin cambios) abre una tx corta READ WRITE y persiste `integrity.chain_run` + un checkpoint por tenant OK (unico INSERT del rol; chain-checkpoint-store.ts), calcula la
// raiz Merkle (SIN firma ni clave ni egress; C-7 pendiente) y detecta truncamiento de cola, tenant desaparecido y copia local en desacuerdo (exit 2). Copia de las ultimas cabezas en el StateDirectory 0600 del uid del proceso
// (CNS_CHAIN_VERIFIER_STATE_DIR; obligatoria fuera de LOCAL). C-10 (Carlos, 2026-10-16): antes de datos reales pasa a incremental desde la ultima cabeza publicada externamente (7f) + recomputo completo diario; en IT0b queda hourly (D-3).
//
// Logica del proceso chain-verifier (sin HTTP, sin egress, SIN K_sub ni IdP: no importa ningun modulo OIDC ni del verifier). ENTRYPOINT (ADR-001 §11): puede importar adaptadores. Un pool UNICO del rol
// `integrity_chain_verifier` con chequeos de arranque (expectedRole, session_user = current_user, sin superusuario, sin GUC app.* ni role del cliente, URL saneada con assertSafeConnectionUrl, catalogo/environment):
// un rol equivocado NO arranca. El recomputo reutiliza el oraculo unico (modules/common/ledger-chain.ts) por la auditoria pura (modules/integrity/ledger-chain-audit.ts). No corrige el ledger ni escribe nada fuera de chain_run/chain_checkpoint. Cero PII y cero secretos en logs: solo ids opacos, enums y conteos; nunca payloads, hashes ni refs de actor.

import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";

import { ChainHeadStateFile } from "../../../infra/adapters/chain-state/chain-head-state-file.ts";
import { anchorSignerIsNoLogin, persistChainRun } from "../../../infra/adapters/postgres/chain-checkpoint-store.ts";
import { forEachTenantChainInSnapshot } from "../../../infra/adapters/postgres/chain-verifier-reader.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { compareLocalHeads, merkleRoot, uniqueAnomalies, witnessHolds } from "../../modules/integrity/chain-checkpoint.ts";
import type { ChainAnomaly, ChainHead, HeadRef, LocalHeadState } from "../../modules/integrity/chain-checkpoint.ts";
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
  /** StateDirectory del proceso (ruta absoluta) para la copia local de cabezas. Obligatorio fuera de LOCAL (se exige al arrancar, tras validar el catalogo). */
  readonly stateDir: string | undefined;
}

const OWN_VARS = new Set(["CNS_CHAIN_VERIFIER_BATCH", "CNS_CHAIN_VERIFIER_ALLOW_EMPTY", "CNS_CHAIN_VERIFIER_STATE_DIR"]);

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
  const rawDir = env.CNS_CHAIN_VERIFIER_STATE_DIR;
  let stateDir: string | undefined;
  if (rawDir !== undefined) {
    if (!isAbsolute(rawDir) || rawDir.length > 200 || /[\u0000-\u001f]/.test(rawDir) || rawDir.split("/").includes("..")) throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_STATE_DIR debe ser una ruta absoluta sin '..'");
    stateDir = rawDir;
  }
  return { batchSize, allowEmpty, stateDir };
}

export interface ChainVerifierRunOptions {
  /** Se invoca con el reporte ANTES de persistirlo (P2-2): una falla de persistencia no puede esconder las anomalias detectadas. */
  readonly onReport?: (report: ChainAuditReport) => void;
}

/** integrity_anchor_signer debe seguir NOLOGIN hasta PR-7f (P2-4): si alguien lo habilito, el proceso no arranca. */
export class ChainVerifierSignerLoginError extends Error {
  readonly code = "ANCHOR_SIGNER_CAN_LOGIN";
  constructor() {
    super("integrity_anchor_signer no esta en NOLOGIN (o no existe) antes de PR-7f. Abortando (ADR-010 rev. 6, fail-closed)");
    this.name = "ChainVerifierSignerLoginError";
  }
}

export interface ChainVerifierProcess {
  /** Una corrida completa. Lanza ante un error de arranque, de precondicion o de lectura (el llamador sale con ERROR). */
  run(options?: ChainVerifierRunOptions): Promise<ChainAuditReport>;
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
  if (environment !== "LOCAL" && config.stateDir === undefined) {
    await pool.end();
    throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_STATE_DIR es obligatorio fuera de LOCAL (copia local de cabezas)");
  }
  try {
    if (!(await anchorSignerIsNoLogin(pool))) throw new ChainVerifierSignerLoginError();
  } catch (error) {
    await pool.end();
    throw error;
  }
  const stateFile = config.stateDir === undefined ? null : new ChainHeadStateFile(config.stateDir, environment);
  return {
    async run(runOptions: ChainVerifierRunOptions = {}) {
      const startedAt = new Date();
      const local: LocalHeadState | null = stateFile === null ? null : await stateFile.read();
      const localHeads: ReadonlyMap<string, HeadRef> = local?.status === "PRESENT" ? local.heads : new Map<string, HeadRef>();
      const results: TenantChainResult[] = [];
      const tailAnomalies: ChainAnomaly[] = [];
      const snapshot = await forEachTenantChainInSnapshot(
        pool,
        async (input) => {
          const result = await auditTenantChain(input.tenantId, input.batches, input.unchainedAfterStart);
          results.push(result);
          if (result.broken !== null) return; // rota: ya es exit 2; no se compara la cola de una cadena que no se pudo recorrer completa
          // Cada testigo (ultimo checkpoint de la base y copia local) debe existir identico en el ledger de ESTE snapshot (F-PR6E-05).
          for (const w of [input.previousHead, localHeads.get(input.tenantId) ?? null]) {
            if (w === null) continue;
            const hashAt = result.head >= w.chainSeq ? await input.hashAtSeq(w.chainSeq) : null;
            if (!witnessHolds(w, result.head, hashAt)) {
              tailAnomalies.push({ kind: "TAIL_TRUNCATED_OR_REWRITTEN", tenantId: input.tenantId });
              break;
            }
          }
        },
        {
          batchSize: config.batchSize,
          onReadable: ({ catalogEnvironment }) => {
            if (config.allowEmpty && catalogEnvironment !== "LOCAL") throw new ChainVerifierConfigError("CNS_CHAIN_VERIFIER_ALLOW_EMPTY solo existe con un catalogo LOCAL");
          },
        },
      );
      const anomalies: ChainAnomaly[] = [...tailAnomalies];
      // Tenants con cabeza persistida (base o copia local) que ya no aparecen en el ledger: borrado de un tenant entero.
      for (const t of new Set([...snapshot.checkpointHeads.keys(), ...localHeads.keys()])) {
        if (!snapshot.tenantIds.has(t)) anomalies.push({ kind: "TENANT_MISSING", tenantId: t });
      }
      if (local !== null) anomalies.push(...compareLocalHeads(local, snapshot.checkpointHeads, environment));
      const report = summarizeChainAudit(results, uniqueAnomalies(anomalies));
      // Base vacia sin anomalias = exit 1 (C7). Con anomalias (p. ej. todos los tenants desaparecieron) se informa como exit 2: es mas especifico.
      if ((snapshot.visited === 0 || report.events === 0) && !config.allowEmpty && report.anomalies.length === 0) throw new ChainVerifierEmptyLedgerError();

      // Persistencia (T-3: tx READ WRITE aparte). Checkpoint solo de tenants plenamente OK; raiz Merkle solo si TODA la corrida es exit 0 (CHECK de la base).
      const flagged = new Set(report.anomalies.map((a) => a.tenantId));
      const heads: ChainHead[] = [];
      const checkpoints = [];
      for (const r of results) {
        if (r.broken !== null || r.unchainedAfterStart > 0 || flagged.has(r.tenantId) || r.head < 1 || r.headHash === null) continue;
        heads.push({ tenantId: r.tenantId, chainSeq: r.head, eventHash: r.headHash });
        checkpoints.push({ tenantId: r.tenantId, chainSeq: r.head, eventHash: r.headHash, verifiedEvents: r.verified });
      }
      const merkle = report.ok ? merkleRoot(heads) : null;
      runOptions.onReport?.(report);
      try {
        await persistChainRun(
          pool,
          {
            runId: randomUUID(),
            startedAt,
            environment,
            tenants: report.tenants,
            events: report.events,
            exitCode: report.ok ? 0 : 2,
            leafCount: merkle?.leafCount ?? 0,
            merkleRoot: merkle?.root ?? null,
            merkleFormat: merkle?.format ?? null,
          },
          checkpoints,
        );
      } catch (error) {
        // P2-2: con anomalias el resultado es exit 2 aunque falle la persistencia (no se degrada a exit 1); sin anomalias, la falla es exit 1.
        if (report.ok) throw error;
        console.error("chain_verify_persist_failed (el reporte anterior sigue vigente: exit 2)");
        return report;
      }
      // La copia local se escribe DESPUES del commit: la base puede ir por delante, nunca por detras (compareLocalHeads). Los tenants no actualizados conservan su cabeza anterior.
      // Con una anomalia GLOBAL (copia ilegible o ausente fuera de LOCAL) NO se reescribe: sanar la copia sin intervencion borraria el hallazgo en la corrida siguiente (decision humana).
      if (stateFile !== null && !report.anomalies.some((a) => a.tenantId === null)) {
        const next = new Map<string, HeadRef>(localHeads);
        for (const h of heads) next.set(h.tenantId, { chainSeq: h.chainSeq, eventHash: h.eventHash });
        await stateFile.write(next);
      }
      return report;
    },
    stop: () => pool.end(),
  };
}
