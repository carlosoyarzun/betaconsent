// Gobierna: ADR-010 rev. 4 §4.2 (funciones SYSTEM: EXECUTE solo `worker`, GRD-CM-15), §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; ... pools por rol"), INV-DBR-02;
// specs/state-machines/revocation.spec.yaml R5/R6/R7 (FN-RV-13..15, executedBy worker), "CARLOS r3 R5-1" (stub interno como unico consumidor en IT0); db/migrations/0042.
// ADR-010 rev. 5 (6d parte 2, G-3 lectura (A)): R4 corre EN LINEA con R3/R3r/RH3 en la base (atomica). El worker es el PROCESO DE RESPALDO: solo atiende Revocation CONFIRMED sin APPLIED (filas anteriores a 0066 o
// una anomalia) con case_state.apply_revocation (idempotente por expected_sequence) y emite alerta sin PII (R4_BACKUP_APPLIED / R4_BACKUP_FAILED). NUNCA ejecuta R3 en nombre del titular: R3 es una accion HUMAN.
//
// Logica del proceso worker (sin HTTP). ENTRYPOINT (ADR-001 §11): puede importar adaptadores. Un pool UNICO del rol `worker` con chequeos de arranque (expectedRole = worker).
// Un ciclo hace: (1) purga de canjes OIDC vencidos (platform.purge_expired_oidc_exchange); (2) claim del outbox (app.outbox_claim, sin tenant) y, por cada evento consent.revoked,
// R5 -> R6 -> R7 de la Revocation contra el stub interno. Las transiciones las escriben las funciones case_state.* (SYSTEM_GUARD); el worker no tiene DML directo.
// IT0 sintetico: el unico consumidor downstream es el stub en memoria (LOCAL); firma la evidencia el propio proceso porque el stub representa al consumidor. Fuera de LOCAL no hay
// consumidor downstream: el ciclo NO reclama el outbox ni ejecuta R5-R7 (sin funcion de acuse ni tope de intentos todavia: F-PR6-20).
// Cero PII y cero secretos en logs: solo contadores y nombres de error.

import { createHash } from "node:crypto";
import { createInMemoryDownstreamStub } from "../../../infra/adapters/in-memory-downstream-stub.adapter.ts";
import type { InMemoryDownstreamStub } from "../../../infra/adapters/in-memory-downstream-stub.adapter.ts";
import { claimOutbox, readOutboxEnvelope } from "../../../infra/adapters/postgres/outbox.adapter.ts";
import { acquireCleanClient } from "../../../infra/adapters/postgres/pool.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import type { ProcessPool, RuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { createForbiddenOutsideTxPorts } from "../../../infra/adapters/postgres/store.ts";
import { PgUnitOfWork } from "../../../infra/adapters/postgres/unit-of-work.ts";
import { attestDownstreamErasure, emitRevocationDownstream, recordDownstreamAck } from "../../modules/revocation/downstream.ts";
import type { RevocationPorts } from "../../modules/revocation/revocation.ts";
import type { DownstreamEvidence, DownstreamEvidenceKind } from "../../ports/downstream-stub.port.ts";

export interface WorkerCycleResult {
  /** Canjes OIDC vencidos purgados. */
  readonly purgedExchanges: number;
  /** Eventos del outbox reclamados en el ciclo. */
  readonly claimed: number;
  /** Revocations que llegaron a COMPLETED (R5-R7) en este ciclo. */
  readonly completed: number;
  /** Eventos cuyo procesamiento fallo (se reintentan al vencer el lease del claim). */
  readonly failed: number;
  /** Respaldo de R4 (G-3): Revocation CONFIRMED sin APPLIED que este ciclo aplico / no pudo aplicar. */
  readonly recoveredR4: number;
  readonly recoveryFailedR4: number;
}

export interface WorkerProcess {
  cycle(): Promise<WorkerCycleResult>;
  stop(): Promise<void>;
}

const FAIL_CLOSED = (name: string) => (): never => {
  throw new Error(`${name} no esta disponible en el proceso worker (fail-closed)`);
};

/** Puertos de revocation del worker: solo uow + stub. Todo lo que el worker no usa falla cerrado. */
export function createWorkerRevocationPorts(uow: PgUnitOfWork, stub: InMemoryDownstreamStub): RevocationPorts {
  return {
    ...createForbiddenOutsideTxPorts(),
    recoveryLinkChannel: { send: FAIL_CLOSED("recoveryLinkChannel") } as unknown as RevocationPorts["recoveryLinkChannel"],
    recoveryTokenPolicy: { ttlMs: 0 },
    tenantResolver: new Proxy({}, { get: FAIL_CLOSED("tenantResolver") }) as unknown as RevocationPorts["tenantResolver"],
    uow,
    downstreamStub: stub,
  } as RevocationPorts;
}

/** Ref de evidencia determinista (idempotencia (revocationRef, ackRef|attestationRef) entre reintentos), con forma UUID v4. */
function evidenceRef(kind: DownstreamEvidenceKind, tenantId: string, revocationRef: string, subscriptionRef: string): string {
  const h = createHash("sha256").update(`${kind}\u0000${tenantId}\u0000${revocationRef}\u0000${subscriptionRef}`, "utf8").digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

async function stubEvidence(stub: InMemoryDownstreamStub, kind: DownstreamEvidenceKind, tenantId: string, revocationRef: string): Promise<DownstreamEvidence[]> {
  const refs = await stub.currentSubscriptionRefs(tenantId);
  return refs.map((subscriptionRef) => {
    const ref = evidenceRef(kind, tenantId, revocationRef, subscriptionRef);
    return { subscriptionRef, evidenceRef: ref, signature: stub.sign(tenantId, kind, revocationRef, subscriptionRef, ref) };
  });
}

/** R5 -> R6 -> R7 (idempotentes) de UNA Revocation contra el stub interno. Devuelve el estado final. */
export async function runDownstreamForRevocation(ports: RevocationPorts, stub: InMemoryDownstreamStub, tenantId: string, revocationRef: string): Promise<string> {
  await emitRevocationDownstream(ports, tenantId, revocationRef);
  await recordDownstreamAck(ports, tenantId, revocationRef, await stubEvidence(stub, "ACK", tenantId, revocationRef));
  const done = await attestDownstreamErasure(ports, tenantId, revocationRef, await stubEvidence(stub, "ERASURE_CONFIRMED", tenantId, revocationRef));
  return done.status;
}

export interface R4RecoveryResult {
  readonly applied: number;
  readonly failed: number;
}

/**
 * Respaldo de R4 (ADR-010 rev. 5 §4.2.a, G-3): encuentra (cross-tenant, solo CONFIRMED: policy revocation_worker_recovery_select) las Revocation CONFIRMED sin APPLIED y las aplica con
 * case_state.apply_revocation en una tx de su tenant; cada aplicacion deja una alerta R4_BACKUP_APPLIED en la misma tx. Un fallo deja la Revocation como estaba, escribe R4_BACKUP_FAILED en una tx
 * aparte (si tambien falla, log sin PII) y no detiene el ciclo. Sin PII: refs opacas y codigos.
 */
export async function recoverConfirmedRevocations(pool: ProcessPool, uow: PgUnitOfWork, batchSize = 20, log: (line: string) => void = (l) => console.error(l)): Promise<R4RecoveryResult> {
  const client = await acquireCleanClient(pool);
  let pending: Array<{ tenant_id: string; revocation_ref: string }> = [];
  try {
    pending = (await client.query<{ tenant_id: string; revocation_ref: string }>(
      "SELECT tenant_id, revocation_ref FROM app.revocation WHERE status = 'CONFIRMED' ORDER BY created_at, revocation_ref LIMIT $1", [batchSize],
    )).rows;
  } finally {
    client.release();
  }
  let applied = 0;
  let failed = 0;
  for (const row of pending) {
    try {
      await uow.withTenantTx(row.tenant_id, async (tx) => {
        const seq = Number((await tx.query<{ n: number }>("SELECT COALESCE(max(sequence), 0)::integer AS n FROM integrity.audit_event WHERE aggregate_id = $1", [row.revocation_ref])).rows[0]?.n ?? 0);
        await tx.query("SELECT case_state.apply_revocation($1::text, $2::integer)", [row.revocation_ref, seq]);
        await tx.query("SELECT ops.record_revocation_apply_alert($1::text, 'R4_BACKUP_APPLIED')", [row.revocation_ref]);
      });
      applied++;
    } catch (error) {
      failed++;
      log(`worker_r4_backup_error name=${(error as Error).name}${typeof (error as { code?: unknown }).code === "string" ? ` code=${(error as { code: string }).code}` : ""}`);
      try {
        await uow.withTenantTx(row.tenant_id, async (tx) => {
          await tx.query("SELECT ops.record_revocation_apply_alert($1::text, 'R4_BACKUP_FAILED')", [row.revocation_ref]);
        });
      } catch {
        log(`revocation_apply_alert reason=R4_BACKUP_FAILED ref=${row.revocation_ref} at=${new Date().toISOString()} persisted=false`);
      }
    }
  }
  return { applied, failed };
}

export interface WorkerCycleDeps {
  readonly pool: ProcessPool;
  readonly environment: RuntimeEnvironment;
  readonly stub?: InMemoryDownstreamStub;
  readonly batchSize?: number;
}

export async function runWorkerCycle(deps: WorkerCycleDeps): Promise<WorkerCycleResult> {
  const uow = new PgUnitOfWork(deps.pool);
  const stub = deps.stub ?? createInMemoryDownstreamStub();
  const ports = createWorkerRevocationPorts(uow, stub);

  let purgedExchanges = 0;
  let claimedRefs: Awaited<ReturnType<typeof claimOutbox>> = [];
  const client = await acquireCleanClient(deps.pool);
  try {
    const purged = await client.query<{ n: number }>("SELECT platform.purge_expired_oidc_exchange() AS n");
    purgedExchanges = Number(purged.rows[0]?.n ?? 0);
    // Fuera de LOCAL no hay consumidor downstream: NO se reclama el outbox (reclamar sin procesar infla `attempts` y retrasa a quien si lo procesara). F-PR6-20.
    if (deps.environment === "LOCAL") claimedRefs = await claimOutbox(client, deps.batchSize ?? 20);
  } finally {
    client.release();
  }

  let completed = 0;
  let failed = 0;
  for (const ref of claimedRefs) {
    try {
      const envelope = await uow.withTenantTx(ref.tenantId, (tx) => readOutboxEnvelope(tx, ref.eventId));
      if (envelope === null) continue;
      const status = await runDownstreamForRevocation(ports, stub, ref.tenantId, envelope.payload.revocationRef);
      if (status === "COMPLETED") completed++;
    } catch (error) {
      failed++;
      console.error(`worker_event_error name=${(error as Error).name}${typeof (error as { code?: unknown }).code === "string" ? ` code=${(error as { code: string }).code}` : ""}`);
    }
  }
  const recovery = await recoverConfirmedRevocations(deps.pool, uow, deps.batchSize ?? 20);
  return { purgedExchanges, claimed: claimedRefs.length, completed, failed, recoveredR4: recovery.applied, recoveryFailedR4: recovery.failed };
}

export interface StartWorkerProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** Arranque fail-closed: environment (enum cerrado) y pool UNICO del rol `worker` con chequeos de arranque (expectedRole = worker, catalogo, membresias). */
export async function startWorkerProcess(options: StartWorkerProcessOptions = {}): Promise<WorkerProcess> {
  const env = options.env ?? process.env;
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const pool = await openProcessPool({ process: "worker", environment, env, max: 4 });
  const stub = createInMemoryDownstreamStub();
  return { cycle: () => runWorkerCycle({ pool, environment, stub }), stop: () => pool.end() };
}

export async function runWorkerLoop(proc: WorkerProcess, signal: AbortSignal, pollMs = 2000): Promise<void> {
  while (!signal.aborted) {
    let busy = false;
    try {
      const r = await proc.cycle();
      busy = r.claimed > 0;
    } catch (error) {
      console.error(`worker_cycle_error name=${(error as Error).name}`);
    }
    if (!busy) await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, pollMs);
      signal.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
    });
  }
}
