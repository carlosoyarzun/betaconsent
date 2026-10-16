// Gobierna: ADR-010 rev. 5 §2 (sexto proceso y credencial: `reconciler` -> `integrity_reconciler`, G-9), §4.2.c (hasta PR-7: exit code != 0 ante cualquier divergencia y log SIN PII: ids opacos,
// tipo de divergencia y conteos, sin payloads), §10 fila 6e, F-PR6-29; INV-DBR-02 (cada proceso arranca solo con su rol exacto), INV-DBR-08. specs/db-roles.spec.yaml.
//
// Logica del proceso reconciler (sin HTTP, sin egress, sin escrituras). ENTRYPOINT (ADR-001 §11): puede importar adaptadores. Un pool UNICO del rol `integrity_reconciler` con chequeos de arranque
// (expectedRole, session_user = current_user, sin superusuario, sin GUC app.* ni role del cliente, URL saneada con assertSafeConnectionUrl, catalogo/environment): un rol equivocado NO arranca.
// Cada corrida concilia estado <-> ledger (modules/integrity/ledger-reconciliation.ts) en un snapshot. NO recomputa la cadena SHA-256: no lee hashes ni payload (7 columnas, 0057) y el recomputo es del proceso
// `chain-verifier` (entrypoints/chain-verifier/, ADR-010 rev. 6, F-PR6E-06; F-06-A). No corrige ni escribe nada: la persistencia de la conciliacion llega en PR-7 (§4.2.c). Cero PII y cero secretos en logs: solo ids opacos, tipos de evento, enums y conteos; nunca payloads ni hashes.

import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { forEachTenantInSnapshot } from "../../../infra/adapters/postgres/reconciler-reader.ts";
import { reconcileTenant } from "../../modules/integrity/ledger-reconciliation.ts";
import type { Divergence, ReconciliationReport } from "../../modules/integrity/ledger-reconciliation.ts";

/** Exit codes del proceso: 0 conciliado, 2 divergencias, 1 arranque fallido o error de lectura (fail-closed). */
export const RECONCILER_EXIT = { OK: 0, ERROR: 1, DIVERGENCE: 2 } as const;
/** Tope de lineas de detalle por corrida (el conteo total siempre se informa). */
export const MAX_LOGGED_DIVERGENCES = 200;

export interface ReconcilerProcess {
  /** Una corrida completa. Lanza ante un error de lectura (el llamador sale con ERROR). */
  run(): Promise<ReconciliationReport>;
  stop(): Promise<void>;
}

export interface StartReconcilerProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** Arranque fail-closed: environment (enum cerrado) y pool UNICO de `integrity_reconciler` con chequeos de arranque. Cualquier fallo lanza antes de leer nada. */
export async function startReconcilerProcess(options: StartReconcilerProcessOptions = {}): Promise<ReconcilerProcess> {
  const env = options.env ?? process.env;
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const pool = await openProcessPool({ process: "reconciler", environment, env, max: 1 });
  return {
    async run() {
      const divergences: Divergence[] = [];
      let events = 0;
      const tenants = await forEachTenantInSnapshot(pool, (input) => {
        events += input.events.length;
        divergences.push(...reconcileTenant(input));
      });
      const byKind: Record<string, number> = {};
      for (const d of divergences) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;
      return { ok: divergences.length === 0, tenants, events, divergences, byKind };
    },
    stop: () => pool.end(),
  };
}

/** Una ref opaca solo se imprime si tiene forma de identificador; si no, se enmascara (defensa en profundidad: nunca texto libre de una fila). */
const OPAQUE_ID = /^[0-9A-Za-z_.:-]{1,100}$/;
const safeId = (value: string | undefined): string => (value === undefined ? "-" : OPAQUE_ID.test(value) ? value : "?");
const safeToken = (value: string | undefined): string => (value === undefined ? "-" : /^[A-Za-z0-9_:]{1,100}$/.test(value) ? value : "?");

/** Lineas de log de una corrida (sin PII). La primera resume; luego una por divergencia hasta el tope. */
export function formatReport(report: ReconciliationReport): string[] {
  const kinds = Object.entries(report.byKind).sort(([a], [b]) => a.localeCompare(b)).map(([k, n]) => `${k}=${n}`).join(",");
  const lines = [`reconciler_run ok=${report.ok} tenants=${report.tenants} events=${report.events} divergences=${report.divergences.length}${kinds === "" ? "" : ` kinds=${kinds}`}`];
  for (const d of report.divergences.slice(0, MAX_LOGGED_DIVERGENCES)) {
    lines.push(
      `reconciler_divergence kind=${d.kind} tenant=${safeId(d.tenantId)} aggregateType=${safeToken(d.aggregateType)} aggregate=${safeId(d.aggregateId)} detail=${safeToken(d.detail)}${d.chainSeq === undefined ? "" : ` chainSeq=${d.chainSeq}`}`,
    );
  }
  if (report.divergences.length > MAX_LOGGED_DIVERGENCES) lines.push(`reconciler_divergences_truncated shown=${MAX_LOGGED_DIVERGENCES} total=${report.divergences.length}`);
  return lines;
}

export function exitCodeFor(report: ReconciliationReport): number {
  return report.ok ? RECONCILER_EXIT.OK : RECONCILER_EXIT.DIVERGENCE;
}
