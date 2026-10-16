// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a puntos 4 y 5 (G-3, lectura (A)); src/server/modules/revocation/apply-guard.ts; db/migrations/0067 (ops.record_revocation_apply_alert)
// y 0070 (case_state.alert_apply_exhausted). Fabrica de la configuracion del guardia de R4 para web (alerta por ops.record_revocation_apply_alert en una tx de tenant SEPARADA) y platform (alerta por la sesion CASE).
// Sin PII: el log de respaldo lo emite apply-guard.ts con codigo de motivo, ref opaca y hora.

import { DEFAULT_APPLY_MAX_ATTEMPTS } from "../../../server/modules/revocation/apply-guard.ts";
import type { ApplyAlertSink, ApplyGuardConfig } from "../../../server/modules/revocation/apply-guard.ts";
import { isTransientTxError } from "./transient-error.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

export interface ApplyGuardOptions {
  readonly maxAttempts?: number;
  readonly backoffBaseMs?: number;
  readonly backoffCapMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly log?: (line: string) => void;
  readonly now?: () => Date;
}

export function createApplyGuardConfig(alert: ApplyAlertSink, options: ApplyGuardOptions = {}): ApplyGuardConfig {
  const base = options.backoffBaseMs ?? 50;
  const cap = options.backoffCapMs ?? 500;
  return {
    maxAttempts: options.maxAttempts ?? DEFAULT_APPLY_MAX_ATTEMPTS,
    backoffMs: (attempt) => Math.floor(Math.random() * Math.min(cap, base * 2 ** (attempt - 1))),
    sleep: options.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
    isTransient: isTransientTxError,
    alert,
    log: options.log ?? ((line) => console.error(line)),
    now: options.now ?? (() => new Date()),
  };
}

/** Alerta de web/worker: tx de tenant SEPARADA (el tenant del caso; la base lo toma del GUC de la unidad de trabajo). */
export function createTenantAlertSink(uow: PgUnitOfWork): ApplyAlertSink {
  return async ({ tenantId, revocationRef, reason }) => {
    await uow.withTenantTx(tenantId, async (tx) => {
      await tx.query("SELECT ops.record_revocation_apply_alert($1::text, $2::text)", [revocationRef, reason]);
    });
  };
}
