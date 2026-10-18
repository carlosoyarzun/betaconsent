// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a puntos 4 y 5 (G-3, lectura (A)); src/server/modules/revocation/apply-guard.ts; db/migrations/0067 (ops.record_revocation_apply_alert)
// y 0070 (case_state.alert_apply_exhausted). Fabrica de la configuracion del guardia de R4 para web (alerta por ops.record_revocation_apply_alert en una tx de tenant SEPARADA) y platform (alerta por la sesion CASE).
// Sin PII: el log de respaldo lo emite apply-guard.ts con codigo de motivo, ref opaca y hora.

import { DomainError } from "../../../server/modules/common/errors.ts";
import { DEFAULT_APPLY_MAX_ATTEMPTS } from "../../../server/modules/revocation/apply-guard.ts";
import type { ApplyAlertSink, ApplyAttemptOutcome, ApplyAttemptSink, ApplyGuardConfig } from "../../../server/modules/revocation/apply-guard.ts";
import { isTransientTxError } from "./transient-error.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

export interface ApplyGuardOptions {
  /** 2B (C6): registro durable del intento no aplicado. Web lo exige (assertWebApplyGuard); platform no lo lleva. */
  readonly attemptSink?: ApplyAttemptSink;
  readonly maxAttempts?: number;
  readonly backoffBaseMs?: number;
  readonly backoffCapMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly log?: (line: string) => void;
  readonly now?: () => Date;
}

/** Guard de dominio = DomainError ya mapeado o SQLSTATE de guard de las funciones case_state (RVxxx, RCxxx, IV009). Todo lo demas (XX000, privilegios, programa) NO es un guard y alerta. */
export function isDomainGuardError(error: unknown): boolean {
  if (error instanceof DomainError) return true;
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^(RV|RC|IV)\d{3}$/.test(code);
}

export function createApplyGuardConfig(alert: ApplyAlertSink, options: ApplyGuardOptions = {}): ApplyGuardConfig {
  const base = options.backoffBaseMs ?? 50;
  const cap = options.backoffCapMs ?? 500;
  return {
    maxAttempts: options.maxAttempts ?? DEFAULT_APPLY_MAX_ATTEMPTS,
    backoffMs: (attempt) => Math.floor(Math.random() * Math.min(cap, base * 2 ** (attempt - 1))),
    sleep: options.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
    isTransient: isTransientTxError,
    isDomainGuard: isDomainGuardError,
    alert,
    ...(options.attemptSink === undefined ? {} : { attemptSink: options.attemptSink }),
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

const OUTCOMES: ReadonlySet<string> = new Set<ApplyAttemptOutcome>(["RECORDED", "DUPLICATE", "NOOP_APPLIED", "NOOP_CAPPED"]);

/**
 * 2B: registro del intento en una tx de tenant SEPARADA (posterior a la alerta). El tenant NUNCA es parametro: la funcion lo toma de app.current_tenant_id() (R-09: el GUC lo fija app_rw; aceptado solo IT0).
 * La funcion case_state.record_revocation_apply_attempt (EXECUTE solo app_rw) valida la matriz de estados, el token y el tope por ciclo; ante un caso no admitido lanza (el guardia cae al log).
 */
export function createTenantAttemptSink(uow: PgUnitOfWork): ApplyAttemptSink {
  return async ({ tenantId, attemptId, attemptRef, recoveryRef, reason, tries }) =>
    uow.withTenantTx(tenantId, async (tx) => {
      const r = await tx.query<{ outcome: string }>(
        "SELECT case_state.record_revocation_apply_attempt($1::uuid, $2::text, $3::text, $4::text, $5::integer) AS outcome",
        [attemptId, attemptRef, recoveryRef ?? null, reason, tries],
      );
      const outcome = r.rows[0]?.outcome;
      if (outcome === undefined || !OUTCOMES.has(outcome)) throw new Error("resultado de registro 2B inesperado");
      return outcome as ApplyAttemptOutcome;
    });
}

/** C6 (SEC-2B-10): el proceso web NO arranca con la guardia de R4 sin sink de registro 2B (fail-closed). Platform no llama a esta funcion. */
export function assertWebApplyGuard(config: ApplyGuardConfig): ApplyGuardConfig {
  if (config.attemptSink === undefined) throw new Error("web: la guardia de R4 exige ApplyAttemptSink (registro 2B, C6). Abortando (fail-closed).");
  return config;
}
