// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a, §4.2.d, §6, §10 fila 6d; specs/db-roles.spec.yaml (platform_rw -> rights_operator SET LOCAL ROLE; approve_case_verification
// EXECUTE platform_rw); db/migrations/0068-0070; src/server/ports/platform-case.port.ts; ADR-001 §11 (solo adapters conocen el SQL).
//
// Cada accion corre en UNA transaccion del pool de platform_rw: BEGIN; set_config('app.session_sid', sid, true) (la BASE valida la sesion y deriva actor, tenant y Revocation); para las de operador
// `SET LOCAL ROLE rights_operator`; UNA funcion de case_state; COMMIT. Nunca se declara principal, tenant ni revocationRef. Un {denied} (step-up) confirma la evidencia y devuelve STEP_UP; RC004 = sesion/caso no valido
// (NOT_FOUND uniforme); SQLSTATE RVxxx/RCxxx = guard de dominio; cualquier otro error se relanza (el guardia de R4 decide si es transitorio). El sid es secreto de sesion: no se registra.

import { DomainError } from "../../../server/modules/common/errors.ts";
import { runBoundedApply } from "../../../server/modules/revocation/apply-guard.ts";
import type { ApplyGuardConfig } from "../../../server/modules/revocation/apply-guard.ts";
import type { CaseOutcome, PlatformCasePort } from "../../../server/ports/platform-case.port.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";
import { mapTransitionError } from "./revocation-transitions.adapter.ts";
import { retryRolledBack } from "./transient-error.ts";

const SID_RE = /^[0-9a-f]{64}$/;

type Actor = "OPERATOR" | "PLATFORM";

export interface PlatformCaseAdapterOptions {
  /** G-3: guardia de R4 para cosign (reintentos acotados, commit ambiguo, alerta). Ausente = un solo intento. */
  readonly applyGuard?: ApplyGuardConfig;
}

export function createPgPlatformCase(pool: PoolLike, options: PlatformCaseAdapterOptions = {}): PlatformCasePort {
  // PR-7a: una tx revertida (clase 40, 55P03) se reintenta con tope; agotado, se relanza el error crudo (el borde responde 503 uniforme).
  function exec(sid: string, actor: Actor, sql: string, params: readonly unknown[]): Promise<CaseOutcome> {
    return retryRolledBack(() => execOnce(sid, actor, sql, params));
  }

  async function execOnce(sid: string, actor: Actor, sql: string, params: readonly unknown[]): Promise<CaseOutcome> {
    if (!SID_RE.test(sid)) return { ok: false, reason: "NOT_FOUND" };
    const client = await acquireCleanClient(pool);
    let broken = false;
    try {
      await client.query("BEGIN");
      try {
        await client.query("SELECT set_config('app.session_sid', $1, true)", [sid]);
        if (actor === "OPERATOR") await client.query("SET LOCAL ROLE rights_operator");
        const r = await client.query<{ r: Record<string, unknown> | null }>(sql, [...params]);
        const value = r.rows[0]?.r ?? null;
        await client.query("COMMIT");
        if (value === null) return { ok: false, reason: "NOT_FOUND" };
        if (typeof value.denied === "string") return { ok: false, reason: "STEP_UP" };
        return { ok: true, data: value };
      } catch (error) {
        try {
          await client.query("ROLLBACK");
        } catch {
          broken = true;
        }
        const code = (error as { code?: unknown } | null)?.code;
        if (code === "RC004" || code === "42501") return { ok: false, reason: "NOT_FOUND" };
        const mapped = mapTransitionError(error);
        if (mapped instanceof DomainError) return { ok: false, reason: mapped.code };
        throw error;
      }
    } finally {
      client.release(broken);
    }
  }

  const op = (sid: string, sql: string, params: readonly unknown[]): Promise<CaseOutcome> => exec(sid, "OPERATOR", sql, params);
  // Los intentos de co-firma NO llevan reintento interno: los acota el guardia de R4 (G-3, maxAttempts); anidar reintentos multiplicaria los intentos de cosign.
  const opOnce = (sid: string, sql: string, params: readonly unknown[]): Promise<CaseOutcome> => execOnce(sid, "OPERATOR", sql, params);

  return {
    propose: (i) => op(i.sid, "SELECT case_state.propose_case_verification($1::text, $2::text, $3::text, $4::integer, $5::integer) AS r", [i.caseRef, i.proposalRef, i.scriptVersion, i.limit.max, i.limit.windowSeconds]),
    approve: (i) => exec(i.sid, "PLATFORM", "SELECT case_state.approve_case_verification($1::text, $2::text, $3::integer, $4::integer) AS r", [i.caseRef, i.proposalRef, i.limit.max, i.limit.windowSeconds]),
    withdraw: (i) => op(i.sid, "SELECT case_state.withdraw_case_verification_proposal($1::text, $2::text, $3::integer, $4::integer) AS r", [i.caseRef, i.proposalRef, i.limit.max, i.limit.windowSeconds]),
    record: (i) => op(i.sid, "SELECT case_state.record_case_confirmation($1::text) AS r", [i.caseRef]),
    close: (i) => op(i.sid, "SELECT case_state.close_case($1::text, $2::text) AS r", [i.caseRef, i.outcome]),
    async cosign(i) {
      const attempt = (): Promise<CaseOutcome> => opOnce(i.sid, "SELECT case_state.cosign_case_confirmation($1::text) AS r", [i.caseRef]);
      const guard = options.applyGuard;
      if (guard === undefined) return attempt();
      // La alerta del agotamiento va por la sesion CASE (tx aparte); la lectura previa al reintento es una funcion de estado SIN efectos (read_case_apply_state): si la misma co-firma ya quedo APPLIED se devuelve el resultado real, sin alerta.
      const withAlert: ApplyGuardConfig = {
        ...guard,
        alert: async ({ reason }) => {
          if (reason !== "R4_RETRIES_EXHAUSTED" && reason !== "R4_APPLY_FAILED") return;
          const r = await op(i.sid, "SELECT case_state.alert_apply_exhausted($1::text, $2::text) AS r", [i.caseRef, reason]);
          if (!r.ok) throw new Error("alert_not_persisted");
        },
      };
      return runBoundedApply(
        withAlert,
        { tenantId: "", revocationRef: () => i.caseRef },
        attempt,
        // Lectura REAL de estado, sin efectos (read_case_apply_state): nunca otra ejecucion de cosign (F-6D2-QA-02).
        async () => {
          const state = await op(i.sid, "SELECT case_state.read_case_apply_state($1::text) AS r", [i.caseRef]);
          return state.ok && state.data.applied === true ? { ok: true, data: state.data } : null;
        },
      );
    },
  };
}
