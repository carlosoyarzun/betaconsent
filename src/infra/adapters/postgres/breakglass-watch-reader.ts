// Gobierna: ADR-010 rev. 6 §4.5.3 (vigilancia de break-glass), F-PR7-03, T-8 de plan PR-7 v3 (timer propio de 1 min en el chain-verifier, sin egress ni credencial nueva), Q-20 (c), C-9 (Carlos 2026-10-16: quien vigila el break-glass es el
// chain-verifier, no el verifier); specs/db-roles.spec.yaml rev. 0.8 (integrity_chain_verifier: USAGE breakglass y SELECT por columnas de breakglass.ceremony, 0085). PR-7e.
//
// Lectura del estado de break-glass con el rol integrity_chain_verifier: LOGIN de ddl_breakglass (pg_roles), sesiones de ddl_breakglass (pg_stat_activity, solo conteo) y ceremonias abiertas
// (breakglass.ceremony: referencia opaca y ventana). Solo lectura; nunca datos del dominio ni de personas.

import { checkBreakglassState, checkDbRoleSettings } from "./database-level.ts";
import type { Queryable } from "./pool.ts";

export interface OpenCeremony {
  readonly ceremonyRef: string;
  readonly openedAtMs: number;
  readonly validUntilMs: number;
}

export interface BreakglassSnapshot {
  readonly nowMs: number;
  readonly canLogin: boolean | null;
  /** Sesiones de ddl_breakglass visibles en pg_stat_activity (null: la vista no las muestra a este rol). */
  readonly sessions: number | null;
  readonly openCeremonies: readonly OpenCeremony[];
  /** Diferencias del estado EXACTO del esquema breakglass y de pg_db_role_setting (F-PR7D-02/05); vacio o ausente = exacto. Solo nombres de objeto y de rol. */
  readonly stateProblems?: readonly string[];
}

export type BreakglassFindingCode = "LOGIN_WITHOUT_CEREMONY" | "SESSION_WITHOUT_CEREMONY" | "CEREMONY_OVERDUE" | "ROLE_NOT_FOUND" | "STATE_DRIFT";

export interface BreakglassFinding {
  readonly code: BreakglassFindingCode;
  /** Referencia opaca de la ceremonia (nunca personas). */
  readonly ceremonyRef?: string;
}

export async function readBreakglassSnapshot(db: Queryable): Promise<BreakglassSnapshot> {
  const state = await db.query<{ now_ms: string; can_login: boolean | null; sessions: string | number | null }>(
    `SELECT (pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000)::pg_catalog.int8::pg_catalog.text AS now_ms,
            (SELECT r.rolcanlogin FROM pg_catalog.pg_roles r WHERE r.rolname = 'ddl_breakglass') AS can_login,
            (SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity a WHERE a.usename = 'ddl_breakglass') AS sessions`,
  );
  const ceremonies = await db.query<{ ceremony_ref: string; opened_ms: string; valid_ms: string }>(
    `SELECT c.ceremony_ref, (pg_catalog.date_part('epoch', c.opened_at) * 1000)::pg_catalog.int8::pg_catalog.text AS opened_ms,
            (pg_catalog.date_part('epoch', c.valid_until) * 1000)::pg_catalog.int8::pg_catalog.text AS valid_ms
       FROM breakglass.ceremony c WHERE c.closed_at IS NULL ORDER BY c.opened_at`,
  );
  const row = state.rows[0];
  return {
    nowMs: Number(row?.now_ms),
    canLogin: row?.can_login ?? null,
    sessions: row?.sessions === null || row?.sessions === undefined ? null : Number(row.sessions),
    openCeremonies: ceremonies.rows.map((c) => ({ ceremonyRef: c.ceremony_ref, openedAtMs: Number(c.opened_ms), validUntilMs: Number(c.valid_ms) })),
    stateProblems: [...(await checkBreakglassState(db)), ...(await checkDbRoleSettings(db))],
  };
}

/**
 * Evaluacion pura (fail-closed): ddl_breakglass con LOGIN o con sesion SIN una ceremonia abierta y vigente (fila abierta con valid_until futuro) es hallazgo; una ceremonia abierta y vencida tambien (se debe cerrar con
 * db/ceremonies/close.sql). Con una ceremonia vigente, LOGIN y sesiones son lo esperado (exit 0).
 */
export function evaluateBreakglass(s: BreakglassSnapshot): BreakglassFinding[] {
  const findings: BreakglassFinding[] = [];
  if (!Number.isFinite(s.nowMs)) throw new Error("breakglass-watch: reloj ilegible");
  if (s.canLogin === null) findings.push({ code: "ROLE_NOT_FOUND" });
  if ((s.stateProblems ?? []).length > 0) findings.push({ code: "STATE_DRIFT" });
  const valid = s.openCeremonies.filter((c) => c.validUntilMs > s.nowMs);
  if (valid.length === 0) {
    if (s.canLogin === true) findings.push({ code: "LOGIN_WITHOUT_CEREMONY" });
    if ((s.sessions ?? 0) > 0) findings.push({ code: "SESSION_WITHOUT_CEREMONY" });
  }
  for (const c of s.openCeremonies) if (c.validUntilMs <= s.nowMs) findings.push({ code: "CEREMONY_OVERDUE", ceremonyRef: c.ceremonyRef });
  return findings;
}
