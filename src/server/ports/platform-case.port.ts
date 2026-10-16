// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a (R4 en linea y atomica; G-3), §4.2.d (funciones de operador sin p_*_by_ref; actor desde la sesion), §6 (P6-5 aprobador RH2 PLATFORM),
// §10 fila 6d; GRD-RC-10, GRD-RC-12; db/migrations/0069-0070; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Acciones de operador/aprobador sobre un caso, ejecutadas por el proceso `platform`. NINGUNA recibe principal, tenant ni revocationRef: el actor y el tenant salen de la sesion que valida la BASE (sid) y la
// Revocation del caso REAL. Un rechazo de step-up (GRD-RC-12) o de sesion es `{ok:false, reason}` (la evidencia ya esta confirmada); un guard de la base es `reason` = codigo de dominio. Cero PII.

import type { StepUpLimit } from "./platform-grant.port.ts";

export type CaseOutcome =
  | { readonly ok: true; readonly data: Readonly<Record<string, unknown>> }
  | { readonly ok: false; readonly reason: "NOT_FOUND" | "STEP_UP" | string };

export interface PlatformCasePort {
  /** RH2 paso 1 (sesion CASE, RIGHTS_OPERATOR; step-up PROPOSE_CASE_VERIFICATION sobre proposalRef). */
  propose(input: { sid: string; caseRef: string; proposalRef: string; scriptVersion: string; limit: StepUpLimit }): Promise<CaseOutcome>;
  /** RH2 paso 2 (sesion PLATFORM, APPROVER; step-up APPROVE_CASE_VERIFICATION sobre proposalRef). */
  approve(input: { sid: string; caseRef: string; proposalRef: string; limit: StepUpLimit }): Promise<CaseOutcome>;
  /** RH2w (sesion CASE; solo el proponente; step-up WITHDRAW_CASE_VERIFICATION). */
  withdraw(input: { sid: string; caseRef: string; proposalRef: string; limit: StepUpLimit }): Promise<CaseOutcome>;
  /** RH3 paso 1 (sesion CASE; sin step-up: LD-03). */
  record(input: { sid: string; caseRef: string }): Promise<CaseOutcome>;
  /** RH3 paso 2 + R4 + C6 EN LA MISMA TX con reintentos acotados, commit ambiguo y alerta (G-3). Al agotarse lanza RevocationApplyUnavailableError (sin acuse de exito). */
  cosign(input: { sid: string; caseRef: string }): Promise<CaseOutcome>;
  /** FN-RC-06 (sesion CASE). */
  close(input: { sid: string; caseRef: string; outcome: "RESOLVED" | "WITHDRAWN" }): Promise<CaseOutcome>;
}
