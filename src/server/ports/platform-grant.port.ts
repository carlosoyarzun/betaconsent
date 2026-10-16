// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (step-up: principal de la sesion validada), §6 (grants P6-3), §10 fila 6d; GRD-RC-10, GRD-RC-12; specs/db-roles.spec.yaml
// (platform_rw: issue_step_up_nonce, request_grant, approve_grant); db/migrations/0060-0062; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Step-up de caso y grants del proceso `platform`. NINGUNA operacion recibe un principal ni un tenant: el principal sale de la sesion PLATFORM que valida la BASE (sid -> fila) y el tenant del caso REAL.
// Un DENY de la base devuelve null (la evidencia ya esta confirmada); un error de base lanza PlatformDeniedError uniforme. Cero PII: refs opacas.

/** Acciones de step-up que implementa la parte 1 de 6d (el enum de la base admite mas; llegan con sus funciones). */
export type CaseStepUpAction = "REQUEST_GRANT" | "APPROVE_GRANT" | "PROPOSE_CASE_VERIFICATION" | "APPROVE_CASE_VERIFICATION" | "WITHDRAW_CASE_VERIFICATION";

/** P-51 por configuracion del proceso (sin default fuera de LOCAL). */
export interface StepUpLimit {
  readonly max: number;
  readonly windowSeconds: number;
}

export interface PlatformGrantPort {
  /** Emite el nonce del step-up (en claro, UNA vez; viaja como `nonce` al IdP) ligado al operador de la sesion, la accion y el destino (REQUEST_GRANT: caseRef; APPROVE_GRANT: requestRef). null = DENY. */
  issueStepUpNonce(input: { sid: string; action: CaseStepUpAction; targetRef: string; ttlSeconds: number }): Promise<string | null>;
  /** Solicita un grant para el operador de la sesion sobre `caseRef` (consume el step-up REQUEST_GRANT en la misma tx). Devuelve requestRef o null. */
  requestGrant(input: { sid: string; caseRef: string; limit: StepUpLimit }): Promise<string | null>;
  /** Aprueba la solicitud (consume el step-up APPROVE_GRANT en la misma tx). `validSeconds` null = defecto de la base (2 h; maximo 4 h, P-23). Devuelve grantRef o null. */
  approveGrant(input: { sid: string; caseRef: string; requestRef: string; validSeconds: number | null; limit: StepUpLimit }): Promise<string | null>;
}
