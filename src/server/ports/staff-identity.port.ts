// Gobierna: contracts/openapi/consent-it0.openapi.yaml securitySchemes.caseSession/
// platformSession (x-pending APR-IDP, "parámetros del IdP: PENDING — Carlos / studio"),
// specs/state-machines/rights-case.spec.yaml GRD-RC-15 (nominal_roster_minimum, ERR-RC-10).
// Puerto (ADR-001 §11): identidad de staff de plataforma (RIGHTS_OPERATOR, aprobadores) para
// las sesiones CASE/PLATFORM. Decisión de Carlos, 2026-09-28, opción (ii): IT0 no tiene IdP
// real; el adaptador in-memory (in-memory-staff-identity.adapter.ts) resuelve contra una lista
// nominal sintética inyectada por el llamador (dev-local-config.ts, fixtures de test), nunca
// contra un directorio real. Este puerto no decide autoridad legal de nadie (LD-03): solo
// expone la lista nominal atestada que GRD-RC-15 exige como piso técnico.

/** Roles de la consola CASE/PLATFORM (sesión `caseSession`). */
export type CaseStaffRole = "RIGHTS_OPERATOR" | "APPROVER";

/**
 * CA-125 (contracts/openapi /staff/enrollments y /staff/invitations*, securitySchemes.staffSession):
 * TENANT_ADMIN es el miembro TENANT de la consola STAFF del colegio (DEC-BR-016 §4); registra
 * actorRole INVITER en el ledger (x-actor del contrato). No es un rol de la consola CASE.
 */
export type StaffRole = CaseStaffRole | "TENANT_ADMIN";

export interface StaffPrincipal {
  /** Ref opaca sintética (p. ej. "staff-synthetic-01"); nunca email, nombre ni RUT. */
  readonly principalRef: string;
  readonly role: StaffRole;
  /**
   * Solo TENANT_ADMIN: membership TENANT vigente (GRD-CM-01/02). El tenant de la sesión STAFF se
   * deriva SIEMPRE de este campo del roster atestado por servidor, nunca de un body ni de un
   * header. Los roles CASE/PLATFORM no tienen tenant propio (van ligados a un caseRef).
   */
  readonly tenantId?: string;
}

export interface StaffIdentityPort {
  findByPrincipalRef(principalRef: string): Promise<StaffPrincipal | null>;
  /** GRD-RC-15: la lista nominal completa, para contar distintos por rol sin reutilización. */
  listRoster(): Promise<readonly StaffPrincipal[]>;
}
