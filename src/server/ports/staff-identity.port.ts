// Gobierna: contracts/openapi/consent-it0.openapi.yaml securitySchemes.caseSession/
// platformSession (x-pending APR-IDP, "parámetros del IdP: PENDING — Carlos / studio"),
// specs/state-machines/rights-case.spec.yaml GRD-RC-15 (nominal_roster_minimum, ERR-RC-10).
// Puerto (ADR-001 §11): identidad de staff de plataforma (RIGHTS_OPERATOR, aprobadores) para
// las sesiones CASE/PLATFORM. Decisión de Carlos, 2026-09-28, opción (ii): IT0 no tiene IdP
// real; el adaptador in-memory (in-memory-staff-identity.adapter.ts) resuelve contra una lista
// nominal sintética inyectada por el llamador (dev-local-config.ts, fixtures de test), nunca
// contra un directorio real. Este puerto no decide autoridad legal de nadie (LD-03): solo
// expone la lista nominal atestada que GRD-RC-15 exige como piso técnico.

export type StaffRole = "RIGHTS_OPERATOR" | "APPROVER";

export interface StaffPrincipal {
  /** Ref opaca sintética (p. ej. "staff-synthetic-01"); nunca email, nombre ni RUT. */
  readonly principalRef: string;
  readonly role: StaffRole;
}

export interface StaffIdentityPort {
  findByPrincipalRef(principalRef: string): StaffPrincipal | null;
  /** GRD-RC-15: la lista nominal completa, para contar distintos por rol sin reutilización. */
  listRoster(): readonly StaffPrincipal[];
}
