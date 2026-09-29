// Gobierna: specs/state-machines/invitation.spec.yaml GRD-IV-02 (subject_belongs_to_tenant),
// tenant-context.spec.yaml GRD-TC-03 ("subjectRef y participationRef del tenant resuelto") y
// common.spec.yaml GRD-CM-03 (Guard P: SchoolParticipation ACTIVE para (contextRef, productRef)).
// Puerto (ADR-001 §11): lectura del catálogo del tenant (sujetos y SchoolParticipation). IT0 no
// tiene todavía un flujo que registre sujetos ni participaciones (FINDING P1 de CA-125): el
// adaptador in-memory se siembra por fixture (dev-local-config.ts / tests) y el dominio NUNCA
// crea ni modifica sujetos ni participaciones. Solo refs opacas UUIDv4; cero PII.

import type { TenantId } from "../modules/common/types.ts";

export type SchoolParticipationStatus = "PENDING_AUTHORIZATION" | "ACTIVE" | "SUSPENDED" | "CLOSED";

export interface SchoolParticipationView {
  readonly participationRef: string;
  readonly contextRef: string;
  readonly productRef: string;
  readonly status: SchoolParticipationStatus;
}

export interface TenantCatalogPort {
  /** GRD-IV-02/GRD-TC-03: el sujeto existe en el catálogo de ESTE tenant (lectura bajo RLS). */
  subjectBelongsToTenant(tenantId: TenantId, subjectRef: string): boolean;
  /** Devuelve null si la participación no existe en este tenant (desconocido = fail-closed). */
  findParticipation(tenantId: TenantId, participationRef: string): SchoolParticipationView | null;
}
