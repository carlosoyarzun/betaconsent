// Gobierna: specs/state-machines/tenant-context.spec.yaml (submachine Enrollment, EN0, GRD-TC-03),
// contracts/openapi/consent-it0.openapi.yaml API-CNS-105 (POST /staff/enrollments).
// Puerto (ADR-001 §11): proyección del ledger para el agregado Enrollment. En IT0 el adaptador
// es in-memory (src/infra/adapters/**); el adaptador de Postgres es otra historia.

import type { TenantId } from "../modules/common/types.ts";

export type EnrollmentState = "ACTIVE" | "CLOSED";

export interface EnrollmentRecord {
  /** Ref opaca UUIDv4 generada en servidor (INV-CM-09). */
  readonly enrollmentRef: string;
  readonly tenantId: TenantId;
  readonly subjectRef: string;
  readonly participationRef: string;
  readonly state: EnrollmentState;
}

export interface EnrollmentRepositoryPort {
  findByRef(tenantId: TenantId, enrollmentRef: string): Promise<EnrollmentRecord | null>;
  /** GRD-TC-03: como máximo un Enrollment ACTIVE por (tenantId, subjectRef, participationRef). */
  findActive(tenantId: TenantId, subjectRef: string, participationRef: string): Promise<EnrollmentRecord | null>;
  save(record: EnrollmentRecord): Promise<void>;
}
