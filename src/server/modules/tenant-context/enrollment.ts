// Gobierna: specs/state-machines/tenant-context.spec.yaml EN0 (OpenEnrollment, fuente STAFF;
// guards comunes GRD-CM-07/13, GRD-TC-03; guardsBySource STAFF GRD-CM-01/02/10),
// contracts/openapi API-CNS-105 (POST /staff/enrollments) y OpenEnrollmentRequest/
// EnrollmentOpened. CA-125. Alcance de este archivo: SOLO EN0 fuente STAFF. EN1 (cierre y
// cascada I9 ENROLLMENT_CLOSED) no está implementado. GRD-CM-01/10 los aplica el entrypoint
// HTTP (sesión y CSRF); GRD-CM-13/14/15 rigen la rama FIXTURE, que no tiene superficie HTTP y
// nunca se ejecuta aquí (TEST-CNS-446: una request con actorType FIXTURE se evalúa como STAFF).
// EN0 no evalúa la fórmula de elegibilidad (STAFF_ADMIN, AUDIT-H01-rev3 N-13).

import { randomUUID } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import { assertActorRoleIn } from "../common/guards.ts";
import type { ActorRole, TenantId } from "../common/types.ts";
import type { EnrollmentRecord, EnrollmentRepositoryPort } from "../../ports/enrollment-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { TenantCatalogPort } from "../../ports/tenant-catalog.port.ts";
import { appendNext } from "../common/ledger-append.ts";

export interface EnrollmentPorts {
  readonly enrollmentRepo: EnrollmentRepositoryPort;
  readonly tenantCatalog: TenantCatalogPort;
  readonly ledger: LedgerPort;
  /** CA-124 (diseño §5): EN0 (verificación + Enrollment + ledger) corre en UNA unidad de trabajo del
   * tenant. Su tenancy comparte `enrollmentRepo`. */
  readonly uow: UnitOfWorkPort;
}

/** EN0: TENANT_ADMIN en la consola STAFF registra actorRole INVITER (x-actor del contrato). */
const EN0_STAFF_ROLES: readonly ActorRole[] = ["INVITER"];

export interface OpenEnrollmentInput {
  readonly subjectRef: string;
  readonly participationRef: string;
}

export interface OpenEnrollmentResult {
  readonly record: EnrollmentRecord;
  /** Sequence del evento ENROLLMENT_STATUS_CHANGED en el agregado (>= 1). */
  readonly sequence: number;
}

/**
 * EN0: null -> ACTIVE. Guards: GRD-CM-07 (rol permitido, ERR-CM-10), GRD-TC-03 (subjectRef y
 * participationRef del tenant resuelto, y a lo sumo un Enrollment ACTIVE por
 * (tenant, subject, participation), ERR-TC-03). Un sujeto o participación que no es de este
 * tenant es indistinguible de uno inexistente (ERR-CM-01, 404 uniforme): nunca revela que existe
 * en otro colegio.
 */
export async function openEnrollment(
  ports: EnrollmentPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: OpenEnrollmentInput,
): Promise<OpenEnrollmentResult> {
  assertActorRoleIn(actorRole, EN0_STAFF_ROLES); // GRD-CM-07

  if (
    !await ports.tenantCatalog.subjectBelongsToTenant(tenantId, input.subjectRef) ||
    await ports.tenantCatalog.findParticipation(tenantId, input.participationRef) === null
  ) {
    throw new DomainError("ERR-CM-01"); // GRD-TC-03 (pertenencia al tenant resuelto)
  }
  if (await ports.enrollmentRepo.findActive(tenantId, input.subjectRef, input.participationRef)) {
    throw new DomainError("ERR-TC-03"); // GRD-TC-03 (single_active_enrollment)
  }

  const record: EnrollmentRecord = {
    enrollmentRef: randomUUID(), // INV-CM-09: Ref UUIDv4 aleatoria, generada en servidor
    tenantId,
    subjectRef: input.subjectRef,
    participationRef: input.participationRef,
    state: "ACTIVE",
  };
  await ports.enrollmentRepo.save(record);
  const event = await appendNext(ports.ledger, {
    eventType: "ENROLLMENT_STATUS_CHANGED",
    tenantId,
    aggregateType: "Enrollment",
    aggregateId: record.enrollmentRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    payload: {
      enrollmentRef: record.enrollmentRef,
      participationRef: record.participationRef,
      subjectRef: record.subjectRef,
      toStatus: "ACTIVE",
    },
    idempotencyKey: `${tenantId}:${record.subjectRef}:${record.participationRef}:en0`,
  });
  return { record, sequence: event.sequence };
}
