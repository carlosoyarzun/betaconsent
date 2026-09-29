// Gobierna: src/server/ports/enrollment-repository.port.ts. Adaptador in-memory IT0.

import type { EnrollmentRecord, EnrollmentRepositoryPort } from "../../server/ports/enrollment-repository.port.ts";

export function createInMemoryEnrollmentRepository(): EnrollmentRepositoryPort {
  const byKey = new Map<string, EnrollmentRecord>();
  const key = (tenantId: string, enrollmentRef: string): string => `${tenantId}\u0000${enrollmentRef}`;

  return {
    async findByRef(tenantId, enrollmentRef) {
      return byKey.get(key(tenantId, enrollmentRef)) ?? null;
    },
    async findActive(tenantId, subjectRef, participationRef) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.subjectRef === subjectRef &&
          record.participationRef === participationRef &&
          record.state === "ACTIVE"
        ) {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.enrollmentRef), { ...record });
    },
  };
}
