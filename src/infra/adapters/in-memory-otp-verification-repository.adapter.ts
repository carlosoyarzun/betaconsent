// Gobierna: src/server/ports/otp-verification-repository.port.ts. Adaptador in-memory IT0.

import type {
  OtpVerificationRecord,
  OtpVerificationRepositoryPort,
} from "../../server/ports/otp-verification-repository.port.ts";

export function createInMemoryOtpVerificationRepository(): OtpVerificationRepositoryPort {
  const byKey = new Map<string, OtpVerificationRecord>();
  const activeStates = new Set(["NOT_STARTED", "CODE_SENT"]);

  function key(tenantId: string, verificationRef: string): string {
    return `${tenantId}\u0000${verificationRef}`;
  }

  return {
    async findByRef(tenantId, verificationRef) {
      return byKey.get(key(tenantId, verificationRef)) ?? null;
    },
    async findActiveByParent(tenantId, parentRef, scope) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.parentRef === parentRef &&
          record.scope === scope &&
          activeStates.has(record.state)
        ) {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.verificationRef), { ...record });
    },
  };
}
