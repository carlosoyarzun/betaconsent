// Gobierna: src/server/ports/downstream-stub.port.ts (R5-1, "CARLOS r3 R5-1"). Stub interno IT0
// LOCAL/CI: sin red ni broker. La "firma" es un HMAC-SHA256 con una clave por instancia (solo para
// que un ACK falso/ajeno no avance el estado en tests); el esquema real es OPEN-CT-02 (pendiente).

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import type {
  DownstreamEvidence,
  DownstreamEvidenceKind,
  DownstreamStubPort,
} from "../../server/ports/downstream-stub.port.ts";

/** Ref UUIDv4 fija del único EventSubscription del stub interno. */
export const INTERNAL_STUB_SUBSCRIPTION_REF = "5717b0b5-0000-4000-8000-000000000001";

export interface InMemoryDownstreamStub extends DownstreamStubPort {
  /** Firma lo que el consumidor real firmaría; solo los tests lo usan. */
  sign(kind: DownstreamEvidenceKind, revocationRef: string, subscriptionRef: string, evidenceRef: string): string;
}

export function createInMemoryDownstreamStub(
  subscriptionRefs: readonly string[] = [INTERNAL_STUB_SUBSCRIPTION_REF],
): InMemoryDownstreamStub {
  const key = randomBytes(32);
  const sign = (kind: DownstreamEvidenceKind, revocationRef: string, subscriptionRef: string, evidenceRef: string): string =>
    createHmac("sha256", key).update(`${kind}\u0000${revocationRef}\u0000${subscriptionRef}\u0000${evidenceRef}`).digest("hex");
  return {
    sign,
    async currentSubscriptionRefs() {
      return [...subscriptionRefs];
    },
    async verifyEvidence(_tenantId, kind, revocationRef, evidence: DownstreamEvidence) {
      const expected = Buffer.from(sign(kind, revocationRef, evidence.subscriptionRef, evidence.evidenceRef), "hex");
      let given: Buffer;
      try {
        given = Buffer.from(evidence.signature, "hex");
      } catch {
        return false;
      }
      return given.length === expected.length && timingSafeEqual(given, expected);
    },
  };
}
