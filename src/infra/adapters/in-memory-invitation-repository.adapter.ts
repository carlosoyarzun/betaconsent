// Gobierna: src/server/ports/invitation-repository.port.ts. Adaptador in-memory IT0.

import type { InvitationRecord, InvitationRepositoryPort } from "../../server/ports/invitation-repository.port.ts";
import { UNSCOPED_LOOKUP, type UnscopedTokenLookup } from "./in-memory-tx.ts";

export type InMemoryInvitationRepository = InvitationRepositoryPort & UnscopedTokenLookup<InvitationRecord>;

export function createInMemoryInvitationRepository(): InMemoryInvitationRepository {
  const byKey = new Map<string, InvitationRecord>();
  const nonTerminalStates = new Set(["DRAFT", "READY", "SENT", "OPENED", "VERIFIED"]);

  function key(tenantId: string, invitationRef: string): string {
    return `${tenantId}\u0000${invitationRef}`;
  }

  function lookupByTokenHash(tokenHash: string): InvitationRecord | null {
    for (const record of byKey.values()) {
      if (record.tokenHash === tokenHash) return record;
    }
    return null;
  }

  return {
    // Lookup sin tenant solo para el TenantResolverPort in-memory (CA-124 §5).
    [UNSCOPED_LOOKUP]: lookupByTokenHash,
    async findByRef(tenantId, invitationRef) {
      return byKey.get(key(tenantId, invitationRef)) ?? null;
    },
    async findActiveBySubject(tenantId, contextRef, subjectRef) {
      for (const record of byKey.values()) {
        if (
          record.tenantId === tenantId &&
          record.contextRef === contextRef &&
          record.subjectRef === subjectRef &&
          nonTerminalStates.has(record.state)
        ) {
          return record;
        }
      }
      return null;
    },
    async findByTokenHash(tokenHash) {
      for (const record of byKey.values()) {
        if (record.tokenHash === tokenHash) {
          return record;
        }
      }
      return null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.invitationRef), { ...record });
    },
  };
}
