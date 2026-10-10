// Gobierna: src/server/ports/invitation-repository.port.ts. Adaptador in-memory IT0.
// CA-124: participante del UnitOfWork in-memory (journal) y, ademas del puerto, expone el lookup
// por tokenHash SIN tenant (UNSCOPED_LOOKUP) solo para el TenantResolverPort in-memory (GRD-IV-07,
// diseno §5: el lookup sin tenant sale del puerto de repo).

import type { InvitationRecord, InvitationRepositoryPort } from "../../server/ports/invitation-repository.port.ts";
import { JournaledMap, TX_JOURNAL, UNSCOPED_LOOKUP, type TxParticipant, type UnscopedTokenLookup } from "./in-memory-tx.ts";

/** Listado de LECTURA para la proyeccion in-memory del roster (API-CNS-116): NO es parte del puerto del dominio.
 * Orden de insercion = orden de creacion (equivale a created_at en el desempate de la prioridad). */
export interface InvitationListing {
  listByTenant(tenantId: string): readonly InvitationRecord[];
}

export type InMemoryInvitationRepository = InvitationRepositoryPort & TxParticipant & UnscopedTokenLookup<InvitationRecord> & InvitationListing;

export function createInMemoryInvitationRepository(): InMemoryInvitationRepository {
  const byKey = new JournaledMap<string, InvitationRecord>();
  const nonTerminalStates = new Set(["DRAFT", "READY", "SENT", "OPENED", "VERIFIED"]);

  function key(tenantId: string, invitationRef: string): string {
    return `${tenantId}\u0000${invitationRef}`;
  }

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    // Lookup sin tenant solo para el TenantResolverPort in-memory (CA-124 §5).
    [UNSCOPED_LOOKUP](tokenHash) {
      for (const record of byKey.values()) {
        if (record.tokenHash === tokenHash) return record;
      }
      return null;
    },
    async findByRef(tenantId, invitationRef) {
      return byKey.get(key(tenantId, invitationRef)) ?? null;
    },
    async findByRefForUpdate(tenantId, invitationRef) {
      return byKey.get(key(tenantId, invitationRef)) ?? null; // la UoW in-memory ya serializa
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
    async existsBySubject(tenantId, contextRef, subjectRef) {
      for (const record of byKey.values()) {
        if (record.tenantId === tenantId && record.contextRef === contextRef && record.subjectRef === subjectRef) return true;
      }
      return false;
    },
    listByTenant(tenantId) {
      return [...byKey.values()].filter((r) => r.tenantId === tenantId);
    },
    async markOtpExhausted(tenantId, invitationRef) {
      const current = byKey.get(key(tenantId, invitationRef));
      if (current) byKey.set(key(tenantId, invitationRef), { ...current, otpExhausted: true });
    },
    async save(record) {
      // otpExhausted es monotona y solo la escribe markOtpExhausted (como la columna de la base, que save no toca).
      const current = byKey.get(key(record.tenantId, record.invitationRef));
      byKey.set(key(record.tenantId, record.invitationRef), { ...record, ...(current?.otpExhausted ? { otpExhausted: true } : {}) });
    },
  };
}
