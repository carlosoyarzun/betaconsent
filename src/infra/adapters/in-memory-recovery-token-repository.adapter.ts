// Gobierna: src/server/ports/recovery-token.port.ts. Adaptador in-memory IT0.
// CA-124: clave (tenantId, recoveryRef) como la tabla `app.recovery_token`; el lookup por
// tokenHash SIN tenant vive fuera del puerto de repo (UNSCOPED_LOOKUP, solo para el
// TenantResolverPort in-memory: diseño §5 "los lookups sin tenant salen de los repos").

import type { RecoveryTokenRecord, RecoveryTokenRepositoryPort } from "../../server/ports/recovery-token.port.ts";
import {
  JournaledMap,
  TX_JOURNAL,
  UNSCOPED_LOOKUP,
  type TxParticipant,
  type UnscopedTokenLookup,
} from "./in-memory-tx.ts";

export type InMemoryRecoveryTokenRepository = RecoveryTokenRepositoryPort & TxParticipant & UnscopedTokenLookup<RecoveryTokenRecord>;

export function createInMemoryRecoveryTokenRepository(): InMemoryRecoveryTokenRepository {
  const byKey = new JournaledMap<string, RecoveryTokenRecord>();
  const key = (tenantId: string, recoveryRef: string): string => `${tenantId}\u0000${recoveryRef}`;

  return {
    [TX_JOURNAL](journal) {
      byKey.journal = journal;
    },
    [UNSCOPED_LOOKUP](tokenHash) {
      for (const record of byKey.values()) {
        if (record.tokenHash === tokenHash) return record;
      }
      return null;
    },
    async findByRef(tenantId, recoveryRef) {
      return byKey.get(key(tenantId, recoveryRef)) ?? null;
    },
    async save(record) {
      byKey.set(key(record.tenantId, record.recoveryRef), { ...record });
    },
    async consume(tenantId, recoveryRef) {
      const found = byKey.get(key(tenantId, recoveryRef));
      if (!found) return;
      byKey.set(key(tenantId, recoveryRef), { ...found, consumedAt: new Date() });
    },
  };
}
