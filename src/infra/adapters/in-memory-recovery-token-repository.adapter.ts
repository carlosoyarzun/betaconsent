// Gobierna: src/server/ports/recovery-token.port.ts. Adaptador in-memory IT0.

import type { RecoveryTokenRecord, RecoveryTokenRepositoryPort } from "../../server/ports/recovery-token.port.ts";

export function createInMemoryRecoveryTokenRepository(): RecoveryTokenRepositoryPort {
  const byTokenHash = new Map<string, RecoveryTokenRecord>();

  return {
    findByTokenHash(tokenHash) {
      return byTokenHash.get(tokenHash) ?? null;
    },
    save(record) {
      byTokenHash.set(record.tokenHash, { ...record });
    },
    consume(tokenHash) {
      const found = byTokenHash.get(tokenHash);
      if (!found) return;
      byTokenHash.set(tokenHash, { ...found, consumedAt: new Date() });
    },
  };
}
