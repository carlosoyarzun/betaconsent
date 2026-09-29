// Gobierna: src/server/ports/recovery-token.port.ts. Adaptador in-memory IT0.

import type { RecoveryTokenRecord, RecoveryTokenRepositoryPort } from "../../server/ports/recovery-token.port.ts";

export function createInMemoryRecoveryTokenRepository(): RecoveryTokenRepositoryPort {
  const byTokenHash = new Map<string, RecoveryTokenRecord>();

  return {
    async findByTokenHash(tokenHash) {
      return byTokenHash.get(tokenHash) ?? null;
    },
    async save(record) {
      byTokenHash.set(record.tokenHash, { ...record });
    },
    async consume(tokenHash) {
      const found = byTokenHash.get(tokenHash);
      if (!found) return;
      byTokenHash.set(tokenHash, { ...found, consumedAt: new Date() });
    },
  };
}
