// Gobierna: src/server/ports/staff-session-store.port.ts (CA-138, SEC-CNS-018 rev. 2 D-3). Adaptador in-memory IT0
// (LOCAL/CI): MISMA semantica que app.staff_session (db/migrations/0021). Clave (tenantId, sidHash): un sid de otro tenant no
// existe. Solo hashes y refs opacas; sin PII. Los tests de contrato compartidos corren las mismas escenas contra los dos.

import { STAFF_SESSION_TOUCH_GRANULARITY_MS, type StaffSessionRecord, type StaffSessionStorePort } from "../../server/ports/staff-session-store.port.ts";

interface Row extends StaffSessionRecord {
  lastSeenAtMs: number;
  revokedAtMs: number | null;
}

export function createInMemoryStaffSessionStore(): StaffSessionStorePort & { readonly rows: () => readonly Readonly<Row>[] } {
  const rows = new Map<string, Row>();
  const keyOf = (tenantId: string, sidHash: string): string => `${tenantId}\u0000${sidHash}`;
  return {
    rows: () => [...rows.values()],
    async create(record) {
      const key = keyOf(record.tenantId, record.sidHash);
      if (rows.has(key)) throw new Error("staff session: sid repetido");
      rows.set(key, { ...record, lastSeenAtMs: record.issuedAtMs, revokedAtMs: null });
    },
    async validateAndTouch(input) {
      const row = rows.get(keyOf(input.tenantId, input.sidHash));
      if (row === undefined) return false;
      if (row.principalRef !== input.principalRef || row.role !== input.role) return false;
      if (row.revokedAtMs !== null) return false;
      if (!(row.expiresAtMs > input.nowMs)) return false;
      if (!(row.lastSeenAtMs > input.nowMs - input.idleTimeoutMs)) return false;
      if (row.lastSeenAtMs < input.nowMs - STAFF_SESSION_TOUCH_GRANULARITY_MS) row.lastSeenAtMs = input.nowMs;
      return true;
    },
    async revoke(tenantId, sidHash, nowMs) {
      const row = rows.get(keyOf(tenantId, sidHash));
      if (row !== undefined && row.revokedAtMs === null) row.revokedAtMs = nowMs;
    },
    async purgeExpired(tenantId, nowMs, retentionMs) {
      let purged = 0;
      for (const [key, row] of rows) {
        if (row.tenantId === tenantId && row.expiresAtMs < nowMs - retentionMs) {
          rows.delete(key);
          purged += 1;
        }
      }
      return purged;
    },
  };
}
