// Gobierna: src/server/ports/case-session-store.port.ts (CA-139, SEC-CNS-018 rev. 2 D-3). Adaptador in-memory IT0
// (LOCAL/CI): MISMA semantica que app.case_session (db/migrations/0022). Clave (tenantId, sidHash): un sid de otro tenant no
// existe. Solo hashes y refs opacas; sin PII. Los tests de contrato compartidos corren las mismas escenas contra los dos.

import { randomUUID } from "node:crypto";

import { createInMemorySecurityEventLog, type InMemorySecurityEventLog } from "./in-memory-security-event.adapter.ts";
import { CASE_SESSION_TOUCH_GRANULARITY_MS, type CaseSessionRecord, type CaseSessionStorePort } from "../../server/ports/case-session-store.port.ts";

interface Row extends CaseSessionRecord {
  readonly sessionRef: string;
  lastSeenAtMs: number;
  revokedAtMs: number | null;
}

/**
 * CA-141: LOGIN/LOGOUT/ROTATION se registran en `securityEvents` (por defecto uno propio, visible en `.securityEvents`) con la misma semantica atomica que
 * Postgres: se valida y escribe el evento ANTES de mutar la sesion, asi que o se aplican ambos o ninguno.
 */
export function createInMemoryCaseSessionStore(
  options: { readonly securityEvents?: InMemorySecurityEventLog } = {},
): CaseSessionStorePort & { readonly rows: () => readonly Readonly<Row>[]; readonly securityEvents: InMemorySecurityEventLog } {
  const securityEvents = options.securityEvents ?? createInMemorySecurityEventLog();
  const rows = new Map<string, Row>();
  const keyOf = (tenantId: string, sidHash: string): string => `${tenantId}\u0000${sidHash}`;
  return {
    rows: () => [...rows.values()],
    securityEvents,
    async create(record) {
      const key = keyOf(record.tenantId, record.sidHash);
      if (rows.has(key)) throw new Error("case session: sid repetido");
      const sessionRef = randomUUID();
      securityEvents.recordSync({
        tenantId: record.tenantId,
        eventType: "CASE_LOGIN",
        actorRef: record.principalRef,
        actorRole: record.role,
        sessionKind: "CASE",
        sessionRef,
        caseRef: record.caseRef,
      });
      rows.set(key, { ...record, sessionRef, lastSeenAtMs: record.issuedAtMs, revokedAtMs: null });
      return { sessionRef };
    },
    async validateAndTouch(input) {
      const row = rows.get(keyOf(input.tenantId, input.sidHash));
      if (row === undefined) return false;
      if (row.caseRef !== input.caseRef || row.principalRef !== input.principalRef || row.role !== input.role) return false;
      if (row.revokedAtMs !== null) return false;
      if (!(row.expiresAtMs > input.nowMs)) return false;
      if (!(row.lastSeenAtMs > input.nowMs - input.idleTimeoutMs)) return false;
      if (row.lastSeenAtMs < input.nowMs - CASE_SESSION_TOUCH_GRANULARITY_MS) row.lastSeenAtMs = input.nowMs;
      return true;
    },
    async revoke(tenantId, sidHash, nowMs, cause) {
      const row = rows.get(keyOf(tenantId, sidHash));
      if (row === undefined || row.revokedAtMs !== null) return false;
      securityEvents.recordSync({
        tenantId,
        eventType: cause === "USER_LOGOUT" ? "CASE_LOGOUT" : "SESSION_REVOKED_BY_ROTATION",
        actorRef: row.principalRef,
        actorRole: row.role,
        sessionKind: "CASE",
        sessionRef: row.sessionRef,
        caseRef: row.caseRef,
      });
      row.revokedAtMs = nowMs;
      return true;
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
