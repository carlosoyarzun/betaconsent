// Gobierna: src/server/ports/security-event.port.ts, db/migrations/0025_ops_security_event.sql, CA-141, specs/session.spec.yaml GRD-SE-14.
// Adaptador in-memory IT0 LOCAL/CI: MISMA semantica que ops.security_event (CHECK espejados en validateSecurityEventEntry). Append-only:
// no expone borrado ni mutacion. `list()` es solo para verificacion (el runtime Postgres no lee, D-5). `failWith` inyecta fallos de escritura
// en tests (atomicidad con los stores de sesion).

import { randomUUID } from "node:crypto";

import {
  SecurityEventWriteError,
  validateSecurityEventEntry,
  type SecurityEventEntry,
  type SecurityEventPort,
  type SecurityEventRecord,
} from "../../server/ports/security-event.port.ts";

export interface InMemorySecurityEventLog extends SecurityEventPort {
  /** Eventos en orden de insercion. */
  list(tenantId?: string): readonly SecurityEventRecord[];
  /** Igual que `record` pero SINCRONO: los stores in-memory validan y escriben el evento antes de mutar la sesion sin ceder el turno (la sesion queda visible de inmediato, como antes de CA-141). */
  recordSync(entry: SecurityEventEntry): void;
  /** Solo tests: mientras devuelva true, `record` falla con SecurityEventWriteError (sin escribir). */
  failWith: (() => boolean) | null;
}

export function createInMemorySecurityEventLog(): InMemorySecurityEventLog {
  const records: SecurityEventRecord[] = [];
  const log: InMemorySecurityEventLog = {
    failWith: null,
    list: (tenantId) => (tenantId === undefined ? [...records] : records.filter((r) => r.tenantId === tenantId)),
    async record(entry: SecurityEventEntry): Promise<void> {
      log.recordSync(entry);
    },
    recordSync(entry: SecurityEventEntry): void {
      validateSecurityEventEntry(entry);
      if (log.failWith?.()) throw new SecurityEventWriteError("XX000");
      records.push({
        tenantId: entry.tenantId,
        eventType: entry.eventType,
        actorRef: entry.actorRef,
        actorRole: entry.actorRole,
        sessionKind: entry.sessionKind,
        sessionRef: entry.sessionRef,
        caseRef: entry.caseRef ?? null,
        eventId: randomUUID(),
        schemaVersion: "1.0.0",
        occurredAt: new Date(),
        environment: "LOCAL",
        dataClass: "SYNTHETIC",
      });
    },
  };
  return log;
}
