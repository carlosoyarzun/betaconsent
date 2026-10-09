// Gobierna: src/server/ports/security-event.port.ts, db/migrations/0025_ops_security_event.sql, CA-141, specs/session.spec.yaml GRD-SE-14.
// Adaptador in-memory IT0 LOCAL/CI: MISMA semantica que ops.security_event (CHECK espejados en validateSecurityEventEntry). Append-only:
// no expone borrado ni mutacion. `list()` es solo para verificacion (el runtime Postgres no lee, D-5). `failWith` inyecta fallos de escritura
// en tests (atomicidad con los stores de sesion).
// SEC-CNS-021 PR-1 (CA-146 / P-34; INV-21-04): admite tambien la familia OTP/RECOVERY/MANAGEMENT con la misma validacion que el CHECK de 0029.
// `list()` sigue devolviendo SOLO los eventos de sesion (contrato previo); `listAll()` devuelve todos en orden de insercion.

import { randomUUID } from "node:crypto";

import {
  SecurityEventWriteError,
  validateSecurityEventEntry,
  isOtpFamilyEntry,
  type AnySecurityEventEntry,
  type AnySecurityEventRecord,
  type OtpFamilySecurityEventRecord,
  type SecurityEventEntry,
  type SecurityEventPort,
  type SecurityEventRecord,
} from "../../server/ports/security-event.port.ts";

export interface InMemorySecurityEventLog extends SecurityEventPort {
  /** Eventos en orden de insercion. */
  list(tenantId?: string): readonly SecurityEventRecord[];
  /** Todos los eventos (sesion y familia OTP/RECOVERY/MANAGEMENT) en orden de insercion. */
  listAll(tenantId?: string): readonly AnySecurityEventRecord[];
  /** Igual que `record` pero SINCRONO: los stores in-memory validan y escriben el evento antes de mutar la sesion sin ceder el turno (la sesion queda visible de inmediato, como antes de CA-141). */
  recordSync(entry: AnySecurityEventEntry): void;
  /** Solo tests: mientras devuelva true, `record` falla con SecurityEventWriteError (sin escribir). */
  failWith: (() => boolean) | null;
}

export function createInMemorySecurityEventLog(): InMemorySecurityEventLog {
  const records: AnySecurityEventRecord[] = [];
  const log: InMemorySecurityEventLog = {
    failWith: null,
    list: (tenantId) =>
      records.filter((r): r is SecurityEventRecord => !isOtpFamilyEntry(r) && (tenantId === undefined || r.tenantId === tenantId)),
    listAll: (tenantId) => (tenantId === undefined ? [...records] : records.filter((r) => r.tenantId === tenantId)),
    async record(entry: AnySecurityEventEntry): Promise<void> {
      log.recordSync(entry);
    },
    recordSync(entry: AnySecurityEventEntry): void {
      validateSecurityEventEntry(entry);
      if (log.failWith?.()) throw new SecurityEventWriteError("XX000");
      if (isOtpFamilyEntry(entry)) {
        const rec: OtpFamilySecurityEventRecord = {
          ...entry,
          eventId: randomUUID(),
          schemaVersion: "1.0.0",
          occurredAt: new Date(),
          environment: "LOCAL",
          dataClass: "SYNTHETIC",
        };
        records.push(rec);
        return;
      }
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
