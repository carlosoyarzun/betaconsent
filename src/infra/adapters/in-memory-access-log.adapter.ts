// Gobierna: src/server/ports/access-log.port.ts, DEC-BR-014 rev. 8 §3 X6, rights-case.spec INV-RC-04
// (CA-128). Adaptador in-memory IT0 LOCAL/CI: participante del UnitOfWork (journal, in-memory-tx.ts).
// Append-only: no expone borrado ni mutacion.

import {
  validateAccessLogEntry,
  type AccessLogEntry,
  type AccessLogPort,
  type AccessLogRecord,
} from "../../server/ports/access-log.port.ts";
import { JournaledList, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

export type InMemoryAccessLog = AccessLogPort & TxParticipant;

export function createInMemoryAccessLogAdapter(): InMemoryAccessLog {
  const records = new JournaledList<AccessLogRecord>();
  return {
    [TX_JOURNAL](journal) {
      records.journal = journal;
    },
    async record(entry: AccessLogEntry): Promise<void> {
      validateAccessLogEntry(entry);
      records.push({
        tenantId: entry.tenantId,
        actorRef: entry.actorRef,
        actorRole: entry.actorRole,
        action: entry.action,
        resourceType: entry.resourceType,
        resourceRef: entry.resourceRef,
        accessedAt: new Date(),
        environment: "LOCAL",
        dataClass: "SYNTHETIC",
      });
    },
    async listByTenant(tenantId) {
      return records.items.filter((r) => r.tenantId === tenantId);
    },
  };
}
