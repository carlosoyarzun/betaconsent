// Gobierna: src/server/ports/access-log.port.ts, db/migrations/0014_ops_access_log.sql,
// DEC-BR-014 rev. 8 §3 X6, rights-case.spec INV-RC-04 (CA-128). ADR-001 §11: solo este adaptador
// conoce el SQL. Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por tenant).

import {
  validateAccessLogEntry,
  type AccessLogEntry,
  type AccessLogPort,
  type AccessLogRecord,
} from "../../../server/ports/access-log.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface AccessLogRow {
  tenant_id: string;
  actor_ref: string;
  actor_role: AccessLogRecord["actorRole"];
  action: AccessLogRecord["action"];
  resource_type: AccessLogRecord["resourceType"];
  resource_ref: string;
  accessed_at: Date;
  environment: AccessLogRecord["environment"];
}

export function createPgAccessLogAdapter(tx: TenantTx): AccessLogPort {
  return {
    async record(entry: AccessLogEntry): Promise<void> {
      validateAccessLogEntry(entry); // misma validacion que el CHECK de la base (falla antes de tocarla)
      await tx.query(
        `INSERT INTO ops.access_log (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [entry.tenantId, entry.actorRef, entry.actorRole, entry.action, entry.resourceType, entry.resourceRef],
      );
    },
    async listByTenant(tenantId) {
      const r = await tx.query<AccessLogRow>(
        `SELECT tenant_id, actor_ref, actor_role, action, resource_type, resource_ref, accessed_at, environment
           FROM ops.access_log WHERE tenant_id = $1 ORDER BY access_seq`,
        [tenantId],
      );
      return r.rows.map((row) => ({
        tenantId: row.tenant_id,
        actorRef: row.actor_ref,
        actorRole: row.actor_role,
        action: row.action,
        resourceType: row.resource_type,
        resourceRef: row.resource_ref,
        accessedAt: row.accessed_at,
        environment: row.environment,
        dataClass: "SYNTHETIC" as const,
      }));
    },
  };
}
