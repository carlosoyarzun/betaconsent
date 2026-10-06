// Gobierna: src/server/ports/security-event.port.ts, db/migrations/0025_ops_security_event.sql, CA-141 (D-5: app_rw solo INSERT),
// specs/session.spec.yaml GRD-SE-14. ADR-001 §11: solo este adaptador conoce el SQL de ops.security_event. Opera DENTRO de la
// transaccion de PgUnitOfWork.withTenantTx (RLS por tenant) de los stores de sesion. Sin RETURNING ni SELECT (el runtime no lee).

import { SecurityEventWriteError, validateSecurityEventEntry, type SecurityEventEntry, type SecurityEventPort } from "../../../server/ports/security-event.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

export function createPgSecurityEventAdapter(tx: Pick<TenantTx, "query">): SecurityEventPort {
  return {
    async record(entry: SecurityEventEntry): Promise<void> {
      validateSecurityEventEntry(entry); // misma validacion que los CHECK de la base (falla antes de tocarla)
      try {
        await tx.query(
          `INSERT INTO ops.security_event (tenant_id, event_type, actor_ref, actor_role, session_kind, session_ref, case_ref)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [entry.tenantId, entry.eventType, entry.actorRef, entry.actorRole, entry.sessionKind, entry.sessionRef, entry.caseRef ?? null],
        );
      } catch (error) {
        // Solo el SQLSTATE: el mensaje/detalle de pg puede traer valores de fila.
        const code = (error as { code?: unknown } | null)?.code;
        throw new SecurityEventWriteError(typeof code === "string" ? code : undefined);
      }
    },
  };
}
