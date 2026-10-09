// Gobierna: src/server/ports/security-event.port.ts, db/migrations/0025_ops_security_event.sql, CA-141 (D-5: app_rw solo INSERT),
// specs/session.spec.yaml GRD-SE-14. SEC-CNS-021 PR-1 (CA-146 / P-34; INV-21-04, INV-21-05): inserta ademas la familia OTP/RECOVERY/MANAGEMENT
// (db/migrations/0029_security_event_otp_family.sql); en este PR ningun emisor la usa aun (PR-2). ADR-001 §11: solo este adaptador conoce el SQL de ops.security_event. Opera DENTRO de la
// transaccion de PgUnitOfWork.withTenantTx (RLS por tenant) de los stores de sesion. Sin RETURNING ni SELECT (el runtime no lee).

import { isOtpFamilyEntry, SecurityEventWriteError, validateSecurityEventEntry, type AnySecurityEventEntry, type SecurityEventPort } from "../../../server/ports/security-event.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

export function createPgSecurityEventAdapter(tx: Pick<TenantTx, "query">): SecurityEventPort {
  return {
    async record(entry: AnySecurityEventEntry): Promise<void> {
      validateSecurityEventEntry(entry); // misma validacion que los CHECK de la base (falla antes de tocarla)
      try {
        if (isOtpFamilyEntry(entry)) {
          // Una sola sentencia para toda la familia: las columnas que no aplican al tipo van NULL (la base lo exige con security_event_otp_shape).
          const e = entry as unknown as Record<string, string | undefined>;
          await tx.query(
            `INSERT INTO ops.security_event (tenant_id, event_type, verification_ref, otp_scope, scope_class, channel_ref, key_kind, window_kind, chain_ref, recovery_ref, trigger_kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
              e.tenantId, e.eventType, e.verificationRef ?? null, e.otpScope ?? null, e.scopeClass ?? null, e.channelRef ?? null,
              e.keyKind ?? null, e.windowKind ?? null, e.chainRef ?? null, e.recoveryRef ?? null, e.trigger ?? null,
            ],
          );
          return;
        }
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
