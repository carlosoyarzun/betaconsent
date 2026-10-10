// Gobierna: SEC-CNS-021 PR-4 (CA-146 / DF-10), src/server/ports/otp-budget.port.ts, db/migrations/0032_otp_budget_p06_v6a.sql, otp-challenge.spec.yaml
// (CFG-OT-BUDGET, GRD-OT-03), ADR-001 §11: solo este adaptador conoce el SQL de ops.otp_budget. Opera DENTRO de la transaccion de PgUnitOfWork.inTenant
// (RLS por app.current_tenant_id()). Cero PII: solo el HMAC de la clave (key_hmac) y contadores.

import type { OtpBudgetKey, OtpBudgetPort } from "../../../server/ports/otp-budget.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

const KEY_PREDICATE =
  "tenant_id = $1 AND scope_class = $2 AND key_kind = $3 AND key_hmac = $4 AND window_kind = $5";

function keyParams(tenantId: string, key: OtpBudgetKey): unknown[] {
  return [tenantId, key.scopeClass, key.keyKind, key.keyHmac, key.windowKind];
}

export function createPgOtpBudgetAdapter(tx: Pick<TenantTx, "query">): OtpBudgetPort {
  return {
    async findExhausted(tenantId, keys, at, limit) {
      for (const key of keys) {
        const r = await tx.query(
          `SELECT 1 FROM ops.otp_budget WHERE ${KEY_PREDICATE} AND expires_at > $6::timestamptz AND failures >= $7`,
          [...keyParams(tenantId, key), at.toISOString(), limit],
        );
        if (r.rows.length > 0) return key;
      }
      return null;
    },
    async reserveFailure(tenantId, keys, at, windowMs, limit) {
      const now = at.toISOString();
      const end = new Date(at.getTime() + windowMs).toISOString();
      const reserved: OtpBudgetKey[] = [];
      for (const key of keys) {
        // Una sola sentencia atomica por clave (GRD-OT-03): el INSERT ... ON CONFLICT DO UPDATE toma el lock de la fila y, al esperar a otra
        // transaccion, reevalua el WHERE contra la version confirmada. Ventana vencida -> arranca otra con failures = 1; vigente con cupo -> +1;
        // vigente sin cupo -> no devuelve fila.
        const r = await tx.query(
          `INSERT INTO ops.otp_budget AS b
             (tenant_id, scope_class, key_kind, key_hmac, key_version, window_kind, window_start, expires_at, failures)
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, 1)
           ON CONFLICT (tenant_id, scope_class, key_kind, key_hmac, window_kind) DO UPDATE SET
             failures = CASE WHEN b.expires_at <= $7::timestamptz THEN 1 ELSE b.failures + 1 END,
             window_start = CASE WHEN b.expires_at <= $7::timestamptz THEN $7::timestamptz ELSE b.window_start END,
             expires_at = CASE WHEN b.expires_at <= $7::timestamptz THEN $8::timestamptz ELSE b.expires_at END
           WHERE b.expires_at <= $7::timestamptz OR b.failures < $9
           RETURNING b.failures`,
          [tenantId, key.scopeClass, key.keyKind, key.keyHmac, key.keyVersion, key.windowKind, now, end, limit],
        );
        if (r.rows.length === 0) {
          // Sin comparacion no se consume: revierte las reservas hechas en ESTA llamada.
          for (const done of reserved) {
            await tx.query(`UPDATE ops.otp_budget SET failures = failures - 1 WHERE ${KEY_PREDICATE} AND failures > 0`, keyParams(tenantId, done));
          }
          return key;
        }
        reserved.push(key);
      }
      return null;
    },
    async releaseFailure(tenantId, keys) {
      for (const key of keys) {
        await tx.query(`UPDATE ops.otp_budget SET failures = failures - 1 WHERE ${KEY_PREDICATE} AND failures > 0`, keyParams(tenantId, key));
      }
    },
  };
}
