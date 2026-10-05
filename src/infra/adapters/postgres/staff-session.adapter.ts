// Gobierna: CA-138, SEC-CNS-018 rev. 2 (D-3), src/server/ports/staff-session-store.port.ts, db/migrations/0021_staff_session.sql,
// ADR-001 §11 (solo este adaptador conoce el SQL de app.staff_session). Cada operacion corre en su propia tx de
// PgUnitOfWork.withTenantTx (GUC de tenant fijado: RLS por app.current_tenant_id()). validateAndTouch es UN solo UPDATE
// condicionado: validar y avanzar la ultima actividad son atomicos (dos requests concurrentes no se pisan).
// Cualquier fallo de la base se propaga al llamador (los bordes responden 503/fail-closed); nunca "valido por defecto".

import type { StaffSessionStorePort } from "../../../server/ports/staff-session-store.port.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

const ts = (n: string): string => `pg_catalog.to_timestamp(${n}::double precision / 1000.0)`;

export function createPgStaffSessionStore(uow: Pick<PgUnitOfWork, "withTenantTx">): StaffSessionStorePort {
  return {
    async create(record) {
      await uow.withTenantTx(record.tenantId, async (tx) => {
        await tx.query(
          `INSERT INTO app.staff_session (tenant_id, sid_hash, principal_ref, role, issued_at, expires_at, last_seen_at)
           VALUES ($1, $2, $3, $4, ${ts("$5")}, ${ts("$6")}, ${ts("$5")})`,
          [record.tenantId, record.sidHash, record.principalRef, record.role, String(record.issuedAtMs), String(record.expiresAtMs)],
        );
      });
    },
    async validateAndTouch(input) {
      return uow.withTenantTx(input.tenantId, async (tx) => {
        const r = await tx.query(
          `UPDATE app.staff_session
              SET last_seen_at = GREATEST(last_seen_at, ${ts("$5")})
            WHERE tenant_id = $1 AND sid_hash = $2 AND principal_ref = $3 AND role = $4
              AND revoked_at IS NULL
              AND expires_at > ${ts("$5")}
              AND last_seen_at > ${ts("$6")}`,
          [input.tenantId, input.sidHash, input.principalRef, input.role, String(input.nowMs), String(input.nowMs - input.idleTimeoutMs)],
        );
        return r.rowCount === 1;
      });
    },
    async revoke(tenantId, sidHash, nowMs) {
      await uow.withTenantTx(tenantId, async (tx) => {
        await tx.query(
          `UPDATE app.staff_session SET revoked_at = ${ts("$3")} WHERE tenant_id = $1 AND sid_hash = $2 AND revoked_at IS NULL`,
          [tenantId, sidHash, String(nowMs)],
        );
      });
    },
    async purgeExpired(tenantId, nowMs, retentionMs) {
      return uow.withTenantTx(tenantId, async (tx) => {
        const r = await tx.query(`DELETE FROM app.staff_session WHERE tenant_id = $1 AND expires_at < ${ts("$2")}`, [tenantId, String(nowMs - retentionMs)]);
        return r.rowCount ?? 0;
      });
    },
  };
}
