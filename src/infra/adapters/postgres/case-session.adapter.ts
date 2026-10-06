// Gobierna: CA-139, SEC-CNS-018 rev. 2 (D-3), src/server/ports/case-session-store.port.ts, db/migrations/0022_case_session.sql,
// ADR-001 §11 (solo este adaptador conoce el SQL de app.case_session). Cada operacion corre en su propia tx de
// PgUnitOfWork.withTenantTx (GUC de tenant fijado: RLS por app.current_tenant_id()). validateAndTouch es UN solo UPDATE
// condicionado: validar y avanzar la ultima actividad son atomicos (dos requests concurrentes no se pisan).
// Cualquier fallo de la base se propaga al llamador (los bordes responden 503/fail-closed); nunca "valido por defecto".

import { CASE_SESSION_TOUCH_GRANULARITY_MS, type CaseSessionStorePort } from "../../../server/ports/case-session-store.port.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

const ts = (n: string): string => `pg_catalog.to_timestamp(${n}::double precision / 1000.0)`;

export function createPgCaseSessionStore(uow: Pick<PgUnitOfWork, "withTenantTx">): CaseSessionStorePort {
  return {
    async create(record) {
      await uow.withTenantTx(record.tenantId, async (tx) => {
        await tx.query(
          `INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at)
           VALUES ($1, $2, $3, $4, $5, ${ts("$6")}, ${ts("$7")}, ${ts("$6")})`,
          [record.tenantId, record.sidHash, record.caseRef, record.principalRef, record.role, String(record.issuedAtMs), String(record.expiresAtMs)],
        );
      });
    },
    async validateAndTouch(input) {
      return uow.withTenantTx(input.tenantId, async (tx) => {
        const cond = `tenant_id = $1 AND sid_hash = $2 AND case_ref = $3 AND principal_ref = $4 AND role = $5
              AND revoked_at IS NULL
              AND expires_at > ${ts("$6")}
              AND last_seen_at > ${ts("$7")}`;
        const params = [input.tenantId, input.sidHash, input.caseRef, input.principalRef, input.role, String(input.nowMs), String(input.nowMs - input.idleTimeoutMs)];
        // P2-4: UPDATE unico (atomico con la revocacion: `revoked_at IS NULL`) solo si la ultima actividad esta atrasada mas que la granularidad.
        const touched = await tx.query(
          `UPDATE app.case_session SET last_seen_at = ${ts("$6")}
            WHERE ${cond} AND last_seen_at < ${ts("$8")}`,
          [...params, String(input.nowMs - CASE_SESSION_TOUCH_GRANULARITY_MS)],
        );
        if (touched.rowCount === 1) return true;
        // Dentro de la ventana: valida con las MISMAS condiciones, sin escribir.
        const fresh = await tx.query(`SELECT 1 FROM app.case_session WHERE ${cond}`, params);
        return fresh.rowCount === 1;
      });
    },
    async revoke(tenantId, sidHash, nowMs) {
      await uow.withTenantTx(tenantId, async (tx) => {
        await tx.query(
          `UPDATE app.case_session SET revoked_at = ${ts("$3")} WHERE tenant_id = $1 AND sid_hash = $2 AND revoked_at IS NULL`,
          [tenantId, sidHash, String(nowMs)],
        );
      });
    },
    async purgeExpired(tenantId, nowMs, retentionMs) {
      return uow.withTenantTx(tenantId, async (tx) => {
        const r = await tx.query(`DELETE FROM app.case_session WHERE tenant_id = $1 AND expires_at < ${ts("$2")}`, [tenantId, String(nowMs - retentionMs)]);
        return r.rowCount ?? 0;
      });
    },
  };
}
