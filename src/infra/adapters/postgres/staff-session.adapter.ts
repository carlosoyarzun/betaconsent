// Gobierna: CA-138, SEC-CNS-018 rev. 2 (D-3), src/server/ports/staff-session-store.port.ts, db/migrations/0021_staff_session.sql,
// ADR-001 §11 (solo este adaptador conoce el SQL de app.staff_session). Cada operacion corre en su propia tx de
// PgUnitOfWork.withTenantTx (GUC de tenant fijado: RLS por app.current_tenant_id()). validateAndTouch es UN solo UPDATE
// condicionado: validar y avanzar la ultima actividad son atomicos (dos requests concurrentes no se pisan).
// CA-141: login/logout/rotacion escriben su evento en ops.security_event EN LA MISMA tx (security-event.adapter.ts; sin evento no hay efecto).
// Cualquier fallo de la base se propaga al llamador (los bordes responden 503/fail-closed); nunca "valido por defecto".

import { STAFF_SESSION_TOUCH_GRANULARITY_MS, type StaffSessionStorePort } from "../../../server/ports/staff-session-store.port.ts";
import type { SecurityEventActorRole } from "../../../server/ports/security-event.port.ts";
import { createPgSecurityEventAdapter } from "./security-event.adapter.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

const ts = (n: string): string => `pg_catalog.to_timestamp(${n}::double precision / 1000.0)`;

export function createPgStaffSessionStore(uow: Pick<PgUnitOfWork, "withTenantTx">): StaffSessionStorePort {
  return {
    async create(record) {
      return uow.withTenantTx(record.tenantId, async (tx) => {
        const inserted = await tx.query<{ session_ref: string }>(
          `INSERT INTO app.staff_session (tenant_id, sid_hash, principal_ref, role, issued_at, expires_at, last_seen_at)
           VALUES ($1, $2, $3, $4, ${ts("$5")}, ${ts("$6")}, ${ts("$5")}) RETURNING session_ref`,
          [record.tenantId, record.sidHash, record.principalRef, record.role, String(record.issuedAtMs), String(record.expiresAtMs)],
        );
        const sessionRef = inserted.rows[0]?.session_ref;
        if (sessionRef === undefined) throw new Error("staff session: INSERT sin session_ref");
        // CA-141: el LOGIN se escribe en la MISMA tx; si falla (SecurityEventWriteError) no queda sesion.
        await createPgSecurityEventAdapter(tx).record({
          tenantId: record.tenantId,
          eventType: "STAFF_LOGIN",
          actorRef: record.principalRef,
          actorRole: record.role,
          sessionKind: "STAFF",
          sessionRef,
        });
        return { sessionRef };
      });
    },
    async validateAndTouch(input) {
      return uow.withTenantTx(input.tenantId, async (tx) => {
        const cond = `tenant_id = $1 AND sid_hash = $2 AND principal_ref = $3 AND role = $4
              AND revoked_at IS NULL
              AND expires_at > ${ts("$5")}
              AND last_seen_at > ${ts("$6")}`;
        const params = [input.tenantId, input.sidHash, input.principalRef, input.role, String(input.nowMs), String(input.nowMs - input.idleTimeoutMs)];
        // P2-4: UPDATE unico (atomico con la revocacion: `revoked_at IS NULL`) solo si la ultima actividad esta atrasada mas que la granularidad.
        const touched = await tx.query(
          `UPDATE app.staff_session SET last_seen_at = ${ts("$5")}
            WHERE ${cond} AND last_seen_at < ${ts("$7")}`,
          [...params, String(input.nowMs - STAFF_SESSION_TOUCH_GRANULARITY_MS)],
        );
        if (touched.rowCount === 1) return true;
        // Dentro de la ventana: valida con las MISMAS condiciones, sin escribir.
        const fresh = await tx.query(`SELECT 1 FROM app.staff_session WHERE ${cond}`, params);
        return fresh.rowCount === 1;
      });
    },
    async revoke(tenantId, sidHash, nowMs, cause) {
      return uow.withTenantTx(tenantId, async (tx) => {
        const revoked = await tx.query<{ session_ref: string; principal_ref: string; role: string  }>(
          `UPDATE app.staff_session SET revoked_at = ${ts("$3")} WHERE tenant_id = $1 AND sid_hash = $2 AND revoked_at IS NULL
             RETURNING session_ref, principal_ref, role`,
          [tenantId, sidHash, String(nowMs)],
        );
        const row = revoked.rows[0];
        if (row === undefined) return false; // desconocida, de otro tenant o ya revocada: idempotente, sin evento
        // CA-141: LOGOUT / ROTATION en la MISMA tx, con el actor de la FILA (no de la cookie); si falla se revierte la revocacion.
        await createPgSecurityEventAdapter(tx).record({
          tenantId,
          eventType: cause === "USER_LOGOUT" ? "STAFF_LOGOUT" : "SESSION_REVOKED_BY_ROTATION",
          actorRef: row.principal_ref,
          actorRole: row.role as SecurityEventActorRole,
          sessionKind: "STAFF",
          sessionRef: row.session_ref,
        });
        return true;
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
