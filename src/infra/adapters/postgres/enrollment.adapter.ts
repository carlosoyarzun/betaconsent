// Gobierna: CA-124 (H09), PR-D; src/server/ports/enrollment-repository.port.ts,
// db/migrations/0010_invitation_otp_rights_case_enrollment.sql, tenant-context.spec.yaml (EN0,
// GRD-TC-03). ADR-001 §11: solo este adaptador conoce el SQL de app.enrollment.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).
// subject_ref y participation_ref se fijan al abrir el enrollment y no son actualizables.

import type { EnrollmentRecord, EnrollmentRepositoryPort, EnrollmentState } from "../../../server/ports/enrollment-repository.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** UNIQUE parcial (tenant_id, subject_ref, participation_ref) WHERE state = 'ACTIVE' (0010, GRD-TC-03). */
export const ENROLLMENT_SINGLE_ACTIVE_UNIQUE = "enrollment_single_active_uq";

interface EnrollmentRow {
  tenant_id: string;
  enrollment_ref: string;
  subject_ref: string;
  participation_ref: string;
  state: EnrollmentState;
}

const COLUMNS = "tenant_id, enrollment_ref, subject_ref, participation_ref, state";

function toRecord(row: EnrollmentRow): EnrollmentRecord {
  return {
    enrollmentRef: row.enrollment_ref,
    tenantId: row.tenant_id,
    subjectRef: row.subject_ref,
    participationRef: row.participation_ref,
    state: row.state,
  };
}

export function createPgEnrollmentRepository(tx: TenantTx): EnrollmentRepositoryPort {
  return {
    async findByRef(tenantId, enrollmentRef) {
      const r = await tx.query<EnrollmentRow>(
        `SELECT ${COLUMNS} FROM app.enrollment WHERE tenant_id = $1 AND enrollment_ref = $2`,
        [tenantId, enrollmentRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findActive(tenantId, subjectRef, participationRef) {
      const r = await tx.query<EnrollmentRow>(
        `SELECT ${COLUMNS} FROM app.enrollment
          WHERE tenant_id = $1 AND subject_ref = $2 AND participation_ref = $3 AND state = 'ACTIVE'
          ORDER BY created_at, enrollment_ref LIMIT 1`,
        [tenantId, subjectRef, participationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      await tx.query(
        `INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, enrollment_ref) DO UPDATE SET state = EXCLUDED.state`,
        [record.tenantId, record.enrollmentRef, record.subjectRef, record.participationRef, record.state],
      );
    },
  };
}
