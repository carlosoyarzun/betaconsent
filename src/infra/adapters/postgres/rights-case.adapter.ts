// Gobierna: CA-124 (H09), PR-D; src/server/ports/rights-case-repository.port.ts,
// db/migrations/0010_invitation_otp_rights_case_enrollment.sql, rights-case.spec.yaml (GRD-RC-02,
// GRD-RC-14), SEC-CNS-015 P2-E. ADR-001 §11: solo este adaptador conoce el SQL de app.rights_case.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).
// chain_ref y revoked_decision_ref se fijan al abrir el caso y no son actualizables.

import type {
  RightsCaseOrigin,
  RightsCaseRecord,
  RightsCaseRepositoryPort,
  RightsCaseStatus,
} from "../../../server/ports/rights-case-repository.port.ts";
import type { ChainRef } from "../../../server/modules/common/types.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** UNIQUE parcial (tenant_id, chain_ref, revoked_decision_ref) WHERE status no terminal (0010, GRD-RC-02). */
export const RIGHTS_CASE_SINGLE_OPEN_UNIQUE = "rights_case_single_open_uq";

interface RightsCaseRow {
  tenant_id: string;
  case_ref: string;
  chain_ref: string;
  revoked_decision_ref: string;
  status: RightsCaseStatus;
  revocation_ref: string | null;
  origin: RightsCaseOrigin | null;
}

const COLUMNS = "tenant_id, case_ref, chain_ref, revoked_decision_ref, status, revocation_ref, origin";

function toRecord(row: RightsCaseRow): RightsCaseRecord {
  return {
    caseRef: row.case_ref,
    tenantId: row.tenant_id,
    chainRef: row.chain_ref as ChainRef,
    revokedDecisionRef: row.revoked_decision_ref,
    status: row.status,
    ...(row.revocation_ref !== null ? { revocationRef: row.revocation_ref } : {}),
    ...(row.origin !== null ? { origin: row.origin } : {}),
  };
}

export function createPgRightsCaseRepository(tx: TenantTx): RightsCaseRepositoryPort {
  return {
    async findOpenByChain(tenantId, chainRef, revokedDecisionRef) {
      const r = await tx.query<RightsCaseRow>(
        `SELECT ${COLUMNS} FROM app.rights_case
          WHERE tenant_id = $1 AND chain_ref = $2 AND revoked_decision_ref = $3
            AND status NOT IN ('RESOLVED', 'WITHDRAWN')
          ORDER BY created_at, case_ref LIMIT 1`,
        [tenantId, chainRef, revokedDecisionRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRef(tenantId, caseRef) {
      const r = await tx.query<RightsCaseRow>(
        `SELECT ${COLUMNS} FROM app.rights_case WHERE tenant_id = $1 AND case_ref = $2`,
        [tenantId, caseRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRefForUpdate(tenantId, caseRef) {
      // Lock de fila hasta COMMIT/ROLLBACK: serializa RC2u/RC3/RC4-6 sobre el mismo caso.
      const r = await tx.query<RightsCaseRow>(
        `SELECT ${COLUMNS} FROM app.rights_case WHERE tenant_id = $1 AND case_ref = $2 FOR UPDATE`,
        [tenantId, caseRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      await tx.query(
        `INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, revocation_ref, origin)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (tenant_id, case_ref) DO UPDATE SET
           status = EXCLUDED.status,
           revocation_ref = EXCLUDED.revocation_ref,
           origin = EXCLUDED.origin`,
        [
          record.tenantId,
          record.caseRef,
          record.chainRef,
          record.revokedDecisionRef,
          record.status,
          record.revocationRef ?? null,
          record.origin ?? null,
        ],
      );
    },
  };
}
