// Gobierna: CA-124 (H09), PR-D; src/server/ports/rights-case-repository.port.ts,
// db/migrations/0010_invitation_otp_rights_case_enrollment.sql, rights-case.spec.yaml (GRD-RC-02,
// GRD-RC-14), SEC-CNS-015 P2-E. ADR-001 §11: solo este adaptador conoce el SQL de case_state.rights_case.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).
// chain_ref y revoked_decision_ref se fijan al abrir el caso y no son actualizables.
// ADR-010 PR-5b (INV-RC-07): app_rw ya NO tiene INSERT/UPDATE sobre case_state.rights_case (0038). Las transiciones reales del dominio las escriben las
// funciones case_state.* (rights-case-transitions.adapter.ts); `save` es solo el contrato de siembra del puerto (LOCAL) y llama
// case_state.seed_local_rights_case, que falla fuera de LOCAL.

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
        `SELECT ${COLUMNS} FROM case_state.rights_case
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
        `SELECT ${COLUMNS} FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2`,
        [tenantId, caseRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRefForUpdate(tenantId, caseRef) {
      // ADR-010 PR-5b: app_rw ya no tiene UPDATE sobre case_state.rights_case y SELECT ... FOR UPDATE lo exige: la lectura NO bloquea. La serializacion
      // de RC2u/RC3/RC4-6 la hace cada funcion case_state.* (FOR UPDATE de la fila + control de la secuencia esperada: una lectura vieja da RV409
      // y el UoW reejecuta con estado fresco).
      const r = await tx.query<RightsCaseRow>(
        `SELECT ${COLUMNS} FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2`,
        [tenantId, caseRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      await tx.query(
        "SELECT case_state.seed_local_rights_case($1::uuid, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text)",
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
