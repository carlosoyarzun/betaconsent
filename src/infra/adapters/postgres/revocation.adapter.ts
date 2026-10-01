// Gobierna: CA-124 (H09), PR-C; src/server/ports/revocation-repository.port.ts,
// db/migrations/0006_revocation_consent_recovery.sql, revocation.spec.yaml, INV-CM-02.
// ADR-001 §11: solo este adaptador conoce el SQL de app.revocation.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (tenant fijado con set_config local):
// RLS filtra por app.current_tenant_id(); tenant_id se pasa ademas en cada filtro y como
// WITH CHECK de INSERT/UPDATE (un tenantId ajeno al de la transaccion es rechazado por la base).

import type { ChainRef } from "../../../server/modules/common/types.ts";
import type {
  RevocationRecord,
  RevocationRepositoryPort,
  RevocationStatus,
} from "../../../server/ports/revocation-repository.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** UNIQUE parcial (tenant_id, revoked_decision_ref) WHERE status NOT IN ('FAILED','COMPLETED') (0015; 0009 era status <> 'FAILED', GRD-RV-04). */
export const OPEN_REVOCATION_UNIQUE = "revocation_open_per_decision_uq";

interface RevocationRow {
  tenant_id: string;
  revocation_ref: string;
  chain_ref: string;
  case_ref: string | null;
  status: RevocationStatus;
  attested_revocation_ref: string | null;
  attested_case_ref: string | null;
  recorded_by_ref: string | null;
  cosigned_by_ref: string | null;
  revoked_decision_ref: string | null;
  verified_auth_path: "OTP" | "RECOVERY" | null;
  verified_recovery_method: "CHANNEL_LINK" | "HUMAN_ASSISTED" | null;
  reason_code: "WITHDRAWN_BY_REQUESTER" | null;
  proposal_ref: string | null;
  proposed_by_ref: string | null;
  verification_script_version: string | null;
  second_approver_ref: string | null;
}

const COLUMNS =
  "tenant_id, revocation_ref, chain_ref, case_ref, status, attested_revocation_ref, attested_case_ref, " +
  "recorded_by_ref, cosigned_by_ref, revoked_decision_ref, verified_auth_path, verified_recovery_method, reason_code, proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref";

function toRecord(row: RevocationRow): RevocationRecord {
  return {
    revocationRef: row.revocation_ref,
    tenantId: row.tenant_id,
    chainRef: row.chain_ref as ChainRef,
    status: row.status,
    ...(row.case_ref !== null ? { caseRef: row.case_ref } : {}),
    ...(row.attested_revocation_ref !== null && row.attested_case_ref !== null
      ? { attestedVerification: { revocationRef: row.attested_revocation_ref, caseRef: row.attested_case_ref } }
      : {}),
    ...(row.recorded_by_ref !== null ? { recordedByRef: row.recorded_by_ref } : {}),
    ...(row.cosigned_by_ref !== null ? { cosignedByRef: row.cosigned_by_ref } : {}),
    ...(row.revoked_decision_ref !== null ? { revokedDecisionRef: row.revoked_decision_ref } : {}),
    ...(row.verified_auth_path !== null ? { verifiedAuthPath: row.verified_auth_path } : {}),
    ...(row.verified_recovery_method !== null ? { verifiedRecoveryMethod: row.verified_recovery_method } : {}),
    ...(row.reason_code !== null ? { reasonCode: row.reason_code } : {}),
    ...(row.proposal_ref !== null && row.proposed_by_ref !== null && row.verification_script_version !== null
      ? { proposal: { proposalRef: row.proposal_ref, proposedByRef: row.proposed_by_ref, verificationScriptVersion: row.verification_script_version } }
      : {}),
    ...(row.second_approver_ref !== null ? { secondApproverRef: row.second_approver_ref } : {}),
  };
}

export function createPgRevocationRepository(tx: TenantTx): RevocationRepositoryPort {
  return {
    async findByRef(tenantId, revocationRef) {
      const r = await tx.query<RevocationRow>(
        `SELECT ${COLUMNS} FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2`,
        [tenantId, revocationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRefForUpdate(tenantId, revocationRef) {
      // Lock de fila hasta COMMIT/ROLLBACK: serializa R2/R3/R4/R8/RH* y relee el estado vigente
      // tras esperar a la unidad ganadora (READ COMMITTED re-evalua la fila bloqueada).
      const r = await tx.query<RevocationRow>(
        `SELECT ${COLUMNS} FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2 FOR UPDATE`,
        [tenantId, revocationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByCase(tenantId, caseRef) {
      const r = await tx.query<RevocationRow>(
        `SELECT ${COLUMNS} FROM app.revocation WHERE tenant_id = $1 AND case_ref = $2 ORDER BY created_at, revocation_ref LIMIT 1`,
        [tenantId, caseRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findOpenByChain(tenantId, chainRef) {
      const r = await tx.query<RevocationRow>(
        `SELECT ${COLUMNS} FROM app.revocation
          WHERE tenant_id = $1 AND chain_ref = $2 AND status NOT IN ('FAILED', 'COMPLETED')
          ORDER BY created_at, revocation_ref LIMIT 1`,
        [tenantId, chainRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findOpenByDecision(tenantId, revokedDecisionRef) {
      const r = await tx.query<RevocationRow>(
        `SELECT ${COLUMNS} FROM app.revocation
          WHERE tenant_id = $1 AND revoked_decision_ref = $2 AND status NOT IN ('FAILED', 'COMPLETED')
          ORDER BY created_at, revocation_ref LIMIT 1`,
        [tenantId, revokedDecisionRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      // Upsert. chain_ref y revoked_decision_ref se fijan al crear (R1/R1r) y no son actualizables
      // (sin grant de columna): un save posterior no puede revincular la revocacion a otra cadena.
      await tx.query(
        `INSERT INTO app.revocation
           (tenant_id, revocation_ref, chain_ref, case_ref, status, attested_revocation_ref, attested_case_ref,
            recorded_by_ref, cosigned_by_ref, revoked_decision_ref, verified_auth_path, verified_recovery_method, reason_code,
            proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         ON CONFLICT (tenant_id, revocation_ref) DO UPDATE SET
           case_ref = EXCLUDED.case_ref,
           status = EXCLUDED.status,
           attested_revocation_ref = EXCLUDED.attested_revocation_ref,
           attested_case_ref = EXCLUDED.attested_case_ref,
           recorded_by_ref = EXCLUDED.recorded_by_ref,
           cosigned_by_ref = EXCLUDED.cosigned_by_ref,
           verified_auth_path = EXCLUDED.verified_auth_path,
           verified_recovery_method = EXCLUDED.verified_recovery_method,
           reason_code = EXCLUDED.reason_code,
           proposal_ref = EXCLUDED.proposal_ref,
           proposed_by_ref = EXCLUDED.proposed_by_ref,
           verification_script_version = EXCLUDED.verification_script_version,
           second_approver_ref = EXCLUDED.second_approver_ref`,
        [
          record.tenantId,
          record.revocationRef,
          record.chainRef,
          record.caseRef ?? null,
          record.status,
          record.attestedVerification?.revocationRef ?? null,
          record.attestedVerification?.caseRef ?? null,
          record.recordedByRef ?? null,
          record.cosignedByRef ?? null,
          record.revokedDecisionRef ?? null,
          record.verifiedAuthPath ?? null,
          record.verifiedRecoveryMethod ?? null,
          record.reasonCode ?? null,
          record.proposal?.proposalRef ?? null,
          record.proposal?.proposedByRef ?? null,
          record.proposal?.verificationScriptVersion ?? null,
          record.secondApproverRef ?? null,
        ],
      );
    },
  };
}
