// Gobierna: CA-124 (H09), PR-D; src/server/ports/otp-verification-repository.port.ts,
// db/migrations/0010_invitation_otp_rights_case_enrollment.sql, otp-challenge.spec.yaml (GRD-OT-04,
// GRD-OT-08, INV-OT-02), SEC-CNS-015 P2-B/P2-E. ADR-001 §11: solo este adaptador conoce el SQL de
// app.otp_verification.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).
// El codigo en claro nunca llega aqui (solo code_hash); scope, padre y canal son inmutables.

import type {
  OtpScope,
  OtpVerificationRecord,
  OtpVerificationRepositoryPort,
  OtpVerificationState,
} from "../../../server/ports/otp-verification-repository.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** UNIQUE parcial (tenant_id, parent_ref, scope) WHERE state IN ('NOT_STARTED','CODE_SENT') (0010, GRD-OT-08). */
export const OTP_SINGLE_ACTIVE_UNIQUE = "otp_single_active_uq";

interface OtpRow {
  tenant_id: string;
  verification_ref: string;
  scope: OtpScope;
  parent_ref: string;
  channel_ref: string;
  code_hash: string;
  attempts: number;
  expires_at: Date;
  consumed_at: Date | null;
  state: OtpVerificationState;
  resend_count: number;
}

const COLUMNS =
  "tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, consumed_at, state, resend_count";

function toRecord(row: OtpRow): OtpVerificationRecord {
  return {
    verificationRef: row.verification_ref,
    tenantId: row.tenant_id,
    scope: row.scope,
    parentRef: row.parent_ref,
    channelRef: row.channel_ref,
    codeHash: row.code_hash,
    attempts: row.attempts,
    expiresAt: row.expires_at,
    ...(row.consumed_at !== null ? { consumedAt: row.consumed_at } : {}),
    state: row.state,
    resendCount: row.resend_count,
  };
}

export function createPgOtpVerificationRepository(tx: TenantTx): OtpVerificationRepositoryPort {
  return {
    async findByRef(tenantId, verificationRef) {
      const r = await tx.query<OtpRow>(
        `SELECT ${COLUMNS} FROM app.otp_verification WHERE tenant_id = $1 AND verification_ref = $2`,
        [tenantId, verificationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRefForUpdate(tenantId, verificationRef) {
      // Lock de fila hasta COMMIT/ROLLBACK: dos verificaciones concurrentes del mismo challenge se
      // serializan y la segunda decide sobre el estado ya confirmado por la primera (GRD-OT-04).
      const r = await tx.query<OtpRow>(
        `SELECT ${COLUMNS} FROM app.otp_verification WHERE tenant_id = $1 AND verification_ref = $2 FOR UPDATE`,
        [tenantId, verificationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findActiveByParent(tenantId, parentRef, scope) {
      const r = await tx.query<OtpRow>(
        `SELECT ${COLUMNS} FROM app.otp_verification
          WHERE tenant_id = $1 AND parent_ref = $2 AND scope = $3 AND state IN ('NOT_STARTED', 'CODE_SENT')
          ORDER BY created_at, verification_ref LIMIT 1`,
        [tenantId, parentRef, scope],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      // Upsert. scope, padre y canal se fijan al emitir y no son actualizables (sin grant de columna).
      await tx.query(
        `INSERT INTO app.otp_verification
           (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, consumed_at, state, resend_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10, $11)
         ON CONFLICT (tenant_id, verification_ref) DO UPDATE SET
           code_hash = EXCLUDED.code_hash,
           attempts = EXCLUDED.attempts,
           expires_at = EXCLUDED.expires_at,
           consumed_at = EXCLUDED.consumed_at,
           state = EXCLUDED.state,
           resend_count = EXCLUDED.resend_count`,
        [
          record.tenantId,
          record.verificationRef,
          record.scope,
          record.parentRef,
          record.channelRef,
          record.codeHash,
          record.attempts,
          record.expiresAt.toISOString(),
          record.consumedAt?.toISOString() ?? null,
          record.state,
          record.resendCount,
        ],
      );
    },
  };
}
