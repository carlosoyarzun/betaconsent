// Gobierna: CA-124 (H09), PR-C; src/server/ports/recovery-token.port.ts,
// db/migrations/0006_revocation_consent_recovery.sql y 0007_tenant_resolve.sql,
// revocation.spec.yaml RV0 / GRD-RV-06 / GRD-RV-23, ADR-006 §4, diseno postgres-design.md §3 y P1-2.
// ADR-001 §11: solo este adaptador conoce el SQL de app.recovery_token y de register_*.
//
// save inserta la proyeccion app.recovery_token (RLS por tenant) y registra el hash en
// tenant_resolve.recovery_token via tenant_resolve.register_recovery_token (SECURITY DEFINER: el
// tenant sale de app.current_tenant_id(), nunca de un parametro), todo en la misma transaccion de
// PgUnitOfWork.inTenant. El token es de un solo uso e inmutable salvo consumed_at.

import type { ChainRef } from "../../../server/modules/common/types.ts";
import type { RecoveryTokenRecord, RecoveryTokenRepositoryPort } from "../../../server/ports/recovery-token.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface RecoveryTokenRow {
  tenant_id: string;
  recovery_ref: string;
  token_hash: string;
  chain_ref: string;
  revoked_decision_ref: string;
  expires_at: Date;
  consumed_at: Date | null;
}

const COLUMNS = "tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at, consumed_at";

function toRecord(row: RecoveryTokenRow): RecoveryTokenRecord {
  return {
    tokenHash: row.token_hash,
    recoveryRef: row.recovery_ref,
    tenantId: row.tenant_id,
    chainRef: row.chain_ref as ChainRef,
    revokedDecisionRef: row.revoked_decision_ref,
    expiresAt: row.expires_at,
    ...(row.consumed_at !== null ? { consumedAt: row.consumed_at } : {}),
  };
}

export function createPgRecoveryTokenRepository(tx: TenantTx): RecoveryTokenRepositoryPort {
  return {
    async findByRef(tenantId, recoveryRef) {
      const r = await tx.query<RecoveryTokenRow>(
        `SELECT ${COLUMNS} FROM app.recovery_token WHERE tenant_id = $1 AND recovery_ref = $2`,
        [tenantId, recoveryRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      const inserted = await tx.query(
        `INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at, consumed_at)
         VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz)
         ON CONFLICT (tenant_id, recovery_ref) DO NOTHING
         RETURNING recovery_ref`,
        [
          record.tenantId,
          record.recoveryRef,
          record.tokenHash,
          record.chainRef,
          record.revokedDecisionRef,
          record.expiresAt.toISOString(),
          record.consumedAt?.toISOString() ?? null,
        ],
      );
      if (inserted.rows.length === 0) {
        // Ya existe: el token es inmutable (salvo consumed_at via consume). Un save identico es
        // idempotente; uno con datos distintos es un error de programacion y se rechaza.
        const existing = await tx.query<RecoveryTokenRow>(
          `SELECT ${COLUMNS} FROM app.recovery_token WHERE tenant_id = $1 AND recovery_ref = $2`,
          [record.tenantId, record.recoveryRef],
        );
        const row = existing.rows[0];
        if (
          !row ||
          row.token_hash !== record.tokenHash ||
          row.chain_ref !== record.chainRef ||
          row.revoked_decision_ref !== record.revokedDecisionRef ||
          row.expires_at.getTime() !== record.expiresAt.getTime()
        ) {
          throw new Error("recovery_token: save sobre una ref existente con datos distintos (el token es inmutable)");
        }
      }
      await tx.query("SELECT tenant_resolve.register_recovery_token($1, $2)", [record.tokenHash, record.recoveryRef]);
    },
    async consume(tenantId, recoveryRef) {
      // Consumo ATOMICO de un solo uso (SEC-CNS-015 P2-D): una sola sentencia UPDATE ... WHERE
      // consumed_at IS NULL RETURNING. Dos POST concurrentes con el mismo token se serializan en el
      // lock de fila; el segundo re-evalua el WHERE (READ COMMITTED), no encuentra fila y recibe
      // `false`. Bajo RLS, otro tenant o una ref inexistente tambien devuelven `false`.
      const r = await tx.query(
        `UPDATE app.recovery_token SET consumed_at = pg_catalog.now()
          WHERE tenant_id = $1 AND recovery_ref = $2 AND consumed_at IS NULL
          RETURNING recovery_ref`,
        [tenantId, recoveryRef],
      );
      return r.rows.length === 1;
    },
  };
}
