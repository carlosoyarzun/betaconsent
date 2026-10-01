// Gobierna: CA-124 (H09), PR-C; src/server/ports/consent-decision-repository.port.ts,
// db/migrations/0006_revocation_consent_recovery.sql, consent-decision.spec.yaml (GRD-CD-08,
// C6), INV-CM-02. ADR-001 §11: solo este adaptador conoce el SQL de app.consent_decision.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).

import { DomainError } from "../../../server/modules/common/errors.ts";
import type {
  ConsentDecisionRecord,
  ConsentDecisionRepositoryPort,
  ConsentDecisionState,
  PurposeDecision,
} from "../../../server/ports/consent-decision-repository.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** UNIQUE parcial (tenant_id, chain_ref) WHERE state IN ('GRANTED','PARTIALLY_GRANTED') (0009, GRD-CD-08). */
export const SINGLE_ACTIVE_GRANT_UNIQUE = "consent_decision_single_active_grant_uq";

interface ConsentDecisionRow {
  tenant_id: string;
  consent_id: string;
  context_ref: string;
  product_ref: string;
  subject_ref: string;
  decision_maker_ref: string;
  invitation_ref: string;
  verification_ref: string;
  chain_ref: string;
  state: ConsentDecisionState;
  purposes: PurposeDecision[];
  prior_steps_complete: boolean;
  steps_recorded: string[];
  receipt_ref: string | null;
}

const COLUMNS =
  "tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, " +
  "verification_ref, chain_ref, state, purposes, prior_steps_complete, steps_recorded, receipt_ref";

function toRecord(row: ConsentDecisionRow): ConsentDecisionRecord {
  return {
    consentId: row.consent_id,
    tenantId: row.tenant_id,
    contextRef: row.context_ref,
    productRef: row.product_ref,
    subjectRef: row.subject_ref,
    decisionMakerRef: row.decision_maker_ref,
    invitationRef: row.invitation_ref,
    verificationRef: row.verification_ref,
    chainRef: row.chain_ref,
    state: row.state,
    purposes: row.purposes,
    priorStepsComplete: row.prior_steps_complete,
    stepsRecorded: row.steps_recorded,
    ...(row.receipt_ref !== null ? { receiptRef: row.receipt_ref } : {}),
  };
}

export function createPgConsentDecisionRepository(tx: TenantTx): ConsentDecisionRepositoryPort {
  return {
    async findByConsentId(tenantId, consentId) {
      const r = await tx.query<ConsentDecisionRow>(
        `SELECT ${COLUMNS} FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2`,
        [tenantId, consentId],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByConsentIdForUpdate(tenantId, consentId) {
      const r = await tx.query<ConsentDecisionRow>(
        `SELECT ${COLUMNS} FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 FOR UPDATE`,
        [tenantId, consentId],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findActiveGrantByChain(tenantId, chainRef) {
      const r = await tx.query<ConsentDecisionRow>(
        `SELECT ${COLUMNS} FROM app.consent_decision
          WHERE tenant_id = $1 AND chain_ref = $2 AND state = 'GRANTED'
          ORDER BY created_at, consent_id LIMIT 1`,
        [tenantId, chainRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      try {
      // Upsert. Las columnas de identidad/vinculo (context, product, subject, decision maker,
      // invitation, verification, chain) se fijan al crear y no son actualizables (sin grant).
      await tx.query(
        `INSERT INTO app.consent_decision
           (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref,
            verification_ref, chain_ref, state, purposes, prior_steps_complete, steps_recorded, receipt_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::text[], $14)
         ON CONFLICT (tenant_id, consent_id) DO UPDATE SET
           state = EXCLUDED.state,
           purposes = EXCLUDED.purposes,
           prior_steps_complete = EXCLUDED.prior_steps_complete,
           steps_recorded = EXCLUDED.steps_recorded,
           receipt_ref = EXCLUDED.receipt_ref`,
        [
          record.tenantId,
          record.consentId,
          record.contextRef,
          record.productRef,
          record.subjectRef,
          record.decisionMakerRef,
          record.invitationRef,
          record.verificationRef,
          record.chainRef,
          record.state,
          JSON.stringify(record.purposes),
          record.priorStepsComplete,
          [...record.stepsRecorded],
          record.receiptRef ?? null,
        ],
      );
      } catch (error) {
        // GRD-CD-08 (single_active_grant_per_chain, INV-1): dos GRANTED concurrentes en la cadena =>
        // la segunda recibe ERR-CD-01 (ALREADY_DECIDED), el mismo error del guard del dominio.
        const e = error as { code?: string; constraint?: string };
        if (e.code === "23505" && e.constraint === SINGLE_ACTIVE_GRANT_UNIQUE) throw new DomainError("ERR-CD-01");
        throw error;
      }
    },
  };
}
