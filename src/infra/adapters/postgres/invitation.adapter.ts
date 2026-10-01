// Gobierna: CA-124 (H09), PR-D; src/server/ports/invitation-repository.port.ts,
// db/migrations/0010_invitation_otp_rights_case_enrollment.sql y 0011_tenant_resolve_invitation_handle.sql,
// invitation.spec.yaml (GRD-IV-01, GRD-IV-05, GRD-IV-07), ADR-006 §4, SEC-CNS-015 P2-B/P2-E.
// ADR-001 §11: solo este adaptador conoce el SQL de app.invitation y de register_invitation_token.
//
// Opera DENTRO de la transaccion de PgUnitOfWork.inTenant (RLS por app.current_tenant_id()).
// save inserta/actualiza la proyeccion y, cuando el registro lleva tokenHash (I3 en adelante),
// registra el hash en tenant_resolve.invitation_token via tenant_resolve.register_invitation_token
// (SECURITY DEFINER: el tenant sale de app.current_tenant_id(), nunca de un parametro). El lookup por
// hash SIN tenant lo hace TenantResolverPort.byInvitationTokenHash, no este repo.

import { InvalidRecipientChannelRefError, type InvitationRecord, type InvitationRepositoryPort, type InvitationState } from "../../../server/ports/invitation-repository.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** CHECK de 0010: recipient_channel_ref solo admite email reservado (app.is_reserved_email). FINDING contrato<->BD (EXT-B/LD-21). */
export const INVITATION_RECIPIENT_CHANNEL_CHECK = "invitation_recipient_channel_reserved";

/** UNIQUE parcial (tenant_id, context_ref, subject_ref) WHERE state no terminal (0010, GRD-IV-01). */
export const INVITATION_SINGLE_NON_TERMINAL_UNIQUE = "invitation_single_non_terminal_uq";

interface InvitationRow {
  tenant_id: string;
  invitation_ref: string;
  context_ref: string;
  product_ref: string;
  subject_ref: string;
  state: InvitationState;
  consent_version: string | null;
  expires_at: Date | null;
  recipient_channel_ref: string | null;
  token_hash: string | null;
  bound_decision_maker_ref: string | null;
  enrollment_ref: string | null;
  participation_ref: string | null;
  reissue_of_ref: string | null;
  recipient_binding: "RECIPIENT_CHANNEL" | "UNBOUND" | null;
}

const COLUMNS =
  "tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, consent_version, expires_at, " +
  "recipient_channel_ref, token_hash, bound_decision_maker_ref, enrollment_ref, participation_ref, reissue_of_ref, recipient_binding";

function toRecord(row: InvitationRow): InvitationRecord {
  return {
    invitationRef: row.invitation_ref,
    tenantId: row.tenant_id,
    contextRef: row.context_ref,
    productRef: row.product_ref,
    subjectRef: row.subject_ref,
    state: row.state,
    ...(row.consent_version !== null ? { consentVersion: row.consent_version } : {}),
    ...(row.expires_at !== null ? { expiresAt: row.expires_at } : {}),
    ...(row.recipient_channel_ref !== null ? { recipientChannelRef: row.recipient_channel_ref } : {}),
    ...(row.token_hash !== null ? { tokenHash: row.token_hash } : {}),
    ...(row.bound_decision_maker_ref !== null ? { boundDecisionMakerRef: row.bound_decision_maker_ref } : {}),
    ...(row.enrollment_ref !== null ? { enrollmentRef: row.enrollment_ref } : {}),
    ...(row.participation_ref !== null ? { participationRef: row.participation_ref } : {}),
    ...(row.reissue_of_ref !== null ? { reissueOfRef: row.reissue_of_ref } : {}),
    ...(row.recipient_binding !== null ? { recipientBinding: row.recipient_binding } : {}),
  };
}

export function createPgInvitationRepository(tx: TenantTx): InvitationRepositoryPort {
  return {
    async findByRef(tenantId, invitationRef) {
      const r = await tx.query<InvitationRow>(
        `SELECT ${COLUMNS} FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2`,
        [tenantId, invitationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findByRefForUpdate(tenantId, invitationRef) {
      // Lock de fila hasta COMMIT/ROLLBACK: serializa I2..I7 sobre la misma invitacion y relee el
      // estado vigente tras esperar a la unidad ganadora (READ COMMITTED re-evalua la fila bloqueada).
      const r = await tx.query<InvitationRow>(
        `SELECT ${COLUMNS} FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 FOR UPDATE`,
        [tenantId, invitationRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async findActiveBySubject(tenantId, contextRef, subjectRef) {
      const r = await tx.query<InvitationRow>(
        `SELECT ${COLUMNS} FROM app.invitation
          WHERE tenant_id = $1 AND context_ref = $2 AND subject_ref = $3
            AND state IN ('DRAFT', 'READY', 'SENT', 'OPENED', 'VERIFIED')
          ORDER BY created_at, invitation_ref LIMIT 1`,
        [tenantId, contextRef, subjectRef],
      );
      const row = r.rows[0];
      return row ? toRecord(row) : null;
    },
    async save(record) {
      // Upsert. La identidad (contexto, producto, sujeto, enrollment, participacion, reemision) se
      // fija al crear y no es actualizable (sin grant de columna).
      try {
        await tx.query(
        `INSERT INTO app.invitation
           (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, consent_version, expires_at,
            recipient_channel_ref, token_hash, bound_decision_maker_ref, enrollment_ref, participation_ref,
            reissue_of_ref, recipient_binding)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9, $10, $11, $12, $13, $14, $15)
         ON CONFLICT (tenant_id, invitation_ref) DO UPDATE SET
           state = EXCLUDED.state,
           consent_version = EXCLUDED.consent_version,
           expires_at = EXCLUDED.expires_at,
           recipient_channel_ref = EXCLUDED.recipient_channel_ref,
           token_hash = EXCLUDED.token_hash,
           bound_decision_maker_ref = EXCLUDED.bound_decision_maker_ref,
           recipient_binding = EXCLUDED.recipient_binding`,
        [
          record.tenantId,
          record.invitationRef,
          record.contextRef,
          record.productRef,
          record.subjectRef,
          record.state,
          record.consentVersion ?? null,
          record.expiresAt?.toISOString() ?? null,
          record.recipientChannelRef ?? null,
          record.tokenHash ?? null,
          record.boundDecisionMakerRef ?? null,
          record.enrollmentRef ?? null,
          record.participationRef ?? null,
          record.reissueOfRef ?? null,
          record.recipientBinding ?? null,
        ],
        );
      } catch (error) {
        // 23514 del CHECK de recipient_channel_ref: valor no admitido por la BD -> error tipado (el borde HTTP da 422).
        const e = error as { code?: unknown; constraint?: unknown } | null;
        if (e?.code === "23514" && e.constraint === INVITATION_RECIPIENT_CHANNEL_CHECK) throw new InvalidRecipientChannelRefError();
        throw error;
      }
      if (record.tokenHash !== undefined) {
        // Idempotente para el mismo (hash, tenant, ref): cada save posterior a I3 lo repite sin efecto.
        await tx.query("SELECT tenant_resolve.register_invitation_token($1, $2)", [record.tokenHash, record.invitationRef]);
      }
    },
  };
}
