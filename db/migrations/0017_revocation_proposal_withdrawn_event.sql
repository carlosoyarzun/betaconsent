-- scope: database
-- Gobierna: CA-128 / DEC-BR-014 rev. 8 §3 X6 (P2 aprobado por Carlos 2026-10-01: retiro de propuesta RH2 pendiente,
-- API-CNS-140), revocation.spec RH2 (propose/approve/withdraw), contracts/schemas/ledger-event-payloads.schema.json
-- REVOCATION_PROPOSAL_WITHDRAWN (solo refs UUIDv4, cero PII). Migración nueva: 0013 está mergeada y no se edita.
--
-- Agrega el tipo REVOCATION_PROPOSAL_WITHDRAWN a la lista blanca de event_type del ledger. La propuesta vive en
-- app.revocation (0016); el retiro la limpia (proposal_ref, proposed_by_ref, verification_script_version a NULL: los
-- CHECK de 0016 permiten el estado "sin propuesta") y la constancia queda en el ledger. No cambia el estado de la
-- revocación (INV-6: FAILED solo por R8). RLS FORCE por tenant de 0006/0016 sigue aplicando sin cambios.
-- Espejo de src/server/modules/common/ledger-event-types.ts (TEST-CNS-912 compara ambos).

ALTER TABLE integrity.audit_event
  DROP CONSTRAINT audit_event_event_type_allowlist;

ALTER TABLE integrity.audit_event
  ADD CONSTRAINT audit_event_event_type_allowlist CHECK (event_type IN (
    'INVITATION_CREATED', 'INVITATION_READY', 'INVITATION_SENT', 'INVITATION_TOKEN_ROTATED', 'INVITATION_OPENED',
    'INVITATION_VERIFIED', 'INVITATION_COMPLETED', 'INVITATION_DECLINED', 'INVITATION_EXPIRED', 'INVITATION_CANCELLED',
    'DECISION_MAKER_CHANNEL_VERIFIED',
    'CONTEXT_INFORMATION_VIEWED', 'CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED',
    'PURPOSE_DECISION_RECORDED', 'CONSENT_GRANTED', 'CONSENT_DECLINED', 'RECEIPT_CREATED', 'CONSENT_REVOKED',
    'REVOCATION_REQUESTED', 'REVOCATION_VERIFIED', 'REVOCATION_CONFIRMED', 'REVOCATION_DOWNSTREAM_EMITTED',
    'REVOCATION_DELIVERED', 'DOWNSTREAM_ERASURE_ATTESTED', 'REVOCATION_FAILED', 'REVOCATION_ESCALATED',
    'REVOCATION_PROPOSAL_WITHDRAWN',
    'RIGHTS_CASE_OPENED', 'RIGHTS_CASE_CONTACTING', 'RIGHTS_CASE_CLOSED',
    'TENANT_STATUS_CHANGED', 'SCHOOL_PARTICIPATION_STATUS_CHANGED', 'ENROLLMENT_STATUS_CHANGED',
    -- TRANSITORIOS (stream SECURITY; common.spec.yaml:141)
    'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
    'MANAGEMENT_TOKEN_ROTATED', 'RECOVERY_TOKEN_ISSUED',
    -- Seed LOCAL
    'TENANT_SEEDED', 'SCHOOL_PARTICIPATION_SEEDED'
  ));
