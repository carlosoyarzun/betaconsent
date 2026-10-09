-- scope: database
-- Gobierna: SEC-CNS-021 PR-2 (aceptada por Carlos 2026-10-08; F-1, D1 a), CA-146, P-34, INV-21-01, INV-CM-01, ADR-002 §3, DEC-BR-017 §6,
-- common.spec.yaml streams.SECURITY (ops.security_event; "no es ledger de consentimiento").
-- Regla de Carlos (2026-10-01): 0000-0029 no se editan; esta migracion es nueva.
--
-- Los eventos del stream SECURITY (OTP_ISSUED, OTP_FAILED, OTP_LOCKED, OTP_EXPIRED, OTP_BUDGET_EXHAUSTED, MANAGEMENT_TOKEN_ROTATED,
-- RECOVERY_TOKEN_ISSUED) dejaron de escribirse en integrity.audit_event: los emisores usan ops.security_event (0029) en la misma tx.
-- Aqui se redefine la lista blanca del ledger SIN esos 7 tipos transitorios (0013, redefinida por 0017). Desde aqui el ledger rechaza
-- esos tipos con 23514 (check_violation).
--
-- REQUISITO: esta migracion EXIGE una base recreada (valido en IT0: LOCAL/CI, solo datos sinteticos). Una base con filas historicas
-- OTP_*/RECOVERY_TOKEN_ISSUED en integrity.audit_event queda INVERIFICABLE tras 0030: verifyChainRows las marca EVENT_TYPE_NOT_ALLOWED (esas
-- filas NO siguen siendo validas; el ledger es append-only y no se purga ni se reescribe, la cadena SHA-256 exige chain_seq contiguo).
-- Ademas, un challenge en curso cuyo OTP_ISSUED ocupa la sequence 1 daria conflicto en V3 (que ahora declara expectedSequence 0).
-- NOT VALID solo evita que ADD CONSTRAINT falle al aplicarse sobre una base no recreada: verifica las filas NUEVAS y no re-valida las
-- existentes. No se ejecuta VALIDATE CONSTRAINT (fallaria sobre esas filas).
--
-- integrity.audit_event pertenece a integrity_owner (0027): todo DDL sobre integrity.* declara SET LOCAL ROLE integrity_owner
-- (unica migracion, junto con 0027, autorizada por tools/spec-checks/integrity-owner-checker.ts). Espejo de
-- src/server/modules/common/ledger-event-types.ts (TEST-CNS-912 lo compara con el CHECK vigente).

SET LOCAL ROLE integrity_owner;

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
    -- Seed LOCAL
    'TENANT_SEEDED', 'SCHOOL_PARTICIPATION_SEEDED'
  )) NOT VALID;

SET LOCAL ROLE consent_owner;
