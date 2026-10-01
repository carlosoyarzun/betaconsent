-- scope: database
-- Gobierna: CA-128 / DEC-BR-014 rev. 8 §3 X6, revocation.spec.yaml RH2 (propose_case_verification +
-- approve_case_verification), GRD-RV-09 (rh2_dual_control_three_humans), ledger-event-payloads REVOCATION_VERIFIED
-- (verifiedByRef, secondApproverRef). Migración nueva: 0006/0009/0015 no se editan.
--
-- app.revocation guarda la propuesta del paso 1 (proposal_ref, proposed_by_ref = verifiedByRef, guion versionado) y el
-- aprobador del paso 2 (second_approver_ref). Refs opacas (CHECK de largo y sin '@'); aprobador distinto del proponente
-- (GRD-RV-09) y propuesta completa o ninguna, impuestos también en la base.

ALTER TABLE app.revocation
  ADD COLUMN proposal_ref                 text CONSTRAINT revocation_proposal_ref_len CHECK (pg_catalog.length(proposal_ref) BETWEEN 1 AND 100),
  ADD COLUMN proposed_by_ref              text CONSTRAINT revocation_proposed_by_len CHECK (pg_catalog.length(proposed_by_ref) BETWEEN 1 AND 100),
  ADD COLUMN verification_script_version  text CONSTRAINT revocation_script_version_shape CHECK (verification_script_version ~ '^[A-Za-z0-9._-]{1,32}$'),
  ADD COLUMN second_approver_ref          text CONSTRAINT revocation_second_approver_len CHECK (pg_catalog.length(second_approver_ref) BETWEEN 1 AND 100),
  ADD CONSTRAINT revocation_proposal_triple CHECK ((proposal_ref IS NULL) = (proposed_by_ref IS NULL) AND (proposal_ref IS NULL) = (verification_script_version IS NULL)),
  ADD CONSTRAINT revocation_rh2_distinct_humans CHECK (second_approver_ref IS NULL OR (proposed_by_ref IS NOT NULL AND second_approver_ref <> proposed_by_ref));

GRANT INSERT (proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref) ON app.revocation TO app_rw;
GRANT UPDATE (proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref) ON app.revocation TO app_rw;
