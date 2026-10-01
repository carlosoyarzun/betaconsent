-- scope: database
-- Gobierna: CA-128 / DEC-BR-014 rev. 8 §3 X6 ("revocación hasta COMPLETED con el stub interno (R5-1)"),
-- revocation.spec.yaml estados DOWNSTREAM_PENDING/DELIVERED/COMPLETED (R5/R6/R7) y GRD-RV-04
-- ("UNIQUE parcial (tenant_id, revoked_decision_ref) WHERE state NOT IN ('COMPLETED','FAILED')").
-- Migración nueva: 0006 y 0009 están mergeadas y no se editan.
--
-- 1) app.revocation.status admite los tres estados post-APPLIED de la spec.
-- 2) El índice de GRD-RV-04 pasa de `status <> 'FAILED'` (0009: IT0 aún sin COMPLETED) al predicado
--    exacto de la spec. GRD-CD-08 (consent_decision_single_active_grant_uq) depende del estado de la
--    ConsentDecision, no del de la Revocation: no cambia.
-- Los eventos de ledger de R5/R6/R7 (REVOCATION_DOWNSTREAM_EMITTED, REVOCATION_DELIVERED,
-- DOWNSTREAM_ERASURE_ATTESTED, RECEIPT_CREATED) ya están en la lista blanca de 0013.

ALTER TABLE app.revocation DROP CONSTRAINT revocation_status_enum;
ALTER TABLE app.revocation ADD CONSTRAINT revocation_status_enum
  CHECK (status IN ('REQUESTED', 'VERIFIED', 'CONFIRMED', 'APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED', 'FAILED'));

DROP INDEX app.revocation_open_per_decision_uq;
CREATE UNIQUE INDEX revocation_open_per_decision_uq
  ON app.revocation (tenant_id, revoked_decision_ref)
  WHERE status NOT IN ('COMPLETED', 'FAILED');
