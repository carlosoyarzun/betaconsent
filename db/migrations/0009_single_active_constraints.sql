-- scope: database
-- Gobierna: CA-124 (H09), PR-C; SEC-CNS-015 P1-2; consent-decision.spec.yaml GRD-CD-08
-- (single_active_grant_per_chain: indice unico parcial sobre la cadena WHERE state IN (GRANTED,
-- PARTIALLY_GRANTED), INV-1) y revocation.spec.yaml GRD-RV-04 (<=1 Revocation no terminal por
-- decision GRANTED revocada, R14-C: UNIQUE parcial (tenant_id, revoked_decision_ref)).
-- 0005..0008 aun no estan en main; esto va en migracion nueva y sustituye el indice no unico de 0006.
--
-- GRD-CD-08: dos decisiones vigentes (GRANTED) de la misma cadena no pueden coexistir; la segunda
--   falla con 23505 (el adaptador lo mapea a ERR-CD-01). 'PARTIALLY_GRANTED' no esta modelado en IT0
--   (el CHECK de state no lo admite) pero el predicado sigue a la spec.
-- GRD-RV-04 equivalente IT0: el modelo IT0 no tiene el estado COMPLETED; "no terminal" = status <> 'FAILED'
--   (APPLIED cuenta como abierta, igual que findOpenByChain). Una revocacion de un ciclo anterior tiene
--   otra revoked_decision_ref, asi que no absorbe la del consentimiento nuevo.
-- revoked_decision_ref pasa a NOT NULL: todos los flujos que crean Revocation (R1, R1r, RC3, seed RH3)
--   la fijan en servidor desde la decision GRANTED vigente (R14-C).

ALTER TABLE app.revocation ALTER COLUMN revoked_decision_ref SET NOT NULL;

DROP INDEX app.consent_decision_active_grant_idx;
CREATE UNIQUE INDEX consent_decision_single_active_grant_uq
  ON app.consent_decision (tenant_id, chain_ref)
  WHERE state IN ('GRANTED', 'PARTIALLY_GRANTED');

CREATE UNIQUE INDEX revocation_open_per_decision_uq
  ON app.revocation (tenant_id, revoked_decision_ref)
  WHERE status <> 'FAILED';
