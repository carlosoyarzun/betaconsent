-- scope: database
-- Gobierna: CA-124 (H09), PR-E; consent-decision.spec.yaml (decisionChainKey = tenantRef, contextRef,
-- subjectRef, decisionMakerRef; opaco, ADR-002 §10), src/server/modules/consent-decision/consent-decision.ts
-- deriveChainRef, ADR-006. Regla de Carlos (2026-10-01): 0000-0012 no se editan; SQL nuevo desde 0013.
--
-- FINDING P1 (contract<->implementation) hallado por el e2e de Postgres (TEST-CNS-872): el dominio deriva
-- chainRef = `chain:<tenantUUID>:<contexto>:<subjectUUID>:dm:<32 hex>` (~128 caracteres con UUIDs), pero 0006
-- limitaba chain_ref a 100 y 0002 limitaba audit_event.aggregate_id a 100 (RECOVERY_TOKEN_ISSUED usa el
-- chainRef como aggregateId). En memoria nunca se notaba. Se alinea con el limite que ya tienen
-- app.rights_case.chain_ref (0010), tenant_resolve.handle.chain_ref (0011) y otp_verification.parent_ref:
-- 255. Solo ensancha un limite de longitud; sin cambio de semantica ni de privilegios.

ALTER TABLE app.consent_decision DROP CONSTRAINT consent_decision_chain_len;
ALTER TABLE app.consent_decision ADD CONSTRAINT consent_decision_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 255);

ALTER TABLE app.revocation DROP CONSTRAINT revocation_chain_len;
ALTER TABLE app.revocation ADD CONSTRAINT revocation_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 255);

ALTER TABLE app.recovery_token DROP CONSTRAINT recovery_token_chain_len;
ALTER TABLE app.recovery_token ADD CONSTRAINT recovery_token_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 255);

ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_aggregate_id_len;
ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_aggregate_id_len CHECK (pg_catalog.length(aggregate_id) BETWEEN 1 AND 255);
