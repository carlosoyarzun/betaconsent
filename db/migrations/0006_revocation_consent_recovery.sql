-- scope: database
-- Gobierna: CA-124 (H09), PR-C; src/server/ports/{consent-decision-repository,revocation-repository,
-- recovery-token}.port.ts, consent-decision.spec.yaml, revocation.spec.yaml (R4, RV0, GRD-RV-04/06),
-- common.spec.yaml INV-CM-02 (tenant_id unica clave de aislamiento), ADR-006 §1/§4-§6,
-- DEC-BR-014 §4 (solo datos sinteticos), diseno postgres-design.md rev. 2 §3.
--
-- Proyecciones de agregado app.consent_decision, app.revocation y app.recovery_token. Garantias:
--   * PK (tenant_id, ref): la ref nunca es clave global; tenant_id es la unica clave de aislamiento;
--   * RLS ENABLE + FORCE con policies por app.current_tenant_id() (SELECT, INSERT WITH CHECK y UPDATE
--     USING + WITH CHECK); sin DELETE/TRUNCATE para runtime;
--   * data_class = 'SYNTHETIC' (CHECK + DEFAULT), sin grant de columna para runtime;
--   * grants minimos por columna: INSERT de las columnas del registro; UPDATE solo de las columnas
--     que cambian de estado (las de identidad/vinculo se fijan al crear y no se actualizan);
--   * ninguna columna de email ni rut/run: solo refs opacas, enums y fechas (P1-5).

CREATE TABLE app.consent_decision (
  tenant_id            uuid        NOT NULL,
  consent_id           text        NOT NULL CONSTRAINT consent_decision_id_len CHECK (pg_catalog.length(consent_id) BETWEEN 1 AND 100),
  context_ref          text        NOT NULL CONSTRAINT consent_decision_context_len CHECK (pg_catalog.length(context_ref) BETWEEN 1 AND 100),
  product_ref          text        NOT NULL CONSTRAINT consent_decision_product_len CHECK (pg_catalog.length(product_ref) BETWEEN 1 AND 100),
  subject_ref          text        NOT NULL CONSTRAINT consent_decision_subject_len CHECK (pg_catalog.length(subject_ref) BETWEEN 1 AND 100),
  decision_maker_ref   text        NOT NULL CONSTRAINT consent_decision_dm_len CHECK (pg_catalog.length(decision_maker_ref) BETWEEN 1 AND 100),
  invitation_ref       text        NOT NULL CONSTRAINT consent_decision_invitation_len CHECK (pg_catalog.length(invitation_ref) BETWEEN 1 AND 100),
  verification_ref     text        NOT NULL CONSTRAINT consent_decision_verification_len CHECK (pg_catalog.length(verification_ref) BETWEEN 1 AND 100),
  chain_ref            text        NOT NULL CONSTRAINT consent_decision_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 100),
  state                text        NOT NULL CONSTRAINT consent_decision_state_enum CHECK (state IN ('PENDING', 'GRANTED', 'DECLINED', 'REVOKED')),
  purposes             jsonb       NOT NULL CONSTRAINT consent_decision_purposes_array CHECK (pg_catalog.jsonb_typeof(purposes) = 'array'),
  prior_steps_complete boolean     NOT NULL,
  steps_recorded       text[]      NOT NULL DEFAULT '{}',
  receipt_ref          text        CONSTRAINT consent_decision_receipt_len CHECK (pg_catalog.length(receipt_ref) BETWEEN 1 AND 100),
  data_class           text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT consent_decision_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at           timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT consent_decision_pkey PRIMARY KEY (tenant_id, consent_id)
);
CREATE INDEX consent_decision_active_grant_idx ON app.consent_decision (tenant_id, chain_ref) WHERE state = 'GRANTED';

CREATE TABLE app.revocation (
  tenant_id                uuid        NOT NULL,
  revocation_ref           text        NOT NULL CONSTRAINT revocation_ref_len CHECK (pg_catalog.length(revocation_ref) BETWEEN 1 AND 100),
  chain_ref                text        NOT NULL CONSTRAINT revocation_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 100),
  case_ref                 text        CONSTRAINT revocation_case_len CHECK (pg_catalog.length(case_ref) BETWEEN 1 AND 100),
  status                   text        NOT NULL CONSTRAINT revocation_status_enum CHECK (status IN ('REQUESTED', 'VERIFIED', 'CONFIRMED', 'APPLIED', 'FAILED')),
  attested_revocation_ref  text        CONSTRAINT revocation_attested_ref_len CHECK (pg_catalog.length(attested_revocation_ref) BETWEEN 1 AND 100),
  attested_case_ref        text        CONSTRAINT revocation_attested_case_len CHECK (pg_catalog.length(attested_case_ref) BETWEEN 1 AND 100),
  recorded_by_ref          text        CONSTRAINT revocation_recorded_by_len CHECK (pg_catalog.length(recorded_by_ref) BETWEEN 1 AND 100),
  cosigned_by_ref          text        CONSTRAINT revocation_cosigned_by_len CHECK (pg_catalog.length(cosigned_by_ref) BETWEEN 1 AND 100),
  revoked_decision_ref     text        CONSTRAINT revocation_decision_len CHECK (pg_catalog.length(revoked_decision_ref) BETWEEN 1 AND 100),
  verified_auth_path       text        CONSTRAINT revocation_auth_path_enum CHECK (verified_auth_path IN ('OTP', 'RECOVERY')),
  verified_recovery_method text        CONSTRAINT revocation_recovery_method_enum CHECK (verified_recovery_method IN ('CHANNEL_LINK', 'HUMAN_ASSISTED')),
  reason_code              text        CONSTRAINT revocation_reason_code_enum CHECK (reason_code IN ('WITHDRAWN_BY_REQUESTER')),
  data_class               text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT revocation_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at               timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT revocation_pkey PRIMARY KEY (tenant_id, revocation_ref),
  -- GRD-RV-10: la atestacion RH2/RH2v lleva (revocationRef, caseRef) completos o ninguno.
  CONSTRAINT revocation_attestation_pair CHECK ((attested_revocation_ref IS NULL) = (attested_case_ref IS NULL))
);
CREATE INDEX revocation_case_idx ON app.revocation (tenant_id, case_ref) WHERE case_ref IS NOT NULL;
CREATE INDEX revocation_chain_idx ON app.revocation (tenant_id, chain_ref, created_at);

CREATE TABLE app.recovery_token (
  tenant_id            uuid        NOT NULL,
  recovery_ref         text        NOT NULL CONSTRAINT recovery_token_ref_len CHECK (pg_catalog.length(recovery_ref) BETWEEN 1 AND 100),
  -- Solo el hash SHA-256 del token persiste (GRD-IV-05); sin UNIQUE aqui: la unicidad global del hash
  -- la custodia tenant_resolve.recovery_token (0007), no una restriccion visible entre tenants.
  token_hash           text        NOT NULL CONSTRAINT recovery_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  chain_ref            text        NOT NULL CONSTRAINT recovery_token_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 100),
  revoked_decision_ref text        NOT NULL CONSTRAINT recovery_token_decision_len CHECK (pg_catalog.length(revoked_decision_ref) BETWEEN 1 AND 100),
  expires_at           timestamptz NOT NULL,
  consumed_at          timestamptz,
  data_class           text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT recovery_token_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at           timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT recovery_token_pkey PRIMARY KEY (tenant_id, recovery_ref)
);

ALTER TABLE app.consent_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.consent_decision FORCE ROW LEVEL SECURITY;
CREATE POLICY consent_decision_tenant_select ON app.consent_decision FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY consent_decision_tenant_insert ON app.consent_decision FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY consent_decision_tenant_update ON app.consent_decision FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

ALTER TABLE app.revocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.revocation FORCE ROW LEVEL SECURITY;
CREATE POLICY revocation_tenant_select ON app.revocation FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY revocation_tenant_insert ON app.revocation FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY revocation_tenant_update ON app.revocation FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

ALTER TABLE app.recovery_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.recovery_token FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_token_tenant_select ON app.recovery_token FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY recovery_token_tenant_insert ON app.recovery_token FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY recovery_token_tenant_update ON app.recovery_token FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON app.consent_decision, app.revocation, app.recovery_token FROM PUBLIC;
GRANT SELECT ON app.consent_decision, app.revocation, app.recovery_token TO app_rw;

GRANT INSERT (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref,
              verification_ref, chain_ref, state, purposes, prior_steps_complete, steps_recorded, receipt_ref)
  ON app.consent_decision TO app_rw;
GRANT UPDATE (state, purposes, prior_steps_complete, steps_recorded, receipt_ref) ON app.consent_decision TO app_rw;

GRANT INSERT (tenant_id, revocation_ref, chain_ref, case_ref, status, attested_revocation_ref, attested_case_ref,
              recorded_by_ref, cosigned_by_ref, revoked_decision_ref, verified_auth_path, verified_recovery_method, reason_code)
  ON app.revocation TO app_rw;
GRANT UPDATE (case_ref, status, attested_revocation_ref, attested_case_ref, recorded_by_ref, cosigned_by_ref,
              verified_auth_path, verified_recovery_method, reason_code)
  ON app.revocation TO app_rw;

GRANT INSERT (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at, consumed_at)
  ON app.recovery_token TO app_rw;
-- El token solo cambia al consumirse (un solo uso, GRD-RV-06/GRD-RV-23).
GRANT UPDATE (consumed_at) ON app.recovery_token TO app_rw;
