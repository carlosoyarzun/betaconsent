-- scope: database
-- Gobierna: CA-124 (H09), PR-D; src/server/ports/{invitation-repository,otp-verification-repository,
-- rights-case-repository,enrollment-repository}.port.ts, invitation.spec.yaml (GRD-IV-01),
-- otp-challenge.spec.yaml (GRD-OT-08), rights-case.spec.yaml (GRD-RC-02), tenant-context.spec.yaml
-- (GRD-TC-03), common.spec.yaml INV-CM-02 (tenant_id unica clave de aislamiento), ADR-006 §1/§4-§6,
-- DEC-BR-014 §4 (solo datos sinteticos), diseno postgres-design.md rev. 2 §3, SEC-CNS-015 P2-B.
-- Regla de Carlos (2026-10-01): 0000-0009 no se editan; todo SQL nuevo desde 0010.
--
-- Proyecciones de agregado app.invitation, app.otp_verification, app.rights_case y app.enrollment.
-- Garantias (mismas que 0006):
--   * PK (tenant_id, ref): la ref nunca es clave global;
--   * RLS ENABLE + FORCE con policies por app.current_tenant_id() (SELECT, INSERT WITH CHECK,
--     UPDATE USING + WITH CHECK); sin DELETE/TRUNCATE para runtime;
--   * data_class = 'SYNTHETIC' (CHECK + DEFAULT), sin grant de columna para runtime;
--   * grants minimos por columna: INSERT de las columnas del registro; UPDATE solo de las columnas
--     que cambian de estado (identidad/vinculo inmutables tras crear);
--   * SEC-CNS-015 P2-B: TODA columna de contacto o destino (aqui invitation.recipient_channel_ref y
--     otp_verification.channel_ref) lleva CHECK app.is_reserved_email(...). Los canales de OTP de
--     scope REVOCATION/MANAGE son refs opacas 'mgmt:<chainRef>' (no contacto) y se admiten solo con
--     ese prefijo; cualquier otro valor debe ser un email de dominio reservado;
--   * unicos parciales que dan a la base la ultima palabra en las carreras (el perdedor reintenta
--     y ve al ganador, ver PgUnitOfWork): GRD-IV-01, GRD-OT-08, GRD-RC-02, GRD-TC-03.

CREATE TABLE app.invitation (
  tenant_id                uuid        NOT NULL,
  invitation_ref           text        NOT NULL CONSTRAINT invitation_ref_len CHECK (pg_catalog.length(invitation_ref) BETWEEN 1 AND 100),
  context_ref              text        NOT NULL CONSTRAINT invitation_context_len CHECK (pg_catalog.length(context_ref) BETWEEN 1 AND 100),
  product_ref              text        NOT NULL CONSTRAINT invitation_product_len CHECK (pg_catalog.length(product_ref) BETWEEN 1 AND 100),
  subject_ref              text        NOT NULL CONSTRAINT invitation_subject_len CHECK (pg_catalog.length(subject_ref) BETWEEN 1 AND 100),
  state                    text        NOT NULL CONSTRAINT invitation_state_enum CHECK (state IN ('DRAFT', 'READY', 'SENT', 'OPENED', 'VERIFIED', 'COMPLETED', 'DECLINED')),
  consent_version          text        CONSTRAINT invitation_consent_version_len CHECK (pg_catalog.length(consent_version) BETWEEN 1 AND 100),
  expires_at               timestamptz,
  -- Destino del OTP (contacto): solo dominios reservados (P1-5, P2-B).
  recipient_channel_ref    text        CONSTRAINT invitation_recipient_channel_reserved CHECK (app.is_reserved_email(recipient_channel_ref)),
  -- Solo el hash SHA-256 del token persiste (GRD-IV-05); la unicidad global del hash la custodia
  -- tenant_resolve.invitation_token (0011), no una restriccion visible entre tenants.
  token_hash               text        CONSTRAINT invitation_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  bound_decision_maker_ref text        CONSTRAINT invitation_dm_len CHECK (pg_catalog.length(bound_decision_maker_ref) BETWEEN 1 AND 100),
  enrollment_ref           text        CONSTRAINT invitation_enrollment_len CHECK (pg_catalog.length(enrollment_ref) BETWEEN 1 AND 100),
  participation_ref        text        CONSTRAINT invitation_participation_len CHECK (pg_catalog.length(participation_ref) BETWEEN 1 AND 100),
  reissue_of_ref           text        CONSTRAINT invitation_reissue_len CHECK (pg_catalog.length(reissue_of_ref) BETWEEN 1 AND 100),
  recipient_binding        text        CONSTRAINT invitation_binding_enum CHECK (recipient_binding IN ('RECIPIENT_CHANNEL', 'UNBOUND')),
  data_class               text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT invitation_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at               timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT invitation_pkey PRIMARY KEY (tenant_id, invitation_ref)
);
-- GRD-IV-01 (single_non_terminal_invitation): <=1 invitacion no terminal por (tenant, contexto, sujeto).
CREATE UNIQUE INDEX invitation_single_non_terminal_uq
  ON app.invitation (tenant_id, context_ref, subject_ref)
  WHERE state IN ('DRAFT', 'READY', 'SENT', 'OPENED', 'VERIFIED');

CREATE TABLE app.otp_verification (
  tenant_id        uuid        NOT NULL,
  verification_ref text        NOT NULL CONSTRAINT otp_verification_ref_len CHECK (pg_catalog.length(verification_ref) BETWEEN 1 AND 100),
  scope            text        NOT NULL CONSTRAINT otp_scope_enum CHECK (scope IN ('DECISION', 'REVOCATION', 'MANAGE')),
  parent_ref       text        NOT NULL CONSTRAINT otp_parent_len CHECK (pg_catalog.length(parent_ref) BETWEEN 1 AND 255),
  -- Destino del OTP (contacto): email de dominio reservado, o ref opaca 'mgmt:' en scope de derechos.
  channel_ref      text        NOT NULL CONSTRAINT otp_channel_reserved CHECK (
                     app.is_reserved_email(channel_ref) OR (scope IN ('REVOCATION', 'MANAGE') AND channel_ref ~ '^mgmt:[^@[:space:]]+$')),
  -- HMAC-SHA256 hex del codigo (P-08); el codigo en claro nunca persiste (INV-OT-02).
  code_hash        text        NOT NULL CONSTRAINT otp_code_hash_shape CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  attempts         integer     NOT NULL CONSTRAINT otp_attempts_nonneg CHECK (attempts >= 0),
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  state            text        NOT NULL CONSTRAINT otp_state_enum CHECK (state IN ('NOT_STARTED', 'CODE_SENT', 'VERIFIED', 'EXPIRED', 'LOCKED', 'FAILED')),
  resend_count     integer     NOT NULL DEFAULT 0 CONSTRAINT otp_resend_nonneg CHECK (resend_count >= 0),
  data_class       text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT otp_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at       timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT otp_verification_pkey PRIMARY KEY (tenant_id, verification_ref)
);
-- GRD-OT-08 (uno activo por (tenant, padre, scope)); "activo" = NOT_STARTED | CODE_SENT.
CREATE UNIQUE INDEX otp_single_active_uq
  ON app.otp_verification (tenant_id, parent_ref, scope)
  WHERE state IN ('NOT_STARTED', 'CODE_SENT');

CREATE TABLE app.rights_case (
  tenant_id            uuid        NOT NULL,
  case_ref             text        NOT NULL CONSTRAINT rights_case_ref_len CHECK (pg_catalog.length(case_ref) BETWEEN 1 AND 100),
  chain_ref            text        NOT NULL CONSTRAINT rights_case_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 255),
  revoked_decision_ref text        NOT NULL CONSTRAINT rights_case_decision_len CHECK (pg_catalog.length(revoked_decision_ref) BETWEEN 1 AND 100),
  status               text        NOT NULL CONSTRAINT rights_case_status_enum CHECK (status IN ('OPEN', 'CONTACTING', 'IN_VERIFICATION', 'RESOLVED', 'WITHDRAWN')),
  revocation_ref       text        CONSTRAINT rights_case_revocation_len CHECK (pg_catalog.length(revocation_ref) BETWEEN 1 AND 100),
  origin               text        CONSTRAINT rights_case_origin_enum CHECK (origin IN ('LIMIT_REACHED', 'CHANNEL_UNREACHABLE', 'REQUESTER_ASKED', 'SCHOOL_REPORTED', 'REQUEST_EXPIRED')),
  data_class           text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT rights_case_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at           timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT rights_case_pkey PRIMARY KEY (tenant_id, case_ref)
);
-- GRD-RC-02: <=1 caso no terminal por (tenant, cadena, decision revocada).
CREATE UNIQUE INDEX rights_case_single_open_uq
  ON app.rights_case (tenant_id, chain_ref, revoked_decision_ref)
  WHERE status NOT IN ('RESOLVED', 'WITHDRAWN');

CREATE TABLE app.enrollment (
  tenant_id         uuid        NOT NULL,
  enrollment_ref    text        NOT NULL CONSTRAINT enrollment_ref_len CHECK (pg_catalog.length(enrollment_ref) BETWEEN 1 AND 100),
  subject_ref       text        NOT NULL CONSTRAINT enrollment_subject_len CHECK (pg_catalog.length(subject_ref) BETWEEN 1 AND 100),
  participation_ref text        NOT NULL CONSTRAINT enrollment_participation_len CHECK (pg_catalog.length(participation_ref) BETWEEN 1 AND 100),
  state             text        NOT NULL CONSTRAINT enrollment_state_enum CHECK (state IN ('ACTIVE', 'CLOSED')),
  data_class        text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT enrollment_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at        timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT enrollment_pkey PRIMARY KEY (tenant_id, enrollment_ref)
);
-- GRD-TC-03 (single_active_enrollment): <=1 ACTIVE por (tenant, sujeto, participacion).
CREATE UNIQUE INDEX enrollment_single_active_uq
  ON app.enrollment (tenant_id, subject_ref, participation_ref)
  WHERE state = 'ACTIVE';

ALTER TABLE app.invitation ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.invitation FORCE ROW LEVEL SECURITY;
CREATE POLICY invitation_tenant_select ON app.invitation FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY invitation_tenant_insert ON app.invitation FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY invitation_tenant_update ON app.invitation FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

ALTER TABLE app.otp_verification ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.otp_verification FORCE ROW LEVEL SECURITY;
CREATE POLICY otp_verification_tenant_select ON app.otp_verification FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY otp_verification_tenant_insert ON app.otp_verification FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY otp_verification_tenant_update ON app.otp_verification FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

ALTER TABLE app.rights_case ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.rights_case FORCE ROW LEVEL SECURITY;
CREATE POLICY rights_case_tenant_select ON app.rights_case FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY rights_case_tenant_insert ON app.rights_case FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY rights_case_tenant_update ON app.rights_case FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

ALTER TABLE app.enrollment ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.enrollment FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tenant_select ON app.enrollment FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY enrollment_tenant_insert ON app.enrollment FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY enrollment_tenant_update ON app.enrollment FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON app.invitation, app.otp_verification, app.rights_case, app.enrollment FROM PUBLIC;
GRANT SELECT ON app.invitation, app.otp_verification, app.rights_case, app.enrollment TO app_rw;

GRANT INSERT (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, consent_version, expires_at,
              recipient_channel_ref, token_hash, bound_decision_maker_ref, enrollment_ref, participation_ref,
              reissue_of_ref, recipient_binding)
  ON app.invitation TO app_rw;
-- Identidad (tenant, ref, contexto, producto, sujeto, enrollment, participacion, reemision) inmutable.
GRANT UPDATE (state, consent_version, expires_at, recipient_channel_ref, token_hash, bound_decision_maker_ref, recipient_binding)
  ON app.invitation TO app_rw;

GRANT INSERT (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, consumed_at, state, resend_count)
  ON app.otp_verification TO app_rw;
-- scope, padre y canal se fijan al emitir el challenge y no cambian (GRD-OT-02).
GRANT UPDATE (code_hash, attempts, expires_at, consumed_at, state, resend_count) ON app.otp_verification TO app_rw;

GRANT INSERT (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, revocation_ref, origin)
  ON app.rights_case TO app_rw;
GRANT UPDATE (status, revocation_ref, origin) ON app.rights_case TO app_rw;

GRANT INSERT (tenant_id, enrollment_ref, subject_ref, participation_ref, state) ON app.enrollment TO app_rw;
GRANT UPDATE (state) ON app.enrollment TO app_rw;
