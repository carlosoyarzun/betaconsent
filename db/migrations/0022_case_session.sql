-- scope: database
-- Gobierna: CA-139 (aprobado por Carlos, 2026-10-06; origen: revision de seguridad de CA-138, P1-1), SEC-CNS-018 rev. 2 (D-3),
-- common.spec.yaml GRD-CM-01 (sesion + ligadura al caso), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-002,
-- ADR-006 §1/§4-§6, src/server/ports/case-session-store.port.ts, DEC-BR-014 §4 (solo datos sinteticos).
-- 0000-0021 no se editan (regla de Carlos tras #34).
--
-- app.case_session: registro SERVIDOR de sesiones CASE (cookie `__Host-cns-case`, que lleva sid/iat/exp firmados y el caseRef).
-- Mismo mecanismo que app.staff_session (0021) para RIGHTS_OPERATOR/APPROVER. Tabla propia (no se generaliza con session_kind):
-- la sesion CASE esta ligada ademas a un case_ref, tiene otro conjunto de roles y otra superficie de grants, y asi 0021 y el
-- codigo STAFF mergeados quedan intactos.
--   * sin PII por construccion: sid_hash (sha256 hex del sid aleatorio de 256 bits; el sid en claro NUNCA persiste),
--     principal_ref opaco (mismo CHECK que ops.access_log), case_ref (ref opaca del caso) y rol (enum);
--   * PK (tenant_id, sid_hash); RLS ENABLE + FORCE por app.current_tenant_id(): un sid de otro tenant no existe para este;
--   * app_rw (rol minimo existente; NO se crean roles nuevos): SELECT, INSERT y UPDATE solo de last_seen_at / revoked_at.
--     Revocacion de un solo sentido (trigger); case_ref/principal/rol/vida inmutables;
--   * limpieza: app_rw solo puede DELETE filas YA expiradas (policy `expires_at < now()`); data_class = 'SYNTHETIC'.

CREATE TABLE app.case_session (
  tenant_id     uuid        NOT NULL,
  sid_hash      text        NOT NULL CONSTRAINT case_session_sid_hash_shape CHECK (sid_hash ~ '^[0-9a-f]{64}$'),
  case_ref      text        NOT NULL CONSTRAINT case_session_case_ref_len CHECK (pg_catalog.length(case_ref) BETWEEN 1 AND 100),
  principal_ref text        NOT NULL CONSTRAINT case_session_principal_ref_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  role          text        NOT NULL CONSTRAINT case_session_role_enum CHECK (role IN ('RIGHTS_OPERATOR', 'APPROVER')),
  issued_at     timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  revoked_at    timestamptz,
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT case_session_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT case_session_pkey PRIMARY KEY (tenant_id, sid_hash),
  CONSTRAINT case_session_exp_after_iat CHECK (expires_at > issued_at),
  CONSTRAINT case_session_last_seen_in_life CHECK (last_seen_at >= issued_at AND last_seen_at <= expires_at)
);

CREATE INDEX case_session_tenant_expires_idx ON app.case_session (tenant_id, expires_at);

CREATE FUNCTION app.case_session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'app.case_session: una sesion revocada no se reactiva (CA-139)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER case_session_revocation_one_way
  BEFORE UPDATE ON app.case_session
  FOR EACH ROW EXECUTE FUNCTION app.case_session_guard();
ALTER TABLE app.case_session ENABLE ALWAYS TRIGGER case_session_revocation_one_way;

ALTER TABLE app.case_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.case_session FORCE ROW LEVEL SECURITY;
CREATE POLICY case_session_tenant_select ON app.case_session FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY case_session_tenant_insert ON app.case_session FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY case_session_tenant_update ON app.case_session FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY case_session_tenant_delete_expired ON app.case_session FOR DELETE TO app_rw
  USING (tenant_id = app.current_tenant_id() AND expires_at < pg_catalog.now());

REVOKE ALL ON app.case_session FROM PUBLIC;
GRANT SELECT ON app.case_session TO app_rw;
GRANT INSERT (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at) ON app.case_session TO app_rw;
GRANT UPDATE (last_seen_at, revoked_at) ON app.case_session TO app_rw;
GRANT DELETE ON app.case_session TO app_rw;
