-- scope: database
-- Gobierna: CA-138 (aprobado por Carlos, 2026-10-05), SEC-CNS-018 rev. 2 (D-3), SEC-CNS-020 (P2-3), common.spec.yaml
-- GRD-CM-01 (sesion + membership), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-002, ADR-006 §1/§4-§6,
-- src/server/ports/staff-session-store.port.ts, DEC-BR-014 §4 (solo datos sinteticos). 0000-0020 no se editan.
--
-- app.staff_session: registro SERVIDOR de sesiones STAFF (cookie `__Host-cns-staff`, que lleva sid/iat/exp firmados).
-- Permite REVOCAR (logout) y expirar por inactividad, que una cookie HMAC sin estado no puede.
--   * sin PII por construccion: solo sid_hash (sha256 hex del sid aleatorio de 256 bits; el sid en claro NUNCA persiste),
--     el principal_ref opaco (`staff-synthetic-NN` o Ref UUIDv4, mismo CHECK que ops.access_log) y el rol (enum);
--   * PK (tenant_id, sid_hash); RLS ENABLE + FORCE por app.current_tenant_id(): un sid de otro tenant no existe para este;
--   * app_rw (rol minimo existente; NO se crean roles nuevos): SELECT, INSERT y UPDATE solo de last_seen_at / revoked_at.
--     La revocacion es de un solo sentido (trigger): una sesion revocada nunca se reactiva;
--   * limpieza: app_rw solo puede DELETE filas YA expiradas (policy `expires_at < now()`); una sesion vigente o revocada
--     pero no expirada nunca se borra. data_class = 'SYNTHETIC' (CHECK + DEFAULT, sin grant de columna);
--   * los instantes los decide el reloj del proceso (inyectable en tests); la base solo los guarda y compara.
-- No es el ledger ni ops.access_log (no se inventa un evento de seguridad nuevo: ver FINDING de CA-138).

CREATE TABLE app.staff_session (
  tenant_id     uuid        NOT NULL,
  sid_hash      text        NOT NULL CONSTRAINT staff_session_sid_hash_shape CHECK (sid_hash ~ '^[0-9a-f]{64}$'),
  principal_ref text        NOT NULL CONSTRAINT staff_session_principal_ref_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  role          text        NOT NULL CONSTRAINT staff_session_role_enum CHECK (role IN ('TENANT_ADMIN', 'RIGHTS_OPERATOR', 'APPROVER')),
  issued_at     timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  revoked_at    timestamptz,
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT staff_session_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT staff_session_pkey PRIMARY KEY (tenant_id, sid_hash),
  CONSTRAINT staff_session_exp_after_iat CHECK (expires_at > issued_at),
  -- P2-5: la ultima actividad nunca queda fuera de la vida de la sesion (app_rw no puede dejarla en el futuro lejano).
  CONSTRAINT staff_session_last_seen_in_life CHECK (last_seen_at >= issued_at AND last_seen_at <= expires_at)
);

CREATE INDEX staff_session_tenant_expires_idx ON app.staff_session (tenant_id, expires_at);

-- Revocacion de un solo sentido: una vez fijado revoked_at no cambia ni se borra (la sesion nunca vuelve a ser valida).
CREATE FUNCTION app.staff_session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'app.staff_session: una sesion revocada no se reactiva (CA-138)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER staff_session_revocation_one_way
  BEFORE UPDATE ON app.staff_session
  FOR EACH ROW EXECUTE FUNCTION app.staff_session_guard();
ALTER TABLE app.staff_session ENABLE ALWAYS TRIGGER staff_session_revocation_one_way;

ALTER TABLE app.staff_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.staff_session FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_session_tenant_select ON app.staff_session FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY staff_session_tenant_insert ON app.staff_session FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY staff_session_tenant_update ON app.staff_session FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY staff_session_tenant_delete_expired ON app.staff_session FOR DELETE TO app_rw
  USING (tenant_id = app.current_tenant_id() AND expires_at < pg_catalog.now());

REVOKE ALL ON app.staff_session FROM PUBLIC;
GRANT SELECT ON app.staff_session TO app_rw;
GRANT INSERT (tenant_id, sid_hash, principal_ref, role, issued_at, expires_at, last_seen_at) ON app.staff_session TO app_rw;
GRANT UPDATE (last_seen_at, revoked_at) ON app.staff_session TO app_rw;
GRANT DELETE ON app.staff_session TO app_rw;
