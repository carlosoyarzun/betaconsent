-- scope: database
-- Gobierna: CA-128 / DEC-BR-014 rev. 8 §3 X6 ("Las lecturas del operador van a un log de acceso en
-- `ops`, no al ledger"), rights-case.spec INV-RC-04 ("cada lectura del operador va a ops.access_log
-- (append-only, sin PII), no al ledger"), GRD-RC-05, ADR-002 §10, ADR-006 §6.3, INV-CM-01
-- (append-only), INV-CM-02 (tenant_id unica clave de aislamiento), DEC-BR-014 §4 (solo sinteticos).
--
-- ops.access_log registra QUE principal de staff leyo QUE recurso (refs opacas), no el contenido:
--   * sin PII por construccion: resource_ref es una Ref UUIDv4 (common.schema.json#/$defs/Ref) y actor_ref el
--     principalRef canonico (`staff-synthetic-NN` del roster IT0 o Ref UUIDv4); un RUT, un nombre o
--     un email no cumplen el CHECK; action/resource_type/actor_role son enums;
--   * append-only: sin UPDATE/DELETE/TRUNCATE para runtime y triggers ENABLE ALWAYS que bloquean
--     tambien al dueno / consent_migrator y a superusuario (incluso con session_replication_role=replica);
--   * RLS ENABLE + FORCE por app.current_tenant_id(); app_rw solo SELECT e INSERT por columnas;
--     worker/platform_rw: nada. accessed_at, environment y data_class los fija la base;
--   * data_class = 'SYNTHETIC' (CHECK + DEFAULT).
-- No participa de la cadena del ledger (no es evento de consentimiento).

CREATE TABLE ops.access_log (
  access_id     uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT access_log_pkey PRIMARY KEY,
  -- Orden de insercion estable (accessed_at = now() es igual dentro de una tx). La identidad no requiere grant de secuencia.
  access_seq    bigint      GENERATED ALWAYS AS IDENTITY NOT NULL,
  tenant_id     uuid        NOT NULL,
  actor_ref     text        NOT NULL CONSTRAINT access_log_actor_ref_shape CHECK (actor_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  actor_role    text        NOT NULL CONSTRAINT access_log_actor_role_enum CHECK (actor_role IN ('RIGHTS_OPERATOR', 'APPROVER', 'TENANT_ADMIN', 'PLATFORM_ADMIN')),
  action        text        NOT NULL CONSTRAINT access_log_action_enum CHECK (action IN ('RIGHTS_CASE_READ')),
  resource_type text        NOT NULL CONSTRAINT access_log_resource_type_enum CHECK (resource_type IN ('RIGHTS_CASE')),
  resource_ref  text        NOT NULL CONSTRAINT access_log_resource_ref_shape CHECK (resource_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  accessed_at   timestamptz NOT NULL DEFAULT pg_catalog.now(),
  environment   text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT access_log_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT access_log_data_class_synthetic CHECK (data_class = 'SYNTHETIC')
);

CREATE INDEX access_log_tenant_accessed_idx ON ops.access_log (tenant_id, accessed_at);

CREATE FUNCTION ops.access_log_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'ops.access_log es append-only (INV-RC-04, INV-CM-01)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER access_log_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.access_log
  FOR EACH ROW EXECUTE FUNCTION ops.access_log_immutable();
CREATE TRIGGER access_log_no_truncate
  BEFORE TRUNCATE ON ops.access_log
  FOR EACH STATEMENT EXECUTE FUNCTION ops.access_log_immutable();
-- ENABLE ALWAYS: tambien bloquean con session_replication_role = replica.
ALTER TABLE ops.access_log ENABLE ALWAYS TRIGGER access_log_no_update_delete;
ALTER TABLE ops.access_log ENABLE ALWAYS TRIGGER access_log_no_truncate;

ALTER TABLE ops.access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.access_log FORCE ROW LEVEL SECURITY;
CREATE POLICY access_log_tenant_select ON ops.access_log FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY access_log_tenant_insert ON ops.access_log FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON ops.access_log FROM PUBLIC;
GRANT SELECT ON ops.access_log TO app_rw;
GRANT INSERT (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref)
  ON ops.access_log TO app_rw;
