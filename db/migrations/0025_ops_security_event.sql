-- scope: database
-- Gobierna: CA-141 (decision de Carlos, 2026-10-06, opcion (a); D-1 sin purga en IT0, D-5 app_rw solo INSERT), common.spec.yaml
-- streams.SECURITY ("ops.security_event: RLS por tenant, solo refs; no es ledger de consentimiento; retencion LD-15"),
-- specs/session.spec.yaml (GRD-SE-14, INV-SE-05/06), contracts/schemas/security-event-payloads.schema.json (API-CNS-184),
-- INV-CM-01 (append-only), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-002 §10, ADR-006 §4-§6, DEC-BR-014 §4.
-- 0000-0024 no se editan.
--
-- ops.security_event registra login y logout de las sesiones STAFF y CASE (refs opacas), separado de ops.access_log (lecturas del operador):
--   * sin PII por construccion: sin sid, sid_hash, cookie, CSRF, IP, user-agent, correo, nombre, RUT ni texto libre. actor_ref/case_ref/
--     session_ref son refs opacas con CHECK; tipos, roles y clases son enums;
--   * append-only: sin UPDATE/DELETE/TRUNCATE para runtime y triggers ENABLE ALWAYS (tambien bloquean al dueno y con replica);
--   * RLS ENABLE + FORCE por app.current_tenant_id(); app_rw SOLO INSERT por columnas (D-5: sin SELECT ni policy SELECT; los tests
--     leen con la conexion del dueno); worker/platform_rw: nada. event_id, event_seq, schema_version, occurred_at, environment y
--     data_class los fija la base;
--   * NO entra a la cadena SHA-256 del ledger: la evidencia de manipulacion es solo append-only, igual que ops.access_log.
-- Las columnas actor_ref..case_ref son NULL a nivel de tabla para que los tipos OTP_* (actor = titular, sin staff) quepan despues.
-- RETENCION: SECURITY_EVENT_RETENTION = PENDING - Carlos (LEGAL DECISION LD-15). IT0 sintetico: no se purga (D-1).
-- Cualquier purga futura = migracion nueva con SECURITY DEFINER de dueno propio y excepcion del trigger solo para filas vencidas.

CREATE TABLE ops.security_event (
  event_id       uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT security_event_pkey PRIMARY KEY,
  event_seq      bigint      GENERATED ALWAYS AS IDENTITY NOT NULL,
  tenant_id      uuid        NOT NULL,
  event_type     text        NOT NULL CONSTRAINT security_event_type_enum CHECK (event_type IN ('STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION')),
  schema_version text        NOT NULL DEFAULT '1.0.0' CONSTRAINT security_event_schema_version_semver CHECK (schema_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  actor_ref      text        CONSTRAINT security_event_actor_ref_shape CHECK (actor_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  actor_role     text        CONSTRAINT security_event_actor_role_enum CHECK (actor_role IN ('TENANT_ADMIN', 'RIGHTS_OPERATOR', 'APPROVER')),
  session_kind   text        CONSTRAINT security_event_session_kind_enum CHECK (session_kind IN ('STAFF', 'CASE')),
  session_ref    uuid        CONSTRAINT security_event_session_ref_uuidv4 CHECK (session_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  case_ref       text        CONSTRAINT security_event_case_ref_uuidv4 CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  occurred_at    timestamptz NOT NULL DEFAULT pg_catalog.now(),
  environment    text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT security_event_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT security_event_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- Forma por familia. Todo tipo de sesion exige actor, rol, clase y session_ref. STAFF_*: kind STAFF sin case_ref. CASE_*: kind CASE con
  -- case_ref y rol de operador/aprobador (los unicos de app.case_session). ROTATION: case_ref presente si y solo si kind CASE (rol CASE restringido).
  CONSTRAINT security_event_session_shape CHECK (
    event_type NOT IN ('STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION')
    OR (
      actor_ref IS NOT NULL AND actor_role IS NOT NULL AND session_kind IS NOT NULL AND session_ref IS NOT NULL
      AND CASE
        WHEN event_type IN ('STAFF_LOGIN', 'STAFF_LOGOUT') THEN session_kind = 'STAFF' AND case_ref IS NULL
        WHEN event_type IN ('CASE_LOGIN', 'CASE_LOGOUT') THEN session_kind = 'CASE' AND case_ref IS NOT NULL AND actor_role IN ('RIGHTS_OPERATOR', 'APPROVER')
        ELSE (session_kind = 'CASE') = (case_ref IS NOT NULL) AND (session_kind = 'STAFF' OR actor_role IN ('RIGHTS_OPERATOR', 'APPROVER'))
      END
    )
  )
);

CREATE INDEX security_event_tenant_occurred_idx ON ops.security_event (tenant_id, occurred_at);
CREATE INDEX security_event_tenant_session_ref_idx ON ops.security_event (tenant_id, session_ref);

CREATE FUNCTION ops.security_event_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'ops.security_event es append-only (INV-CM-01)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER security_event_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.security_event
  FOR EACH ROW EXECUTE FUNCTION ops.security_event_immutable();
CREATE TRIGGER security_event_no_truncate
  BEFORE TRUNCATE ON ops.security_event
  FOR EACH STATEMENT EXECUTE FUNCTION ops.security_event_immutable();
-- ENABLE ALWAYS: tambien bloquean con session_replication_role = replica.
ALTER TABLE ops.security_event ENABLE ALWAYS TRIGGER security_event_no_update_delete;
ALTER TABLE ops.security_event ENABLE ALWAYS TRIGGER security_event_no_truncate;

ALTER TABLE ops.security_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.security_event FORCE ROW LEVEL SECURITY;
-- D-5: solo INSERT. Sin policy SELECT (y sin grant SELECT): el runtime escribe, no lee.
CREATE POLICY security_event_tenant_insert ON ops.security_event FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON ops.security_event FROM PUBLIC;
GRANT INSERT (tenant_id, event_type, actor_ref, actor_role, session_kind, session_ref, case_ref)
  ON ops.security_event TO app_rw;
