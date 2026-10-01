-- scope: database
-- Gobierna: CA-124 (H09), PR-B; ADR-002 §2/§8, ADR-006 §1/§4-§6, common.spec.yaml ledgerEnvelope
-- (checks, concurrency), INV-CM-01 (append-only), INV-CM-02 (tenant_id unica clave de aislamiento),
-- GRD-CM-11, DEC-BR-014 §4 (solo datos sinteticos), SEC-CNS-012 (P1-5, P1-6).
--
-- Ledger de eventos integrity.audit_event. Garantias:
--   * append-only: sin grant de UPDATE/DELETE/TRUNCATE para runtime Y triggers ENABLE ALWAYS
--     que bloquean UPDATE/DELETE/TRUNCATE incluso al dueno o con session_replication_role=replica;
--   * UNIQUE (tenant_id, aggregate_id, sequence): el control optimista de concurrencia (R4);
--   * RLS ENABLE + FORCE con policies por app.current_tenant_id() (nunca current_user);
--   * data_class = 'SYNTHETIC' por CHECK + DEFAULT; environment = default del catalogo de la
--     base (ops.db_catalog) y sin grant de columna para runtime (SEC N2-06);
--   * grants minimos a app_rw: INSERT por columnas y SELECT. worker/platform_rw: nada.
-- La cadena de hash (payloadHash/previousEventHash/eventHash) llega con ADR-011/DEC-BR-009.

-- Entorno de la base (GRD-CM-11): DEFAULT de las tablas de eventos. STABLE, sin privilegios
-- extra (el runtime ya tiene SELECT sobre ops.db_catalog).
CREATE FUNCTION ops.catalog_environment() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT environment FROM ops.db_catalog $$;
GRANT EXECUTE ON FUNCTION ops.catalog_environment() TO app_rw, worker, platform_rw;

CREATE TABLE integrity.audit_event (
  event_id             uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT audit_event_pkey PRIMARY KEY,
  tenant_id            uuid        NOT NULL,
  aggregate_type       text        NOT NULL CONSTRAINT audit_event_aggregate_type_len CHECK (pg_catalog.length(aggregate_type) BETWEEN 1 AND 100),
  aggregate_id         text        NOT NULL CONSTRAINT audit_event_aggregate_id_len CHECK (pg_catalog.length(aggregate_id) BETWEEN 1 AND 100),
  sequence             integer     NOT NULL CONSTRAINT audit_event_sequence_positive CHECK (sequence >= 1),
  event_type           text        NOT NULL CONSTRAINT audit_event_event_type_len CHECK (pg_catalog.length(event_type) BETWEEN 1 AND 100),
  actor_type           text        NOT NULL CONSTRAINT audit_event_actor_type_enum CHECK (actor_type IN ('HUMAN', 'SYSTEM_GUARD', 'FIXTURE')),
  actor_role           text        CONSTRAINT audit_event_actor_role_enum CHECK (actor_role IN ('DECISION_MAKER', 'INVITER', 'CONTEXT_OWNER', 'PLATFORM_ADMIN', 'RIGHTS_OPERATOR', 'UNVERIFIED_BEARER')),
  recorded_by_ref      text,
  cosigned_by_ref      text,
  payload              jsonb       NOT NULL CONSTRAINT audit_event_payload_object CHECK (pg_catalog.jsonb_typeof(payload) = 'object'),
  idempotency_key_hash text        CONSTRAINT audit_event_idem_hash_shape CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
  occurred_at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  environment          text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT audit_event_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  evidentiary          boolean     NOT NULL DEFAULT false,
  data_class           text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT audit_event_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT audit_event_evidentiary_only_production CHECK (evidentiary = false OR environment = 'PRODUCTION'),
  CONSTRAINT audit_event_fixture_only_local CHECK (actor_type <> 'FIXTURE' OR environment = 'LOCAL'),
  CONSTRAINT audit_event_sequence_unique UNIQUE (tenant_id, aggregate_id, sequence),
  CONSTRAINT audit_event_idempotency_unique UNIQUE (tenant_id, aggregate_id, idempotency_key_hash)
);

CREATE FUNCTION integrity.audit_event_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'integrity.audit_event es append-only (INV-CM-01, ADR-002 §2)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER audit_event_no_update_delete
  BEFORE UPDATE OR DELETE ON integrity.audit_event
  FOR EACH ROW EXECUTE FUNCTION integrity.audit_event_immutable();
CREATE TRIGGER audit_event_no_truncate
  BEFORE TRUNCATE ON integrity.audit_event
  FOR EACH STATEMENT EXECUTE FUNCTION integrity.audit_event_immutable();
-- ENABLE ALWAYS: tambien bloquean con session_replication_role = replica.
ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete;
ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_truncate;

ALTER TABLE integrity.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_tenant_select ON integrity.audit_event FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY audit_event_tenant_insert ON integrity.audit_event FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());

-- Minimo privilegio: sin UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER. INSERT por columnas: event_id,
-- occurred_at, environment, evidentiary y data_class los fija la base (defaults), no el servicio.
REVOKE ALL ON integrity.audit_event FROM PUBLIC;
GRANT SELECT ON integrity.audit_event TO app_rw;
GRANT INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role,
              recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash)
  ON integrity.audit_event TO app_rw;
