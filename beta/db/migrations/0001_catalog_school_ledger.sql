-- Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-02.
-- origen (DDL adaptado a UN solo dueño, consent_owner):
--   db/migrations/0001_schemas_catalog.sql@9345b78 (catálogo inmutable), 0002_ledger.sql:24-79@9345b78 (ledger append-only),
--   0013_ledger_chain.sql:25-45@9345b78 (cadena + lista blanca), 0047_adr010_ledger_gen_enrollment_dmv.sql:109-205@9345b78
--   (ledger_gen.canonical_json + ledger_append).
-- El runner la ejecuta como consent_owner (SET LOCAL ROLE) en una sola transacción.
--
-- Qué NO se copia (plan v2 §3): ledger_writer/ledger_gen_owner/integrity_owner (un solo dueño), tenant_resolve, CHECK data_class='SYNTHETIC'
-- por tabla (el gate único es el catálogo + assertEnvironment), is_reserved_email, actores FIXTURE/INVITER, evidentiary.

REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS integrity AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS ops AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS ledger_gen AUTHORIZATION consent_owner;

-- Ninguna función nueva es ejecutable por PUBLIC; el EXECUTE se concede una por una.
ALTER DEFAULT PRIVILEGES FOR ROLE consent_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Solo USAGE (nunca CREATE) para el proceso web. ledger_gen no se concede: las funciones del ledger las llaman triggers SECURITY DEFINER.
GRANT USAGE ON SCHEMA app, integrity, ops TO consent_app;

-- Catálogo de la base: fila única, inmutable salvo por migración. Es el ÚNICO gate de entorno:
-- el servicio no arranca si CNS_ENVIRONMENT no coincide (src/db/assert-environment.ts).
CREATE TABLE ops.db_catalog (
  id             boolean     PRIMARY KEY DEFAULT true CONSTRAINT db_catalog_single_row CHECK (id),
  environment    text        NOT NULL CONSTRAINT db_catalog_environment_allowed CHECK (environment IN ('LOCAL', 'REAL')),
  data_class     text        NOT NULL CONSTRAINT db_catalog_data_class_allowed CHECK (data_class IN ('SYNTHETIC', 'REAL')),
  last_backup_at timestamptz,
  provisioned_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  -- LOCAL <=> SYNTHETIC y REAL <=> REAL: no hay estados mixtos.
  CONSTRAINT db_catalog_env_class_pair CHECK ((environment = 'LOCAL') = (data_class = 'SYNTHETIC'))
);
INSERT INTO ops.db_catalog (environment, data_class) VALUES ('LOCAL', 'SYNTHETIC');

CREATE FUNCTION ops.db_catalog_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'ops.db_catalog es inmutable; el cambio a REAL es una migración revisada por Carlos' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER db_catalog_no_update_delete BEFORE UPDATE OR DELETE ON ops.db_catalog
  FOR EACH ROW EXECUTE FUNCTION ops.db_catalog_immutable();
CREATE TRIGGER db_catalog_no_truncate BEFORE TRUNCATE ON ops.db_catalog
  FOR EACH STATEMENT EXECUTE FUNCTION ops.db_catalog_immutable();
-- ENABLE ALWAYS: también con session_replication_role = replica.
ALTER TABLE ops.db_catalog ENABLE ALWAYS TRIGGER db_catalog_no_update_delete;
ALTER TABLE ops.db_catalog ENABLE ALWAYS TRIGGER db_catalog_no_truncate;
GRANT SELECT ON ops.db_catalog TO consent_app;

CREATE FUNCTION ops.catalog_environment() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT environment FROM ops.db_catalog $$;
CREATE FUNCTION ops.catalog_data_class() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT data_class FROM ops.db_catalog $$;
GRANT EXECUTE ON FUNCTION ops.catalog_environment(), ops.catalog_data_class() TO consent_app;

-- Colegio único (1 tenant = 1 colegio, DEC-BR-015). tenant_id sigue siendo la única clave de aislamiento.
-- La constante vive en app.current_tenant_id(); app.school tiene una sola fila y una FK desde cada tabla de dominio.
CREATE FUNCTION app.current_tenant_id() RETURNS uuid
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT '00000000-0000-4000-8000-000000000001'::uuid $$;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO consent_app;

CREATE TABLE app.school (
  tenant_id    uuid    PRIMARY KEY DEFAULT app.current_tenant_id() CONSTRAINT school_tenant_is_constant CHECK (tenant_id = app.current_tenant_id()),
  display_name text    NOT NULL CONSTRAINT school_display_name_len CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 120),
  singleton    boolean NOT NULL DEFAULT true UNIQUE CONSTRAINT school_singleton CHECK (singleton),
  created_at   timestamptz NOT NULL DEFAULT pg_catalog.now()
);
INSERT INTO app.school (display_name) VALUES ('Colegio beta (sintetico)');
ALTER TABLE app.school ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.school FORCE ROW LEVEL SECURITY;
CREATE POLICY school_tenant_select ON app.school FOR SELECT TO consent_app, consent_owner
  USING (tenant_id = app.current_tenant_id());
GRANT SELECT ON app.school TO consent_app;

-- Ledger integrity.audit_event --------------------------------------------------------------------------------------------------------
-- Append-only: sin UPDATE/DELETE/TRUNCATE para nadie (REVOKE + trigger ENABLE ALWAYS que rechaza incluso al dueño).
-- Solo escribe el dueño, vía los triggers SECURITY DEFINER de ledger_gen; consent_app solo lee.
CREATE TABLE integrity.audit_event (
  event_id             uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT audit_event_pkey PRIMARY KEY,
  tenant_id            uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  aggregate_type       text        NOT NULL CONSTRAINT audit_event_aggregate_type_len CHECK (pg_catalog.length(aggregate_type) BETWEEN 1 AND 100),
  aggregate_id         text        NOT NULL CONSTRAINT audit_event_aggregate_id_len CHECK (pg_catalog.length(aggregate_id) BETWEEN 1 AND 100),
  sequence             integer     NOT NULL CONSTRAINT audit_event_sequence_positive CHECK (sequence >= 1),
  event_type           text        NOT NULL CONSTRAINT audit_event_event_type_len CHECK (pg_catalog.length(event_type) BETWEEN 1 AND 100),
  actor_type           text        NOT NULL CONSTRAINT audit_event_actor_type_enum CHECK (actor_type IN ('HUMAN', 'SYSTEM_GUARD')),
  actor_role           text        CONSTRAINT audit_event_actor_role_enum CHECK (actor_role IN ('DECISION_MAKER', 'OPERATOR', 'SYSTEM', 'UNVERIFIED_BEARER')),
  -- Siempre NULL en v2; se conservan porque entran al sobre del hash (idéntico al verificador TS portado).
  recorded_by_ref      text,
  cosigned_by_ref      text,
  payload              jsonb       NOT NULL CONSTRAINT audit_event_payload_object CHECK (pg_catalog.jsonb_typeof(payload) = 'object'),
  idempotency_key_hash text        CONSTRAINT audit_event_idem_hash_shape CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
  occurred_at          timestamptz NOT NULL DEFAULT pg_catalog.now() CONSTRAINT audit_event_occurred_at_is_now CHECK (occurred_at = pg_catalog.now()),
  environment          text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT audit_event_environment_enum CHECK (environment IN ('LOCAL', 'REAL')),
  data_class           text        NOT NULL DEFAULT ops.catalog_data_class() CONSTRAINT audit_event_data_class_enum CHECK (data_class IN ('SYNTHETIC', 'REAL')),
  chain_seq            bigint      NOT NULL CONSTRAINT audit_event_chain_seq_positive CHECK (chain_seq >= 1),
  payload_hash         text        NOT NULL CONSTRAINT audit_event_payload_hash_shape CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  previous_event_hash  text        NOT NULL CONSTRAINT audit_event_previous_hash_shape CHECK (previous_event_hash ~ '^[0-9a-f]{64}$'),
  event_hash           text        NOT NULL CONSTRAINT audit_event_event_hash_shape CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_event_environment_is_catalog CHECK (environment = ops.catalog_environment()),
  CONSTRAINT audit_event_sequence_unique UNIQUE (tenant_id, aggregate_id, sequence),
  CONSTRAINT audit_event_idempotency_unique UNIQUE (tenant_id, aggregate_id, idempotency_key_hash),
  CONSTRAINT audit_event_chain_seq_unique UNIQUE (tenant_id, chain_seq),
  CONSTRAINT audit_event_previous_hash_unique UNIQUE (tenant_id, previous_event_hash),
  -- Lista blanca de tipos de evento (subconjunto del repo anterior: lo que emiten los triggers de beta/). Ampliar = migración nueva.
  CONSTRAINT audit_event_event_type_allowlist CHECK (event_type IN (
    'INVITATION_CREATED', 'INVITATION_SENT', 'INVITATION_TOKEN_ROTATED', 'INVITATION_OPENED', 'INVITATION_VERIFIED',
    'INVITATION_COMPLETED', 'INVITATION_DECLINED', 'INVITATION_CANCELLED',
    'DECISION_MAKER_CHANNEL_VERIFIED', 'OTP_LOCKED',
    'CONSENT_GRANTED', 'CONSENT_DECLINED', 'RECEIPT_CREATED', 'CONSENT_REVOKED',
    'REVOCATION_REQUESTED', 'REVOCATION_VERIFIED', 'REVOCATION_CONFIRMED', 'REVOCATION_APPLIED', 'REVOCATION_HELD'
  ))
);

CREATE FUNCTION integrity.audit_event_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'integrity.audit_event es append-only' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER audit_event_no_update_delete BEFORE UPDATE OR DELETE ON integrity.audit_event
  FOR EACH ROW EXECUTE FUNCTION integrity.audit_event_immutable();
CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON integrity.audit_event
  FOR EACH STATEMENT EXECUTE FUNCTION integrity.audit_event_immutable();
-- ENABLE ALWAYS: también bloquean al dueño y con session_replication_role = replica.
ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete;
ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_truncate;

ALTER TABLE integrity.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_tenant_select ON integrity.audit_event FOR SELECT TO consent_app, consent_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY audit_event_tenant_insert ON integrity.audit_event FOR INSERT TO consent_owner
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON integrity.audit_event FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON integrity.audit_event FROM PUBLIC, consent_owner, consent_app;
GRANT SELECT ON integrity.audit_event TO consent_app;
-- consent_app NO tiene INSERT: el ledger solo se escribe por los triggers emit_* (SECURITY DEFINER, dueño consent_owner).

-- JSON canónico idéntico a canonicalJson de beta/src/ledger/ledger-chain.ts: claves ordenadas por punto de código (COLLATE "C"), sin espacios.
-- Los vectores dorados TS<->SQL están en beta/tests/integration/ledger-chain.test.ts.
CREATE FUNCTION ledger_gen.canonical_json(p_value jsonb) RETURNS text
  LANGUAGE plpgsql IMMUTABLE
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  t text := pg_catalog.jsonb_typeof(p_value);
BEGIN
  IF t = 'object' THEN
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_value) k WHERE k ~ '[\U00010000-\U0010FFFF]') THEN
      RAISE EXCEPTION 'canonical_json: claves fuera del BMP no admitidas (orden TS<->SQL divergente)' USING ERRCODE = '22023';
    END IF;
    RETURN '{' || COALESCE((SELECT pg_catalog.string_agg(pg_catalog.to_jsonb(e.key)::text || ':' || ledger_gen.canonical_json(e.value), ',' ORDER BY e.key COLLATE "C")
                              FROM pg_catalog.jsonb_each(p_value) e), '') || '}';
  ELSIF t = 'array' THEN
    RETURN '[' || COALESCE((SELECT pg_catalog.string_agg(ledger_gen.canonical_json(a.v), ',' ORDER BY a.ord)
                              FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY AS a(v, ord)), '') || ']';
  END IF;
  RETURN p_value::text;
END
$fn$;

-- Append del ledger (tenant SIEMPRE app.current_tenant_id(); recorded_by/cosigned NULL; la secuencia del agregado es max+1 bajo el lock por tenant).
-- Dedupe estricto: la misma clave solo es un reintento si agregado, tipo, actor y payload canónico son IGUALES (RV002 si difieren).
CREATE FUNCTION ledger_gen.ledger_append(
  p_aggregate_type text, p_aggregate_id text, p_event_type text, p_actor_type text, p_actor_role text,
  p_payload jsonb, p_idempotency_key text,
  OUT o_sequence integer, OUT o_deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_key_hash text;
  v_current integer;
  v_chain_seq bigint;
  v_prev text;
  v_occurred text;
  v_env text;
  v_payload_hash text;
  v_event_hash text;
  v_now timestamptz := pg_catalog.now();
  v_dup_type text;
  v_dup_agg text;
  v_dup_payload jsonb;
  v_dup_actor_type text;
  v_dup_actor_role text;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ledger-chain:' || v_tenant::text, 0));

  IF p_idempotency_key IS NOT NULL THEN
    v_key_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_idempotency_key, 'UTF8')), 'hex');
    SELECT e.sequence, e.event_type, e.aggregate_type, e.payload, e.actor_type, e.actor_role
      INTO o_sequence, v_dup_type, v_dup_agg, v_dup_payload, v_dup_actor_type, v_dup_actor_role
      FROM integrity.audit_event e
     WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id AND e.idempotency_key_hash = v_key_hash;
    IF FOUND THEN
      IF v_dup_type IS DISTINCT FROM p_event_type OR v_dup_agg IS DISTINCT FROM p_aggregate_type
         OR v_dup_actor_type IS DISTINCT FROM p_actor_type OR v_dup_actor_role IS DISTINCT FROM p_actor_role
         OR ledger_gen.canonical_json(v_dup_payload) IS DISTINCT FROM ledger_gen.canonical_json(p_payload) THEN
        RAISE EXCEPTION 'clave de idempotencia reutilizada con otro evento (tipo, agregado, actor o payload)' USING ERRCODE = 'RV002';
      END IF;
      o_deduped := true;
      RETURN;
    END IF;
  END IF;

  SELECT COALESCE(pg_catalog.max(e.sequence), 0) INTO v_current
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id;

  SELECT e.chain_seq, e.event_hash INTO v_chain_seq, v_prev
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant ORDER BY e.chain_seq DESC LIMIT 1;
  v_chain_seq := COALESCE(v_chain_seq, 0) + 1;
  v_prev := COALESCE(v_prev, pg_catalog.repeat('0', 64));
  v_occurred := pg_catalog.to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  v_env := ops.catalog_environment();
  v_payload_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(ledger_gen.canonical_json(p_payload), 'UTF8')), 'hex');
  v_event_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(ledger_gen.canonical_json(pg_catalog.jsonb_build_object(
    'v', 2, 'tenantId', v_tenant, 'chainSeq', v_chain_seq, 'aggregateType', p_aggregate_type, 'aggregateId', p_aggregate_id,
    'sequence', v_current + 1, 'eventType', p_event_type, 'actorType', p_actor_type, 'actorRole', p_actor_role,
    'recordedByRef', NULL::text, 'cosignedByRef', NULL::text, 'idempotencyKeyHash', v_key_hash,
    'occurredAt', v_occurred, 'environment', v_env, 'payloadHash', v_payload_hash, 'previousEventHash', v_prev)), 'UTF8')), 'hex');

  INSERT INTO integrity.audit_event
    (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload,
     idempotency_key_hash, chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  VALUES
    (v_tenant, p_aggregate_type, p_aggregate_id, v_current + 1, p_event_type, p_actor_type, p_actor_role, NULL, NULL, p_payload,
     v_key_hash, v_chain_seq, v_payload_hash, v_prev, v_event_hash, v_now, v_env);
  o_sequence := v_current + 1;
  o_deduped := false;
END
$fn$;

REVOKE ALL ON FUNCTION ledger_gen.canonical_json(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.ledger_append(text, text, text, text, text, jsonb, text) FROM PUBLIC;
