-- scope: database
-- Gobierna: CA-124 (H09), PR-B; contracts/schemas/outbox-events.schema.json (API-CNS-185),
-- common.spec.yaml (stream OUTBOX at-least-once, INV-CM-01, INV-CM-02), ADR-002 §8, ADR-006 §1/§4-§6,
-- DEC-BR-014 §4 (solo datos sinteticos), SEC-CNS-012 (P1-2, P1-6).
--
-- Outbox transaccional app.outbox. Garantias:
--   * dedupe del productor: UNIQUE (tenant_id, dedupe_key);
--   * RLS ENABLE + FORCE por app.current_tenant_id(); app_rw solo INSERT (por columnas) y SELECT;
--   * data_class = 'SYNTHETIC' (CHECK + DEFAULT), environment = default del catalogo;
--   * el claim del worker (cruza tenants, at-least-once) es una funcion SECURITY DEFINER que
--     devuelve SOLO (tenant_id, event_id), sin columnas del sobre (diseno rev. 2 §4 P1-6). Es de un
--     rol dedicado NOLOGIN/NOBYPASSRLS (outbox_claimer, 0004) con grants por columna y policies
--     propias; consent_owner no tiene policies de claim. EXECUTE solo para `worker`, que luego lee
--     el sobre dentro de inTenant (policy por app.current_tenant_id(), nunca cross-tenant).

CREATE TABLE app.outbox (
  event_id       uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT outbox_pkey PRIMARY KEY,
  tenant_id      uuid        NOT NULL,
  dedupe_key     text        NOT NULL CONSTRAINT outbox_dedupe_key_len CHECK (pg_catalog.length(dedupe_key) BETWEEN 1 AND 200),
  event_type     text        NOT NULL CONSTRAINT outbox_event_type_enum CHECK (event_type IN ('consent.revoked')),
  schema_version text        NOT NULL CONSTRAINT outbox_schema_version_semver CHECK (schema_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  context_ref    text        NOT NULL,
  subject_ref    text        NOT NULL,
  occurred_at    timestamptz NOT NULL,
  payload        jsonb       NOT NULL CONSTRAINT outbox_payload_object CHECK (pg_catalog.jsonb_typeof(payload) = 'object'),
  environment    text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT outbox_environment_allowed CHECK (environment IN ('LOCAL', 'DEV', 'STAGING')),
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT outbox_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  status         text        NOT NULL DEFAULT 'PENDING' CONSTRAINT outbox_status_enum CHECK (status IN ('PENDING', 'CLAIMED', 'DELIVERED')),
  attempts       integer     NOT NULL DEFAULT 0 CONSTRAINT outbox_attempts_nonnegative CHECK (attempts >= 0),
  claimed_at     timestamptz,
  created_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT outbox_dedupe_unique UNIQUE (tenant_id, dedupe_key)
);
CREATE INDEX outbox_claimable_idx ON app.outbox (created_at, event_id) WHERE status IN ('PENDING', 'CLAIMED');

-- El sobre del evento es inmutable: solo cambian las columnas de estado del claim/entrega.
CREATE FUNCTION app.outbox_envelope_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF (NEW.event_id, NEW.tenant_id, NEW.dedupe_key, NEW.event_type, NEW.schema_version, NEW.context_ref,
      NEW.subject_ref, NEW.occurred_at, NEW.payload, NEW.environment, NEW.data_class, NEW.created_at)
     IS DISTINCT FROM
     (OLD.event_id, OLD.tenant_id, OLD.dedupe_key, OLD.event_type, OLD.schema_version, OLD.context_ref,
      OLD.subject_ref, OLD.occurred_at, OLD.payload, OLD.environment, OLD.data_class, OLD.created_at) THEN
    RAISE EXCEPTION 'app.outbox: el sobre del evento es inmutable (solo status/attempts/claimed_at)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER outbox_envelope_immutable BEFORE UPDATE ON app.outbox
  FOR EACH ROW EXECUTE FUNCTION app.outbox_envelope_immutable();
ALTER TABLE app.outbox ENABLE ALWAYS TRIGGER outbox_envelope_immutable;

ALTER TABLE app.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_tenant_select ON app.outbox FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY outbox_tenant_insert ON app.outbox FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id() AND status = 'PENDING' AND attempts = 0);
-- El worker lee el sobre solo del tenant de su unidad de trabajo (inTenant), nunca cross-tenant.
CREATE POLICY outbox_worker_select ON app.outbox FOR SELECT TO worker
  USING (tenant_id = app.current_tenant_id());
-- Policies del claim (cruzan tenants por diseno): solo outbox_claimer y solo filas reclamables.
CREATE POLICY outbox_claim_select ON app.outbox FOR SELECT TO outbox_claimer
  USING (status IN ('PENDING', 'CLAIMED'));
CREATE POLICY outbox_claim_update ON app.outbox FOR UPDATE TO outbox_claimer
  USING (status IN ('PENDING', 'CLAIMED'))
  WITH CHECK (status = 'CLAIMED');

REVOKE ALL ON app.outbox FROM PUBLIC;
GRANT SELECT ON app.outbox TO app_rw, worker;
GRANT INSERT (tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, occurred_at, payload)
  ON app.outbox TO app_rw;
-- outbox_claimer: minimo por columna. SELECT incluye attempts porque `attempts = attempts + 1` lo lee.
GRANT USAGE ON SCHEMA app TO outbox_claimer;
GRANT SELECT (event_id, tenant_id, status, claimed_at, created_at, attempts) ON app.outbox TO outbox_claimer;
GRANT UPDATE (status, claimed_at, attempts) ON app.outbox TO outbox_claimer;

-- Claim at-least-once: toma hasta p_limit (1..100) eventos PENDING, o CLAIMED con lease vencido,
-- con FOR UPDATE SKIP LOCKED, los marca CLAIMED y devuelve solo (tenant_id, event_id). El lease es
-- una constante del servidor (60 s): el llamador no puede acortarlo para robar un claim vigente.
-- La funcion se crea con dueno outbox_claimer: CREATE temporal en el esquema app (el migrador hace
-- SET ROLE outbox_claimer sin heredar privilegios) y se revoca de inmediato.
GRANT CREATE ON SCHEMA app TO outbox_claimer;
SET LOCAL ROLE outbox_claimer;
CREATE FUNCTION app.outbox_claim(p_limit integer)
  RETURNS TABLE (tenant_id uuid, event_id uuid)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
  WITH picked AS (
    SELECT o.event_id
      FROM app.outbox o
     WHERE o.status = 'PENDING'
        OR (o.status = 'CLAIMED' AND o.claimed_at < pg_catalog.now() - pg_catalog.make_interval(secs => 60))
     ORDER BY o.created_at, o.event_id
     LIMIT LEAST(GREATEST(p_limit, 1), 100)
       FOR UPDATE SKIP LOCKED
  )
  UPDATE app.outbox AS u
     SET status = 'CLAIMED', claimed_at = pg_catalog.now(), attempts = u.attempts + 1
    FROM picked
   WHERE u.event_id = picked.event_id
  RETURNING u.tenant_id, u.event_id
$$;
REVOKE ALL ON FUNCTION app.outbox_claim(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.outbox_claim(integer) TO worker;
SET LOCAL ROLE consent_owner;
REVOKE CREATE ON SCHEMA app FROM outbox_claimer;
