-- scope: database
-- Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.2, §4.3; D5), CA-146, P-34, INV-21-07/08/09/18/19, SEC-CNS-006 rev. 5,
-- ADR-010 rev. 3 §4.1, INV-CM-01 (append-only), INV-CM-02 (tenant_id unica clave de aislamiento).
-- Regla de Carlos (2026-10-01): 0000-0030 no se editan; esta migracion es nueva.
--
-- LD-15 sigue ABIERTA (LEGAL DECISION): los 30 dias de retencion son un PLACEHOLDER de Carlos (2026-10-08), NO un valor aprobado definitivo.
-- Queda registrado en ops.retention_policy.decision_ref. Cambiarlo exige una migracion nueva que deshabilite y rehabilite el trigger de la tabla.
--
-- Esta migracion NO se re-ejecuta en cada deploy (alcance database: se registra por checksum en ops.schema_migration). Lo unico que se
-- re-ejecuta es el alcance cluster (roles; 0028 sigue idempotente). Este PR no agrega migraciones de alcance cluster.
--
-- 1. ops.retention_policy: politica por store, solo-agregar (UPDATE/DELETE/TRUNCATE siempre fallan). Sin grants de runtime.
-- 2. ops.purge_run: evidencia de cada corrida (una fila por tenant con filas vencidas + una fila resumen con tenant_id NULL, siempre).
--    Solo se inserta desde ops.purge_p34; solo se borra por la propia purga (store 'purge_run') y solo filas vencidas.
-- 3. ops.security_event_guard(): reemplaza a ops.security_event_immutable() en el trigger de UPDATE/DELETE de ops.security_event (mismo nombre de
--    trigger). UPDATE siempre falla. DELETE solo pasa si lo ejecuta security_event_owner (current_user) dentro de ops.purge_p34 (bandera
--    ops.purge_active) Y la fila esta vencida segun la politica. Un superusuario o consent_owner que borra directamente: error. Residual R-21-2
--    (aceptado IT0b): quien pueda SET ROLE security_event_owner y fijar la bandera a mano borra, pero SOLO filas ya vencidas y sin dejar purge_run.
--    TRUNCATE sigue prohibido (trigger BEFORE STATEMENT ENABLE ALWAYS).
-- 4. ops.purge_p34(store, esperado) SECURITY DEFINER (dueno security_event_owner): verifica que la politica coincide con lo esperado, borra solo
--    lo vencido, verifica la post-condicion (0 vencidas restantes, borradas = elegibles) e inserta purge_run en la misma tx. EXECUTE solo worker.
--    Stores habilitados en este PR: security_event, otp_verification, purge_run. otp_budget llega con SEC-CNS-021 PR-4 (su tabla no existe aun).
-- 5. ops.purge_run_summary(run_id) (solo worker; conteos para el CLI) y ops.retention_status(): lectura de la politica y de la ultima corrida por store, para los chequeos de arranque del runtime (app_rw y
--    worker no tienen acceso directo a retention_policy/purge_run). Sin datos de tenant.
-- 6. app.otp_verification: security_event_owner recibe SELECT por columnas (tenant_id, expires_at) y DELETE, acotados por policy a filas vencidas.
--    No lee code_hash ni channel_ref (correo).

-- A. Como consent_owner (dueno de app.otp_verification, ops.db_catalog y del esquema ops): accesos que la purga necesita.
GRANT USAGE ON SCHEMA app TO security_event_owner;
GRANT SELECT ON ops.db_catalog TO security_event_owner;
GRANT EXECUTE ON FUNCTION ops.catalog_environment() TO security_event_owner;
-- Para crear sus objetos security_event_owner necesita CREATE en ops (grant temporal; se revoca en C).
GRANT USAGE, CREATE ON SCHEMA ops TO security_event_owner;

-- B. Como security_event_owner: todo objeto nuevo nace con ese dueno.
SET LOCAL ROLE security_event_owner;

CREATE TABLE ops.retention_policy (
  store        text     NOT NULL CONSTRAINT retention_policy_pkey PRIMARY KEY
                        CONSTRAINT retention_policy_store_enum CHECK (store IN ('security_event', 'otp_budget', 'otp_verification', 'purge_run')),
  retention    interval NOT NULL CONSTRAINT retention_policy_min_1_day CHECK (retention >= interval '1 day'),
  decision_ref text     NOT NULL CONSTRAINT retention_policy_decision_ref_len CHECK (pg_catalog.length(decision_ref) BETWEEN 1 AND 200)
);

-- Guard generico solo-agregar (retention_policy; TRUNCATE de purge_run). El mensaje usa el nombre de la tabla.
CREATE FUNCTION ops.append_only_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION '%.% es append-only (INV-CM-01)', TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;

REVOKE ALL ON FUNCTION ops.append_only_guard() FROM PUBLIC;

CREATE TRIGGER retention_policy_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.retention_policy
  FOR EACH ROW EXECUTE FUNCTION ops.append_only_guard();
CREATE TRIGGER retention_policy_no_truncate
  BEFORE TRUNCATE ON ops.retention_policy
  FOR EACH STATEMENT EXECUTE FUNCTION ops.append_only_guard();
ALTER TABLE ops.retention_policy ENABLE ALWAYS TRIGGER retention_policy_no_update_delete;
ALTER TABLE ops.retention_policy ENABLE ALWAYS TRIGGER retention_policy_no_truncate;

ALTER TABLE ops.retention_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.retention_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_policy_owner_select ON ops.retention_policy FOR SELECT TO security_event_owner USING (true);
CREATE POLICY retention_policy_owner_insert ON ops.retention_policy FOR INSERT TO security_event_owner WITH CHECK (true);
REVOKE ALL ON ops.retention_policy FROM PUBLIC;

-- PLACEHOLDER P-34 (Carlos, 2026-10-08): 30 dias. LD-15 abierta. otp_budget lo agrega SEC-CNS-021 PR-4.
INSERT INTO ops.retention_policy (store, retention, decision_ref) VALUES
  ('security_event',   interval '30 days', 'P-34 placeholder (Carlos 2026-10-08); LD-15 abierta: no es un valor aprobado definitivo'),
  ('otp_verification', interval '30 days', 'P-34 placeholder (Carlos 2026-10-08, D5); LD-15 abierta: no es un valor aprobado definitivo'),
  ('purge_run',        interval '30 days', 'P-34 placeholder (Carlos 2026-10-08, D5); LD-15 abierta: no es un valor aprobado definitivo');

CREATE TABLE ops.purge_run (
  row_id                      uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT purge_run_pkey PRIMARY KEY,
  run_id                      uuid        NOT NULL,
  store                       text        NOT NULL CONSTRAINT purge_run_store_enum CHECK (store IN ('security_event', 'otp_budget', 'otp_verification', 'purge_run')),
  tenant_id                   uuid,
  cutoff                      timestamptz NOT NULL,
  retention                   interval    NOT NULL CONSTRAINT purge_run_retention_min_1_day CHECK (retention >= interval '1 day'),
  eligible_before             bigint      NOT NULL CONSTRAINT purge_run_eligible_nonneg CHECK (eligible_before >= 0),
  deleted_count               bigint      NOT NULL CONSTRAINT purge_run_deleted_nonneg CHECK (deleted_count >= 0),
  remaining_older_than_cutoff bigint      NOT NULL CONSTRAINT purge_run_remaining_zero CHECK (remaining_older_than_cutoff = 0),
  min_deleted_at              timestamptz,
  max_deleted_at              timestamptz,
  started_at                  timestamptz NOT NULL,
  finished_at                 timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  environment                 text        NOT NULL DEFAULT ops.catalog_environment() CONSTRAINT purge_run_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  data_class                  text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT purge_run_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT purge_run_deleted_eq_eligible CHECK (deleted_count = eligible_before),
  CONSTRAINT purge_run_deleted_range CHECK ((deleted_count = 0) = (min_deleted_at IS NULL AND max_deleted_at IS NULL) AND (min_deleted_at IS NULL OR min_deleted_at <= max_deleted_at)),
  CONSTRAINT purge_run_time_order CHECK (finished_at >= started_at)
);
-- tenant_id NULL = fila resumen de la corrida (una por run_id y store); no hay dos filas por (run, store, tenant).
CREATE UNIQUE INDEX purge_run_tenant_uq ON ops.purge_run (run_id, store, tenant_id) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX purge_run_summary_uq ON ops.purge_run (run_id, store) WHERE tenant_id IS NULL;
CREATE INDEX purge_run_store_finished_idx ON ops.purge_run (store, finished_at);

-- ops.security_event_guard(): UPDATE siempre falla. DELETE de fila solo pasa para security_event_owner dentro de ops.purge_p34 y solo si la fila esta
-- vencida segun ops.retention_policy (IF anidados: Postgres no garantiza el orden de evaluacion de AND). Aplica a ops.security_event y ops.purge_run.
CREATE FUNCTION ops.security_event_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_ts        timestamptz;
  v_retention interval;
BEGIN
  IF TG_OP = 'DELETE' AND current_user = 'security_event_owner'
     AND COALESCE(pg_catalog.current_setting('ops.purge_active', true), '') = 'on' THEN
    IF TG_TABLE_NAME = 'security_event' THEN
      v_ts := OLD.occurred_at;
    ELSIF TG_TABLE_NAME = 'purge_run' THEN
      v_ts := OLD.finished_at;
    END IF;
    IF v_ts IS NOT NULL THEN
      SELECT p.retention INTO v_retention FROM ops.retention_policy p WHERE p.store = TG_TABLE_NAME;
      IF v_retention IS NOT NULL AND v_ts < pg_catalog.now() - v_retention THEN
        RETURN OLD;
      END IF;
    END IF;
  END IF;
  RAISE EXCEPTION '%.% es append-only (INV-CM-01); solo ops.purge_p34 puede borrar filas vencidas (P-34)', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'integrity_constraint_violation';
END
$$;

REVOKE ALL ON FUNCTION ops.security_event_guard() FROM PUBLIC;

-- ops.security_event: el trigger de UPDATE/DELETE pasa a ops.security_event_guard() (mismo nombre); TRUNCATE sigue con ops.security_event_immutable().
DROP TRIGGER security_event_no_update_delete ON ops.security_event;
CREATE TRIGGER security_event_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.security_event
  FOR EACH ROW EXECUTE FUNCTION ops.security_event_guard();
ALTER TABLE ops.security_event ENABLE ALWAYS TRIGGER security_event_no_update_delete;

CREATE TRIGGER purge_run_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.purge_run
  FOR EACH ROW EXECUTE FUNCTION ops.security_event_guard();
CREATE TRIGGER purge_run_no_truncate
  BEFORE TRUNCATE ON ops.purge_run
  FOR EACH STATEMENT EXECUTE FUNCTION ops.append_only_guard();
ALTER TABLE ops.purge_run ENABLE ALWAYS TRIGGER purge_run_no_update_delete;
ALTER TABLE ops.purge_run ENABLE ALWAYS TRIGGER purge_run_no_truncate;

ALTER TABLE ops.purge_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.purge_run FORCE ROW LEVEL SECURITY;
CREATE POLICY purge_run_owner_select ON ops.purge_run FOR SELECT TO security_event_owner USING (true);
CREATE POLICY purge_run_owner_insert ON ops.purge_run FOR INSERT TO security_event_owner WITH CHECK (true);
CREATE POLICY purge_run_purge_delete ON ops.purge_run FOR DELETE TO security_event_owner
  USING (finished_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'purge_run'));
REVOKE ALL ON ops.purge_run FROM PUBLIC;

-- ops.security_event: FORCE RLS aplica tambien al dueno. Policies de la purga: ver solo lo vencido y borrar solo lo vencido.
CREATE POLICY security_event_purge_select ON ops.security_event FOR SELECT TO security_event_owner
  USING (occurred_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'security_event'));
CREATE POLICY security_event_purge_delete ON ops.security_event FOR DELETE TO security_event_owner
  USING (occurred_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'security_event'));

-- Purga verificable (INV-21-07/08/09). Fail-closed: cualquier discrepancia aborta la tx completa (no se borra nada).
CREATE FUNCTION ops.purge_p34(p_store text, p_expected interval) RETURNS uuid
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_run       uuid        := pg_catalog.gen_random_uuid();
  v_started   timestamptz := pg_catalog.clock_timestamp();
  v_policy    interval;
  v_cutoff    timestamptz;
  v_rows      jsonb;
  v_remaining bigint;
BEGIN
  IF p_store IS NULL OR p_expected IS NULL THEN
    RAISE EXCEPTION 'purge_p34: store y retencion esperada son obligatorios' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_store NOT IN ('security_event', 'otp_verification', 'purge_run') THEN
    RAISE EXCEPTION 'purge_p34: store no habilitado (%)', p_store USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT p.retention INTO v_policy FROM ops.retention_policy p WHERE p.store = p_store;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'purge_p34: sin politica de retencion para el store %', p_store USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF v_policy < interval '1 day' THEN
    RAISE EXCEPTION 'purge_p34: la retencion de % es menor a 1 dia', p_store USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF v_policy <> p_expected THEN
    RAISE EXCEPTION 'purge_p34: la retencion esperada no coincide con ops.retention_policy (%)', p_store USING ERRCODE = 'invalid_parameter_value';
  END IF;

  v_cutoff := pg_catalog.now() - v_policy;
  PERFORM pg_catalog.set_config('ops.purge_active', 'on', true);

  IF p_store = 'security_event' THEN
    WITH eligible AS (
      SELECT e.tenant_id, pg_catalog.count(*) AS n FROM ops.security_event e WHERE e.occurred_at < v_cutoff GROUP BY e.tenant_id
    ), deleted AS (
      DELETE FROM ops.security_event e WHERE e.occurred_at < v_cutoff RETURNING e.tenant_id, e.occurred_at
    ), agg AS (
      SELECT d.tenant_id, pg_catalog.count(*) AS n, pg_catalog.min(d.occurred_at) AS mn, pg_catalog.max(d.occurred_at) AS mx FROM deleted d GROUP BY d.tenant_id
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('tenant_id', l.tenant_id, 'eligible', l.n, 'deleted', COALESCE(a.n, 0), 'min', a.mn, 'max', a.mx)), '[]'::jsonb)
      INTO v_rows FROM eligible l LEFT JOIN agg a ON a.tenant_id = l.tenant_id;
    SELECT pg_catalog.count(*) INTO v_remaining FROM ops.security_event e WHERE e.occurred_at < v_cutoff;
  ELSIF p_store = 'otp_verification' THEN
    WITH eligible AS (
      SELECT o.tenant_id, pg_catalog.count(*) AS n FROM app.otp_verification o WHERE o.expires_at < v_cutoff GROUP BY o.tenant_id
    ), deleted AS (
      DELETE FROM app.otp_verification o WHERE o.expires_at < v_cutoff RETURNING o.tenant_id, o.expires_at
    ), agg AS (
      SELECT d.tenant_id, pg_catalog.count(*) AS n, pg_catalog.min(d.expires_at) AS mn, pg_catalog.max(d.expires_at) AS mx FROM deleted d GROUP BY d.tenant_id
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('tenant_id', l.tenant_id, 'eligible', l.n, 'deleted', COALESCE(a.n, 0), 'min', a.mn, 'max', a.mx)), '[]'::jsonb)
      INTO v_rows FROM eligible l LEFT JOIN agg a ON a.tenant_id = l.tenant_id;
    SELECT pg_catalog.count(*) INTO v_remaining FROM app.otp_verification o WHERE o.expires_at < v_cutoff;
  ELSE
    -- purge_run: la corrida en curso aun no inserto sus filas, por lo que nunca se borra a si misma.
    WITH eligible AS (
      SELECT r.tenant_id, pg_catalog.count(*) AS n FROM ops.purge_run r WHERE r.finished_at < v_cutoff GROUP BY r.tenant_id
    ), deleted AS (
      DELETE FROM ops.purge_run r WHERE r.finished_at < v_cutoff RETURNING r.tenant_id, r.finished_at
    ), agg AS (
      SELECT d.tenant_id, pg_catalog.count(*) AS n, pg_catalog.min(d.finished_at) AS mn, pg_catalog.max(d.finished_at) AS mx FROM deleted d GROUP BY d.tenant_id
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('tenant_id', l.tenant_id, 'eligible', l.n, 'deleted', COALESCE(a.n, 0), 'min', a.mn, 'max', a.mx)), '[]'::jsonb)
      INTO v_rows FROM eligible l LEFT JOIN agg a ON a.tenant_id IS NOT DISTINCT FROM l.tenant_id;
    SELECT pg_catalog.count(*) INTO v_remaining FROM ops.purge_run r WHERE r.finished_at < v_cutoff;
  END IF;

  IF v_remaining <> 0 THEN
    RAISE EXCEPTION 'purge_p34: quedan % filas vencidas en % tras la purga; se aborta sin borrar', v_remaining, p_store USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  -- Una fila por tenant con filas vencidas y una fila resumen (tenant_id NULL), aun si no habia nada que borrar (prueba de que la corrida ocurrio).
  INSERT INTO ops.purge_run (run_id, store, tenant_id, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff,
                             min_deleted_at, max_deleted_at, started_at)
  SELECT v_run, p_store, (r.j ->> 'tenant_id')::uuid, v_cutoff, v_policy, (r.j ->> 'eligible')::bigint, (r.j ->> 'deleted')::bigint, 0,
         (r.j ->> 'min')::timestamptz, (r.j ->> 'max')::timestamptz, v_started
    FROM pg_catalog.jsonb_array_elements(v_rows) AS r(j)
   WHERE (r.j ->> 'tenant_id') IS NOT NULL;  -- las filas resumen borradas (tenant_id NULL) solo cuentan en el resumen de la corrida
  INSERT INTO ops.purge_run (run_id, store, tenant_id, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff,
                             min_deleted_at, max_deleted_at, started_at)
  SELECT v_run, p_store, NULL, v_cutoff, v_policy,
         COALESCE(pg_catalog.sum((r.j ->> 'eligible')::bigint), 0)::bigint, COALESCE(pg_catalog.sum((r.j ->> 'deleted')::bigint), 0)::bigint, 0,
         pg_catalog.min((r.j ->> 'min')::timestamptz), pg_catalog.max((r.j ->> 'max')::timestamptz), v_started
    FROM pg_catalog.jsonb_array_elements(v_rows) AS r(j);

  PERFORM pg_catalog.set_config('ops.purge_active', 'off', true);
  RETURN v_run;
END
$$;
REVOKE ALL ON FUNCTION ops.purge_p34(text, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.purge_p34(text, interval) TO worker;

-- Estado de retencion para los chequeos de arranque (solo lectura; sin datos de tenant).
CREATE FUNCTION ops.retention_status() RETURNS TABLE (store text, retention_days numeric, last_run_at timestamptz)
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
  SELECT p.store,
         extract(epoch FROM p.retention) / 86400,
         (SELECT pg_catalog.max(r.finished_at) FROM ops.purge_run r WHERE r.store = p.store AND r.tenant_id IS NULL)
    FROM ops.retention_policy p
   ORDER BY p.store
$$;
REVOKE ALL ON FUNCTION ops.retention_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.retention_status() TO app_rw, worker;

-- Resumen de una corrida para el CLI (worker no lee purge_run): solo conteos agregados, sin tenant_id.
CREATE FUNCTION ops.purge_run_summary(p_run_id uuid) RETURNS TABLE (store text, tenants bigint, eligible_before bigint, deleted_count bigint, remaining_older_than_cutoff bigint)
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
  SELECT s.store,
         (SELECT pg_catalog.count(*) FROM ops.purge_run t WHERE t.run_id = s.run_id AND t.store = s.store AND t.tenant_id IS NOT NULL),
         s.eligible_before, s.deleted_count, s.remaining_older_than_cutoff
    FROM ops.purge_run s
   WHERE s.run_id = p_run_id AND s.tenant_id IS NULL
$$;
REVOKE ALL ON FUNCTION ops.purge_run_summary(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.purge_run_summary(uuid) TO worker;

-- C. De vuelta como consent_owner: grants y policies sobre app.otp_verification (su dueno no cambia) y retiro del CREATE temporal.
SET LOCAL ROLE consent_owner;

GRANT SELECT (tenant_id, expires_at), DELETE ON app.otp_verification TO security_event_owner;
CREATE POLICY otp_verification_purge_select ON app.otp_verification FOR SELECT TO security_event_owner
  USING (expires_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'otp_verification'));
CREATE POLICY otp_verification_purge_delete ON app.otp_verification FOR DELETE TO security_event_owner
  USING (expires_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'otp_verification'));

REVOKE CREATE ON SCHEMA ops FROM security_event_owner;

-- D. Aserciones (INV-21-06/07): la migracion aborta si algo no quedo como se declara. Se consulta el catalogo por nombre.
DO $assert$
DECLARE
  t record;
BEGIN
  IF pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE') THEN
    RAISE EXCEPTION 'security_event_owner conserva CREATE en el esquema ops (el grant temporal no quedo revocado)';
  END IF;

  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'ops' AND c.relname IN ('retention_policy', 'purge_run') AND c.relkind = 'r') <> 2 THEN
    RAISE EXCEPTION 'faltan ops.retention_policy u ops.purge_run';
  END IF;
  -- Tablas nuevas: dueno, ENABLE + FORCE RLS, sin acceso de consent_owner ni de runtime.
  FOR t IN SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.pg_get_userbyid(c.relowner) AS owner
             FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'ops' AND c.relname IN ('retention_policy', 'purge_run') AND c.relkind = 'r' LOOP
    IF t.owner <> 'security_event_owner' THEN RAISE EXCEPTION 'ops.% no pertenece a security_event_owner', t.relname; END IF;
    IF NOT (t.relrowsecurity AND t.relforcerowsecurity) THEN RAISE EXCEPTION 'ops.% sin ENABLE/FORCE ROW LEVEL SECURITY', t.relname; END IF;
    IF pg_catalog.has_table_privilege('consent_owner', t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
      RAISE EXCEPTION 'consent_owner conserva privilegios sobre ops.%', t.relname;
    END IF;
    IF pg_catalog.has_any_column_privilege('app_rw', t.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_table_privilege('app_rw', t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege('worker', t.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_table_privilege('worker', t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege('platform_rw', t.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_table_privilege('platform_rw', t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
      RAISE EXCEPTION 'un rol de runtime tiene privilegios sobre ops.%', t.relname;
    END IF;
  END LOOP;

  -- Funciones: dueno, SECURITY DEFINER donde corresponde, search_path fijo, EXECUTE solo a quien debe.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'ops' AND p.proname IN ('purge_p34', 'purge_run_summary', 'retention_status', 'security_event_guard', 'append_only_guard')) <> 5 THEN
    RAISE EXCEPTION 'faltan funciones de la purga P-34';
  END IF;
  FOR t IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'ops' AND p.proname IN ('purge_p34', 'purge_run_summary', 'retention_status', 'security_event_guard', 'append_only_guard') LOOP
    IF t.owner <> 'security_event_owner' THEN RAISE EXCEPTION 'ops.%() no pertenece a security_event_owner', t.proname; END IF;
    IF t.proconfig IS NULL OR NOT (t.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) THEN RAISE EXCEPTION 'ops.%() sin search_path fijo', t.proname; END IF;
    IF (t.proname IN ('purge_p34', 'purge_run_summary', 'retention_status')) <> t.prosecdef THEN RAISE EXCEPTION 'ops.%(): SECURITY DEFINER inesperado', t.proname; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar ops.%()', t.proname; END IF;
    IF t.proname IN ('purge_p34', 'purge_run_summary') AND NOT (pg_catalog.has_function_privilege('worker', t.oid, 'EXECUTE')
        AND NOT pg_catalog.has_function_privilege('app_rw', t.oid, 'EXECUTE') AND NOT pg_catalog.has_function_privilege('platform_rw', t.oid, 'EXECUTE')) THEN
      RAISE EXCEPTION 'ops.% solo debe ser ejecutable por worker', t.proname;
    END IF;
    IF t.proname IN ('security_event_guard', 'append_only_guard')
       AND (pg_catalog.has_function_privilege('app_rw', t.oid, 'EXECUTE') OR pg_catalog.has_function_privilege('worker', t.oid, 'EXECUTE')) THEN
      RAISE EXCEPTION 'las funciones de trigger no deben ser ejecutables por el runtime';
    END IF;
  END LOOP;

  -- Triggers ENABLE ALWAYS con la funcion declarada (6: 2 de security_event, 2 de purge_run, 2 de retention_policy).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_catalog.pg_proc p ON p.oid = g.tgfoid
       WHERE n.nspname = 'ops' AND g.tgenabled = 'A' AND NOT g.tgisinternal
         AND ((c.relname = 'security_event' AND g.tgname = 'security_event_no_update_delete' AND p.proname = 'security_event_guard' AND (g.tgtype & 1) = 1 AND (g.tgtype & 2) = 2 AND (g.tgtype & 8) = 8 AND (g.tgtype & 16) = 16)
           OR (c.relname = 'security_event' AND g.tgname = 'security_event_no_truncate' AND p.proname = 'security_event_immutable' AND (g.tgtype & 2) = 2 AND (g.tgtype & 32) = 32)
           OR (c.relname = 'purge_run' AND g.tgname = 'purge_run_no_update_delete' AND p.proname = 'security_event_guard' AND (g.tgtype & 1) = 1 AND (g.tgtype & 2) = 2 AND (g.tgtype & 8) = 8 AND (g.tgtype & 16) = 16)
           OR (c.relname = 'purge_run' AND g.tgname = 'purge_run_no_truncate' AND p.proname = 'append_only_guard' AND (g.tgtype & 2) = 2 AND (g.tgtype & 32) = 32)
           OR (c.relname = 'retention_policy' AND g.tgname = 'retention_policy_no_update_delete' AND p.proname = 'append_only_guard' AND (g.tgtype & 1) = 1 AND (g.tgtype & 2) = 2 AND (g.tgtype & 8) = 8 AND (g.tgtype & 16) = 16)
           OR (c.relname = 'retention_policy' AND g.tgname = 'retention_policy_no_truncate' AND p.proname = 'append_only_guard' AND (g.tgtype & 2) = 2 AND (g.tgtype & 32) = 32))) <> 6 THEN
    RAISE EXCEPTION 'los triggers append-only de security_event / purge_run / retention_policy deben ser ENABLE ALWAYS y ejecutar la funcion declarada';
  END IF;

  -- ops.security_event: sigue siendo del dueno, con FORCE RLS y exactamente 3 policies (INSERT de app_rw; SELECT y DELETE de lo vencido).
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'ops' AND c.relname = 'security_event' AND c.relrowsecurity AND c.relforcerowsecurity
                    AND pg_catalog.pg_get_userbyid(c.relowner) = 'security_event_owner') THEN
    RAISE EXCEPTION 'ops.security_event perdio ENABLE/FORCE ROW LEVEL SECURITY o su dueno';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'ops' AND c.relname = 'security_event') <> 3 THEN
    RAISE EXCEPTION 'ops.security_event debe tener exactamente 3 policies';
  END IF;
  IF pg_catalog.has_any_column_privilege('app_rw', 'ops.security_event', 'SELECT,UPDATE')
     OR pg_catalog.has_table_privilege('app_rw', 'ops.security_event', 'DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR pg_catalog.has_any_column_privilege('worker', 'ops.security_event', 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('worker', 'ops.security_event', 'DELETE,TRUNCATE') THEN
    RAISE EXCEPTION 'un rol de runtime gano privilegios sobre ops.security_event';
  END IF;

  -- app.otp_verification: security_event_owner solo lee tenant_id y expires_at y borra; no lee code_hash ni channel_ref.
  IF NOT pg_catalog.has_column_privilege('security_event_owner', 'app.otp_verification', 'expires_at', 'SELECT')
     OR pg_catalog.has_column_privilege('security_event_owner', 'app.otp_verification', 'channel_ref', 'SELECT')
     OR pg_catalog.has_column_privilege('security_event_owner', 'app.otp_verification', 'code_hash', 'SELECT')
     OR pg_catalog.has_table_privilege('security_event_owner', 'app.otp_verification', 'INSERT,UPDATE,TRUNCATE')
     OR NOT pg_catalog.has_table_privilege('security_event_owner', 'app.otp_verification', 'DELETE') THEN
    RAISE EXCEPTION 'privilegios de security_event_owner sobre app.otp_verification distintos de los declarados';
  END IF;
END
$assert$;
