-- scope: database
-- Gobierna: SEC-CNS-021 PR-5 (aceptada por Carlos 2026-10-08; §4.2, §4.3, D5, F-6), CA-146, P-34, INV-21-07/08/09/10/19, SEC-CNS-006 rev. 5,
-- ADR-010 rev. 3 §4.1, INV-CM-01, INV-CM-02 (tenant_id unica clave de aislamiento).
-- Regla de Carlos (2026-10-01): 0000-0032 no se editan; esta migracion es nueva.
--
-- LD-15 sigue ABIERTA (LEGAL DECISION): los 30 dias de ops.otp_budget son un PLACEHOLDER (Carlos, 2026-10-08), NO un valor aprobado definitivo.
--
-- 1. ops.retention_policy: fila 'otp_budget' (30 dias, placeholder). La tabla es solo-agregar por TRIGGER sobre UPDATE/DELETE/TRUNCATE; un INSERT
--    no lo dispara, de modo que NO hace falta deshabilitar ni rehabilitar el trigger (se verifica en el assert que los triggers siguen ENABLE ALWAYS).
--    La policy de INSERT de security_event_owner (0031) basta bajo FORCE RLS.
-- 2. ops.otp_budget: security_event_owner (su dueno) recibe policies de SELECT y DELETE acotadas a filas vencidas por expires_at
--    (expires_at < now() - retencion del store). FORCE RLS aplica al dueno, por eso sin policy no veria ni borraria nada. Los runtime roles no cambian.
-- 3. ops.purge_p34 pasa a admitir el store 'otp_budget' (CREATE OR REPLACE; mismo patron: SECURITY DEFINER, search_path fijo, TimeZone=UTC,
--    advisory lock 7240131, EXECUTE solo worker). ops.retention_status() y ops.purge_run_summary() son genericos por store y no cambian.
--
-- Residual R-21-2 (0031, aceptado solo IT0b sintetico) aplica tambien a otp_budget: quien pueda SET ROLE security_event_owner puede borrar sin purge_run.

-- A. Como consent_owner: CREATE temporal en ops para el dueno (se revoca en C).
GRANT USAGE, CREATE ON SCHEMA ops TO security_event_owner;

-- B. Como security_event_owner.
SET LOCAL ROLE security_event_owner;

-- PLACEHOLDER P-34 (Carlos, 2026-10-08, D5): 30 dias. LD-15 abierta.
INSERT INTO ops.retention_policy (store, retention, decision_ref) VALUES
  ('otp_budget', interval '30 days', 'P-34 placeholder (Carlos 2026-10-08, D5); LD-15 abierta: no es un valor aprobado definitivo');

-- Minimo privilegio (P2-1): el dueno deja de leer key_hmac y demas columnas. La purga solo necesita tenant_id y expires_at (SELECT por columnas,
-- suficiente para count(*), el WHERE y el RETURNING de ops.purge_p34) y DELETE. Sin INSERT/UPDATE/TRUNCATE/REFERENCES/TRIGGER para el dueno.
REVOKE ALL ON ops.otp_budget FROM security_event_owner;
GRANT SELECT (tenant_id, expires_at), DELETE ON ops.otp_budget TO security_event_owner;

CREATE POLICY otp_budget_purge_select ON ops.otp_budget FOR SELECT TO security_event_owner
  USING (expires_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'otp_budget'));
CREATE POLICY otp_budget_purge_delete ON ops.otp_budget FOR DELETE TO security_event_owner
  USING (expires_at < pg_catalog.now() - (SELECT p.retention FROM ops.retention_policy p WHERE p.store = 'otp_budget'));

-- Aserciones sobre la politica (consent_owner no puede leer retention_policy: se verifican aqui, como security_event_owner).
DO $policy$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ops.retention_policy p WHERE p.store = 'otp_budget' AND p.retention = interval '30 days' AND p.decision_ref LIKE '%LD-15 abierta%') THEN
    RAISE EXCEPTION 'falta la politica placeholder de otp_budget en ops.retention_policy (30 dias, LD-15 abierta)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM ops.retention_policy) <> 4 THEN
    RAISE EXCEPTION 'ops.retention_policy debe tener exactamente 4 stores (security_event, otp_budget, otp_verification, purge_run)';
  END IF;
END
$policy$;

-- Purga verificable (INV-21-07/08/09), ahora con el store otp_budget (SEC-CNS-021 PR-5). Mismo patron que 0031 (CREATE OR REPLACE conserva dueno y grants; se repiten).
CREATE OR REPLACE FUNCTION ops.purge_p34(p_store text, p_expected interval) RETURNS uuid
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  SET "TimeZone" = 'UTC'
  AS $$
DECLARE
  v_run       uuid        := pg_catalog.gen_random_uuid();
  v_started   timestamptz := pg_catalog.clock_timestamp();
  v_policy    interval;
  v_cutoff    timestamptz;
  v_rows      jsonb;
  v_remaining bigint;
BEGIN
  -- Serializa corridas concurrentes (cualquier store) con una clave constante: 7240131 (SEC-CNS-021 PR-3; distinta de 7240124/7240125 del runner/harness).
  PERFORM pg_catalog.pg_advisory_xact_lock(7240131);
  IF p_store IS NULL OR p_expected IS NULL THEN
    RAISE EXCEPTION 'purge_p34: store y retencion esperada son obligatorios' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_store NOT IN ('security_event', 'otp_budget', 'otp_verification', 'purge_run') THEN
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
  ELSIF p_store = 'otp_budget' THEN
    -- Vence por expires_at (fin de la ventana de fallos; 0032). Las claves son HMAC: no hay refs en claro. Solo filas vencidas segun la politica.
    WITH eligible AS (
      SELECT b.tenant_id, pg_catalog.count(*) AS n FROM ops.otp_budget b WHERE b.expires_at < v_cutoff GROUP BY b.tenant_id
    ), deleted AS (
      DELETE FROM ops.otp_budget b WHERE b.expires_at < v_cutoff RETURNING b.tenant_id, b.expires_at
    ), agg AS (
      SELECT d.tenant_id, pg_catalog.count(*) AS n, pg_catalog.min(d.expires_at) AS mn, pg_catalog.max(d.expires_at) AS mx FROM deleted d GROUP BY d.tenant_id
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('tenant_id', l.tenant_id, 'eligible', l.n, 'deleted', COALESCE(a.n, 0), 'min', a.mn, 'max', a.mx)), '[]'::jsonb)
      INTO v_rows FROM eligible l LEFT JOIN agg a ON a.tenant_id = l.tenant_id;
    SELECT pg_catalog.count(*) INTO v_remaining FROM ops.otp_budget b WHERE b.expires_at < v_cutoff;
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
  INSERT INTO ops.purge_run (purge_id, store, tenant_id, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff,
                             min_deleted_at, max_deleted_at, started_at)
  SELECT v_run, p_store, (r.j ->> 'tenant_id')::uuid, v_cutoff, v_policy, (r.j ->> 'eligible')::bigint, (r.j ->> 'deleted')::bigint, 0,
         (r.j ->> 'min')::timestamptz, (r.j ->> 'max')::timestamptz, v_started
    FROM pg_catalog.jsonb_array_elements(v_rows) AS r(j)
   WHERE (r.j ->> 'tenant_id') IS NOT NULL;  -- las filas resumen borradas (tenant_id NULL) solo cuentan en el resumen de la corrida
  INSERT INTO ops.purge_run (purge_id, store, tenant_id, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff,
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

-- C. De vuelta como consent_owner: retiro del CREATE temporal.
SET LOCAL ROLE consent_owner;
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
    IF t.proname = 'purge_p34' AND NOT (t.proconfig @> ARRAY['TimeZone=UTC']) THEN RAISE EXCEPTION 'ops.purge_p34() sin TimeZone=UTC'; END IF;
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
  -- Policies de security_event: nombre, comando y roles exactos (no solo el conteo). polcmd: a=INSERT, r=SELECT, w=UPDATE, d=DELETE.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'ops' AND c.relname = 'security_event')
     IS DISTINCT FROM 'security_event_app_rw_insert:a:app_rw security_event_owner_update:w:security_event_owner security_event_purge_delete:d:security_event_owner security_event_purge_select:r:security_event_owner' THEN
    RAISE EXCEPTION 'las policies de ops.security_event no son exactamente las declaradas (rol y comando)';
  END IF;
  -- Policies de app.otp_verification para security_event_owner: solo SELECT y DELETE.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text, ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'app' AND c.relname = 'otp_verification'
         AND (SELECT pg_catalog.bool_or(pg_catalog.pg_get_userbyid(x) = 'security_event_owner') FROM pg_catalog.unnest(p.polroles) AS x))
     IS DISTINCT FROM 'otp_verification_purge_delete:d otp_verification_purge_select:r' THEN
    RAISE EXCEPTION 'las policies de security_event_owner sobre app.otp_verification no son exactamente SELECT y DELETE';
  END IF;
  -- consent_owner es el unico miembro de security_event_owner.
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(m.member), ',' ORDER BY pg_catalog.pg_get_userbyid(m.member))
        FROM pg_catalog.pg_auth_members m WHERE m.roleid = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'security_event_owner'))
     IS DISTINCT FROM 'consent_owner' THEN
    RAISE EXCEPTION 'consent_owner debe ser el unico miembro de security_event_owner';
  END IF;
  -- security_event_owner no tiene SELECT en ninguna columna de app.otp_verification salvo tenant_id y expires_at.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
              WHERE a.attrelid = (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'otp_verification')
                AND a.attnum > 0 AND NOT a.attisdropped AND a.attname NOT IN ('tenant_id', 'expires_at')
                AND pg_catalog.has_column_privilege('security_event_owner', a.attrelid, a.attnum, 'SELECT,INSERT,UPDATE,REFERENCES')) THEN
    RAISE EXCEPTION 'security_event_owner tiene privilegios sobre columnas de app.otp_verification distintas de tenant_id y expires_at';
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

  -- SEC-CNS-021 PR-5: politica de otp_budget y purga habilitada para el store.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'ops' AND p.proname = 'purge_p34' AND pg_catalog.strpos(p.prosrc, 'otp_budget') > 0
                    AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'] AND p.proconfig @> ARRAY['TimeZone=UTC']
                    AND pg_catalog.pg_get_userbyid(p.proowner) = 'security_event_owner') THEN
    RAISE EXCEPTION 'ops.purge_p34 no admite otp_budget o perdio SECURITY DEFINER / search_path / TimeZone / dueno';
  END IF;
  -- ops.otp_budget: 5 policies exactas (3 de app_rw de 0032 + SELECT y DELETE de la purga para security_event_owner); la purga filtra por expires_at.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = 'ops.otp_budget'::pg_catalog.regclass)
     IS DISTINCT FROM 'otp_budget_purge_delete:d:security_event_owner otp_budget_purge_select:r:security_event_owner otp_budget_tenant_insert:a:app_rw otp_budget_tenant_select:r:app_rw otp_budget_tenant_update:w:app_rw' THEN
    RAISE EXCEPTION 'las policies de ops.otp_budget no son exactamente las declaradas (rol y comando)';
  END IF;
  -- Policies de purga: expresion con vencimiento por expires_at contra la politica del store otp_budget (pg_get_expr normaliza los literales).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = 'ops.otp_budget'::pg_catalog.regclass AND p.polname IN ('otp_budget_purge_select', 'otp_budget_purge_delete')
         AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%expires_at < %'
         AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%retention_policy%'
         AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%store = ''otp_budget''::text%') <> 2 THEN
    RAISE EXCEPTION 'las policies de purga de ops.otp_budget deben acotar por expires_at contra la politica del store otp_budget';
  END IF;
  -- EXECUTE de ops.purge_p34 (proacl exacta): solo el dueno y worker; nada para PUBLIC ni otros roles.
  IF (SELECT pg_catalog.string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END || ':' || a.privilege_type, ',' ORDER BY a.grantee::pg_catalog.regrole::pg_catalog.text)
        FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(p.proacl) AS a
       WHERE p.oid = 'ops.purge_p34(text, interval)'::pg_catalog.regprocedure)
     IS DISTINCT FROM 'security_event_owner:EXECUTE,worker:EXECUTE' THEN
    RAISE EXCEPTION 'la ACL de ops.purge_p34 debe ser exactamente EXECUTE para security_event_owner y worker';
  END IF;
  -- security_event_owner sobre ops.otp_budget: SELECT solo en tenant_id y expires_at (no key_hmac), DELETE; nada mas (P2-1).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
              WHERE a.attrelid = 'ops.otp_budget'::pg_catalog.regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.attname NOT IN ('tenant_id', 'expires_at')
                AND pg_catalog.has_column_privilege('security_event_owner', a.attrelid, a.attnum, 'SELECT,INSERT,UPDATE,REFERENCES'))
     OR pg_catalog.has_column_privilege('security_event_owner', 'ops.otp_budget', 'key_hmac', 'SELECT')
     OR NOT pg_catalog.has_column_privilege('security_event_owner', 'ops.otp_budget', 'expires_at', 'SELECT')
     OR NOT pg_catalog.has_column_privilege('security_event_owner', 'ops.otp_budget', 'tenant_id', 'SELECT')
     OR pg_catalog.has_table_privilege('security_event_owner', 'ops.otp_budget', 'INSERT,UPDATE,TRUNCATE,REFERENCES,TRIGGER')
     OR NOT pg_catalog.has_table_privilege('security_event_owner', 'ops.otp_budget', 'DELETE') THEN
    RAISE EXCEPTION 'privilegios de security_event_owner sobre ops.otp_budget distintos de SELECT(tenant_id, expires_at) y DELETE';
  END IF;
  -- Sin cambios para el runtime en ops.otp_budget: app_rw sin DELETE; worker y platform_rw sin acceso; consent_owner sin privilegios; RLS forzada.
  IF pg_catalog.has_table_privilege('app_rw', 'ops.otp_budget', 'DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR pg_catalog.has_any_column_privilege('worker', 'ops.otp_budget', 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('worker', 'ops.otp_budget', 'DELETE,TRUNCATE')
     OR pg_catalog.has_any_column_privilege('platform_rw', 'ops.otp_budget', 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('platform_rw', 'ops.otp_budget', 'DELETE,TRUNCATE')
     OR pg_catalog.has_table_privilege('consent_owner', 'ops.otp_budget', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR pg_catalog.has_table_privilege('public', 'ops.otp_budget', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'los privilegios de runtime sobre ops.otp_budget cambiaron';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = 'ops.otp_budget'::pg_catalog.regclass AND c.relrowsecurity AND c.relforcerowsecurity
                    AND pg_catalog.pg_get_userbyid(c.relowner) = 'security_event_owner') THEN
    RAISE EXCEPTION 'ops.otp_budget perdio ENABLE/FORCE ROW LEVEL SECURITY o su dueno';
  END IF;
END
$assert$;
