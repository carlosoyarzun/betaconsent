-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a puntos 4 y 5 (G-3, lectura (A) confirmada el 2026-10-15: agotamiento de reintentos = alerta a operacion en una tx SEPARADA y
-- posterior al rollback, evento sin PII en ops.security_event con el tenant del caso y un codigo de motivo; proceso de respaldo del `worker` para Revocation CONFIRMED sin APPLIED, que "emite alerta"),
-- §10 fila 6d, §15.3 punto 4; F-PR6-25 (lectura (A); LEGAL DECISION de lo que se le dice al titular y del registro durable en R1r-R3r: NO se resuelve aqui); INV-21-04 (solo refs opacas y enums; cero PII).
-- 0045 y 0066 son anteriores: lo nuevo va en migracion nueva.
--
-- 1) ops.security_event (dueno security_event_owner; DDL con SET LOCAL ROLE security_event_owner, mismo patron que 0045): tipo nuevo REVOCATION_APPLY_ALERT con dos columnas nuevas, alert_reason (enum cerrado:
--      R4_RETRIES_EXHAUSTED = el llamador agoto los reintentos de R3/R3r/RH3 + R4 y la tx se revirtio; R4_BACKUP_APPLIED = el worker aplico R4 sobre una Revocation CONFIRMED sin APPLIED;
--      R4_BACKUP_FAILED = el worker no pudo aplicarla) y revocation_ref (UUIDv4 opaco: en R1r-R3r tras el rollback es la ref generada para el intento, que no queda persistida). Sin PII, sin payload, sin IP.
--      Los demas tipos las llevan NULL (CHECK security_event_apply_alert_cols_only_for_type). CHECK type_enum (14 tipos) y otp_shape (rama nueva) actualizados.
-- 2) Policy security_event_alert_insert (FOR INSERT TO security_event_owner, tenant = app.current_tenant_id() y SOLO ese tipo). app_rw y platform_rw NO reciben INSERT directo del tipo nuevo: lo escribe la funcion.
-- 3) ops.record_revocation_apply_alert(revocation_ref text, reason text) RETURNS void (dueno security_event_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico). El tenant sale SIEMPRE de
--      app.current_tenant_id() (nunca de un parametro); sin tenant, ref que no es UUIDv4 o motivo fuera del enum = error. EXECUTE solo app_rw (web: agotamiento de R3/R3r) y worker (respaldo). El proceso platform (RH3) la
--      alcanza solo por platform.alert_case_apply_exhausted (0069), que valida la sesion CASE y deriva el tenant de ella.
-- 4) Descubrimiento de Revocation CONFIRMED sin APPLIED para el proceso de respaldo del worker SIN ampliar su lectura de app.revocation (P2-1 / F-6D3-SEC-01; reemplaza la policy cross-tenant TO worker de la
--      primera version de esta migracion, que dejaba al worker leer TODAS las columnas de las filas CONFIRMED de todos los tenants; F-PR6-47 NO es esto: F-PR6-47 son los defectos de QA de 6d parte 2).
--      case_state.list_confirmed_unapplied(limit, skip_refs) RETURNS TABLE(o_tenant_id, o_revocation_ref) (dueno transition_owner, SECURITY DEFINER, search_path fijo, sin SQL dinamico, EXECUTE solo worker): devuelve
--      SOLO (tenant_id, revocation_ref) de filas status = 'CONFIRMED', sin las refs de `skip_refs` (backoff por fila del worker), maximo 1..100. Lo habilita UNA policy de SELECT TO transition_owner
--      (revocation_transition_recovery_select) que solo se cumple si la funcion fijo case_state.effect = 'list_confirmed_unapplied' en su propia tx; las demas funciones de transition_owner siguen acotadas a su tenant.
--      El worker mantiene su policy tenant-acotada de 0042 y NO gana ninguna policy cross-tenant.
-- Idempotente: ADD COLUMN IF NOT EXISTS, DROP CONSTRAINT IF EXISTS + ADD, DROP POLICY/FUNCTION IF EXISTS + CREATE, CREATE OR REPLACE y GRANT/REVOKE repetibles.

-- A. Como consent_owner: USAGE sobre app y CREATE en ops para el dueno (temporales si no los tenia). Se recuerdan en GUC locales a la tx.
SELECT pg_catalog.set_config('m0067.had_app_usage', pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE')::pg_catalog.text, true);
SELECT pg_catalog.set_config('m0067.had_ops_create', pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE')::pg_catalog.text, true);
GRANT USAGE ON SCHEMA app TO security_event_owner;
GRANT CREATE ON SCHEMA ops TO security_event_owner;
-- La funcion y la policy nuevas evaluan app.current_tenant_id() con los privilegios del dueno (FORCE RLS aplica al dueno): EXECUTE permanente y minimo (el dueno no es asumible por ningun proceso de runtime).
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO security_event_owner;
GRANT EXECUTE ON FUNCTION ops.catalog_environment() TO security_event_owner; -- DEFAULT de ops.security_event.environment

-- B. Como security_event_owner.
SET LOCAL ROLE security_event_owner;

ALTER TABLE ops.security_event
  ADD COLUMN IF NOT EXISTS alert_reason text,
  ADD COLUMN IF NOT EXISTS revocation_ref uuid;

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_alert_reason_enum;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_alert_reason_enum CHECK (alert_reason IN ('R4_RETRIES_EXHAUSTED', 'R4_BACKUP_APPLIED', 'R4_BACKUP_FAILED'));
ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_revocation_ref_uuidv4;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_revocation_ref_uuidv4
  CHECK (revocation_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_apply_alert_cols_only_for_type;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_apply_alert_cols_only_for_type
  CHECK (event_type = 'REVOCATION_APPLY_ALERT' OR (alert_reason IS NULL AND revocation_ref IS NULL));

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_type_enum;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_type_enum CHECK (event_type IN (
  'STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION',
  'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
  'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED', 'GUEST_MESSAGE_DELIVERY_FAILED', 'REVOCATION_APPLY_ALERT'));

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_otp_shape;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_otp_shape CHECK (
  CASE
    WHEN event_type IN ('STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION') THEN
      verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
      AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
    ELSE
      actor_ref IS NULL AND actor_role IS NULL AND session_kind IS NULL AND session_ref IS NULL AND case_ref IS NULL
      AND CASE event_type
        WHEN 'OTP_ISSUED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NOT NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_FAILED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_LOCKED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_EXPIRED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_BUDGET_EXHAUSTED' THEN
          verification_ref IS NOT NULL AND scope_class IS NOT NULL AND key_kind IS NOT NULL AND window_kind IS NOT NULL
          AND otp_scope IS NULL AND channel_ref IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
          AND (key_kind <> 'INVITATION' OR scope_class = 'DECISION')
          AND (key_kind <> 'CHAIN' OR scope_class = 'RIGHTS')
          AND (window_kind <> 'DAYS_30' OR (scope_class = 'RIGHTS' AND key_kind = 'CHAIN'))
          AND (window_kind <> 'LIFETIME' OR (scope_class = 'DECISION' AND key_kind = 'INVITATION'))
        WHEN 'RECOVERY_TOKEN_ISSUED' THEN
          recovery_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('REQUESTER_ASKED', 'LIMIT_REACHED', 'CASE_CONTACT', 'SCHOOL_REPORTED')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL
        WHEN 'MANAGEMENT_TOKEN_ROTATED' THEN
          chain_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('RECEIPT_REISSUED', 'FAILURE_CAP')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND recovery_ref IS NULL
        WHEN 'GUEST_MESSAGE_DELIVERY_FAILED' THEN
          delivery_kind IS NOT NULL AND receipt_ref IS NOT NULL
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'REVOCATION_APPLY_ALERT' THEN
          alert_reason IS NOT NULL AND revocation_ref IS NOT NULL AND delivery_kind IS NULL AND receipt_ref IS NULL
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        ELSE false
      END
  END
);

DROP POLICY IF EXISTS security_event_alert_insert ON ops.security_event;
CREATE POLICY security_event_alert_insert ON ops.security_event FOR INSERT TO security_event_owner
  WITH CHECK (tenant_id = app.current_tenant_id() AND event_type = 'REVOCATION_APPLY_ALERT');

ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION ops.record_revocation_apply_alert(p_revocation_ref text, p_reason text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = '42501'; END IF;
  IF p_revocation_ref IS NULL OR p_revocation_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'revocation_ref invalida' USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR p_reason NOT IN ('R4_RETRIES_EXHAUSTED', 'R4_BACKUP_APPLIED', 'R4_BACKUP_FAILED') THEN
    RAISE EXCEPTION 'motivo de alerta invalido' USING ERRCODE = '22023';
  END IF;
  INSERT INTO ops.security_event (tenant_id, event_type, alert_reason, revocation_ref)
  VALUES (v_tenant, 'REVOCATION_APPLY_ALERT', p_reason, p_revocation_ref::pg_catalog.uuid);
END
$fn$;

REVOKE ALL ON FUNCTION ops.record_revocation_apply_alert(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.record_revocation_apply_alert(text, text) TO app_rw, worker;

-- C. De vuelta a consent_owner: policy de transition_owner sobre app.revocation (dueno: consent_owner) y retiro de los temporales.
SET LOCAL ROLE consent_owner;
DROP POLICY IF EXISTS revocation_worker_recovery_select ON app.revocation; -- version anterior de esta migracion (nunca mergeada): ya no existe
DROP POLICY IF EXISTS revocation_transition_recovery_select ON app.revocation;
CREATE POLICY revocation_transition_recovery_select ON app.revocation FOR SELECT TO transition_owner
  USING (status = 'CONFIRMED' AND pg_catalog.current_setting('case_state.effect', true) = 'list_confirmed_unapplied');

-- D. La funcion (transition_owner necesita CREATE temporal en case_state, como en 0070).
SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner;
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
DROP FUNCTION IF EXISTS case_state.list_confirmed_unapplied(integer, text[]);
CREATE FUNCTION case_state.list_confirmed_unapplied(p_limit integer, p_skip_refs text[]) RETURNS TABLE (o_tenant_id uuid, o_revocation_ref text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF session_user <> 'worker' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN RAISE EXCEPTION 'limite invalido' USING ERRCODE = '22023'; END IF;
  IF pg_catalog.cardinality(COALESCE(p_skip_refs, ARRAY[]::text[])) > 1000 THEN RAISE EXCEPTION 'lista de omision demasiado grande' USING ERRCODE = '22023'; END IF;
  PERFORM pg_catalog.set_config('case_state.effect', 'list_confirmed_unapplied', true);
  RETURN QUERY
    SELECT r.tenant_id, r.revocation_ref FROM app.revocation r
     WHERE r.status = 'CONFIRMED' AND r.revocation_ref <> ALL (COALESCE(p_skip_refs, ARRAY[]::text[]))
     ORDER BY r.created_at, r.revocation_ref LIMIT p_limit;
END
$fn$;
REVOKE ALL ON FUNCTION case_state.list_confirmed_unapplied(integer, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION case_state.list_confirmed_unapplied(integer, text[]) TO worker;
SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;
DO $revoke$
BEGIN
  IF pg_catalog.current_setting('m0067.had_app_usage') <> 'true' THEN REVOKE USAGE ON SCHEMA app FROM security_event_owner; END IF;
  IF pg_catalog.current_setting('m0067.had_ops_create') <> 'true' THEN REVOKE CREATE ON SCHEMA ops FROM security_event_owner; END IF;
END
$revoke$;

DO $assert67$
DECLARE
  tbl oid := 'ops.security_event'::pg_catalog.regclass;
  rv oid;
  f record;
  v_def text;
  r text;
BEGIN
  IF pg_catalog.pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = tbl)) <> 'security_event_owner' THEN RAISE EXCEPTION '0067: ops.security_event debe seguir siendo de security_event_owner'; END IF;
  IF pg_catalog.current_setting('m0067.had_ops_create') <> 'true' AND pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE') THEN RAISE EXCEPTION '0067: el CREATE temporal sobre ops no quedo revocado'; END IF;
  IF pg_catalog.current_setting('m0067.had_app_usage') <> 'true' AND pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE') THEN RAISE EXCEPTION '0067: el USAGE temporal sobre app no quedo revocado'; END IF;
  -- Tipo: 14 tipos con el nuevo; forma con la rama nueva; columnas nuevas solo en el tipo nuevo.
  SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO v_def FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.conname = 'security_event_type_enum' AND c.convalidated;
  IF v_def IS NULL OR v_def NOT LIKE '%REVOCATION_APPLY_ALERT%' OR (pg_catalog.length(v_def) - pg_catalog.length(pg_catalog.replace(v_def, '''::text', ''))) / 7 <> 14 THEN
    RAISE EXCEPTION '0067: security_event_type_enum no enumera exactamente los 14 tipos esperados';
  END IF;
  SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO v_def FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.conname = 'security_event_otp_shape' AND c.convalidated;
  IF v_def IS NULL OR v_def NOT LIKE '%REVOCATION_APPLY_ALERT%' OR v_def NOT LIKE '%GUEST_MESSAGE_DELIVERY_FAILED%' OR v_def NOT LIKE '%LIFETIME%' THEN
    RAISE EXCEPTION '0067: security_event_otp_shape no tiene la rama del tipo nuevo (o perdio una anterior)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.convalidated
        AND c.conname IN ('security_event_alert_reason_enum', 'security_event_revocation_ref_uuidv4', 'security_event_apply_alert_cols_only_for_type')) <> 3 THEN
    RAISE EXCEPTION '0067: faltan CHECK de las columnas nuevas o no estan validados';
  END IF;
  -- Policies: las 4 de antes mas la nueva del dueno; app_rw NO gana el tipo nuevo.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl)
     IS DISTINCT FROM 'security_event_alert_insert:a:security_event_owner security_event_app_rw_insert:a:app_rw security_event_owner_update:w:security_event_owner security_event_purge_delete:d:security_event_owner security_event_purge_select:r:security_event_owner' THEN
    RAISE EXCEPTION '0067: las policies de ops.security_event no son exactamente las declaradas';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl AND p.polname = 'security_event_app_rw_insert' AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%REVOCATION_APPLY_ALERT%') THEN
    RAISE EXCEPTION '0067: app_rw no puede insertar REVOCATION_APPLY_ALERT directamente (solo por la funcion)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl AND p.polname = 'security_event_alert_insert'
                   AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%tenant_id = app.current_tenant_id()%'
                   AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%REVOCATION_APPLY_ALERT%') THEN
    RAISE EXCEPTION '0067: security_event_alert_insert perdio el aislamiento por tenant o el tipo';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker'] LOOP
    IF pg_catalog.has_column_privilege(r, tbl, 'alert_reason', 'INSERT') OR pg_catalog.has_column_privilege(r, tbl, 'revocation_ref', 'INSERT')
       OR pg_catalog.has_column_privilege(r, tbl, 'alert_reason', 'SELECT') OR pg_catalog.has_column_privilege(r, tbl, 'revocation_ref', 'SELECT') THEN
      RAISE EXCEPTION '0067: % tiene privilegios directos sobre las columnas de la alerta', r;
    END IF;
  END LOOP;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = tbl) THEN RAISE EXCEPTION '0067: ops.security_event perdio ENABLE/FORCE ROW LEVEL SECURITY'; END IF;

  -- Funcion de la alerta: dueno, SECURITY DEFINER, search_path, sin SQL dinamico, EXECUTE exacto (app_rw y worker), tenant del GUC.
  SELECT p.oid, p.prosrc, p.prosecdef, p.proconfig, p.proacl, p.proowner, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ops' AND p.proname = 'record_revocation_apply_alert';
  IF f.oid IS NULL OR f.owner <> 'security_event_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] OR f.prosrc ~* '\mexecute\M'
     OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION '0067: ops.record_revocation_apply_alert no es la declarada (dueno, SECURITY DEFINER, search_path, sin SQL dinamico, sin EXECUTE PUBLIC)';
  END IF;
  IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                 FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner), '') IS DISTINCT FROM 'app_rw,worker' THEN
    RAISE EXCEPTION '0067: la ACL de ops.record_revocation_apply_alert no es exactamente app_rw,worker';
  END IF;
  IF pg_catalog.has_function_privilege('platform_rw', f.oid, 'EXECUTE') OR pg_catalog.has_function_privilege('integrity_verifier', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION '0067: platform_rw/integrity_verifier no pueden ejecutar ops.record_revocation_apply_alert directamente';
  END IF;
  IF f.prosrc !~ 'app\.current_tenant_id\(\)' OR pg_catalog.pg_get_function_arguments(f.oid) ~* 'tenant' THEN
    RAISE EXCEPTION '0067: ops.record_revocation_apply_alert debe tomar el tenant de app.current_tenant_id() y no recibirlo como parametro';
  END IF;

  -- worker: SIN policy cross-tenant propia, sin escritura; el descubrimiento es la funcion de transition_owner (solo CONFIRMED, solo 2 columnas).
  SELECT c.oid INTO rv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'revocation';
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND (p.polname = 'revocation_worker_recovery_select' OR pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true'
               AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'worker') = ANY (p.polroles))) THEN
    RAISE EXCEPTION '0067: el worker no puede tener una policy cross-tenant sobre app.revocation (P2-1)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polname = 'revocation_transition_recovery_select' AND p.polcmd = 'r'
        AND pg_catalog.array_length(p.polroles, 1) = 1 AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'transition_owner'
        AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%CONFIRMED%' AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%list_confirmed_unapplied%') <> 1 THEN
    RAISE EXCEPTION '0067: falta la policy revocation_transition_recovery_select (SELECT, TO transition_owner, CONFIRMED y solo bajo list_confirmed_unapplied)';
  END IF;
  IF pg_catalog.has_any_column_privilege('worker', rv, 'INSERT,UPDATE,REFERENCES') OR pg_catalog.has_table_privilege('worker', rv, 'DELETE,TRUNCATE,TRIGGER') THEN
    RAISE EXCEPTION '0067: worker tiene privilegios de escritura sobre app.revocation';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'integrity_verifier', 'worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polname = 'revocation_transition_recovery_select' AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = r) = ANY (p.polroles)) THEN
      RAISE EXCEPTION '0067: la policy de recuperacion alcanza a %', r;
    END IF;
  END LOOP;
  SELECT p.oid, p.prosrc, p.prosecdef, p.proconfig, p.proacl, p.proowner, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'list_confirmed_unapplied';
  IF f.oid IS NULL OR f.owner <> 'transition_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] OR f.prosrc ~* '\mexecute\M'
     OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION '0067: case_state.list_confirmed_unapplied no es la declarada (dueno, SECURITY DEFINER, search_path, sin SQL dinamico, sin EXECUTE PUBLIC)';
  END IF;
  IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                 FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner), '') IS DISTINCT FROM 'worker' THEN
    RAISE EXCEPTION '0067: la ACL de case_state.list_confirmed_unapplied no es exactamente worker';
  END IF;
  IF pg_catalog.has_schema_privilege('transition_owner', 'case_state', 'CREATE') THEN RAISE EXCEPTION '0067: el CREATE temporal de transition_owner sobre case_state no quedo revocado'; END IF;
END
$assert67$;
