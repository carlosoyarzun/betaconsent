-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7 (open_platform_session / open_case_session), §5.3 (invariantes), §6 (revalidacion en cada accion), §10 fila PR-6c,
-- G-7 (aserciones de un solo uso, ligadas a operador y operacion), G-8 (state verificado en la base); seguridad rev. c puntos 5 y 6; revision de seguridad de 6b: F-PR6-32 (consume_login_assertion se
-- llama en la MISMA transaccion que crea la sesion), F-PR6-37 (rol ACTIVE re-chequeado al abrir), F-PR6-34 (open_case_session exige RIGHTS_OPERATOR + grant). Depende de 0050-0052.
--
-- Que agrega (SECURITY DEFINER, dueno grant_owner, search_path = pg_catalog, pg_temp, sin SQL dinamico, EXECUTE revocado a PUBLIC; ante un DENY NO lanzan excepcion: devuelven NULL / 0 filas / false,
-- porque la asercion consumida y la evidencia de rechazo DEBEN confirmarse; un error de base si propaga y revierte todo, incluido el evento: sin evento no hay sesion):
--   platform.open_platform_session (platform_rw)   consume la asercion LOGIN_PLATFORM (sha256(state) = state_hash, un solo uso, <= P-52) EN LA MISMA tx; el principal sale de la asercion, nunca de la request;
--                                                  exige rol de plataforma ACTIVE (F-PR6-37); el sid (256 bits aprox.) lo genera la BASE y solo se persiste su sha256; escribe PLATFORM_LOGIN. Rotacion: si la request trae
--                                                  la sesion previa, se revoca (con sus sesiones CASE) en la misma tx.
--   platform.open_case_session (platform_rw)       exige sesion PLATFORM vigente DEL MISMO principal que la asercion LOGIN_CASE (sha256(case_ref) = target_ref_hash; consumida en la misma tx), rol
--                                                  RIGHTS_OPERATOR ACTIVE y un rights_case_grant vigente del operador para ese caso; la sesion CASE vence a lo sumo con el grant y con su sesion PLATFORM; escribe CASE_LOGIN.
--   platform.validate_session (platform_rw)        valida y avanza la actividad (granularidad 60 s); REVALIDA rol ACTIVE (y, en CASE, grant y sesion PLATFORM) en cada llamada. 0 filas ante cualquier fallo.
--   platform.revoke_session (platform_rw)          logout: revoca en servidor (idempotente); revocar la PLATFORM revoca sus sesiones CASE; escribe PLATFORM_LOGOUT / CASE_LOGOUT.
--   platform.revoke_session_internal (INTERNA, sin EXECUTE de runtime)   logica comun de revocacion y rotacion.
-- Una asercion consumida y luego rechazada (rol inactivo, sin sesion PLATFORM, sin grant) queda quemada: no se puede reintentar con la misma. Un fallo ANTES de consumir (state ajeno, vencido, ya usado) no
-- escribe evento: no hay principal confiable y un INSERT por request seria un vector de DoS de escritura (R-SE-07). Los eventos de rechazo posteriores llevan el principal y NUNCA IP ni sub_hmac.
-- Los valores de vida (absoluta/inactividad) los pasa el proceso platform por configuracion (sin default fuera de LOCAL); la base solo acota rangos (techos de 4 h y 15 min = P-36 PLATFORM y P-25 CASE, SEC-CNS-006 rev. 5 §1, ACCEPTED 2026-09-26).

-- 0. CREATE temporal para grant_owner (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. revoke_session_internal ------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.revoke_session_internal(p_sid_hash text, p_kind text, p_cause text)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_row record;
BEGIN
  IF p_sid_hash IS NULL OR p_sid_hash !~ '^[0-9a-f]{64}$' OR p_kind IS NULL OR p_kind NOT IN ('PLATFORM', 'CASE') OR p_cause IS NULL OR p_cause NOT IN ('USER_LOGOUT', 'ROTATION') THEN
    RETURN false;
  END IF;
  UPDATE platform.platform_session s SET revoked_at = pg_catalog.now(), revoke_cause = p_cause
   WHERE s.sid_hash = p_sid_hash AND s.session_kind = p_kind AND s.revoked_at IS NULL
  RETURNING s.session_ref, s.principal_ref, s.case_ref INTO v_row;
  IF NOT FOUND THEN RETURN false; END IF;
  INSERT INTO platform.session_event (event_type, reason_code, principal_ref, session_kind, session_ref, case_ref)
  VALUES (CASE WHEN p_cause = 'ROTATION' THEN 'SESSION_ROTATED' WHEN p_kind = 'PLATFORM' THEN 'PLATFORM_LOGOUT' ELSE 'CASE_LOGOUT' END,
          p_cause, v_row.principal_ref, p_kind, v_row.session_ref, v_row.case_ref);
  IF p_kind = 'PLATFORM' THEN
    -- Las sesiones CASE cuelgan de la PLATFORM: caen con ella (cada una con su evento).
    WITH c AS (
      UPDATE platform.platform_session x SET revoked_at = pg_catalog.now(), revoke_cause = 'PARENT_REVOKED'
       WHERE x.parent_session_ref = v_row.session_ref AND x.revoked_at IS NULL
      RETURNING x.session_ref, x.principal_ref, x.case_ref)
    INSERT INTO platform.session_event (event_type, reason_code, principal_ref, session_kind, session_ref, case_ref)
    SELECT 'CASE_LOGOUT', 'PARENT_REVOKED', c.principal_ref, 'CASE', c.session_ref, c.case_ref FROM c;
  END IF;
  RETURN true;
END
$$;

-- 2. open_platform_session ---------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.open_platform_session(p_exchange_ref uuid, p_state text, p_absolute_seconds integer, p_idle_seconds integer, p_previous_sid text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_hex       constant text := '^[0-9a-f]{64}$';
  v_principal text;
  v_assertion uuid;
  v_sid       text;
  v_session   uuid;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  IF p_exchange_ref IS NULL OR p_state IS NULL OR p_state !~ '^[A-Za-z0-9_-]{22,128}$'
     OR p_absolute_seconds IS NULL OR p_absolute_seconds < 60 OR p_absolute_seconds > 14400
     OR p_idle_seconds IS NULL OR p_idle_seconds < 60 OR p_idle_seconds > 900 OR p_idle_seconds > p_absolute_seconds
     OR (p_previous_sid IS NOT NULL AND p_previous_sid !~ c_hex) THEN
    RETURN NULL;
  END IF;
  -- F-PR6-32 / P1-1: la asercion LOGIN_PLATFORM se verifica (state, kind, vigencia <= P-52) y se consume atomicamente EN ESTA transaccion. El principal sale de la asercion.
  v_principal := platform.consume_login_assertion(p_exchange_ref, p_state, 'LOGIN_PLATFORM', NULL);
  IF v_principal IS NULL THEN RETURN NULL; END IF;
  -- F-PR6-37: el rol se re-chequea AQUI, no se confia en lo registrado al atestar.
  IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.status = 'ACTIVE') THEN
    INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref) VALUES ('LOGIN_REJECTED', 'ROLE_INACTIVE', 'LOGIN_PLATFORM', v_principal);
    RETURN NULL;
  END IF;
  -- Rotacion: la sesion previa de este navegador se revoca (con sus sesiones CASE).
  IF p_previous_sid IS NOT NULL THEN
    PERFORM platform.revoke_session_internal(pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_previous_sid, 'UTF8')), 'hex'), 'PLATFORM', 'ROTATION');
  END IF;
  SELECT l.assertion_ref INTO v_assertion FROM platform.login_assertion l WHERE l.exchange_ref = p_exchange_ref;
  -- sid: dos uuid v4 (2 x 122 bits aleatorios) en hex; solo su sha256 se persiste.
  v_sid := pg_catalog.replace(pg_catalog.gen_random_uuid()::pg_catalog.text || pg_catalog.gen_random_uuid()::pg_catalog.text, '-', '');
  INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, expires_at, idle_seconds)
  VALUES (pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_sid, 'UTF8')), 'hex'), 'PLATFORM', v_principal, v_assertion,
          pg_catalog.now() + pg_catalog.make_interval(secs => p_absolute_seconds), p_idle_seconds)
  RETURNING session_ref INTO v_session;
  INSERT INTO platform.session_event (event_type, principal_ref, session_kind, session_ref) VALUES ('PLATFORM_LOGIN', v_principal, 'PLATFORM', v_session);
  RETURN v_sid;
END
$$;

-- 3. open_case_session -------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.open_case_session(
    p_exchange_ref uuid, p_state text, p_case_ref text, p_platform_sid text, p_absolute_seconds integer, p_idle_seconds integer, p_previous_case_sid text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_hex       constant text := '^[0-9a-f]{64}$';
  v_principal text;
  v_assertion uuid;
  v_parent    platform.platform_session%ROWTYPE;
  v_grant     platform.rights_case_grant%ROWTYPE;
  v_reason    text := NULL;
  v_sid       text;
  v_session   uuid;
  v_expires   timestamptz;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  IF p_exchange_ref IS NULL OR p_state IS NULL OR p_state !~ '^[A-Za-z0-9_-]{22,128}$'
     OR p_case_ref IS NULL OR p_case_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_platform_sid IS NULL OR p_platform_sid !~ c_hex
     OR p_absolute_seconds IS NULL OR p_absolute_seconds < 60 OR p_absolute_seconds > 14400
     OR p_idle_seconds IS NULL OR p_idle_seconds < 60 OR p_idle_seconds > 900 OR p_idle_seconds > p_absolute_seconds
     OR (p_previous_case_sid IS NOT NULL AND p_previous_case_sid !~ c_hex) THEN
    RETURN NULL;
  END IF;
  -- La asercion LOGIN_CASE solo sirve para ESTE caso (G-7, F-PR6-27): target_ref_hash = sha256(case_ref). Se consume EN ESTA transaccion.
  v_principal := platform.consume_login_assertion(p_exchange_ref, p_state, 'LOGIN_CASE', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_case_ref, 'UTF8')), 'hex'));
  IF v_principal IS NULL THEN RETURN NULL; END IF;
  <<decide>>
  BEGIN
    -- Sesion PLATFORM vigente (no revocada, dentro de su vida absoluta y de inactividad) del MISMO principal que la asercion.
    SELECT * INTO v_parent FROM platform.platform_session s
     WHERE s.sid_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_platform_sid, 'UTF8')), 'hex') AND s.session_kind = 'PLATFORM'
       AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.now() AND s.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => s.idle_seconds)
     FOR SHARE;
    -- FOR SHARE: un logout concurrente de la sesion PLATFORM espera a que esta tx termine (y su cascada ve la sesion CASE nueva) o, si ya termino, aqui no se encuentra la sesion: nunca queda una CASE sin revocar.
    IF NOT FOUND THEN v_reason := 'NO_SESSION'; EXIT decide; END IF;
    IF v_parent.principal_ref <> v_principal THEN v_reason := 'PRINCIPAL_MISMATCH'; EXIT decide; END IF;
    -- F-PR6-37 / F-PR6-34: rol RIGHTS_OPERATOR ACTIVE re-chequeado aqui.
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.platform_role = 'RIGHTS_OPERATOR' AND a.status = 'ACTIVE') THEN
      v_reason := 'ROLE_INACTIVE'; EXIT decide;
    END IF;
    -- Grant atestado y vigente del operador para ESTE caso (el mas largo si hay varios).
    SELECT * INTO v_grant FROM platform.rights_case_grant g
     WHERE g.operator_principal_ref = v_principal AND g.case_ref = p_case_ref AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
     ORDER BY g.expires_at DESC LIMIT 1;
    IF NOT FOUND THEN v_reason := 'NO_GRANT'; EXIT decide; END IF;
  END;
  IF v_reason IS NOT NULL THEN
    INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref, case_ref) VALUES ('LOGIN_REJECTED', v_reason, 'LOGIN_CASE', v_principal, p_case_ref);
    RETURN NULL;
  END IF;
  IF p_previous_case_sid IS NOT NULL THEN
    PERFORM platform.revoke_session_internal(pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_previous_case_sid, 'UTF8')), 'hex'), 'CASE', 'ROTATION');
  END IF;
  SELECT l.assertion_ref INTO v_assertion FROM platform.login_assertion l WHERE l.exchange_ref = p_exchange_ref;
  -- La sesion CASE no vive mas que el grant ni que su sesion PLATFORM.
  v_expires := LEAST(pg_catalog.now() + pg_catalog.make_interval(secs => p_absolute_seconds), v_parent.expires_at, v_grant.expires_at);
  v_sid := pg_catalog.replace(pg_catalog.gen_random_uuid()::pg_catalog.text || pg_catalog.gen_random_uuid()::pg_catalog.text, '-', '');
  INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, parent_session_ref, tenant_id, case_ref, grant_ref, expires_at, idle_seconds)
  VALUES (pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_sid, 'UTF8')), 'hex'), 'CASE', v_principal, v_assertion, v_parent.session_ref, v_grant.tenant_id, p_case_ref, v_grant.grant_ref,
          v_expires, p_idle_seconds)
  RETURNING session_ref INTO v_session;
  INSERT INTO platform.session_event (event_type, principal_ref, session_kind, session_ref, case_ref) VALUES ('CASE_LOGIN', v_principal, 'CASE', v_session, p_case_ref);
  RETURN v_sid;
END
$$;

-- 4. validate_session --------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.validate_session(p_sid text, p_kind text)
  RETURNS TABLE (o_session_ref uuid, o_session_kind text, o_principal_ref text, o_case_ref text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_s platform.platform_session%ROWTYPE;
BEGIN
  IF session_user <> 'platform_rw' OR p_sid IS NULL OR p_sid !~ '^[0-9a-f]{64}$' OR p_kind IS NULL OR p_kind NOT IN ('PLATFORM', 'CASE') THEN RETURN; END IF;
  SELECT * INTO v_s FROM platform.platform_session s
   WHERE s.sid_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_sid, 'UTF8')), 'hex') AND s.session_kind = p_kind
     AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.now() AND s.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => s.idle_seconds);
  IF NOT FOUND THEN RETURN; END IF;
  -- Revalidacion en cada llamada (ADR-010 §6): el rol sigue ACTIVE y, en CASE, el grant sigue vigente y la sesion PLATFORM de la que cuelga sigue viva.
  IF p_kind = 'PLATFORM' THEN
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_s.principal_ref AND a.status = 'ACTIVE') THEN RETURN; END IF;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_s.principal_ref AND a.platform_role = 'RIGHTS_OPERATOR' AND a.status = 'ACTIVE')
       OR NOT EXISTS (SELECT 1 FROM platform.rights_case_grant g WHERE g.grant_ref = v_s.grant_ref AND g.operator_principal_ref = v_s.principal_ref AND g.case_ref = v_s.case_ref
                         AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now())
       OR NOT EXISTS (SELECT 1 FROM platform.platform_session p WHERE p.session_ref = v_s.parent_session_ref AND p.revoked_at IS NULL AND p.expires_at > pg_catalog.now()
                         AND p.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => p.idle_seconds)) THEN
      RETURN;
    END IF;
  END IF;
  -- Avanza la actividad solo si esta atrasada mas que la granularidad (60 s): una escritura por minuto, no por request.
  UPDATE platform.platform_session x SET last_seen_at = pg_catalog.now() WHERE x.session_ref = v_s.session_ref AND x.last_seen_at < pg_catalog.now() - interval '60 seconds';
  -- La actividad de una sesion CASE mantiene viva a su sesion PLATFORM (la inactividad de la padre tambien invalida la hija).
  IF p_kind = 'CASE' THEN
    UPDATE platform.platform_session x SET last_seen_at = pg_catalog.now() WHERE x.session_ref = v_s.parent_session_ref AND x.last_seen_at < pg_catalog.now() - interval '60 seconds';
  END IF;
  RETURN QUERY SELECT v_s.session_ref, v_s.session_kind, v_s.principal_ref, v_s.case_ref;
END
$$;

-- 5. revoke_session ----------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.revoke_session(p_sid text, p_kind text)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF session_user <> 'platform_rw' OR p_sid IS NULL OR p_sid !~ '^[0-9a-f]{64}$' OR p_kind IS NULL OR p_kind NOT IN ('PLATFORM', 'CASE') THEN RETURN false; END IF;
  RETURN platform.revoke_session_internal(pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_sid, 'UTF8')), 'hex'), p_kind, 'USER_LOGOUT');
END
$$;

-- 6. ACL ---------------------------------------------------------------------------------------------------------------------------------------------
REVOKE ALL ON FUNCTION platform.revoke_session_internal(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.open_platform_session(uuid, text, integer, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.open_case_session(uuid, text, text, text, integer, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.validate_session(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.revoke_session(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.open_platform_session(uuid, text, integer, integer, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.open_case_session(uuid, text, text, text, integer, integer, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.validate_session(text, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.revoke_session(text, text) TO platform_rw;
-- revoke_session_internal: ningun GRANT (interna).

-- 7. Revocar el CREATE temporal.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

-- 8. Aserciones (fail-closed): firma, dueno, SECURITY DEFINER, search_path, ACL exacta, sin SQL dinamico y reglas por prosrc.
DO $assert$
DECLARE
  spec text[];
  t record;
  r text;
  n integer;
  roles text[] := ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'platform_schema_owner'];
BEGIN
  FOREACH spec SLICE 1 IN ARRAY ARRAY[
    ARRAY['open_platform_session', 'platform_rw'], ARRAY['open_case_session', 'platform_rw'], ARRAY['validate_session', 'platform_rw'],
    ARRAY['revoke_session', 'platform_rw'], ARRAY['revoke_session_internal', '']
  ] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION 'platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' THEN RAISE EXCEPTION 'platform.% no pertenece a grant_owner', spec[1]; END IF;
    IF NOT t.prosecdef THEN RAISE EXCEPTION 'platform.% debe ser SECURITY DEFINER', spec[1]; END IF;
    IF t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'platform.% sin search_path fijo exacto', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION 'la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '% puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
  END LOOP;
  -- Reglas por codigo (las que el spec exige).
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'open_platform_session';
  IF t.prosrc !~ 'session_user <> .platform_rw.' OR t.prosrc !~ 'platform\.consume_login_assertion\(p_exchange_ref, p_state, .LOGIN_PLATFORM., NULL\)'
     OR t.prosrc !~ 'a\.status = .ACTIVE.' OR t.prosrc !~ 'gen_random_uuid' THEN
    RAISE EXCEPTION 'platform.open_platform_session perdio una regla (platform_rw, consumo de la asercion en la misma tx, rol ACTIVE, sid generado por la base)';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'open_case_session';
  IF t.prosrc !~ 'platform\.consume_login_assertion\(p_exchange_ref, p_state, .LOGIN_CASE.' OR t.prosrc !~ 'v_parent\.principal_ref <> v_principal'
     OR t.prosrc !~ 'platform_role = .RIGHTS_OPERATOR.' OR t.prosrc !~ 'platform\.rights_case_grant' OR t.prosrc !~ 'v_grant\.expires_at' THEN
    RAISE EXCEPTION 'platform.open_case_session perdio una regla (asercion LOGIN_CASE ligada al caso, misma sesion/principal, RIGHTS_OPERATOR, grant vigente)';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'validate_session';
  IF t.prosrc !~ 'platform_role_assignment' OR t.prosrc !~ 'rights_case_grant' OR t.prosrc !~ 'revoked_at IS NULL' THEN
    RAISE EXCEPTION 'platform.validate_session perdio la revalidacion de rol/grant/sesion';
  END IF;
  -- Ninguna funcion de sesion devuelve ni recibe el principal desde la request.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
              WHERE s.nspname = 'platform' AND p.proname IN ('open_platform_session', 'open_case_session') AND pg_catalog.pg_get_function_arguments(p.oid) ~* 'principal') THEN
    RAISE EXCEPTION 'open_*_session no puede recibir el principal como parametro (sale de la asercion)';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
