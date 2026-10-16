-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 paso 7 (open_case_session exige un rights_case_grant atestado y vigente), §6 (la sesion se revalida en cada accion contra el
-- grant); F-PR6-40: "validate_session re-verifica tenant y caso" (el tenant de `rights_case_grant`/`platform_session` debe ser el del caso REAL). Depende de 0053 (funciones que se reemplazan) y 0059-0060.
-- 0053 es inmutable: los reemplazos van aqui, con las MISMAS firmas (ACL de 0053 conservada: EXECUTE solo platform_rw).
--
-- Que cambia:
--   platform.open_case_session  : ademas de lo de 0053, el caso debe existir (exactamente una fila, via platform.rights_case_of) y NO ser terminal, su tenant debe ser el del grant y el operador no debe tener Membership TENANT; si no, rechazo
--                                 CASE_MISMATCH con evento LOGIN_REJECTED (la asercion queda consumida, igual que NO_GRANT).
--   platform.validate_session   : en CASE, en CADA llamada, el caso debe seguir existiendo con el tenant de la sesion y el de su grant (un grant o sesion sembrados con tenant ajeno al caso real no validan).
-- Resto del cuerpo = 0053.

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.open_case_session(
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
    -- GRD-RC-10 / P2-c: el operador no tiene Membership TENANT (se re-chequea al abrir la sesion CASE).
    IF EXISTS (SELECT 1 FROM platform.tenant_membership m WHERE m.principal_ref = v_principal) THEN v_reason := 'TENANT_MEMBER'; EXIT decide; END IF;
    -- Grant atestado y vigente del operador para ESTE caso (el mas largo si hay varios).
    SELECT * INTO v_grant FROM platform.rights_case_grant g
     WHERE g.operator_principal_ref = v_principal AND g.case_ref = p_case_ref AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
     ORDER BY g.expires_at DESC LIMIT 1;
    IF NOT FOUND THEN v_reason := 'NO_GRANT'; EXIT decide; END IF;
    -- F-PR6-40: el caso EXISTE de verdad (exactamente una fila en app.rights_case) y su tenant es el del grant: la sesion CASE hereda el tenant del caso real, no de lo que diga una fila suelta.
    IF NOT EXISTS (SELECT 1 FROM platform.rights_case_of(p_case_ref) c WHERE c.o_tenant_id = v_grant.tenant_id AND c.o_status NOT IN ('RESOLVED', 'WITHDRAWN')) THEN v_reason := 'CASE_MISMATCH'; EXIT decide; END IF;
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
CREATE OR REPLACE FUNCTION platform.validate_session(p_sid text, p_kind text)
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
                         AND p.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => p.idle_seconds))
       -- F-PR6-40: tenant y caso se RE-VERIFICAN en cada llamada contra el caso real y contra el grant (el tenant de la sesion = el del caso = el del grant).
       OR NOT EXISTS (SELECT 1 FROM platform.rights_case_of(v_s.case_ref) c JOIN platform.rights_case_grant g2 ON g2.grant_ref = v_s.grant_ref AND g2.tenant_id = c.o_tenant_id
                       WHERE c.o_tenant_id = v_s.tenant_id AND c.o_status NOT IN ('RESOLVED', 'WITHDRAWN'))
       -- F-PR6-46 (fail-closed): un caso que pasa a estado terminal (RESOLVED/WITHDRAWN) corta la sesion CASE.
       -- Membership TENANT sobrevenida: tambien corta (GRD-RC-10, revalidacion en cada sesion).
       OR EXISTS (SELECT 1 FROM platform.tenant_membership m WHERE m.principal_ref = v_s.principal_ref) THEN
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


SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

DO $assert$
DECLARE
  t record;
  r text;
  n integer;
  spec text[];
  roles text[] := ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'];
BEGIN
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['open_case_session', 'platform_rw'], ARRAY['validate_session', 'platform_rw']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0063: platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0063: platform.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION '0063: PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0063: la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '0063: % puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0063: platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
    IF t.prosrc !~ 'platform\.rights_case_of\(' THEN RAISE EXCEPTION '0063: platform.% perdio la re-verificacion de tenant y caso (F-PR6-40)', spec[1]; END IF;
  END LOOP;
  -- Las reglas de 0053 se conservan.
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'open_case_session';
  IF t.prosrc !~ 'platform\.consume_login_assertion\(p_exchange_ref, p_state, .LOGIN_CASE.' OR t.prosrc !~ 'v_parent\.principal_ref <> v_principal'
     OR t.prosrc !~ 'platform_role = .RIGHTS_OPERATOR.' OR t.prosrc !~ 'platform\.rights_case_grant' OR t.prosrc !~ 'v_grant\.expires_at' OR t.prosrc !~ 'CASE_MISMATCH' THEN
    RAISE EXCEPTION '0063: platform.open_case_session perdio una regla';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'validate_session';
  IF t.prosrc !~ 'platform_role_assignment' OR t.prosrc !~ 'rights_case_grant' OR t.prosrc !~ 'revoked_at IS NULL' THEN RAISE EXCEPTION '0063: platform.validate_session perdio la revalidacion de rol/grant/sesion'; END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0063: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
