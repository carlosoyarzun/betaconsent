-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 ("el principal_ref del nonce sale de la sesion validada"), §5.2 paso 8 (step-up posterior), §5.4 (P-51), §10 fila 6d,
-- §11.3 G-6; registers/findings-register-IT0.md F-PR6-39 (nota STEP_UP: el principal de STEP_UP no puede salir de app.principal_ref declarado), F-PR6-35 (b)(c). Depende de 0050-0054, 0059.
-- 0051 y 0054 son inmutables: los reemplazos van aqui, con la MISMA firma (la ACL se conserva: EXECUTE solo platform_rw).
--
-- Que agrega (grant_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico; las internas SIN EXECUTE de ningun rol de runtime):
--   platform.session_principal(sid)  INTERNA. Resuelve el sid (64 hex, GUC app.session_sid fijado por el adapter) por sha256 contra platform.platform_session: kind PLATFORM, no revocada, dentro de su vida
--                                    absoluta y de inactividad. Devuelve el principal de ESA fila (o NULL). Es el patron sid -> fila de 0054, ahora compartido.
--   platform.rights_case_of(case_ref) INTERNA. Tenant y estado del caso REAL (app.rights_case, solo si hay exactamente UNA fila con ese case_ref: ambiguo o inexistente = 0 filas). F-PR6-40.
--   platform.begin_oidc_authorization (reemplazo de 0054, misma firma): STEP_UP YA NO toma el principal de app.principal_ref declarado; igual que LOGIN_CASE sale de la sesion PLATFORM validada en la base
--                                    (sin sesion viva = DENY NO_PRINCIPAL, evidencia en authorization_check, sin crear la fila). El conteo de P-51 incluye los consumos fallidos del nonce (STEP_UP_REJECTED, 0061).
--                                    LOGIN_PLATFORM y LOGIN_CASE no cambian. Resto del cuerpo = 0054.

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION platform.session_principal(p_sid text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_principal text;
BEGIN
  IF p_sid IS NULL OR p_sid !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;
  SELECT s.principal_ref INTO v_principal FROM platform.platform_session s
   WHERE s.sid_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_sid, 'UTF8')), 'hex') AND s.session_kind = 'PLATFORM'
     AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.now() AND s.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => s.idle_seconds);
  RETURN v_principal;
END
$$;

CREATE FUNCTION platform.rights_case_of(p_case_ref text)
  RETURNS TABLE (o_tenant_id uuid, o_status text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_n      integer;
  v_tenant uuid;
  v_status text;
BEGIN
  IF p_case_ref IS NULL THEN RETURN; END IF;
  SELECT pg_catalog.count(*)::integer, (pg_catalog.array_agg(c.tenant_id))[1], (pg_catalog.array_agg(c.status))[1] INTO v_n, v_tenant, v_status
    FROM app.rights_case c WHERE c.case_ref = p_case_ref;
  IF v_n = 1 THEN RETURN QUERY SELECT v_tenant, v_status; END IF;
END
$$;

REVOKE ALL ON FUNCTION platform.session_principal(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.rights_case_of(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.begin_oidc_authorization(
    p_kind text, p_state_hash text, p_binding text, p_pkce_verifier text, p_target_ref_hash text, p_ttl_seconds integer,
    p_max_awaiting integer, p_p51_max integer, p_p51_window_seconds integer)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy      constant text := 'ADR010-PR6B-v1';
  c_principal   constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  c_hex         constant text := '^[0-9a-f]{64}$';
  -- Tope de reencolados de un mismo nonce tras REJECTED (PLACEHOLDER tecnico de 0036, no aprobado).
  c_max_rejects constant integer := 3;
  v_principal   text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_sid         text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_valid_kind  boolean := COALESCE(p_kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE', 'STEP_UP'), false);
  v_reason      text := NULL;
  v_limit       text := NULL;
  v_window      integer := NULL;
  v_ref         uuid;
  v_action      text;
  v_tenant      uuid;
  v_session_principal text;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'platform_rw' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    IF NOT v_valid_kind THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 600 THEN v_reason := 'INVALID_TTL'; EXIT decide; END IF;
    IF p_state_hash IS NULL OR p_state_hash !~ c_hex OR p_binding IS NULL OR p_binding !~ c_hex
       OR p_pkce_verifier IS NULL OR p_pkce_verifier !~ '^[A-Za-z0-9._~-]{43,128}$'
       OR (p_kind = 'LOGIN_CASE') <> (p_target_ref_hash IS NOT NULL) OR (p_target_ref_hash IS NOT NULL AND p_target_ref_hash !~ c_hex)
       OR (p_max_awaiting IS NOT NULL AND (p_max_awaiting < 1 OR p_max_awaiting > 1000000)) THEN
      v_reason := 'INVALID_INPUT'; EXIT decide;
    END IF;
    -- Principal (P6-1): LOGIN_PLATFORM nace sin principal; LOGIN_CASE y STEP_UP lo traen de la sesion PLATFORM que la BASE valida (F-PR6-36, F-PR6-39), y debe tener un rol de plataforma ACTIVE.
    IF p_kind = 'LOGIN_PLATFORM' THEN
      IF v_principal IS NOT NULL OR v_sid IS NOT NULL THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
    ELSE
      -- El principal NUNCA sale de un valor declarado por el llamador (GUC app.principal_ref): sale de la fila de platform.platform_session que resuelve el sid (GUC de transaccion app.session_sid,
      -- fijado por el adapter desde la cookie) por sha256 (kind PLATFORM, no revocada, dentro de su vida absoluta y de inactividad). Un principal declarado distinto del de la sesion invalida la solicitud.
      -- En STEP_UP la evidencia es authorization_check (enum cerrado): "sin sesion" se registra como NO_PRINCIPAL.
      IF v_sid IS NULL OR v_sid !~ c_hex THEN v_reason := CASE WHEN p_kind = 'STEP_UP' THEN 'NO_PRINCIPAL' ELSE 'NO_SESSION' END; EXIT decide; END IF;
      v_session_principal := platform.session_principal(v_sid);
      IF v_session_principal IS NULL THEN v_reason := CASE WHEN p_kind = 'STEP_UP' THEN 'NO_PRINCIPAL' ELSE 'NO_SESSION' END; EXIT decide; END IF;
      IF v_principal IS NOT NULL AND v_principal IS DISTINCT FROM v_session_principal THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
      v_principal := v_session_principal;
      IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; EXIT decide; END IF;
      IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.status = 'ACTIVE') THEN v_reason := 'NO_ROLE'; EXIT decide; END IF;
    END IF;
    -- P-53: tope global de filas AWAITING_CALLBACK vigentes SOLO para LOGIN_PLATFORM (el unico inicio sin sesion; LOGIN_CASE y STEP_UP exigen principal con rol y no deben quedar bloqueados por un
    -- flood anonimo). Sin valor aprobado: NULL = sin tope solo en LOCAL, lo impone el startup-check de platform. Lock global transaccional ANTES de contar: dos inicios concurrentes no pueden pasar
    -- ambos por el ultimo cupo (la fila se inserta en esta misma transaccion, con el lock tomado).
    IF p_kind = 'LOGIN_PLATFORM' AND p_max_awaiting IS NOT NULL THEN
      PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.p53.awaiting', 0));
    END IF;
    IF p_kind = 'LOGIN_PLATFORM' AND p_max_awaiting IS NOT NULL
       AND (SELECT pg_catalog.count(*) FROM platform.oidc_exchange e WHERE e.status = 'AWAITING_CALLBACK' AND e.expires_at > pg_catalog.now()) >= p_max_awaiting THEN
      v_reason := 'AWAITING_CAP'; v_limit := 'P-53'; EXIT decide;
    END IF;
    IF p_kind = 'STEP_UP' THEN
      -- Nonce de step-up vigente del mismo principal (igual que 0036).
      SELECT n.action, n.tenant_id INTO v_action, v_tenant FROM platform.action_nonce n
       WHERE n.nonce_hash = p_binding AND n.principal_ref = v_principal AND n.attested_at IS NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now();
      IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
      IF (SELECT pg_catalog.count(*) FROM platform.grant_assertion g WHERE g.binding = p_binding AND g.decision = 'REJECTED') >= c_max_rejects THEN
        v_reason := 'RETRY_LIMIT'; EXIT decide;
      END IF;
      -- P-51 (G-6): intentos de confirmacion de acciones sensibles por operador en la ventana (inicios de step-up + consumos fallidos del nonce, 0061). Sin configuracion valida se rechaza (fail-closed).
      IF p_p51_max IS NULL OR p_p51_max < 1 OR p_p51_max > 1000 OR p_p51_window_seconds IS NULL OR p_p51_window_seconds < 60 OR p_p51_window_seconds > 86400 THEN
        v_reason := 'INVALID_INPUT'; EXIT decide;
      END IF;
      -- Lock por principal ANTES de contar (carrera: N inicios concurrentes del mismo operador no pueden superar P-51).
      PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.p51.' || v_principal, 0));
      IF (SELECT pg_catalog.count(*) FROM platform.session_event s
           WHERE s.event_type IN ('STEP_UP_BEGIN', 'STEP_UP_REJECTED') AND s.principal_ref = v_principal AND s.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds)) >= p_p51_max THEN
        v_reason := 'RATE_LIMITED'; v_limit := 'P-51'; v_window := p_p51_window_seconds; EXIT decide;
      END IF;
    END IF;
    INSERT INTO platform.oidc_exchange (binding, principal_ref, kind, state_hash, target_ref_hash, status, pkce_verifier, expires_at)
    VALUES (p_binding, v_principal, p_kind, p_state_hash, p_target_ref_hash, 'AWAITING_CALLBACK', p_pkce_verifier, pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_seconds))
    ON CONFLICT DO NOTHING
    RETURNING exchange_ref INTO v_ref;
    IF v_ref IS NULL THEN v_reason := 'DUPLICATE_EXCHANGE'; EXIT decide; END IF;
    IF p_kind = 'STEP_UP' THEN
      INSERT INTO platform.session_event (event_type, kind, principal_ref) VALUES ('STEP_UP_BEGIN', 'STEP_UP', v_principal);
    END IF;
  END;

  IF v_valid_kind AND v_reason IS NOT NULL AND v_reason <> 'CALLER_ROLE' THEN
    IF v_limit IS NOT NULL THEN
      -- UN solo evento de limite por (limite, principal) y ventana (no uno por rechazo: un flood no puede inflar session_event). P-53 no tiene ventana: se usa 900 s.
      IF NOT EXISTS (SELECT 1 FROM platform.session_event e
                      WHERE e.event_type = 'LIMIT_EXCEEDED' AND e.limit_kind = v_limit AND e.principal_ref IS NOT DISTINCT FROM (CASE WHEN v_principal ~ c_principal THEN v_principal END)
                        AND e.at > pg_catalog.now() - pg_catalog.make_interval(secs => COALESCE(v_window, 900))) THEN
        INSERT INTO platform.session_event (event_type, kind, principal_ref, limit_kind, window_seconds)
        VALUES ('LIMIT_EXCEEDED', p_kind, CASE WHEN v_principal ~ c_principal THEN v_principal END, v_limit, v_window);
      END IF;
    ELSIF p_kind <> 'STEP_UP' THEN
      INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref)
      VALUES ('LOGIN_REJECTED', v_reason, p_kind, CASE WHEN v_principal ~ c_principal THEN v_principal END);
    END IF;
  END IF;
  IF p_kind = 'STEP_UP' THEN
    INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
    VALUES ('ENQUEUE_EXCHANGE', v_tenant, v_action, CASE WHEN v_principal ~ c_principal THEN v_principal END, NULL,
            CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  END IF;
  RETURN v_ref;
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
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['session_principal', ''], ARRAY['rights_case_of', ''], ARRAY['begin_oidc_authorization', 'platform_rw']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0060: platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0060: platform.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION '0060: PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0060: la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '0060: % puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0060: platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
  END LOOP;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'begin_oidc_authorization';
  IF t.prosrc !~ 'app\.session_sid' OR t.prosrc !~ 'platform\.session_principal\(v_sid\)' OR t.prosrc !~ 'v_principal := v_session_principal' OR t.prosrc !~ 'STEP_UP_REJECTED' THEN
    RAISE EXCEPTION '0060: platform.begin_oidc_authorization perdio la resolucion del principal por sesion (F-PR6-36/39)';
  END IF;
  -- Ningun camino toma el principal de un valor declarado: v_principal declarado solo se COMPARA con el de la sesion.
  IF t.prosrc !~ 'v_principal IS NOT NULL AND v_principal IS DISTINCT FROM v_session_principal' THEN
    RAISE EXCEPTION '0060: platform.begin_oidc_authorization debe rechazar un principal declarado distinto del de la sesion';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0060: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
