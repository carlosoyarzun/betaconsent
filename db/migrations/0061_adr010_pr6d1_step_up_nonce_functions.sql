-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (§4.3(1): el principal del nonce sale de la sesion validada; enum con REQUEST_GRANT y APPROVE_GRANT), §5.2 paso 8,
-- §5.4 (P-51: 5 intentos / 10 min por operador en el inicio de step-up Y en el consumo del nonce; P-52: aserciones de 5 min desde auth_time, un solo uso), §10 fila 6d, §11.3 G-6/G-7;
-- GRD-RC-12 (specs/state-machines/rights-case.spec.yaml: step-up + nonce por accion + asercion del IdP; sin ATTESTED por integrity_verifier no hay efecto); F-PR6-39 (nota STEP_UP), F-PR6-35 (b)(c).
-- Depende de 0059 y 0060. 0000-0058 son inmutables.
--
-- Que agrega (grant_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico):
--   platform.issue_step_up_nonce(action, target_ref, ttl)  (EXECUTE solo platform_rw)  Emite el nonce del step-up de las acciones de caso REQUEST_GRANT / APPROVE_GRANT. El principal sale de la sesion
--       PLATFORM que la BASE valida (GUC app.session_sid -> platform.session_principal), NUNCA de app.principal_ref ni de un parametro. Liga el nonce a (principal, accion, sha256(target_ref)): REQUEST_GRANT ->
--       case_ref (UUIDv4); APPROVE_GRANT -> request_ref de una grant_request PENDING, vigente (P-37) y de OTRO solicitante. Rol: REQUEST_GRANT = RIGHTS_OPERATOR ACTIVE; APPROVE_GRANT = APPROVER ACTIVE.
--       Alcance PLATFORM (sin tenant: el tenant lo deriva la accion del caso real). TTL 1..600 s. Devuelve el nonce en claro UNA vez (solo se persiste su sha256) o NULL ante DENY, con evidencia en
--       authorization_check (ISSUE_NONCE) confirmada (la funcion no lanza ante un DENY).
--   platform.consume_step_up(principal, action, target_ref, p51_max, p51_window)  INTERNA (sin EXECUTE de ningun rol de runtime; solo la llaman request_grant / approve_grant, 0062, EN LA MISMA
--       transaccion que el efecto). Devuelve NULL si consumio el nonce o el motivo del rechazo. En orden: (1) lock por operador (el mismo de P-51 de begin) y conteo de P-51: inicios de step-up
--       + consumos fallidos en la ventana; sobre el limite = RATE_LIMITED con UN evento LIMIT_EXCEEDED por ventana; (2) busca el nonce ATTESTED del MISMO principal y accion, ligado a sha256(target_ref), vigente y
--       no consumido, con una grant_assertion ATTESTED del mismo binding y principal; (3) P-52: auth_time dentro de 5 min (ASSERTION_STALE); (4) UPDATE ... consumed_at WHERE consumed_at IS NULL (un solo uso).
--       Un rechazo (2)-(4) escribe STEP_UP_REJECTED (cuenta para P-51; sin IP ni sub_hmac). Una aserción de otra accion, otro destino u otro operador no existe para esta busqueda: STEP_UP_MISSING.
--       Sin configuracion valida de P-51 (NULL o fuera de rango) se rechaza (fail-closed).
-- Valores aprobados (SEC-CNS-006 rev. 5; G-6/G-7, Carlos 2026-10-15): P-51 = 5 / 10 min (los pasa platform por configuracion; la base solo acota rangos); P-52 = 300 s desde auth_time (constante en la base).

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. issue_step_up_nonce -------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.issue_step_up_nonce(p_action text, p_target_ref text, p_ttl_seconds integer)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy    constant text := 'ADR010-PR6D1-v1';
  c_principal constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  c_uuid      constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
  v_sid       text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_principal text;
  v_reason    text := NULL;
  v_nonce     text;
  v_req       platform.grant_request%ROWTYPE;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'platform_rw' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    IF p_action IS NULL OR p_action NOT IN ('REQUEST_GRANT', 'APPROVE_GRANT') THEN v_reason := 'UNKNOWN_ACTION'; EXIT decide; END IF;
    -- El principal sale de la sesion PLATFORM validada por la base, nunca de la request (F-PR6-39).
    v_principal := platform.session_principal(v_sid);
    IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; v_principal := NULL; EXIT decide; END IF;
    IF p_target_ref IS NULL OR p_target_ref !~ (CASE p_action WHEN 'REQUEST_GRANT' THEN c_principal ELSE c_uuid END) THEN v_reason := 'INVALID_RESOURCE'; EXIT decide; END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 600 THEN v_reason := 'INVALID_TTL'; EXIT decide; END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a
                    WHERE a.principal_ref = v_principal AND a.status = 'ACTIVE'
                      AND a.platform_role = CASE p_action WHEN 'REQUEST_GRANT' THEN 'RIGHTS_OPERATOR' ELSE 'APPROVER' END) THEN
      v_reason := 'NO_ROLE'; EXIT decide;
    END IF;
    IF p_action = 'APPROVE_GRANT' THEN
      -- La solicitud debe estar PENDING y vigente (P-37) y no ser del propio aprobador.
      SELECT * INTO v_req FROM platform.grant_request r WHERE r.request_ref = p_target_ref::pg_catalog.uuid AND r.status = 'PENDING' AND r.expires_at > pg_catalog.now();
      IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
      IF v_req.requested_by_ref = v_principal OR v_req.operator_principal_ref = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
    END IF;
    -- 244 bits de aleatoriedad (dos UUIDv4); solo se persiste el hash.
    v_nonce := pg_catalog.replace(pg_catalog.gen_random_uuid()::pg_catalog.text || pg_catalog.gen_random_uuid()::pg_catalog.text, '-', '');
    INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at)
    VALUES (pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_nonce, 'UTF8')), 'hex'), 'PLATFORM', NULL, p_action,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_target_ref, 'UTF8')), 'hex'), v_principal, pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_seconds));
  END;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('ISSUE_NONCE', NULL,
          CASE WHEN p_action IN ('REQUEST_GRANT', 'APPROVE_GRANT') THEN p_action END,
          v_principal,
          CASE WHEN p_target_ref ~ c_uuid THEN p_target_ref END,
          CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  IF v_reason IS NOT NULL THEN RETURN NULL; END IF;
  RETURN v_nonce;
END
$$;

-- 2. consume_step_up (interna) -------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.consume_step_up(p_principal text, p_action text, p_target_ref text, p_p51_max integer, p_p51_window_seconds integer)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_principal constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  -- P-52 (SEC-CNS-006 rev. 5 / G-7, aprobado): la aserción vive 5 min DESDE auth_time.
  c_p52       constant interval := interval '5 minutes';
  v_nonce     text;
  v_auth_time timestamptz;
  v_reason    text := NULL;
BEGIN
  IF p_principal IS NULL OR p_principal !~ c_principal OR p_action IS NULL OR p_action NOT IN ('REQUEST_GRANT', 'APPROVE_GRANT') OR p_target_ref IS NULL
     OR p_p51_max IS NULL OR p_p51_max < 1 OR p_p51_max > 1000 OR p_p51_window_seconds IS NULL OR p_p51_window_seconds < 60 OR p_p51_window_seconds > 86400 THEN
    RETURN 'INVALID_INPUT';
  END IF;
  <<decide>>
  BEGIN
    -- P-51: lock por operador (el MISMO que begin_oidc_authorization) ANTES de contar; el inicio de este step-up ya cuenta (STEP_UP_BEGIN), por eso el limite es "mas de P-51".
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.p51.' || p_principal, 0));
    IF (SELECT pg_catalog.count(*) FROM platform.session_event s
         WHERE s.event_type IN ('STEP_UP_BEGIN', 'STEP_UP_REJECTED') AND s.principal_ref = p_principal AND s.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds)) > p_p51_max THEN
      -- UN solo evento de limite por (limite, principal) y ventana (un flood no infla session_event).
      IF NOT EXISTS (SELECT 1 FROM platform.session_event e
                      WHERE e.event_type = 'LIMIT_EXCEEDED' AND e.limit_kind = 'P-51' AND e.principal_ref = p_principal
                        AND e.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds)) THEN
        INSERT INTO platform.session_event (event_type, kind, principal_ref, limit_kind, window_seconds) VALUES ('LIMIT_EXCEEDED', 'STEP_UP', p_principal, 'P-51', p_p51_window_seconds);
      END IF;
      RETURN 'RATE_LIMITED';
    END IF;
    -- Nonce ATTESTED del mismo principal, accion y destino (sha256(target_ref)), vigente y sin consumir, con la aserción del IdP atestada para ese binding y principal.
    SELECT n.nonce_hash, g.auth_time INTO v_nonce, v_auth_time FROM platform.action_nonce n
      JOIN platform.grant_assertion g ON g.binding = n.nonce_hash AND g.decision = 'ATTESTED' AND g.principal_ref = n.principal_ref
     WHERE n.principal_ref = p_principal AND n.action = p_action AND n.scope = 'PLATFORM' AND n.tenant_id IS NULL
       AND n.refs_digest = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_target_ref, 'UTF8')), 'hex')
       AND n.attested_at IS NOT NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     ORDER BY n.issued_at LIMIT 1 FOR UPDATE OF n;
    IF v_nonce IS NULL THEN v_reason := 'STEP_UP_MISSING'; EXIT decide; END IF;
    IF v_auth_time IS NULL OR v_auth_time < pg_catalog.now() - c_p52 THEN v_reason := 'ASSERTION_STALE'; EXIT decide; END IF;
    UPDATE platform.action_nonce SET consumed_at = pg_catalog.now() WHERE nonce_hash = v_nonce AND consumed_at IS NULL;
    IF NOT FOUND THEN v_reason := 'STEP_UP_MISSING'; EXIT decide; END IF;
  END;
  IF v_reason IS NOT NULL THEN
    INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref) VALUES ('STEP_UP_REJECTED', v_reason, 'STEP_UP', p_principal);
  END IF;
  RETURN v_reason;
END
$$;

REVOKE ALL ON FUNCTION platform.issue_step_up_nonce(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.consume_step_up(text, text, text, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.issue_step_up_nonce(text, text, integer) TO platform_rw;
-- consume_step_up: ningun GRANT (interna).

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
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['issue_step_up_nonce', 'platform_rw'], ARRAY['consume_step_up', '']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0061: platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0061: platform.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION '0061: PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0061: la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '0061: % puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0061: platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
  END LOOP;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'issue_step_up_nonce';
  IF t.prosrc !~ 'platform\.session_principal\(v_sid\)' OR t.prosrc !~ 'session_user <> .platform_rw.' OR t.prosrc ~ 'app\.principal_ref' THEN
    RAISE EXCEPTION '0061: platform.issue_step_up_nonce perdio la regla (principal de la sesion validada, platform_rw)';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'consume_step_up';
  IF t.prosrc !~ 'pg_advisory_xact_lock' OR t.prosrc !~ 'STEP_UP_REJECTED' OR t.prosrc !~ 'consumed_at IS NULL' OR t.prosrc !~ 'c_p52' OR t.prosrc !~ 'n\.refs_digest' OR t.prosrc !~ 'n\.principal_ref = p_principal' THEN
    RAISE EXCEPTION '0061: platform.consume_step_up perdio una regla (lock P-51, ligadura a operador/accion/destino, P-52, un solo uso)';
  END IF;
  -- Ninguna funcion de step-up recibe el principal desde la request.
  IF pg_catalog.pg_get_function_arguments((SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'issue_step_up_nonce')) ~* 'principal' THEN
    RAISE EXCEPTION '0061: issue_step_up_nonce no puede recibir el principal como parametro';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0061: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
