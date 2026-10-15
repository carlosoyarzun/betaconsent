-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 paso 6 (LOGIN_CASE con sesion PLATFORM vigente), §10 fila PR-6c; revision de seguridad de 6b: F-PR6-36.
-- Depende de 0051 (funcion que se reemplaza) y 0052/0053 (platform_session). 0051 es inmutable: el reemplazo va aqui, con la MISMA firma (la ACL de 0051 se conserva: EXECUTE solo platform_rw).
--
-- Que cambia: platform.begin_oidc_authorization con p_kind = 'LOGIN_CASE' ya NO confia en el principal declarado por el llamador (GUC app.principal_ref). La BASE valida la sesion PLATFORM vigente:
-- el sid (GUC de transaccion app.session_sid, fijado por el adapter desde la cookie) se resuelve por sha256 contra platform.platform_session (kind PLATFORM, no revocada, dentro de su vida absoluta y de
-- inactividad) y el principal sale de ESA fila. Sin sesion viva = NO_SESSION (DENY con evento, sin crear la fila). Un principal declarado distinto del de la sesion invalida la solicitud.
-- LOGIN_PLATFORM no admite sesion ni principal; STEP_UP no cambia (su principal sigue saliendo del GUC hasta 6d, que lo liga a la sesion validada). Resto del cuerpo = 0051.

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

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
    -- Principal (P6-1): LOGIN_PLATFORM nace sin principal; LOGIN_CASE y STEP_UP lo traen de la transaccion (sesion validada) y debe tener un rol de plataforma ACTIVE.
    IF p_kind = 'LOGIN_PLATFORM' THEN
      IF v_principal IS NOT NULL OR v_sid IS NOT NULL THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
    ELSE
      IF p_kind = 'LOGIN_CASE' THEN
        -- F-PR6-36: el principal de LOGIN_CASE sale de la platform_session PLATFORM vigente que la BASE valida (sid -> sha256 -> fila viva), no de un principal declarado por el llamador.
        -- Un principal declarado (GUC app.principal_ref) distinto del de la sesion invalida la solicitud.
        IF v_sid IS NULL OR v_sid !~ c_hex THEN v_reason := 'NO_SESSION'; EXIT decide; END IF;
        SELECT s.principal_ref INTO v_session_principal FROM platform.platform_session s
         WHERE s.sid_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_sid, 'UTF8')), 'hex') AND s.session_kind = 'PLATFORM'
           AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.now() AND s.last_seen_at > pg_catalog.now() - pg_catalog.make_interval(secs => s.idle_seconds);
        IF NOT FOUND THEN v_reason := 'NO_SESSION'; EXIT decide; END IF;
        IF v_principal IS NOT NULL AND v_principal IS DISTINCT FROM v_session_principal THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
        v_principal := v_session_principal;
      END IF;
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
      -- P-51 (G-6): intentos de confirmacion de acciones sensibles por operador en la ventana. Sin configuracion valida se rechaza (fail-closed).
      IF p_p51_max IS NULL OR p_p51_max < 1 OR p_p51_max > 1000 OR p_p51_window_seconds IS NULL OR p_p51_window_seconds < 60 OR p_p51_window_seconds > 86400 THEN
        v_reason := 'INVALID_INPUT'; EXIT decide;
      END IF;
      -- Lock por principal ANTES de contar (carrera: N inicios concurrentes del mismo operador no pueden superar P-51).
      PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.p51.' || v_principal, 0));
      IF (SELECT pg_catalog.count(*) FROM platform.session_event s
           WHERE s.event_type = 'STEP_UP_BEGIN' AND s.principal_ref = v_principal AND s.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds)) >= p_p51_max THEN
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
BEGIN
  SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'platform' AND p.proname = 'begin_oidc_authorization' AND p.pronargs = 9;
  IF t.oid IS NULL THEN RAISE EXCEPTION 'falta platform.begin_oidc_authorization (9 argumentos)'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'begin_oidc_authorization') <> 1 THEN
    RAISE EXCEPTION 'platform.begin_oidc_authorization debe existir exactamente una vez';
  END IF;
  IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN
    RAISE EXCEPTION 'platform.begin_oidc_authorization: dueno/SECURITY DEFINER/search_path incorrectos';
  END IF;
  IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar platform.begin_oidc_authorization'; END IF;
  IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                 FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM 'platform_rw' THEN
    RAISE EXCEPTION 'la ACL de platform.begin_oidc_authorization no es exactamente [platform_rw]';
  END IF;
  IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'platform.begin_oidc_authorization contiene EXECUTE (SQL dinamico prohibido)'; END IF;
  IF t.prosrc !~ 'app\.session_sid' OR t.prosrc !~ 'platform\.platform_session' OR t.prosrc !~ 's\.session_kind = .PLATFORM.' OR t.prosrc !~ 's\.revoked_at IS NULL'
     OR t.prosrc !~ 'v_principal := v_session_principal' OR t.prosrc !~ 'NO_SESSION' THEN
    RAISE EXCEPTION 'platform.begin_oidc_authorization perdio la validacion de la sesion PLATFORM en LOGIN_CASE (F-PR6-36)';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
