-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.3(2)(3), §5.1, §5.2 pasos 1-4, §5.3, §5.4 (P-48, P-51, P-52, P-53), §10 fila PR-6b;
-- decisiones G-5 (reautenticacion: auth_time validado), G-6 (limites), G-7 (asercion LOGIN de 5 min desde auth_time, un solo uso, ligada al operador y a la operacion),
-- G-8 (state verificado en la base; exchangeRef fuera de la URL); FINDINGs F-PR6-01/02/15/16/17/18/26/27/31. Depende de 0050 (esquema). 0036 y 0040 son inmutables: todo va aqui.
--
-- Que agrega (SECURITY DEFINER, dueno grant_owner, search_path = pg_catalog, pg_temp, sin SQL dinamico, EXECUTE revocado a PUBLIC; ante un DENY NO lanzan excepcion: devuelven
-- NULL/false para que la evidencia se confirme, igual que 0036):
--   platform.begin_oidc_authorization (platform_rw)   crea la fila AWAITING_CALLBACK (state_hash, PKCE, binding = sha256(nonce), kind, target_ref_hash). Aplica P-53 (tope global, falla
--                                                     cerrado con evento) y P-51 (STEP_UP: intentos por operador). Reemplaza a enqueue_oidc_exchange.
--   platform.complete_oidc_callback (platform_rw)     AWAITING_CALLBACK -> PENDING solo si sha256(state) coincide, vigente y sin uso previo (un solo uso, UPDATE condicional).
--   platform.exchange_status (platform_rw)            estado de la solicitud, solo con (exchange_ref, state) coherentes; sin code ni claims (contrato G-8: ref en cookie, no en la URL).
--   platform.claim_oidc_exchange v2 (integrity_verifier)  ahora devuelve kind y principal_ref (NULL en LOGIN_PLATFORM). DROP + CREATE (cambia el tipo de retorno).
--   platform.record_assertion v2 (integrity_verifier) solo STEP_UP; identidad versionada (acepta cualquier key_version registrada del principal). Resto = 0040.
--   platform.record_login_assertion (integrity_verifier)  resuelve el principal en la BASE por (key_version, sub_hmac) y NO lo devuelve (N6'); valida auth_time (G-5: no futuro y
--                                                     >= created_at - skew), rol ACTIVE del kind, principal = oidc_exchange.principal_ref en LOGIN_CASE (rechazo + evento si difiere),
--                                                     P-48 (fallos por principal resuelto en la ventana; los ATTESTED NO cuentan) y P-52 (expires_at = auth_time + P-52). Fuera de
--                                                     configuracion valida (P-48/P-52 NULL o fuera de rango) rechaza NOT_CONFIGURED (fail-closed). NUNCA persiste sub_hmac.
--   platform.consume_login_assertion (INTERNA: sin EXECUTE para ningun rol de runtime)  verifica sha256(state) = state_hash, kind, target_ref_hash y vigencia, y consume la asercion
--                                                     atomicamente (un solo uso). La llamaran open_platform_session / open_case_session (6c, misma tx que crea la sesion).
--   platform.record_limit_event (platform_rw)         evento de P-49/P-50 (los aplica el proceso platform en memoria); sin IP.
-- Se elimina platform.enqueue_oidc_exchange (0036): platform_rw ya no encola code por una via sin state.
--
-- Valores de P-48..P-52, P-53: los fija el llamador por configuracion (nada de defaults en la base); la base solo acota rangos y rechaza NULL. La base NO conoce el entorno: el
-- "fuera de LOCAL sin configuracion no arranca" lo imponen los startup-checks de los procesos (platform: P-49/P-50/P-51/P-53; verifier: P-48/P-52).
-- LOGIN_CASE/STEP_UP toman el principal de la GUC app.principal_ref (fijada por el adapter desde la sesion; la sesion PLATFORM llega en 6c).
-- Roles del kind (record_login_assertion): LOGIN_PLATFORM acepta cualquier rol de plataforma ACTIVE; LOGIN_CASE, RIGHTS_OPERATOR o APPROVER. open_case_session (6c) vuelve a exigir
-- RIGHTS_OPERATOR + grant (F-PR6-34).

-- 0. CREATE temporal para grant_owner (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. begin_oidc_authorization ----------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.begin_oidc_authorization(
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
  v_valid_kind  boolean := COALESCE(p_kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE', 'STEP_UP'), false);
  v_reason      text := NULL;
  v_limit       text := NULL;
  v_window      integer := NULL;
  v_ref         uuid;
  v_action      text;
  v_tenant      uuid;
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
      IF v_principal IS NOT NULL THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
    ELSE
      IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; EXIT decide; END IF;
      IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.status = 'ACTIVE') THEN v_reason := 'NO_ROLE'; EXIT decide; END IF;
    END IF;
    -- P-53: tope global de filas AWAITING_CALLBACK vigentes (sin valor aprobado: NULL = sin tope solo en LOCAL, lo impone el startup-check de platform).
    IF p_max_awaiting IS NOT NULL
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
      INSERT INTO platform.session_event (event_type, kind, principal_ref, limit_kind, window_seconds)
      VALUES ('LIMIT_EXCEEDED', p_kind, CASE WHEN v_principal ~ c_principal THEN v_principal END, v_limit, v_window);
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

-- 2. complete_oidc_callback ------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.complete_oidc_callback(p_state text, p_code text)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_ref uuid;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  -- state: >= 128 bits en base64url (22+ caracteres). Entrada invalida => NULL (el handler responde 404 uniforme y cuenta para P-49).
  IF p_state IS NULL OR p_state !~ '^[A-Za-z0-9_-]{22,128}$' OR p_code IS NULL OR pg_catalog.length(p_code) > 512 OR p_code !~ '^[!-~]+$' THEN RETURN NULL; END IF;
  -- Un solo uso y vigencia: el UPDATE condicional es la comprobacion (state reusado, ajeno o vencido => ninguna fila).
  UPDATE platform.oidc_exchange e SET status = 'PENDING', code = p_code
   WHERE e.state_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_state, 'UTF8')), 'hex')
     AND e.status = 'AWAITING_CALLBACK' AND e.expires_at > pg_catalog.now()
  RETURNING e.exchange_ref INTO v_ref;
  RETURN v_ref;
END
$$;

-- 3. exchange_status -------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.exchange_status(p_exchange_ref uuid, p_state text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_status text;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  IF p_exchange_ref IS NULL OR p_state IS NULL OR p_state !~ '^[A-Za-z0-9_-]{22,128}$' THEN RETURN NULL; END IF;
  SELECT e.status INTO v_status FROM platform.oidc_exchange e
   WHERE e.exchange_ref = p_exchange_ref AND e.expires_at > pg_catalog.now()
     AND e.state_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_state, 'UTF8')), 'hex');
  RETURN v_status;
END
$$;

-- 4. claim_oidc_exchange v2 (cambia el tipo de retorno: DROP + CREATE) ----------------------------------------------------------------------------
DROP FUNCTION platform.claim_oidc_exchange(integer);
CREATE FUNCTION platform.claim_oidc_exchange(p_lease_seconds integer)
  RETURNS TABLE (o_exchange_ref uuid, o_binding text, o_principal_ref text, o_kind text, o_code text, o_pkce_verifier text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF session_user <> 'integrity_verifier' OR p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 120 THEN
    RETURN;
  END IF;
  RETURN QUERY
  WITH pick AS (
    SELECT e.exchange_ref FROM platform.oidc_exchange e
     WHERE e.status = 'PENDING' AND e.expires_at > pg_catalog.now() AND (e.claimed_until IS NULL OR e.claimed_until <= pg_catalog.now())
     ORDER BY e.created_at LIMIT 1 FOR UPDATE SKIP LOCKED),
  upd AS (
    UPDATE platform.oidc_exchange x SET claimed_until = pg_catalog.now() + pg_catalog.make_interval(secs => p_lease_seconds)
      FROM pick WHERE x.exchange_ref = pick.exchange_ref
    RETURNING x.exchange_ref, x.binding, x.principal_ref, x.kind, x.code, x.pkce_verifier)
  SELECT upd.exchange_ref, upd.binding, upd.principal_ref, upd.kind, upd.code, upd.pkce_verifier FROM upd;
END
$$;

-- 5. record_assertion v2: solo STEP_UP + identidad versionada. Mismo cuerpo que 0040 salvo (a) e.kind = 'STEP_UP' y (b) el mapeo sub_hmac <-> principal acepta cualquier key_version registrada.
CREATE OR REPLACE FUNCTION platform.record_assertion(
    p_exchange_ref uuid, p_decision text, p_reason text, p_sub_hmac text, p_assertion_hash text, p_auth_time timestamptz, p_acr text, p_amr text[])
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy   constant text := 'ADR010-PR4-v1';
  c_hex      constant text := '^[0-9a-f]{64}$';
  -- Tolerancia de reloj (valor NO aprobado por Carlos; F-PR6-07, skew PENDING igual que P-36): la misma de 0040.
  c_skew     constant interval := interval '2 minutes';
  v_ex       platform.oidc_exchange%ROWTYPE;
  v_found    boolean := false;
  v_reason   text := NULL;
  v_decision text := 'REJECTED';
  v_action   text;
  v_tenant   uuid;
  v_issued   timestamptz;
  v_input_ok boolean;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'integrity_verifier' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    SELECT * INTO v_ex FROM platform.oidc_exchange e
     WHERE e.exchange_ref = p_exchange_ref AND e.status = 'PENDING' AND e.kind = 'STEP_UP' AND e.expires_at > pg_catalog.now()
       AND e.claimed_until IS NOT NULL AND e.claimed_until > pg_catalog.now() FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'EXCHANGE_NOT_FOUND'; EXIT decide; END IF;
    v_found := true;
    v_input_ok := COALESCE(p_decision IN ('ATTESTED', 'REJECTED')
      AND (p_sub_hmac IS NULL OR p_sub_hmac ~ c_hex) AND (p_assertion_hash IS NULL OR p_assertion_hash ~ c_hex)
      AND (p_acr IS NULL OR p_acr ~ '^[A-Za-z0-9:._-]{1,128}$')
      AND (p_amr IS NULL OR (pg_catalog.cardinality(p_amr) BETWEEN 1 AND 8 AND pg_catalog.array_to_string(p_amr, ',') ~ '^[A-Za-z0-9:._-]{1,64}(,[A-Za-z0-9:._-]{1,64}){0,7}$'))
      AND (p_decision = 'REJECTED' OR (p_sub_hmac IS NOT NULL AND p_assertion_hash IS NOT NULL AND p_auth_time IS NOT NULL))
      AND (p_decision = 'ATTESTED' OR p_reason IN ('SUB_MISMATCH', 'INVALID_CLAIMS', 'EXCHANGE_FAILED')), false);
    IF NOT v_input_ok THEN
      v_reason := 'INVALID_CLAIMS'; EXIT decide;
    END IF;
    IF p_decision = 'REJECTED' THEN v_reason := p_reason; EXIT decide; END IF;

    -- ATTESTED solicitado: N6 (sub_hmac <-> principal_ref, cualquier key_version registrada), auth_time razonable, nonce vigente del mismo principal y binding.
    IF NOT EXISTS (SELECT 1 FROM platform.principal_identity i WHERE i.principal_ref = v_ex.principal_ref AND i.sub_hmac = p_sub_hmac) THEN v_reason := 'SUB_MISMATCH'; EXIT decide; END IF;
    IF p_auth_time > pg_catalog.now() + c_skew THEN v_reason := 'INVALID_CLAIMS'; EXIT decide; END IF;
    SELECT n.action, n.tenant_id, n.issued_at INTO v_action, v_tenant, v_issued FROM platform.action_nonce n
     WHERE n.nonce_hash = v_ex.binding AND n.principal_ref = v_ex.principal_ref AND n.attested_at IS NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    IF p_auth_time < v_issued - c_skew THEN v_reason := 'INVALID_CLAIMS'; EXIT decide; END IF;
    UPDATE platform.action_nonce SET attested_at = pg_catalog.now() WHERE nonce_hash = v_ex.binding AND attested_at IS NULL;
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    v_decision := 'ATTESTED';
  END;

  IF v_found THEN
    IF v_decision = 'REJECTED' AND v_action IS NULL THEN
      SELECT n.action, n.tenant_id INTO v_action, v_tenant FROM platform.action_nonce n WHERE n.nonce_hash = v_ex.binding AND n.principal_ref = v_ex.principal_ref;
    END IF;
    UPDATE platform.oidc_exchange SET status = v_decision, code = NULL, pkce_verifier = NULL, decided_at = pg_catalog.now() WHERE exchange_ref = v_ex.exchange_ref;
    INSERT INTO platform.grant_assertion (exchange_ref, binding, principal_ref, decision, reason_code, sub_hmac, assertion_hash, auth_time, acr, amr)
    VALUES (v_ex.exchange_ref, v_ex.binding, v_ex.principal_ref, v_decision, CASE WHEN v_decision = 'REJECTED' THEN COALESCE(v_reason, 'INVALID_CLAIMS') END,
            CASE WHEN v_input_ok THEN p_sub_hmac END, CASE WHEN v_input_ok THEN p_assertion_hash END, CASE WHEN v_input_ok THEN p_auth_time END,
            CASE WHEN v_input_ok THEN p_acr END, CASE WHEN v_input_ok THEN p_amr END);
  END IF;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('RECORD_ASSERTION', v_tenant, v_action, CASE WHEN v_found THEN v_ex.principal_ref END, NULL,
          CASE WHEN v_decision = 'ATTESTED' THEN 'ALLOW' ELSE 'DENY' END,
          CASE WHEN v_decision = 'ATTESTED' THEN 'OK' ELSE COALESCE(v_reason, 'INVALID_CLAIMS') END, c_policy);
  RETURN v_decision = 'ATTESTED';
END
$$;

-- 6. record_login_assertion --------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.record_login_assertion(
    p_exchange_ref uuid, p_decision text, p_reason text, p_sub_hmac text, p_key_version smallint, p_assertion_hash text, p_auth_time timestamptz, p_acr text, p_amr text[],
    p_p48_max integer, p_p48_window_seconds integer, p_p52_seconds integer)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_hex      constant text := '^[0-9a-f]{64}$';
  -- Tolerancia de reloj de auth_time (G-5): la misma de record_assertion; valor NO aprobado (skew PENDING junto con P-36). Fuera de LOCAL sigue siendo condicion previa a STAGING.
  c_skew     constant interval := interval '2 minutes';
  v_ex       platform.oidc_exchange%ROWTYPE;
  v_found    boolean := false;
  v_reason   text := NULL;
  v_decision text := 'REJECTED';
  v_principal text := NULL;
  v_expires  timestamptz := NULL;
  v_input_ok boolean;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'integrity_verifier' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    SELECT * INTO v_ex FROM platform.oidc_exchange e
     WHERE e.exchange_ref = p_exchange_ref AND e.status = 'PENDING' AND e.kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE') AND e.expires_at > pg_catalog.now()
       AND e.claimed_until IS NOT NULL AND e.claimed_until > pg_catalog.now() FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'EXCHANGE_NOT_FOUND'; EXIT decide; END IF;
    v_found := true;
    v_input_ok := COALESCE(p_decision IN ('ATTESTED', 'REJECTED')
      AND (p_sub_hmac IS NULL OR p_sub_hmac ~ c_hex) AND (p_assertion_hash IS NULL OR p_assertion_hash ~ c_hex)
      AND (p_acr IS NULL OR p_acr ~ '^[A-Za-z0-9:._-]{1,128}$')
      AND (p_amr IS NULL OR (pg_catalog.cardinality(p_amr) BETWEEN 1 AND 8 AND pg_catalog.array_to_string(p_amr, ',') ~ '^[A-Za-z0-9:._-]{1,64}(,[A-Za-z0-9:._-]{1,64}){0,7}$'))
      AND (p_decision = 'REJECTED' OR (p_sub_hmac IS NOT NULL AND p_key_version BETWEEN 1 AND 1000 AND p_assertion_hash IS NOT NULL AND p_auth_time IS NOT NULL))
      AND (p_decision = 'ATTESTED' OR p_reason IN ('INVALID_CLAIMS', 'EXCHANGE_FAILED')), false);
    IF NOT v_input_ok THEN v_reason := 'INVALID_CLAIMS'; EXIT decide; END IF;
    IF p_decision = 'REJECTED' THEN v_reason := p_reason; EXIT decide; END IF;

    -- Fail-closed (G-6/G-7): P-48 y P-52 vienen por configuracion; NULL o fuera de rango => rechazo. P-52 no puede superar los 5 min aprobados.
    IF p_p52_seconds IS NULL OR p_p52_seconds < 1 OR p_p52_seconds > 300
       OR p_p48_max IS NULL OR p_p48_max < 1 OR p_p48_max > 1000
       OR p_p48_window_seconds IS NULL OR p_p48_window_seconds < 60 OR p_p48_window_seconds > 86400 THEN
      v_reason := 'NOT_CONFIGURED'; EXIT decide;
    END IF;
    -- La BASE resuelve el principal por (key_version, sub_hmac) (N6'). Sin mapeo: REJECTED sin persistir el sub_hmac y sin crear ningun principal (sin JIT).
    SELECT i.principal_ref INTO v_principal FROM platform.principal_identity i WHERE i.key_version = p_key_version AND i.sub_hmac = p_sub_hmac;
    IF v_principal IS NULL THEN v_reason := 'NO_MAPPING'; EXIT decide; END IF;
    -- P-48: solo los intentos FALLIDOS del principal resuelto en la ventana (los ATTESTED legitimos no cuentan: con prompt=login en cada sesion bloquearian al operador).
    IF (SELECT pg_catalog.count(*) FROM platform.login_assertion a
         WHERE a.principal_ref = v_principal AND a.decision = 'REJECTED' AND a.reason_code IN ('ROLE_INACTIVE', 'AUTH_TIME_INVALID', 'PRINCIPAL_MISMATCH')
           AND a.recorded_at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p48_window_seconds)) >= p_p48_max THEN
      v_reason := 'RATE_LIMITED'; EXIT decide;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment r
                    WHERE r.principal_ref = v_principal AND r.status = 'ACTIVE'
                      AND ((v_ex.kind = 'LOGIN_PLATFORM' AND r.platform_role IN ('PLATFORM', 'RIGHTS_OPERATOR', 'APPROVER', 'CONTEXT_OWNER'))
                           OR (v_ex.kind = 'LOGIN_CASE' AND r.platform_role IN ('RIGHTS_OPERATOR', 'APPROVER')))) THEN
      v_reason := 'ROLE_INACTIVE'; EXIT decide;
    END IF;
    -- LOGIN_CASE: el principal que se autentica debe ser el de la sesion PLATFORM que inicio el flujo (seguridad rev. c, punto 6).
    IF v_ex.kind = 'LOGIN_CASE' AND v_principal IS DISTINCT FROM v_ex.principal_ref THEN v_reason := 'PRINCIPAL_MISMATCH'; EXIT decide; END IF;
    -- G-5: reautenticacion real. auth_time presente (ya exigido), no futuro y no anterior a la creacion del flujo (menos skew).
    IF p_auth_time > pg_catalog.now() + c_skew OR p_auth_time < v_ex.created_at - c_skew THEN v_reason := 'AUTH_TIME_INVALID'; EXIT decide; END IF;
    -- G-7 / P-52: la vida se cuenta desde auth_time (no desde el canje ni desde la hora de la asercion).
    v_expires := p_auth_time + pg_catalog.make_interval(secs => p_p52_seconds);
    IF v_expires <= pg_catalog.now() THEN v_reason := 'AUTH_TIME_INVALID'; EXIT decide; END IF;
    v_decision := 'ATTESTED';
  END;

  IF v_found THEN
    UPDATE platform.oidc_exchange SET status = v_decision, code = NULL, pkce_verifier = NULL, decided_at = pg_catalog.now() WHERE exchange_ref = v_ex.exchange_ref;
    INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, target_ref_hash, principal_ref, decision, reason_code, assertion_hash, auth_time, acr, amr, expires_at)
    VALUES (v_ex.exchange_ref, v_ex.kind, v_ex.state_hash, v_ex.target_ref_hash, v_principal, v_decision,
            CASE WHEN v_decision = 'REJECTED' THEN COALESCE(v_reason, 'INVALID_CLAIMS') END,
            CASE WHEN v_decision = 'ATTESTED' THEN p_assertion_hash END, CASE WHEN v_decision = 'ATTESTED' THEN p_auth_time END,
            CASE WHEN v_decision = 'ATTESTED' THEN p_acr END, CASE WHEN v_decision = 'ATTESTED' THEN p_amr END, CASE WHEN v_decision = 'ATTESTED' THEN v_expires END);
    IF v_decision = 'REJECTED' THEN
      -- Evento sin sub_hmac ni IP (P2(f), F-PR6-31). El principal solo si la base lo resolvio.
      IF v_reason = 'RATE_LIMITED' THEN
        INSERT INTO platform.session_event (event_type, kind, principal_ref, limit_kind, window_seconds)
        VALUES ('LIMIT_EXCEEDED', v_ex.kind, v_principal, 'P-48', p_p48_window_seconds);
      ELSIF v_reason = 'PRINCIPAL_MISMATCH' THEN
        INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref, peer_principal_ref)
        VALUES ('LOGIN_PRINCIPAL_MISMATCH', v_reason, v_ex.kind, v_principal, v_ex.principal_ref);
      ELSE
        INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref)
        VALUES ('LOGIN_REJECTED', COALESCE(v_reason, 'INVALID_CLAIMS'), v_ex.kind, v_principal);
      END IF;
    END IF;
  END IF;
  -- NO devuelve el principal (N6'): solo si quedo ATTESTED.
  RETURN v_decision = 'ATTESTED';
END
$$;

-- 7. consume_login_assertion (INTERNA) -------------------------------------------------------------------------------------------------------------
-- Sin EXECUTE para ningun rol de runtime: la llamaran open_platform_session / open_case_session (6c, mismas SECURITY DEFINER de grant_owner) en la misma tx que crea la sesion.
-- Devuelve el principal de la asercion o NULL. Verifica en la base: sha256(state) = state_hash de la fila (cierra login CSRF y exchange_ref como portador), kind, target_ref_hash
-- (en LOGIN_CASE sha256(case_ref) debe igualar el de la asercion) y vigencia (<= P-52 desde auth_time), y consume atomicamente (un solo uso).
CREATE FUNCTION platform.consume_login_assertion(p_exchange_ref uuid, p_state text, p_kind text, p_target_ref_hash text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_assertion uuid;
  v_principal text;
BEGIN
  IF p_exchange_ref IS NULL OR p_state IS NULL OR p_state !~ '^[A-Za-z0-9_-]{22,128}$'
     OR COALESCE(p_kind NOT IN ('LOGIN_PLATFORM', 'LOGIN_CASE'), true)
     OR (p_kind = 'LOGIN_CASE') <> (p_target_ref_hash IS NOT NULL) OR (p_target_ref_hash IS NOT NULL AND p_target_ref_hash !~ '^[0-9a-f]{64}$') THEN
    RETURN NULL;
  END IF;
  SELECT a.assertion_ref INTO v_assertion
    FROM platform.oidc_exchange e JOIN platform.login_assertion a ON a.exchange_ref = e.exchange_ref
   WHERE e.exchange_ref = p_exchange_ref AND e.status = 'ATTESTED' AND e.kind = p_kind
     AND e.state_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_state, 'UTF8')), 'hex')
     AND a.decision = 'ATTESTED' AND a.kind = p_kind AND a.state_hash = e.state_hash
     AND a.target_ref_hash IS NOT DISTINCT FROM p_target_ref_hash
     AND a.consumed_at IS NULL AND a.expires_at > pg_catalog.now()
   FOR UPDATE OF a;
  IF NOT FOUND THEN RETURN NULL; END IF;
  UPDATE platform.login_assertion SET consumed_at = pg_catalog.now()
   WHERE assertion_ref = v_assertion AND consumed_at IS NULL AND expires_at > pg_catalog.now()
  RETURNING principal_ref INTO v_principal;
  RETURN v_principal;
END
$$;

-- 8. record_limit_event (P-49/P-50, aplicados por el proceso platform en memoria) ----------------------------------------------------------------
CREATE FUNCTION platform.record_limit_event(p_limit_kind text, p_window_seconds integer)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_principal text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN; END IF;
  IF p_limit_kind IS NULL OR p_limit_kind NOT IN ('P-49', 'P-50') OR p_window_seconds IS NULL OR p_window_seconds < 1 OR p_window_seconds > 86400 THEN RETURN; END IF;
  IF v_principal IS NOT NULL AND v_principal !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RETURN; END IF;
  -- Sin IP (ni completa ni truncada): el origen de un intento anonimo no es necesariamente del equipo (F-PR6-31, LEGAL DECISION si se quisiera persistir).
  INSERT INTO platform.session_event (event_type, principal_ref, limit_kind, window_seconds) VALUES ('LIMIT_EXCEEDED', v_principal, p_limit_kind, p_window_seconds);
END
$$;

-- 9. Retiro de enqueue_oidc_exchange y ACL ------------------------------------------------------------------------------------------------------------
DROP FUNCTION platform.enqueue_oidc_exchange(text, text, text, integer);

REVOKE ALL ON FUNCTION platform.begin_oidc_authorization(text, text, text, text, text, integer, integer, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.complete_oidc_callback(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.exchange_status(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.claim_oidc_exchange(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.record_login_assertion(uuid, text, text, text, smallint, text, timestamptz, text, text[], integer, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.consume_login_assertion(uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.record_limit_event(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.begin_oidc_authorization(text, text, text, text, text, integer, integer, integer, integer) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.complete_oidc_callback(text, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.exchange_status(uuid, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.record_limit_event(text, integer) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.claim_oidc_exchange(integer) TO integrity_verifier;
GRANT EXECUTE ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) TO integrity_verifier;
GRANT EXECUTE ON FUNCTION platform.record_login_assertion(uuid, text, text, text, smallint, text, timestamptz, text, text[], integer, integer, integer) TO integrity_verifier;
-- consume_login_assertion: ningun GRANT (interna).

-- 10. Revocar el CREATE temporal.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

-- 11. Aserciones (fail-closed): firma, dueno, SECURITY DEFINER, search_path, ACL exacta, sin SQL dinamico y reglas por prosrc.
DO $assert$
DECLARE
  spec text[];
  t record;
  r text;
  n integer;
  roles text[] := ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'platform_schema_owner'];
BEGIN
  -- name | EXECUTE exacto (lista ordenada, sin el dueno; vacio = nadie)
  FOREACH spec SLICE 1 IN ARRAY ARRAY[
    ARRAY['begin_oidc_authorization', 'platform_rw'], ARRAY['complete_oidc_callback', 'platform_rw'], ARRAY['exchange_status', 'platform_rw'],
    ARRAY['claim_oidc_exchange', 'integrity_verifier'], ARRAY['record_assertion', 'integrity_verifier'], ARRAY['record_login_assertion', 'integrity_verifier'],
    ARRAY['consume_login_assertion', ''], ARRAY['record_limit_event', 'platform_rw']
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
  -- enqueue_oidc_exchange ya no existe (platform_rw no encola code por una via sin state).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'enqueue_oidc_exchange') THEN
    RAISE EXCEPTION 'platform.enqueue_oidc_exchange debe haberse retirado';
  END IF;
  -- Reglas por codigo.
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'record_login_assertion';
  IF t.prosrc !~ 'session_user <> .integrity_verifier.' OR t.prosrc !~ 'p_auth_time < v_ex\.created_at - c_skew' OR t.prosrc !~ 'p_auth_time \+ pg_catalog\.make_interval'
     OR t.prosrc !~ 'v_principal IS DISTINCT FROM v_ex\.principal_ref' OR t.prosrc !~ 'p_p52_seconds > 300' OR t.prosrc !~ 'NOT_CONFIGURED' THEN
    RAISE EXCEPTION 'platform.record_login_assertion perdio una regla (verifier, auth_time >= created_at - skew, P-52 desde auth_time, mismo principal en LOGIN_CASE, fail-closed)';
  END IF;
  IF t.prosrc ~* 'RETURN\s+v_principal' THEN RAISE EXCEPTION 'platform.record_login_assertion devuelve el principal (N6'')'; END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'consume_login_assertion';
  IF t.prosrc !~ 'consumed_at IS NULL' OR t.prosrc !~ 'state_hash = pg_catalog\.encode\(pg_catalog\.sha256' OR t.prosrc !~ 'target_ref_hash IS NOT DISTINCT FROM p_target_ref_hash' OR t.prosrc !~ 'expires_at > pg_catalog\.now\(\)' THEN
    RAISE EXCEPTION 'platform.consume_login_assertion perdio una regla (state_hash, target_ref_hash, vigencia, un solo uso)';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'record_assertion';
  IF t.prosrc !~ 'e\.kind = .STEP_UP.' OR t.prosrc !~ 'p_auth_time < v_issued - c_skew' OR t.prosrc !~ 'p_auth_time > pg_catalog\.now\(\) \+ c_skew' THEN
    RAISE EXCEPTION 'platform.record_assertion perdio una regla (solo STEP_UP, P-36 estructural, auth_time futuro)';
  END IF;
  -- Solo record_assertion fija attested_at (por codigo).
  IF (SELECT pg_catalog.string_agg(p.proname::pg_catalog.text, ',' ORDER BY p.proname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
       WHERE s.nspname = 'platform' AND p.prosrc ~* 'set\s+attested_at') IS DISTINCT FROM 'record_assertion' THEN
    RAISE EXCEPTION 'solo platform.record_assertion puede fijar attested_at';
  END IF;
  -- Nadie conserva CREATE en el esquema platform.
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
