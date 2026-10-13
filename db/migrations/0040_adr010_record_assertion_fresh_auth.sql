-- scope: database
-- Gobierna: ADR-010 rev. 4 (Notion), decision de Carlos del 2026-10-12 registrada bajo PR-4 #87: "(1) P-36 step-up exige reautenticacion fresca (auth_time >= issued_at del
-- nonce - skew; prompt=login/max_age); (2) MFA/acr obligatorio fuera de LOCAL (requiredAcrAnyOf no vacio)". Plan: ADR-010 PR-6-0. Hallazgos: registers/findings-register-IT0.md
-- F-A10-20 y F-A10-21 (parcial), F-PR6-03. 0036 ya esta mergeada y es inmutable (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- Que cambia: platform.record_assertion (CREATE OR REPLACE; misma firma, dueno grant_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp y ACL intactos).
-- Antes solo rechazaba un auth_time futuro; ahora, para ATTESTED, ademas rechaza (REJECTED / INVALID_CLAIMS, sin atestar el nonce) si auth_time < action_nonce.issued_at - skew.
-- (2) MFA/acr fuera de LOCAL se impone en el verifier (TS, validateVerifierConfig); la base no conoce la lista de acr (APR-IDP: PENDING).
-- Tolerancia (skew): la base NO tenia un parametro de skew; se reutiliza el unico valor que ya existia en esta funcion (interval '2 minutes', tolerancia de auth_time futuro,
-- igual a MAX_CLOCK_SKEW_SECONDS de id-token.ts). NO es un valor aprobado por Carlos: queda explicito como c_skew para que un cambio futuro sea un CREATE OR REPLACE.
-- Tampoco se fija aqui el valor numerico de P-36 (edad maxima del auth_time): sigue PENDING (placeholder MAX_AUTH_AGE_CAP_SECONDS).
-- Idempotente: CREATE OR REPLACE y GRANT/REVOKE repetibles. prompt=login / max_age van en PR-6b (no existe aun la redireccion al IdP).

-- 0. CREATE temporal para grant_owner (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

-- 1. record_assertion v2 (grant_owner).
SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- NOTA: exige un lease vigente (claim_oidc_exchange). Ver 0036 para el modelo completo (N6: sub_hmac <-> principal_ref; unica via de attested_at).
CREATE OR REPLACE FUNCTION platform.record_assertion(
    p_exchange_ref uuid, p_decision text, p_reason text, p_sub_hmac text, p_assertion_hash text, p_auth_time timestamptz, p_acr text, p_amr text[])
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy   constant text := 'ADR010-PR4-v1';
  c_hex      constant text := '^[0-9a-f]{64}$';
  -- Tolerancia de reloj: la misma que ya usaba esta funcion para auth_time futuro (2 min = MAX_CLOCK_SKEW_SECONDS de id-token.ts). Valor no aprobado por Carlos: ver cabecera.
  c_skew     constant interval := interval '2 minutes';
  -- c_skew debe ser <= skew del verifier TS (DEFAULT_CLOCK_SKEW_SECONDS = 30 s): hoy es MAS laxo (F-PR6-07); cerrar antes de cualquier entorno no LOCAL.
  v_ex       platform.oidc_exchange%ROWTYPE;
  v_found    boolean := false;
  v_reason   text := NULL;
  v_decision text := 'REJECTED';
  v_mapped   text;
  v_action   text;
  v_tenant   uuid;
  v_issued   timestamptz;
  v_input_ok boolean;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'integrity_verifier' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    SELECT * INTO v_ex FROM platform.oidc_exchange e
     WHERE e.exchange_ref = p_exchange_ref AND e.status = 'PENDING' AND e.expires_at > pg_catalog.now()
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
      -- Entrada invalida: la solicitud se cierra REJECTED/INVALID_CLAIMS (y se anulan los secretos); nunca queda un ATTESTED parcial.
      v_reason := 'INVALID_CLAIMS'; EXIT decide;
    END IF;
    IF p_decision = 'REJECTED' THEN v_reason := p_reason; EXIT decide; END IF;

    -- ATTESTED solicitado: N6 (sub_hmac <-> principal_ref), auth_time razonable, nonce vigente del mismo principal y binding.
    SELECT i.sub_hmac INTO v_mapped FROM platform.principal_identity i WHERE i.principal_ref = v_ex.principal_ref;
    IF v_mapped IS NULL OR v_mapped <> p_sub_hmac THEN v_reason := 'SUB_MISMATCH'; EXIT decide; END IF;
    IF p_auth_time > pg_catalog.now() + c_skew THEN v_reason := 'INVALID_CLAIMS'; EXIT decide; END IF;
    SELECT n.action, n.tenant_id, n.issued_at INTO v_action, v_tenant, v_issued FROM platform.action_nonce n
     WHERE n.nonce_hash = v_ex.binding AND n.principal_ref = v_ex.principal_ref AND n.attested_at IS NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    -- Decision de Carlos (2026-10-12, ADR-010 rev. 4 PR-4 #87, P-36 (1)): el step-up exige reautenticacion FRESCA: el auth_time del IdP no puede ser anterior a la emision del nonce (menos la tolerancia).
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

REVOKE ALL ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) TO integrity_verifier;

-- 2. Revocar el CREATE temporal.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

-- 3. Aserciones: firma, dueno, SECURITY DEFINER, search_path, ACL exacta y la nueva regla (por prosrc).
DO $assert$
DECLARE
  t record;
  r text;
  n integer;
BEGIN
  SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'platform' AND p.proname = 'record_assertion';
  IF n <> 1 THEN RAISE EXCEPTION 'platform.record_assertion debe existir exactamente una vez (hay %)', n; END IF;
  SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, p.prorettype::pg_catalog.regtype::pg_catalog.text AS rettype,
         pg_catalog.pg_get_function_identity_arguments(p.oid) AS args, pg_catalog.pg_get_userbyid(p.proowner) AS owner
    INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'platform' AND p.proname = 'record_assertion';
  IF t.args <> 'p_exchange_ref uuid, p_decision text, p_reason text, p_sub_hmac text, p_assertion_hash text, p_auth_time timestamp with time zone, p_acr text, p_amr text[]'
     OR t.rettype <> 'boolean' THEN RAISE EXCEPTION 'platform.record_assertion cambio de firma'; END IF;
  IF t.owner <> 'grant_owner' THEN RAISE EXCEPTION 'platform.record_assertion no pertenece a grant_owner'; END IF;
  IF NOT t.prosecdef THEN RAISE EXCEPTION 'platform.record_assertion debe ser SECURITY DEFINER'; END IF;
  IF t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'platform.record_assertion sin search_path fijo exacto'; END IF;
  IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar platform.record_assertion'; END IF;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
        FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner) IS DISTINCT FROM 'integrity_verifier' THEN
    RAISE EXCEPTION 'la ACL de platform.record_assertion no es exactamente EXECUTE para integrity_verifier';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'platform_schema_owner'] LOOP
    IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar platform.record_assertion', r; END IF;
  END LOOP;
  IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'platform.record_assertion contiene EXECUTE (SQL dinamico prohibido)'; END IF;
  IF t.prosrc !~ 'p_auth_time < v_issued - c_skew' OR t.prosrc !~ 'n\.issued_at INTO' THEN RAISE EXCEPTION 'platform.record_assertion no impone auth_time >= issued_at - skew (P-36)'; END IF;
  IF t.prosrc !~ 'p_auth_time > pg_catalog\.now\(\) \+ c_skew' THEN RAISE EXCEPTION 'platform.record_assertion perdio el rechazo de auth_time futuro'; END IF;
  IF t.prosrc !~ 'session_user <> .integrity_verifier.' THEN RAISE EXCEPTION 'platform.record_assertion perdio la comprobacion del llamador'; END IF;
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
