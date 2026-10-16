-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §6 ("Grants (P6-3)": grant_request y rights_case_grant completos, vida <= P-23, pendiente expira segun P-37; aprobador distinto del
-- solicitante, GRD-RC-10 sin relajar), §10 filas 6c y 6d, §5.4 (P-51); GRD-RC-10 y GRD-RC-12 (step-up obligatorio para aprobar), INV-13; SEC-CNS-006 rev. 5 §1 (ACCEPTED 2026-09-26): P-23 grant <= 4 h (defecto 2 h;
-- renovar = nueva doble aprobacion), P-37 grant_request pendiente vence a 1 h, vencida no aprobable y se registra; F-PR6-40 (tenant y case_ref derivados del caso REAL). Depende de 0059-0061.
--
-- Que agrega (grant_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico, EXECUTE solo platform_rw). El principal sale SIEMPRE de la sesion PLATFORM validada por la base (GUC app.session_sid ->
-- platform.session_principal): ninguna funcion recibe un principal como parametro. Ante un DENY NO lanzan excepcion (devuelven NULL) para que la evidencia (session_event) se confirme; un error de base revierte todo,
-- incluido el consumo del nonce. Sin ledger: solo platform.session_event (respeta TEST-CNS-1470 y la particion de pares).
--   platform.request_grant(case_ref, p51_max, p51_window)            -> request_ref
--       RIGHTS_OPERATOR ACTIVE (el receptor pide para SI MISMO: operator = solicitante = principal de la sesion), sin Membership TENANT (GRD-RC-10), caso REAL (exactamente una fila en app.rights_case, no terminal;
--       el tenant sale de ESA fila), ninguna solicitud PENDING vigente del mismo (caso, operador) (lock por par), step-up REQUEST_GRANT consumido en la MISMA tx (GRD-RC-12). expires_at = now() + 1 h (P-37).
--   platform.approve_grant(case_ref, request_ref, valid_seconds, p51_max, p51_window)  -> grant_ref
--       APPROVER ACTIVE (PRIVACY_LEGAL o SECURITY), distinto del solicitante y del operador (SELF_APPROVAL), solicitud PENDING del caso indicado (FOR UPDATE), VIGENTE (si vencio: no se aprueba y se registra
--       GRANT_REJECTED/REQUEST_EXPIRED, P-37), tenant re-derivado del caso real y coincidente con el de la solicitud, operador todavia RIGHTS_OPERATOR ACTIVE, step-up APPROVE_GRANT sobre la request_ref consumido en la
--       MISMA tx. valid_seconds: NULL = 7200 (defecto 2 h); rango 60..14400 (P-23: > 4 h se RECHAZA, no se recorta). Crea el rights_case_grant con request_ref y approved_by_ref.
-- NO implementado aqui (FINDING F-PR6-43): el cruce "ningun grant del caso lo aprueba el aprobador de una RH2/RH2v del caso" (GRD-RC-10, INV-14) depende del aprobador RH2 con sesion PLATFORM (P6-5, 6d parte 2).
-- NO implementado (FINDING F-PR6-44): vinculo de renovacion de INV-15 (mismo approved_by_ref que el grant original) contradice "renovar = nueva doble aprobacion" (P-23); cada grant es nuevo y doblemente aprobado.

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. request_grant ---------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.request_grant(p_case_ref text, p_p51_max integer, p_p51_window_seconds integer)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_case      constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  v_sid       text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_principal text;
  v_reason    text := NULL;
  v_tenant    uuid;
  v_status    text;
  v_request   uuid;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  v_principal := platform.session_principal(v_sid);
  -- Sin sesion viva no hay principal confiable: sin evento (un INSERT por request sin sesion seria un vector de DoS de escritura, R-SE-07).
  IF v_principal IS NULL THEN RETURN NULL; END IF;
  <<decide>>
  BEGIN
    IF p_case_ref IS NULL OR p_case_ref !~ c_case THEN v_reason := 'INVALID_INPUT'; p_case_ref := NULL; EXIT decide; END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.platform_role = 'RIGHTS_OPERATOR' AND a.status = 'ACTIVE') THEN
      v_reason := 'NO_ROLE'; EXIT decide;
    END IF;
    -- GRD-RC-10: el operador no tiene Membership TENANT.
    IF EXISTS (SELECT 1 FROM platform.tenant_membership m WHERE m.principal_ref = v_principal) THEN v_reason := 'TENANT_MEMBER'; EXIT decide; END IF;
    -- Una solicitud por (caso, operador) a la vez: el lock serializa solicitudes concurrentes del mismo par.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.grant.' || v_principal || '.' || p_case_ref, 0));
    -- F-PR6-40: tenant del caso REAL (no de la request).
    SELECT c.o_tenant_id, c.o_status INTO v_tenant, v_status FROM platform.rights_case_of(p_case_ref) c;
    IF v_tenant IS NULL THEN v_reason := 'CASE_NOT_FOUND'; EXIT decide; END IF;
    IF v_status IN ('RESOLVED', 'WITHDRAWN') THEN v_reason := 'CASE_CLOSED'; EXIT decide; END IF;
    IF EXISTS (SELECT 1 FROM platform.grant_request r
                WHERE r.tenant_id = v_tenant AND r.case_ref = p_case_ref AND r.operator_principal_ref = v_principal AND r.status = 'PENDING' AND r.expires_at > pg_catalog.now()) THEN
      v_reason := 'REQUEST_PENDING'; EXIT decide;
    END IF;
    -- GRD-RC-12: step-up REQUEST_GRANT (nonce ATTESTED, ligado a este operador y a este caso) consumido en ESTA transaccion, justo antes del efecto.
    v_reason := platform.consume_step_up(v_principal, 'REQUEST_GRANT', p_case_ref, p_p51_max, p_p51_window_seconds);
    IF v_reason IS NOT NULL THEN EXIT decide; END IF;
    -- P-37: la solicitud pendiente vence a 1 h.
    INSERT INTO platform.grant_request (tenant_id, case_ref, operator_principal_ref, requested_by_ref, expires_at)
    VALUES (v_tenant, p_case_ref, v_principal, v_principal, pg_catalog.now() + interval '1 hour')
    RETURNING request_ref INTO v_request;
    INSERT INTO platform.session_event (event_type, principal_ref, case_ref, request_ref) VALUES ('GRANT_REQUESTED', v_principal, p_case_ref, v_request);
  END;
  IF v_reason IS NOT NULL THEN
    INSERT INTO platform.session_event (event_type, reason_code, principal_ref, case_ref) VALUES ('GRANT_REJECTED', v_reason, v_principal, p_case_ref);
    RETURN NULL;
  END IF;
  RETURN v_request;
END
$$;

-- 2. approve_grant ---------------------------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.approve_grant(p_case_ref text, p_request_ref uuid, p_valid_seconds integer, p_p51_max integer, p_p51_window_seconds integer)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_case      constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  -- P-23 (SEC-CNS-006 rev. 5 §1, ACCEPTED 2026-09-26): defecto 2 h, maximo 4 h. Piso tecnico de 60 s.
  c_default   constant integer := 7200;
  c_max       constant integer := 14400;
  v_sid       text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_principal text;
  v_reason    text := NULL;
  v_req       platform.grant_request%ROWTYPE;
  v_tenant    uuid;
  v_status    text;
  v_seconds   integer;
  v_grant     uuid;
  v_peer      text := NULL;
BEGIN
  IF session_user <> 'platform_rw' THEN RETURN NULL; END IF;
  v_principal := platform.session_principal(v_sid);
  IF v_principal IS NULL THEN RETURN NULL; END IF;
  <<decide>>
  BEGIN
    IF p_case_ref IS NULL OR p_case_ref !~ c_case OR p_request_ref IS NULL THEN v_reason := 'INVALID_INPUT'; p_case_ref := NULL; EXIT decide; END IF;
    v_seconds := COALESCE(p_valid_seconds, c_default);
    IF v_seconds < 60 OR v_seconds > c_max THEN v_reason := 'INVALID_INPUT'; EXIT decide; END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_principal AND a.platform_role = 'APPROVER' AND a.status = 'ACTIVE') THEN
      v_reason := 'NO_ROLE'; EXIT decide;
    END IF;
    -- La solicitud DEL CASO indicado, bloqueada: dos aprobaciones concurrentes se serializan y la segunda la ve APPROVED.
    SELECT * INTO v_req FROM platform.grant_request r WHERE r.request_ref = p_request_ref AND r.case_ref = p_case_ref FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
    v_peer := v_req.operator_principal_ref;
    IF v_req.status <> 'PENDING' THEN v_reason := 'REQUEST_NOT_PENDING'; EXIT decide; END IF;
    -- P-37: una solicitud vencida NO es aprobable (se registra como REQUEST_EXPIRED). El CHECK de la tabla tambien lo impide.
    IF v_req.expires_at <= pg_catalog.now() THEN v_reason := 'REQUEST_EXPIRED'; EXIT decide; END IF;
    -- GRD-RC-10: aprobador distinto del solicitante y del operador receptor.
    IF v_req.requested_by_ref = v_principal OR v_req.operator_principal_ref = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
    -- F-PR6-40: el tenant se RE-DERIVA del caso real y debe coincidir con el de la solicitud.
    SELECT c.o_tenant_id, c.o_status INTO v_tenant, v_status FROM platform.rights_case_of(p_case_ref) c;
    IF v_tenant IS NULL OR v_tenant <> v_req.tenant_id THEN v_reason := 'CASE_NOT_FOUND'; EXIT decide; END IF;
    IF v_status IN ('RESOLVED', 'WITHDRAWN') THEN v_reason := 'CASE_CLOSED'; EXIT decide; END IF;
    -- El operador sigue siendo RIGHTS_OPERATOR ACTIVE (el rol pudo cambiar durante la hora de vigencia de la solicitud).
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_req.operator_principal_ref AND a.platform_role = 'RIGHTS_OPERATOR' AND a.status = 'ACTIVE') THEN
      v_reason := 'OPERATOR_INACTIVE'; EXIT decide;
    END IF;
    -- GRD-RC-12: step-up APPROVE_GRANT (ligado a este aprobador y a ESTA solicitud) consumido en ESTA transaccion, justo antes del efecto.
    v_reason := platform.consume_step_up(v_principal, 'APPROVE_GRANT', p_request_ref::pg_catalog.text, p_p51_max, p_p51_window_seconds);
    IF v_reason IS NOT NULL THEN EXIT decide; END IF;
    UPDATE platform.grant_request SET status = 'APPROVED', approved_by_ref = v_principal, approved_at = pg_catalog.now() WHERE request_ref = v_req.request_ref AND status = 'PENDING';
    IF NOT FOUND THEN v_reason := 'REQUEST_NOT_PENDING'; EXIT decide; END IF;
    INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at, request_ref, approved_by_ref)
    VALUES (v_req.tenant_id, v_req.case_ref, v_req.operator_principal_ref, pg_catalog.now() + pg_catalog.make_interval(secs => v_seconds), v_req.request_ref, v_principal)
    RETURNING grant_ref INTO v_grant;
    INSERT INTO platform.session_event (event_type, principal_ref, peer_principal_ref, case_ref, request_ref) VALUES ('GRANT_APPROVED', v_principal, v_peer, p_case_ref, v_req.request_ref);
  END;
  IF v_reason IS NOT NULL THEN
    INSERT INTO platform.session_event (event_type, reason_code, principal_ref, peer_principal_ref, case_ref, request_ref)
    VALUES ('GRANT_REJECTED', v_reason, v_principal, v_peer, p_case_ref, CASE WHEN v_peer IS NOT NULL THEN p_request_ref END);
    RETURN NULL;
  END IF;
  RETURN v_grant;
END
$$;

REVOKE ALL ON FUNCTION platform.request_grant(text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.approve_grant(text, uuid, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.request_grant(text, integer, integer) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.approve_grant(text, uuid, integer, integer, integer) TO platform_rw;

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
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['request_grant', 'platform_rw'], ARRAY['approve_grant', 'platform_rw']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0062: platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0062: platform.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION '0062: PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0062: la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '0062: % puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0062: platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
    IF t.prosrc ~ 'app\.principal_ref' OR t.prosrc !~ 'platform\.session_principal\(v_sid\)' OR t.prosrc !~ 'platform\.consume_step_up\(' OR t.prosrc !~ 'platform\.rights_case_of\(p_case_ref\)'
       OR t.prosrc !~ 'session_user <> .platform_rw.' THEN
      RAISE EXCEPTION '0062: platform.% perdio una regla (principal de la sesion, step-up en la misma tx, caso real)', spec[1];
    END IF;
    IF pg_catalog.pg_get_function_arguments(t.oid) ~* 'principal|tenant' THEN RAISE EXCEPTION '0062: platform.% no puede recibir principal ni tenant como parametro', spec[1]; END IF;
  END LOOP;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'approve_grant';
  IF t.prosrc !~ 'SELF_APPROVAL' OR t.prosrc !~ 'REQUEST_EXPIRED' OR t.prosrc !~ 'c_max' OR t.prosrc !~ 'FOR UPDATE' OR t.prosrc !~ 'APPROVE_GRANT' THEN
    RAISE EXCEPTION '0062: platform.approve_grant perdio una regla (aprobador distinto, P-37, P-23, lock de la solicitud, step-up APPROVE_GRANT)';
  END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'request_grant';
  IF t.prosrc !~ 'REQUEST_GRANT' OR t.prosrc !~ 'RIGHTS_OPERATOR' OR t.prosrc !~ 'interval ''1 hour''' THEN
    RAISE EXCEPTION '0062: platform.request_grant perdio una regla (RIGHTS_OPERATOR, step-up REQUEST_GRANT, P-37 1 h)';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0062: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
