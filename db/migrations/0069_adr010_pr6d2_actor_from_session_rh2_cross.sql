-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.d y §10 fila 6d (funciones de operador con actor desde la sesion: platform.require_case_actor / require_platform_actor, EXECUTE solo
-- transition_owner), §6 (GRD-RC-10 sin relajar: "el aprobador debe ser PRIVACY_LEGAL/SECURITY, distinto del solicitante y del aprobador de RH2 del caso"; P6-5: aprobador de RH2 con sesion PLATFORM), §5.4 (P-51);
-- GRD-RC-10, GRD-RC-12, INV-13, INV-14 (specs/state-machines/rights-case.spec.yaml); F-PR6-43 (condicion de merge de Carlos, 2026-10-15), F-PR6-39, F-A10-26/27; F-PR6-25 (alerta de RH3 por platform).
-- Depende de 0059-0063 y 0066-0068. 0000-0065 son inmutables: los reemplazos van aqui, con las MISMAS firmas.
--
-- Que agrega (grant_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico):
--   platform.case_verification (tabla, dueno grant_owner, FORCE RLS, append-only, sin privilegios de runtime): aprobaciones de RH2 por principal PLATFORM (tenant, caso, revocation, proposal, proponente, aprobador). Es lo que
--       permite el cruce GRD-RC-10 en ambos sentidos con identidades comparables. F-A10-27 (mover TODA la propuesta RH2 a esta tabla) sigue ABIERTO: la propuesta sigue en app.revocation, ahora con el principal de la sesion.
--   platform.require_case_actor(case_ref, role) -> principal  (EXECUTE solo transition_owner): valida EN LA BASE la sesion CASE (GUC app.session_sid; revalida rol, grant, sesion PLATFORM padre, caso real y Membership),
--       exige que el caso de la sesion sea el pedido y FIJA app.tenant_id desde la sesion (nunca desde la request). Si no, SQLSTATE RC004 (404 uniforme).
--   platform.require_platform_actor(role, case_ref) -> principal  (EXECUTE solo transition_owner): igual con la sesion PLATFORM y el rol (APPROVER) ACTIVE, sin Membership TENANT; el tenant sale del caso REAL (rights_case_of).
--   platform.record_rh2_approval(revocation_ref, case_ref, proposal_ref, proposed_by, approver) (EXECUTE solo transition_owner): cruce GRD-RC-10 (el aprobador de RH2 no es aprobador NI receptor de un grant del caso) y registro.
--   platform.alert_case_apply_exhausted(revocation_ref) (EXECUTE platform_rw): alerta de agotamiento de RH3 por la sesion CASE validada (tenant de la sesion) via ops.record_revocation_apply_alert (0067).
--   issue_step_up_nonce / consume_step_up REEMPLAZADAS: admiten tambien PROPOSE/APPROVE/WITHDRAW_CASE_VERIFICATION (RH2; GRD-RC-12). Propose y withdraw: RIGHTS_OPERATOR; approve: APPROVER. consume_step_up (interna) pasa a ser
--       EXECUTE de transition_owner: la llaman las funciones de RH2 en la misma tx que el efecto.
--   approve_grant REEMPLAZADA: rechaza (GRANT_REJECTED / RH2_APPROVER) al aprobador de una RH2 del caso. rights_case_grant_insert_guard REEMPLAZADA: el mismo cruce como red de seguridad de la base (un grant no nace
--       con aprobador = aprobador de RH2 del caso). Un test cubre ambos caminos; GRD-RC-10 sale de traceability/x8-exceptions.csv.
-- Decision de Carlos 2026-10-15 (F-PR6-44, opcion A): sin renovaciones; request_grant ya rechaza GRANT_ACTIVE (0062).

SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;
GRANT USAGE ON SCHEMA platform TO transition_owner;
SET LOCAL ROLE consent_owner;
-- grant_owner llama ops.record_revocation_apply_alert (dueno security_event_owner, 0067): USAGE sobre ops y EXECUTE (permanente y minimo; grant_owner no es asumible por runtime).
GRANT USAGE ON SCHEMA ops TO grant_owner;
SET LOCAL ROLE security_event_owner;
GRANT EXECUTE ON FUNCTION ops.record_revocation_apply_alert(text, text) TO grant_owner;
SET LOCAL ROLE consent_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. platform.case_verification ----------------------------------------------------------------------------------------------------------
CREATE TABLE platform.case_verification (
  verification_ref uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT case_verification_pkey PRIMARY KEY,
  tenant_id        uuid        NOT NULL,
  case_ref         text        NOT NULL CONSTRAINT case_verification_case_ref_shape CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  revocation_ref   text        NOT NULL CONSTRAINT case_verification_revocation_ref_shape CHECK (revocation_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  proposal_ref     text        NOT NULL CONSTRAINT case_verification_proposal_ref_shape CHECK (proposal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  proposed_by_ref  text        NOT NULL CONSTRAINT case_verification_proposed_by_shape CHECK (proposed_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  approved_by_ref  text        NOT NULL CONSTRAINT case_verification_approved_by_shape CHECK (approved_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  approved_at      timestamptz NOT NULL DEFAULT pg_catalog.now(),
  data_class       text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT case_verification_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT case_verification_distinct CHECK (approved_by_ref <> proposed_by_ref),
  CONSTRAINT case_verification_proposal_uq UNIQUE (tenant_id, proposal_ref)
);
CREATE INDEX case_verification_case_idx ON platform.case_verification (tenant_id, case_ref);
ALTER TABLE platform.case_verification ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.case_verification FORCE ROW LEVEL SECURITY;
CREATE POLICY case_verification_owner_select ON platform.case_verification FOR SELECT TO grant_owner USING (true);
CREATE POLICY case_verification_owner_insert ON platform.case_verification FOR INSERT TO grant_owner WITH CHECK (true);
REVOKE ALL ON platform.case_verification FROM PUBLIC;

CREATE FUNCTION platform.case_verification_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'platform.case_verification es append-only (GRD-RC-10, INV-14)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.case_verification_guard() FROM PUBLIC;
CREATE TRIGGER case_verification_no_mutation BEFORE UPDATE OR DELETE ON platform.case_verification FOR EACH ROW EXECUTE FUNCTION platform.case_verification_guard();
CREATE TRIGGER case_verification_no_truncate BEFORE TRUNCATE ON platform.case_verification FOR EACH STATEMENT EXECUTE FUNCTION platform.case_verification_guard();
ALTER TABLE platform.case_verification ENABLE ALWAYS TRIGGER case_verification_no_mutation;
ALTER TABLE platform.case_verification ENABLE ALWAYS TRIGGER case_verification_no_truncate;

-- 2. Red de seguridad en la base: un grant no nace con aprobador = aprobador de RH2 del caso (GRD-RC-10, INV-14).
CREATE OR REPLACE FUNCTION platform.rights_case_grant_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM platform.case_verification cv WHERE cv.tenant_id = NEW.tenant_id AND cv.case_ref = NEW.case_ref AND cv.approved_by_ref = NEW.approved_by_ref) THEN
    RAISE EXCEPTION 'platform.rights_case_grant: el aprobador de una RH2 del caso no aprueba grants del caso (GRD-RC-10, INV-14)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM platform.grant_request r
              WHERE r.request_ref = NEW.request_ref AND r.status = 'APPROVED' AND r.approved_by_ref = NEW.approved_by_ref AND r.requested_by_ref <> NEW.approved_by_ref) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.rights_case_grant: solo nace de una grant_request APPROVED por ese aprobador, distinto del solicitante (ADR-010 §6, GRD-RC-10, P-37)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

-- 3. Actor desde la sesion ---------------------------------------------------------------------------------------------------------------
CREATE FUNCTION platform.require_case_actor(p_case_ref text, p_role text) RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_sid       text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_session   record;
  v_tenant    uuid;
BEGIN
  IF session_user <> 'platform_rw' OR p_role IS DISTINCT FROM 'RIGHTS_OPERATOR' OR p_case_ref IS NULL OR v_sid IS NULL OR v_sid !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'sesion CASE no valida' USING ERRCODE = 'RC004';
  END IF;
  -- validate_session revalida en esta llamada rol, grant, sesion PLATFORM padre, caso real/tenant y Membership; devuelve vacio si algo falla.
  SELECT v.* INTO v_session FROM platform.validate_session(v_sid, 'CASE') v;
  IF v_session.o_principal_ref IS NULL OR v_session.o_case_ref IS DISTINCT FROM p_case_ref THEN
    RAISE EXCEPTION 'sesion CASE no valida' USING ERRCODE = 'RC004';
  END IF;
  SELECT s.tenant_id INTO v_tenant FROM platform.platform_session s WHERE s.session_ref = v_session.o_session_ref;
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'sesion CASE no valida' USING ERRCODE = 'RC004'; END IF;
  -- El tenant sale de la sesion (grant del caso real), nunca de la request: se fija para el resto de la tx.
  PERFORM pg_catalog.set_config('app.tenant_id', v_tenant::pg_catalog.text, true);
  RETURN v_session.o_principal_ref;
END
$$;

CREATE FUNCTION platform.require_platform_actor(p_role text, p_case_ref text) RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_sid       text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_session   record;
  v_tenant    uuid;
  v_status    text;
BEGIN
  IF session_user <> 'platform_rw' OR p_role IS DISTINCT FROM 'APPROVER' OR p_case_ref IS NULL OR v_sid IS NULL OR v_sid !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'sesion PLATFORM no valida' USING ERRCODE = 'RC004';
  END IF;
  SELECT v.* INTO v_session FROM platform.validate_session(v_sid, 'PLATFORM') v;
  IF v_session.o_principal_ref IS NULL THEN RAISE EXCEPTION 'sesion PLATFORM no valida' USING ERRCODE = 'RC004'; END IF;
  IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_session.o_principal_ref AND a.platform_role = p_role AND a.status = 'ACTIVE')
     OR EXISTS (SELECT 1 FROM platform.tenant_membership m WHERE m.principal_ref = v_session.o_principal_ref) THEN
    RAISE EXCEPTION 'rol no autorizado' USING ERRCODE = 'RC004';
  END IF;
  -- El tenant sale del caso REAL (una sola fila, no terminal).
  SELECT c.o_tenant_id, c.o_status INTO v_tenant, v_status FROM platform.rights_case_of(p_case_ref) c;
  IF v_tenant IS NULL OR v_status IN ('RESOLVED', 'WITHDRAWN') THEN RAISE EXCEPTION 'caso no valido' USING ERRCODE = 'RC004'; END IF;
  PERFORM pg_catalog.set_config('app.tenant_id', v_tenant::pg_catalog.text, true);
  RETURN v_session.o_principal_ref;
END
$$;

CREATE FUNCTION platform.record_rh2_approval(p_revocation_ref text, p_case_ref text, p_proposal_ref text, p_proposed_by text, p_approver text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RC004'; END IF;
  -- GRD-RC-10 / INV-14 (en el otro sentido): el aprobador de RH2 no es aprobador NI receptor de ningun grant del caso.
  IF EXISTS (SELECT 1 FROM platform.rights_case_grant g
              WHERE g.tenant_id = v_tenant AND g.case_ref = p_case_ref AND (g.approved_by_ref = p_approver OR g.operator_principal_ref = p_approver))
     OR EXISTS (SELECT 1 FROM platform.grant_request r
                 WHERE r.tenant_id = v_tenant AND r.case_ref = p_case_ref AND r.status = 'PENDING' AND (r.operator_principal_ref = p_approver OR r.requested_by_ref = p_approver)) THEN
    RAISE EXCEPTION 'el aprobador de RH2 no es aprobador ni receptor de un grant del caso' USING ERRCODE = 'RC004';
  END IF;
  INSERT INTO platform.case_verification (tenant_id, case_ref, revocation_ref, proposal_ref, proposed_by_ref, approved_by_ref)
  VALUES (v_tenant, p_case_ref, p_revocation_ref, p_proposal_ref, p_proposed_by, p_approver);
END
$$;

CREATE FUNCTION platform.alert_case_apply_exhausted(p_revocation_ref text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_sid     text := NULLIF(pg_catalog.current_setting('app.session_sid', true), '');
  v_session record;
  v_tenant  uuid;
BEGIN
  IF session_user <> 'platform_rw' OR v_sid IS NULL OR v_sid !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'sesion CASE no valida' USING ERRCODE = 'RC004'; END IF;
  SELECT v.* INTO v_session FROM platform.validate_session(v_sid, 'CASE') v;
  IF v_session.o_principal_ref IS NULL THEN RAISE EXCEPTION 'sesion CASE no valida' USING ERRCODE = 'RC004'; END IF;
  SELECT s.tenant_id INTO v_tenant FROM platform.platform_session s WHERE s.session_ref = v_session.o_session_ref;
  PERFORM pg_catalog.set_config('app.tenant_id', v_tenant::pg_catalog.text, true);
  PERFORM ops.record_revocation_apply_alert(p_revocation_ref, 'R4_RETRIES_EXHAUSTED');
END
$$;

-- 4. Reemplazos con la misma firma (ACL de 0061/0062 conservada) -------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION platform.issue_step_up_nonce(p_action text, p_target_ref text, p_ttl_seconds integer)
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
    IF p_action IS NULL OR p_action NOT IN ('REQUEST_GRANT', 'APPROVE_GRANT', 'PROPOSE_CASE_VERIFICATION', 'APPROVE_CASE_VERIFICATION', 'WITHDRAW_CASE_VERIFICATION') THEN v_reason := 'UNKNOWN_ACTION'; EXIT decide; END IF;
    -- El principal sale de la sesion PLATFORM validada por la base, nunca de la request (F-PR6-39).
    v_principal := platform.session_principal(v_sid);
    IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; v_principal := NULL; EXIT decide; END IF;
    IF p_target_ref IS NULL OR p_target_ref !~ (CASE WHEN p_action <> 'APPROVE_GRANT' THEN c_principal ELSE c_uuid END) THEN v_reason := 'INVALID_RESOURCE'; EXIT decide; END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 600 THEN v_reason := 'INVALID_TTL'; EXIT decide; END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a
                    WHERE a.principal_ref = v_principal AND a.status = 'ACTIVE'
                      AND a.platform_role = CASE WHEN p_action IN ('REQUEST_GRANT', 'PROPOSE_CASE_VERIFICATION', 'WITHDRAW_CASE_VERIFICATION') THEN 'RIGHTS_OPERATOR' ELSE 'APPROVER' END) THEN
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
          CASE WHEN p_action IN ('REQUEST_GRANT', 'APPROVE_GRANT', 'PROPOSE_CASE_VERIFICATION', 'APPROVE_CASE_VERIFICATION', 'WITHDRAW_CASE_VERIFICATION') THEN p_action END,
          v_principal,
          CASE WHEN p_target_ref ~ c_uuid THEN p_target_ref END,
          CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  IF v_reason IS NOT NULL THEN RETURN NULL; END IF;
  RETURN v_nonce;
END
$$;

-- 2. consume_step_up (interna) -------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION platform.consume_step_up(p_principal text, p_action text, p_target_ref text, p_p51_max integer, p_p51_window_seconds integer)
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
  v_count     integer;
BEGIN
  IF p_principal IS NULL OR p_principal !~ c_principal OR p_action IS NULL OR p_action NOT IN ('REQUEST_GRANT', 'APPROVE_GRANT', 'PROPOSE_CASE_VERIFICATION', 'APPROVE_CASE_VERIFICATION', 'WITHDRAW_CASE_VERIFICATION') OR p_target_ref IS NULL
     OR p_p51_max IS NULL OR p_p51_max < 1 OR p_p51_max > 1000 OR p_p51_window_seconds IS NULL OR p_p51_window_seconds < 60 OR p_p51_window_seconds > 86400 THEN
    RETURN 'INVALID_INPUT';
  END IF;
  <<decide>>
  BEGIN
    -- P-51: lock por operador (el MISMO que begin_oidc_authorization) ANTES de contar. El conteo incluye el inicio de ESTE step-up (STEP_UP_BEGIN) y los consumos fallidos previos.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('platform.p51.' || p_principal, 0));
    SELECT pg_catalog.count(*)::integer INTO v_count FROM platform.session_event s
     WHERE s.event_type IN ('STEP_UP_BEGIN', 'STEP_UP_REJECTED') AND s.principal_ref = p_principal AND s.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds);
    -- Nonce ATTESTED del mismo principal, accion y destino (sha256(target_ref)), vigente y sin consumir, con la aserción del IdP atestada para ese binding y principal.
    SELECT n.nonce_hash, g.auth_time INTO v_nonce, v_auth_time FROM platform.action_nonce n
      JOIN platform.grant_assertion g ON g.binding = n.nonce_hash AND g.decision = 'ATTESTED' AND g.principal_ref = n.principal_ref
     WHERE n.principal_ref = p_principal AND n.action = p_action AND n.scope = 'PLATFORM' AND n.tenant_id IS NULL
       AND n.refs_digest = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_target_ref, 'UTF8')), 'hex')
       AND n.attested_at IS NOT NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     ORDER BY n.issued_at LIMIT 1 FOR UPDATE OF n;
    IF v_nonce IS NULL THEN v_reason := 'STEP_UP_MISSING';
    ELSIF v_auth_time IS NULL OR v_auth_time < pg_catalog.now() - c_p52 THEN v_reason := 'ASSERTION_STALE';
    END IF;
    IF v_reason IS NULL THEN
      -- Exito permitido con conteo <= P-51 (el inicio de este step-up ya esta contado: P-51 inicios legitimos, P-51 acciones).
      IF v_count > p_p51_max THEN v_reason := 'RATE_LIMITED'; END IF;
    ELSIF v_count >= p_p51_max THEN
      -- Un intento FALLIDO que ya no cabe en P-51: se rechaza como RATE_LIMITED sin registrar otro STEP_UP_REJECTED (el conteo no crece sobre el limite).
      v_reason := 'RATE_LIMITED';
    END IF;
    IF v_reason = 'RATE_LIMITED' THEN
      -- UN solo evento de limite por (limite, principal) y ventana (un flood no infla session_event).
      IF NOT EXISTS (SELECT 1 FROM platform.session_event e
                      WHERE e.event_type = 'LIMIT_EXCEEDED' AND e.limit_kind = 'P-51' AND e.principal_ref = p_principal
                        AND e.at > pg_catalog.now() - pg_catalog.make_interval(secs => p_p51_window_seconds)) THEN
        INSERT INTO platform.session_event (event_type, kind, principal_ref, limit_kind, window_seconds) VALUES ('LIMIT_EXCEEDED', 'STEP_UP', p_principal, 'P-51', p_p51_window_seconds);
      END IF;
      RETURN v_reason;
    END IF;
    IF v_reason IS NULL THEN
      UPDATE platform.action_nonce SET consumed_at = pg_catalog.now() WHERE nonce_hash = v_nonce AND consumed_at IS NULL;
      IF NOT FOUND THEN v_reason := 'STEP_UP_MISSING'; END IF;
    END IF;
  END;
  IF v_reason IS NOT NULL THEN
    INSERT INTO platform.session_event (event_type, reason_code, kind, principal_ref) VALUES ('STEP_UP_REJECTED', v_reason, 'STEP_UP', p_principal);
  END IF;
  RETURN v_reason;
END
$$;


CREATE OR REPLACE FUNCTION platform.approve_grant(p_case_ref text, p_request_ref uuid, p_valid_seconds integer, p_p51_max integer, p_p51_window_seconds integer)
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
    -- GRD-RC-10 / INV-14 (F-PR6-43, condicion de merge de Carlos): el aprobador de una RH2 del caso (platform.case_verification) no aprueba ningun grant de ese caso.
    IF EXISTS (SELECT 1 FROM platform.case_verification cv WHERE cv.tenant_id = v_req.tenant_id AND cv.case_ref = p_case_ref AND cv.approved_by_ref = v_principal) THEN
      v_reason := 'RH2_APPROVER'; EXIT decide;
    END IF;
    -- F-PR6-40: el tenant se RE-DERIVA del caso real y debe coincidir con el de la solicitud.
    SELECT c.o_tenant_id, c.o_status INTO v_tenant, v_status FROM platform.rights_case_of(p_case_ref) c;
    IF v_tenant IS NULL OR v_tenant <> v_req.tenant_id THEN v_reason := 'CASE_NOT_FOUND'; EXIT decide; END IF;
    IF v_status IN ('RESOLVED', 'WITHDRAWN') THEN v_reason := 'CASE_CLOSED'; EXIT decide; END IF;
    -- El operador sigue siendo RIGHTS_OPERATOR ACTIVE (el rol pudo cambiar durante la hora de vigencia de la solicitud).
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a WHERE a.principal_ref = v_req.operator_principal_ref AND a.platform_role = 'RIGHTS_OPERATOR' AND a.status = 'ACTIVE') THEN
      v_reason := 'OPERATOR_INACTIVE'; EXIT decide;
    END IF;
    -- GRD-RC-10: el operador receptor tampoco tiene Membership TENANT al aprobar (pudo obtenerla durante la hora de vigencia de la solicitud).
    IF EXISTS (SELECT 1 FROM platform.tenant_membership m WHERE m.principal_ref = v_req.operator_principal_ref) THEN v_reason := 'TENANT_MEMBER'; EXIT decide; END IF;
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


REVOKE ALL ON FUNCTION platform.require_case_actor(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.require_platform_actor(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.record_rh2_approval(text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.alert_case_apply_exhausted(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.require_case_actor(text, text) TO transition_owner;
GRANT EXECUTE ON FUNCTION platform.require_platform_actor(text, text) TO transition_owner;
GRANT EXECUTE ON FUNCTION platform.record_rh2_approval(text, text, text, text, text) TO transition_owner;
GRANT EXECUTE ON FUNCTION platform.alert_case_apply_exhausted(text) TO platform_rw;
-- consume_step_up (interna, 0061) la llaman ahora tambien las funciones de RH2 de transition_owner en la misma tx.
GRANT EXECUTE ON FUNCTION platform.consume_step_up(text, text, text, integer, integer) TO transition_owner;

SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

DO $assert69$
DECLARE
  t record;
  r text;
  n integer;
  spec text[];
  roles text[] := ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'integrity_reconciler', 'consent_owner', 'consent_migrator', 'membership_owner', 'case_state_owner', 'platform_schema_owner'];
BEGIN
  FOREACH spec SLICE 1 IN ARRAY ARRAY[
      ARRAY['require_case_actor', 'transition_owner'], ARRAY['require_platform_actor', 'transition_owner'], ARRAY['record_rh2_approval', 'transition_owner'],
      ARRAY['alert_case_apply_exhausted', 'platform_rw'], ARRAY['approve_grant', 'platform_rw'], ARRAY['issue_step_up_nonce', 'platform_rw'], ARRAY['consume_step_up', 'transition_owner']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0069: platform.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO t
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = spec[1];
    IF t.owner <> 'grant_owner' OR NOT t.prosecdef OR t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0069: platform.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION '0069: PUBLIC puede ejecutar platform.%', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0069: la ACL de platform.% no es exactamente [%]', spec[1], spec[2];
    END IF;
    FOREACH r IN ARRAY roles LOOP
      IF pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') AND r <> ALL (string_to_array(spec[2], ',')) THEN RAISE EXCEPTION '0069: % puede ejecutar platform.%', r, spec[1]; END IF;
    END LOOP;
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0069: platform.% contiene EXECUTE (SQL dinamico prohibido)', spec[1]; END IF;
  END LOOP;
  -- Las funciones de actor no reciben principal ni tenant.
  FOREACH r IN ARRAY ARRAY['require_case_actor', 'require_platform_actor'] LOOP
    IF pg_catalog.pg_get_function_arguments((SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = r)) ~* 'principal|tenant' THEN
      RAISE EXCEPTION '0069: platform.% no puede recibir principal ni tenant', r;
    END IF;
  END LOOP;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'approve_grant';
  IF t.prosrc !~ 'RH2_APPROVER' OR t.prosrc !~ 'platform\.case_verification' OR t.prosrc !~ 'SELF_APPROVAL' OR t.prosrc !~ 'platform\.consume_step_up\(' THEN RAISE EXCEPTION '0069: approve_grant perdio el cruce GRD-RC-10 o una regla anterior'; END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'rights_case_grant_insert_guard';
  IF t.prosrc !~ 'platform\.case_verification' THEN RAISE EXCEPTION '0069: rights_case_grant_insert_guard perdio el cruce GRD-RC-10'; END IF;
  SELECT p.prosrc INTO t FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'platform' AND p.proname = 'issue_step_up_nonce';
  IF t.prosrc !~ 'APPROVE_CASE_VERIFICATION' OR t.prosrc !~ 'platform\.session_principal\(v_sid\)' THEN RAISE EXCEPTION '0069: issue_step_up_nonce sin las acciones de RH2 o sin el principal de la sesion'; END IF;
  -- case_verification: dueno, sin privilegios de runtime, append-only (triggers ENABLE ALWAYS), FORCE RLS.
  SELECT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity INTO t FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = 'case_verification';
  IF t.oid IS NULL OR pg_catalog.pg_get_userbyid(t.relowner) <> 'grant_owner' OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity THEN RAISE EXCEPTION '0069: platform.case_verification no es la declarada'; END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'integrity_reconciler', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'] LOOP
    IF pg_catalog.has_table_privilege(r, t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege(r, t.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0069: % tiene privilegios sobre platform.case_verification', r;
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g WHERE g.tgrelid = t.oid AND NOT g.tgisinternal AND g.tgenabled = 'A') <> 2 THEN RAISE EXCEPTION '0069: faltan los triggers append-only de case_verification (ENABLE ALWAYS)'; END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text, ',' ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid = t.oid) IS DISTINCT FROM 'case_verification_owner_insert,case_verification_owner_select' THEN
    RAISE EXCEPTION '0069: las policies de case_verification no son exactamente las del dueno';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0069: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert69$;
