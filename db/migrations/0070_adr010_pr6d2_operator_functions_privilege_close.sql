-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §2 (filas web/app_rw "No puede", platform_rw, rights_operator, worker), §4.2.a (R4 en linea; EXECUTE de apply_revocation solo worker, P2(d)), §4.2.d (funciones
-- de operador sin p_*_by_ref; actor desde la sesion; step-up en la misma tx; seed_local_* sin app_rw), §10 fila 6d, §11.3 G-3; specs/state-machines/revocation.spec.yaml (RH2, RH3, FN-RV-07..12), rights-case.spec.yaml (FN-RC-06, GRD-RC-10,
-- GRD-RC-12), db-roles.spec.yaml (INV-DBR-06); registers/findings-register-IT0.md F-A10-26 (CIERRE POR PRIVILEGIO), F-A10-28, F-PR6-39 (parte 2), F-PR6-14/19/25. Depende de 0066-0069. 0037/0038/0039 son inmutables.
--
-- (La Revocation de cada accion sale del caso real: app.rights_case.revocation_ref bajo el tenant de la sesion; la request solo trae caseRef.)
-- 1) Funciones de operador NUEVAS (transition_owner, SECURITY DEFINER, search_path fijo, sin SQL dinamico); las de firma antigua (con p_*_by_ref / p_operator_ref / p_expected_sequence) se ELIMINAN. Ninguna recibe principal ni
--    tenant: el actor sale de platform.require_case_actor (sesion CASE) o platform.require_platform_actor (sesion PLATFORM, aprobador RH2) y FIJA app.tenant_id desde la sesion. Solo `session_user = platform_rw`. El control
--    optimista de secuencia lo da el lock de la fila de la Revocation / del caso (todo escritor del agregado la bloquea primero) y se lee la secuencia bajo el lock. Un fallo de step-up (GRD-RC-12) NO lanza: devuelve
--    {denied: <motivo>} para que la evidencia (STEP_UP_REJECTED, P-51) se confirme; el resto de guards lanza y revierte todo (incluido el consumo del nonce).
--      propose_case_verification(case_ref, proposal_ref, script_version, p51_max, p51_window)  EXECUTE rights_operator  (RH2 paso 1; step-up PROPOSE_CASE_VERIFICATION)
--      withdraw_case_verification_proposal(case_ref, proposal_ref, p51_max, p51_window)       EXECUTE rights_operator  (RH2w; solo el proponente; step-up WITHDRAW_CASE_VERIFICATION)
--      approve_case_verification(case_ref, proposal_ref, p51_max, p51_window)                 EXECUTE platform_rw     (RH2 paso 2; sesion PLATFORM, rol APPROVER; step-up APPROVE_CASE_VERIFICATION; registra el
--                                                                                                              aprobador en platform.case_verification y aplica el cruce GRD-RC-10)
--      record_case_confirmation(case_ref)                                                     EXECUTE rights_operator  (RH3 paso 1; sin step-up: LEGAL DECISION LD-03)
--      cosign_case_confirmation(case_ref)                                                     EXECUTE rights_operator  (RH3 paso 2 + R4 + C6 EN LA MISMA TX, excepcion unica a GRD-CM-15; FOR UPDATE de la decision antes
--                                                                                                              del primer append; atomica: si R4 falla se revierte todo)
--      close_case(case_ref, outcome)                                                                          EXECUTE rights_operator  (FN-RC-06; GRD-RC-10 por la sesion CASE; sin la restriccion LOCAL de 0038)
-- 2) CIERRE DE F-A10-26 POR PRIVILEGIO: REVOKE EXECUTE a app_rw de case_state.apply_revocation (queda solo worker, proceso de respaldo), y de case_state.seed_local_revocation / seed_local_rights_case (F-A10-28). app_rw ya no tiene
--    EXECUTE de ninguna funcion de operador, SYSTEM ni de siembra, ni de r4_apply (interna). platform_rw no recibe EXECUTE directo de nada de operador salvo approve_case_verification (con sesion PLATFORM). Los asserts de
--    ACL exacta de esta migracion fallan cerrado.
-- Idempotente: DROP FUNCTION IF EXISTS, CREATE FUNCTION nuevas, GRANT/REVOKE repetibles.

SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final del bloque
GRANT USAGE ON SCHEMA case_state TO platform_rw;       -- platform_rw ejecuta approve_case_verification y hace SET LOCAL ROLE rights_operator
GRANT USAGE ON SCHEMA case_state TO rights_operator;
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

DROP FUNCTION IF EXISTS case_state.propose_case_verification(text, text, text, text, text, integer);
DROP FUNCTION IF EXISTS case_state.approve_case_verification(text, text, text, text, integer);
DROP FUNCTION IF EXISTS case_state.withdraw_case_verification_proposal(text, text, text, text, integer);
DROP FUNCTION IF EXISTS case_state.record_case_confirmation(text, text, text, integer);
DROP FUNCTION IF EXISTS case_state.cosign_case_confirmation(text, text, text, integer);
DROP FUNCTION IF EXISTS case_state.close_case(text, text, integer, text);

-- Secuencia vigente del agregado, leida BAJO el lock de su fila (ver cabecera).
CREATE FUNCTION case_state.current_sequence(p_aggregate_id text) RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT COALESCE(pg_catalog.max(e.sequence), 0)::integer FROM integrity.audit_event e WHERE e.tenant_id = app.current_tenant_id() AND e.aggregate_id = p_aggregate_id
$fn$;

-- RH2 paso 1: registra la propuesta (proponente = principal de la sesion CASE); sin transicion ni evento.
CREATE FUNCTION case_state.propose_case_verification(
  p_case_ref text, p_proposal_ref text, p_verification_script_version text, p_p51_max integer, p_p51_window_seconds integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_revref text;
  v_actor text;
  v_denied text;
  v_rev app.revocation;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'propose_case_verification', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  -- La Revocation del caso sale del caso REAL (app.rights_case.revocation_ref, bajo el tenant de la sesion), nunca de la request.
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  v_denied := platform.consume_step_up(v_actor, 'PROPOSE_CASE_VERIFICATION', p_proposal_ref, p_p51_max, p_p51_window_seconds);
  IF v_denied IS NOT NULL THEN RETURN pg_catalog.jsonb_build_object('denied', v_denied); END IF;
  v_rev := case_state.lock_revocation(v_revref);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  IF v_rev.status <> 'REQUESTED' OR v_rev.proposal_ref IS NOT NULL THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET proposal_ref = p_proposal_ref, proposed_by_ref = v_actor, verification_script_version = p_verification_script_version
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  RETURN pg_catalog.jsonb_build_object('ok', true);
END
$fn$;

-- RH2 paso 2: REQUESTED -> VERIFIED HUMAN_ASSISTED; aprobador = principal de la sesion PLATFORM (rol APPROVER), distinto del proponente; cruce GRD-RC-10.
CREATE FUNCTION case_state.approve_case_verification(
  p_case_ref text, p_proposal_ref text, p_p51_max integer, p_p51_window_seconds integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_revref text;
  v_actor text;
  v_denied text;
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'approve_case_verification', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_platform_actor('APPROVER', p_case_ref);
  -- La Revocation del caso sale del caso REAL (app.rights_case.revocation_ref, bajo el tenant de la sesion), nunca de la request.
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  v_denied := platform.consume_step_up(v_actor, 'APPROVE_CASE_VERIFICATION', p_proposal_ref, p_p51_max, p_p51_window_seconds);
  IF v_denied IS NOT NULL THEN RETURN pg_catalog.jsonb_build_object('denied', v_denied); END IF;
  v_rev := case_state.lock_revocation(v_revref);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref OR v_rev.proposal_ref IS DISTINCT FROM p_proposal_ref THEN RAISE EXCEPTION 'propuesta ajena' USING ERRCODE = 'RV001'; END IF;
  IF v_actor = v_rev.proposed_by_ref THEN RAISE EXCEPTION 'aprobador igual al proponente' USING ERRCODE = 'RV004'; END IF; -- ERR-RV-07
  IF v_rev.status <> 'REQUESTED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  -- GRD-RC-10 / INV-14: el aprobador de RH2 no es aprobador ni receptor de ningun grant del caso (record_rh2_approval lanza RV004 -> ERR-RV-07, 403).
  PERFORM platform.record_rh2_approval(v_revref, p_case_ref, p_proposal_ref, v_rev.proposed_by_ref, v_actor);
  UPDATE app.revocation
     SET status = 'VERIFIED', attested_revocation_ref = v_rev.revocation_ref, attested_case_ref = v_rev.case_ref,
         verified_auth_path = 'RECOVERY', verified_recovery_method = 'HUMAN_ASSISTED', second_approver_ref = v_actor
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', v_revref, 'REVOCATION_VERIFIED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', v_revref, 'authPath', 'RECOVERY', 'recoveryMethod', 'HUMAN_ASSISTED', 'caseRef', p_case_ref,
      'verifiedByRef', v_rev.proposed_by_ref, 'secondApproverRef', v_actor, 'assuranceLevel', 'LD-02-PLACEHOLDER-V1'),
    v_revref || ':rh2:' || p_proposal_ref, case_state.current_sequence(v_revref));
  RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', v_ev.o_sequence);
END
$fn$;

-- RH2w: solo el proponente retira, solo con la Revocation REQUESTED; la Revocation no cambia de estado (INV-6).
CREATE FUNCTION case_state.withdraw_case_verification_proposal(
  p_case_ref text, p_proposal_ref text, p_p51_max integer, p_p51_window_seconds integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_revref text;
  v_actor text;
  v_denied text;
  v_rev app.revocation;
  v_ev record;
  v_prev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'withdraw_case_verification_proposal', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  -- La Revocation del caso sale del caso REAL (app.rights_case.revocation_ref, bajo el tenant de la sesion), nunca de la request.
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  v_denied := platform.consume_step_up(v_actor, 'WITHDRAW_CASE_VERIFICATION', p_proposal_ref, p_p51_max, p_p51_window_seconds);
  IF v_denied IS NOT NULL THEN RETURN pg_catalog.jsonb_build_object('denied', v_denied); END IF;
  v_rev := case_state.lock_revocation(v_revref);
  -- RH2w replay idempotente (F-6D2-QA-01): el MISMO proponente repite el retiro de una propuesta ya retirada -> mismo resultado, sin segundo evento ni cambio. Otro principal o una propuesta que nunca existio caen en 'propuesta ajena'.
  IF v_rev.case_ref IS NOT DISTINCT FROM p_case_ref AND v_rev.proposal_ref IS DISTINCT FROM p_proposal_ref THEN
    SELECT e.sequence, e.payload INTO v_prev FROM integrity.audit_event e
     WHERE e.tenant_id = v_rev.tenant_id AND e.aggregate_id = v_revref AND e.event_type = 'REVOCATION_PROPOSAL_WITHDRAWN'
       AND e.idempotency_key_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_revref || ':rh2w:' || p_proposal_ref, 'UTF8')), 'hex');
    IF FOUND AND v_prev.payload ->> 'withdrawnByRef' = v_actor THEN
      RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', v_prev.sequence, 'replay', true);
    END IF;
  END IF;
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref OR v_rev.proposal_ref IS DISTINCT FROM p_proposal_ref THEN RAISE EXCEPTION 'propuesta ajena' USING ERRCODE = 'RV001'; END IF;
  IF v_actor IS DISTINCT FROM v_rev.proposed_by_ref THEN RAISE EXCEPTION 'solo el proponente retira' USING ERRCODE = 'RV004'; END IF;
  IF v_rev.status <> 'REQUESTED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET proposal_ref = NULL, proposed_by_ref = NULL, verification_script_version = NULL
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', v_revref, 'REVOCATION_PROPOSAL_WITHDRAWN', 'HUMAN', 'RIGHTS_OPERATOR', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', v_revref, 'caseRef', p_case_ref, 'proposalRef', p_proposal_ref,
      'verificationScriptVersion', v_rev.verification_script_version, 'withdrawnByRef', v_actor),
    v_revref || ':rh2w:' || p_proposal_ref, case_state.current_sequence(v_revref));
  RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', v_ev.o_sequence);
END
$fn$;

-- RH3 paso 1: registra recorded_by_ref (principal de la sesion CASE) sin transicion ni evento. Sin step-up (LD-03).
CREATE FUNCTION case_state.record_case_confirmation(p_case_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_revref text;
  v_actor text;
  v_rev app.revocation;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'record_case_confirmation', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  -- La Revocation del caso sale del caso REAL (app.rights_case.revocation_ref, bajo el tenant de la sesion), nunca de la request.
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  v_rev := case_state.lock_revocation(v_revref);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  IF v_rev.status <> 'VERIFIED' OR v_rev.attested_revocation_ref IS DISTINCT FROM v_rev.revocation_ref OR v_rev.attested_case_ref IS DISTINCT FROM p_case_ref THEN
    RAISE EXCEPTION 'RH3 sin RH2 atestada' USING ERRCODE = 'RV006'; -- ERR-RV-20
  END IF;
  UPDATE app.revocation SET recorded_by_ref = v_actor WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  RETURN pg_catalog.jsonb_build_object('ok', true);
END
$fn$;

-- RH3 paso 2 + R4 + C6 en la misma tx: cuatro ojos (co-firmante = principal de la sesion CASE, distinto del registrador).
CREATE FUNCTION case_state.cosign_case_confirmation(p_case_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_revref text;
  v_actor text;
  v_rev app.revocation;
  v_dec_state text;
  v_ev record;
  v_r4 jsonb;
  v_lt bigint;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'cosign_case_confirmation', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  -- La Revocation del caso sale del caso REAL (app.rights_case.revocation_ref, bajo el tenant de la sesion), nunca de la request.
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  SELECT s.setting::bigint INTO v_lt FROM pg_catalog.pg_settings s WHERE s.name = 'lock_timeout';
  IF v_lt = 0 OR v_lt > 5000 THEN PERFORM pg_catalog.set_config('lock_timeout', '5000ms', true); END IF;
  v_rev := case_state.lock_revocation(v_revref);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  -- Replay idempotente (commit ambiguo, G-3): la MISMA co-firma ya aplicada devuelve el resultado REAL sin reaplicar ni duplicar eventos.
  IF v_rev.status IN ('APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED') AND v_rev.cosigned_by_ref IS NOT DISTINCT FROM v_actor THEN
    RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', case_state.current_sequence(v_revref), 'applied', true, 'replay', true);
  END IF;
  IF v_rev.status <> 'VERIFIED' OR v_rev.attested_revocation_ref IS DISTINCT FROM v_rev.revocation_ref OR v_rev.attested_case_ref IS DISTINCT FROM p_case_ref THEN
    RAISE EXCEPTION 'RH3 sin RH2 atestada' USING ERRCODE = 'RV006'; -- ERR-RV-20
  END IF;
  IF v_rev.recorded_by_ref IS NULL OR v_actor = v_rev.recorded_by_ref THEN RAISE EXCEPTION 'RH3 exige cuatro ojos' USING ERRCODE = 'RV005'; END IF; -- ERR-RV-18
  -- P2(c): la decision afectada se bloquea ANTES del primer append al ledger; sin decision revocable no hay R3 (y la tx no deja nada).
  SELECT d.state INTO v_dec_state FROM app.consent_decision d
   WHERE d.tenant_id = v_rev.tenant_id AND d.consent_id = v_rev.revoked_decision_ref FOR UPDATE;
  IF NOT FOUND OR v_dec_state NOT IN ('GRANTED', 'REVOKED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET status = 'CONFIRMED', cosigned_by_ref = v_actor WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', v_revref, 'REVOCATION_CONFIRMED', 'HUMAN', 'DECISION_MAKER',
    v_rev.recorded_by_ref, v_actor,
    pg_catalog.jsonb_build_object('revocationRef', v_revref, 'recordedByRef', v_rev.recorded_by_ref, 'cosignedByRef', v_actor),
    v_revref || ':rh3', case_state.current_sequence(v_revref));
  v_r4 := case_state.r4_apply(v_revref, v_ev.o_sequence);
  RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', (v_r4 ->> 'sequence')::integer, 'applied', true);
END
$fn$;

-- Lectura de estado SIN EFECTOS para el reintento de RH3 (G-3, F-6D2-QA-02): la Revocation del caso real ya esta aplicada por la co-firma de ESTA sesion? Devuelve {applied, sequence} o {applied:false}. No escribe
-- en el ledger ni en app.*, no consume step-up; solo revalida la sesion CASE (require_case_actor, sin evento). Misma condicion que el replay de cosign_case_confirmation.
CREATE FUNCTION case_state.read_case_apply_state(p_case_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_actor text;
  v_revref text;
  v_rev app.revocation;
BEGIN
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RETURN pg_catalog.jsonb_build_object('applied', false); END IF;
  SELECT r.* INTO v_rev FROM app.revocation r WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = v_revref AND r.case_ref = p_case_ref;
  IF FOUND AND v_rev.status IN ('APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED') AND v_rev.cosigned_by_ref IS NOT DISTINCT FROM v_actor THEN
    RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', case_state.current_sequence(v_revref), 'applied', true, 'replay', true);
  END IF;
  RETURN pg_catalog.jsonb_build_object('applied', false);
END
$fn$;

-- FN-RC-06 close_case: RC4.RESOLVED / RC4.WITHDRAWN (desde IN_VERIFICATION) y RC5 / RC6 (desde CONTACTING); GRD-RC-09 como en 0038/0039; GRD-RC-10 por la sesion CASE.
CREATE FUNCTION case_state.close_case(p_case_ref text, p_outcome text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_actor text;
  v_case app.rights_case;
  v_ok boolean;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'close_case', true);
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  IF p_outcome IS NULL OR p_outcome NOT IN ('RESOLVED', 'WITHDRAWN') THEN RAISE EXCEPTION 'outcome invalido' USING ERRCODE = 'RV002'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  v_case := case_state.lock_rights_case(p_case_ref);
  IF v_case.status NOT IN ('CONTACTING', 'IN_VERIFICATION') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF; -- ERR-CM-06
  IF p_outcome = 'RESOLVED' THEN
    SELECT EXISTS (SELECT 1 FROM app.revocation r
                    WHERE r.tenant_id = v_case.tenant_id AND r.chain_ref = v_case.chain_ref AND r.revoked_decision_ref = v_case.revoked_decision_ref
                      AND (v_case.revocation_ref IS NULL OR r.revocation_ref = v_case.revocation_ref)
                      AND r.created_at >= v_case.created_at
                      AND r.status IN ('APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED')) INTO v_ok;
  ELSE
    SELECT EXISTS (SELECT 1 FROM app.revocation r
                    WHERE r.tenant_id = v_case.tenant_id AND r.chain_ref = v_case.chain_ref AND r.revoked_decision_ref = v_case.revoked_decision_ref
                      AND (v_case.revocation_ref IS NULL OR r.revocation_ref = v_case.revocation_ref)
                      AND r.created_at >= v_case.created_at
                      AND r.status = 'FAILED' AND r.reason_code = 'WITHDRAWN_BY_REQUESTER') INTO v_ok;
  END IF;
  IF NOT v_ok THEN RAISE EXCEPTION 'precondicion de cierre no cumplida' USING ERRCODE = 'RC003'; END IF; -- ERR-RC-03
  UPDATE app.rights_case SET status = p_outcome WHERE tenant_id = v_case.tenant_id AND case_ref = v_case.case_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('RightsCase', p_case_ref, 'RIGHTS_CASE_CLOSED', 'HUMAN', 'RIGHTS_OPERATOR', v_actor, NULL,
    pg_catalog.jsonb_build_object('caseRef', p_case_ref, 'outcome', p_outcome), p_case_ref || ':closed', case_state.current_sequence(p_case_ref));
  RETURN pg_catalog.jsonb_build_object('ok', true, 'sequence', v_ev.o_sequence);
END
$fn$;


-- Alerta de agotamiento de RH3 (G-3): tx SEPARADA y posterior al rollback; la Revocation sale del caso real y el tenant de la sesion CASE validada. Sin PII.
CREATE FUNCTION case_state.alert_apply_exhausted(p_case_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_actor text;
  v_revref text;
BEGIN
  IF session_user <> 'platform_rw' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  v_actor := platform.require_case_actor(p_case_ref, 'RIGHTS_OPERATOR');
  SELECT c.revocation_ref INTO v_revref FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF v_revref IS NULL THEN RAISE EXCEPTION 'caso sin Revocation' USING ERRCODE = 'RV001'; END IF;
  PERFORM ops.record_revocation_apply_alert(v_revref, 'R4_RETRIES_EXHAUSTED');
  RETURN pg_catalog.jsonb_build_object('ok', true);
END
$fn$;

-- EXECUTE minimo por rol. current_sequence es interna (solo las funciones de este dueno la llaman).
REVOKE ALL ON FUNCTION case_state.current_sequence(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.propose_case_verification(text, text, text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.approve_case_verification(text, text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.withdraw_case_verification_proposal(text, text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.record_case_confirmation(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.cosign_case_confirmation(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.close_case(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.alert_apply_exhausted(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.read_case_apply_state(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION case_state.propose_case_verification(text, text, text, integer, integer) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.withdraw_case_verification_proposal(text, text, integer, integer) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.record_case_confirmation(text) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.cosign_case_confirmation(text) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.close_case(text, text) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.alert_apply_exhausted(text) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.read_case_apply_state(text) TO rights_operator;
GRANT EXECUTE ON FUNCTION case_state.approve_case_verification(text, text, integer, integer) TO platform_rw;

-- F-A10-26: R4 solo worker (respaldo); F-A10-28: siembras LOCAL sin app_rw.
REVOKE EXECUTE ON FUNCTION case_state.apply_revocation(text, integer) FROM app_rw;
REVOKE EXECUTE ON FUNCTION case_state.seed_local_revocation(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text) FROM app_rw;
REVOKE EXECUTE ON FUNCTION case_state.seed_local_rights_case(uuid, text, text, text, text, text, text) FROM app_rw;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;

DO $assert70$
DECLARE
  f record;
  r text;
  n integer;
  oid_fn oid;
  spec text[];
  all_fns text[] := ARRAY['propose_case_verification', 'approve_case_verification', 'withdraw_case_verification_proposal', 'record_case_confirmation', 'cosign_case_confirmation', 'close_case', 'alert_apply_exhausted', 'read_case_apply_state',
                          'apply_revocation', 'r4_apply', 'current_sequence', 'mark_downstream_emitted', 'record_downstream_ack', 'record_erasure_attestation', 'seed_local_revocation', 'seed_local_rights_case'];
BEGIN
  -- ACL exacta de las funciones de operador, SYSTEM e internas.
  FOREACH spec SLICE 1 IN ARRAY ARRAY[
      ARRAY['propose_case_verification', 'rights_operator'], ARRAY['withdraw_case_verification_proposal', 'rights_operator'], ARRAY['record_case_confirmation', 'rights_operator'],
      ARRAY['cosign_case_confirmation', 'rights_operator'], ARRAY['close_case', 'rights_operator'], ARRAY['alert_apply_exhausted', 'rights_operator'], ARRAY['read_case_apply_state', 'rights_operator'], ARRAY['approve_case_verification', 'platform_rw'],
      ARRAY['apply_revocation', 'worker'], ARRAY['mark_downstream_emitted', 'worker'], ARRAY['record_downstream_ack', 'worker'], ARRAY['record_erasure_attestation', 'worker'],
      ARRAY['r4_apply', ''], ARRAY['current_sequence', ''], ARRAY['seed_local_revocation', ''], ARRAY['seed_local_rights_case', '']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0070: case_state.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = spec[1];
    IF f.owner <> 'transition_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0070: case_state.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1]; END IF;
    IF pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN RAISE EXCEPTION '0070: PUBLIC puede ejecutar case_state.%', spec[1]; END IF;
    IF f.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0070: case_state.% contiene SQL dinamico', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0070: la ACL de case_state.% no es exactamente [%]', spec[1], spec[2];
    END IF;
  END LOOP;
  -- F-A10-26 cerrado por privilegio: ni app_rw ni ningun otro runtime (salvo lo declarado) alcanza operador/SYSTEM/siembras/internas.
  FOR f IN SELECT p.oid, p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = ANY (all_fns) LOOP
    FOREACH r IN ARRAY ARRAY['app_rw', 'integrity_verifier', 'integrity_reconciler'] LOOP
      IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '0070: % puede ejecutar case_state.% (F-A10-26/28)', r, f.proname; END IF;
    END LOOP;
    IF f.proname <> 'approve_case_verification' AND pg_catalog.has_function_privilege('platform_rw', f.oid, 'EXECUTE') THEN RAISE EXCEPTION '0070: platform_rw puede ejecutar case_state.% sin SET ROLE', f.proname; END IF;
    IF f.proname NOT IN ('apply_revocation', 'mark_downstream_emitted', 'record_downstream_ack', 'record_erasure_attestation') AND pg_catalog.has_function_privilege('worker', f.oid, 'EXECUTE') THEN
      RAISE EXCEPTION '0070: worker puede ejecutar case_state.% (solo las SYSTEM)', f.proname;
    END IF;
  END LOOP;
  -- Reglas que no se pueden perder en cada funcion de operador.
  FOR f IN SELECT p.proname, p.prosrc, pg_catalog.pg_get_function_arguments(p.oid) AS args FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
            WHERE s.nspname = 'case_state' AND p.proname IN ('propose_case_verification', 'approve_case_verification', 'withdraw_case_verification_proposal', 'record_case_confirmation', 'cosign_case_confirmation', 'close_case', 'alert_apply_exhausted', 'read_case_apply_state') LOOP
    IF f.args ~* 'by_ref|operator_ref|actor_ref|principal|tenant|approver_ref' THEN RAISE EXCEPTION '0070: case_state.% no puede recibir actor, principal ni tenant (%)', f.proname, f.args; END IF;
    IF f.prosrc !~ 'platform\.require_(case|platform)_actor\(' OR f.prosrc !~ 'session_user <> .platform_rw.' THEN RAISE EXCEPTION '0070: case_state.% perdio el actor desde la sesion o la restriccion de llamador', f.proname; END IF;
    IF f.proname IN ('propose_case_verification', 'approve_case_verification', 'withdraw_case_verification_proposal') AND f.prosrc !~ 'platform\.consume_step_up\(' THEN RAISE EXCEPTION '0070: case_state.% perdio el step-up (GRD-RC-12)', f.proname; END IF;
  END LOOP;
  SELECT p.prosrc INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'cosign_case_confirmation';
  IF f.prosrc !~ 'case_state\.r4_apply\(' OR pg_catalog.strpos(f.prosrc, 'FOR UPDATE') > pg_catalog.strpos(f.prosrc, 'ledger_append') OR f.prosrc !~ 'RV005' THEN
    RAISE EXCEPTION '0070: cosign_case_confirmation perdio R4 en la misma tx, el FOR UPDATE previo al ledger o los cuatro ojos';
  END IF;
  SELECT p.prosrc INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'approve_case_verification';
  IF f.prosrc !~ 'platform\.record_rh2_approval\(' OR f.prosrc !~ 'require_platform_actor\(.APPROVER.' THEN RAISE EXCEPTION '0070: approve_case_verification perdio el cruce GRD-RC-10 o el aprobador PLATFORM'; END IF;
  -- Esquema: solo USAGE de lectura para los roles declarados; nadie conserva CREATE.
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'case_state' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'app_rw:USAGE,platform_rw:USAGE,rights_operator:USAGE,transition_owner:USAGE,worker:USAGE' THEN
    RAISE EXCEPTION '0070: la ACL del esquema case_state no es exactamente USAGE para app_rw, platform_rw, rights_operator, transition_owner y worker';
  END IF;
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'rights_operator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '0070: % conserva CREATE en el esquema case_state', r; END IF;
  END LOOP;
END
$assert70$;
