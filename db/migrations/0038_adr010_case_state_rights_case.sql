-- scope: database
-- Gobierna: ADR-010 rev. 4 §4.2 y §7 fila PR-5 (segunda mitad, PR-5b); specs/state-machines/rights-case.spec.yaml `dbEnforcement`
-- (FN-RC-01, FN-RC-02, FN-RC-03, FN-RC-06; TRG-RC-01; revokedFromAppRw; INV-RC-07); specs/db-roles.spec.yaml (transition_owner, Q-18;
-- INV-DBR-07); GRD-RC-01, GRD-RC-02, GRD-RC-04, GRD-RC-07, GRD-RC-09, GRD-RC-14, GRD-CM-15; registers/findings-register-IT0.md F-A10-01,
-- F-A10-02, F-A10-26. Decisiones de Carlos del 2026-10-11 (ADR-010 rev. 4). Regla de Carlos (2026-10-01): 0000-0037 no se editan; todo
-- cambio SQL va en migracion nueva.
--
-- Alcance PR-5b: la base impone la maquina de estados de app.rights_case y app_rw deja de poder escribir en el ledger los eventos de
-- Revocation, RightsCase y CONSENT_REVOKED (INV-DBR-07). Mismo patron que 0037: efecto fijado al entrar (case_state.effect), trigger
-- ENABLE ALWAYS que exige current_user = transition_owner y el efecto, lock + assert_sequence, ledger_append como transition_owner y
-- aislamiento por tenant (app.current_tenant_id(); nunca un parametro).
--
-- 1) app.rights_case: app_rw solo lee. INSERT/UPDATE son de transition_owner (policies *_transition_*; la de UPDATE excluye los estados
--    terminales en USING: una fila RESOLVED/WITHDRAWN no se puede modificar ni revertir).
-- 2) Funciones: FN-RC-01 open_rights_case_bearer (RC1 BEARER), FN-RC-02 confirm_case_return (RC2u), FN-RC-03 (lado rights_case de RC3:
--    se REEMPLAZA case_state.express_revocation_intent_in_case, que en 0037 solo escribia la Revocation) y FN-RC-06 close_case
--    (RC4.RESOLVED, RC4.WITHDRAWN, RC5, RC6). Auxiliares: lock_rights_case, seed_local_rights_case (siembra SOLO LOCAL del contrato `save`).
-- 3) DDL sobre integrity.* (SET LOCAL ROLE integrity_owner; allowlist de integrity-owner-checker.ts; antes de PR-7): la policy de INSERT
--    de app_rw excluye aggregate_type Revocation/RightsCase y event_type CONSENT_REVOKED (INV-DBR-07, DECIDIDO Q-18). Cierra F-A10-01 en el
--    alcance que el spec define; los demas tipos de evento (ConsentDecision, Invitation, Enrollment, DecisionMakerVerification, tenant) NO
--    tienen funcion gobernada en el spec y siguen con el INSERT de app_rw bajo RLS por tenant (hallazgo F-A10-30, decision de Carlos).
--
-- Desviaciones DOCUMENTADAS respecto del spec (FINDINGs del PR; ninguna cambia semantica de consentimiento/revocacion/elegibilidad):
--   * No implementadas en PR-5b: FN-RC-04 start_case_contact (RC2 + RV0), FN-RC-05/FN-RV-16 escalate_expired_revocation (R9 + RC1 SYSTEM) y
--     FN-RC-07 report_school_revocation_intent (RC0). El dominio TS no implementa RC0, RC2 ni R9 (no hay llamador ni test): el trigger
--     rechaza cualquier efecto no declarado (fail-closed), asi que esas transiciones siguen cerradas hasta su PR.
--   * close_case: el spec lo asigna a platform_rw + rights_operator, pero platform_rw NO tiene EXECUTE (aun no es miembro de rights_operator y no
--     existen los entrypoints platform, PR-6); EXECUTE solo para app_rw, interino (F-A10-26): en IT0 el codigo corre en el proceso web. Exige la
--     ref del operador (p_operator_ref -> recorded_by_ref del evento): sin sesion CASE no se atribuye el cierre a un operador anonimo. No valida sesion CASE ni grant (GRD-RC-10): llega con PR-6. La migracion aborta si el
--     catalogo no es LOCAL y app_rw puede ejecutarla; startup-checks.ts tambien.
--   * app.case_session y los CASE_* de ops.security_event NO se tocan: el spec los asigna a PR-5 pero dependen de platform.open_case_session /
--     platform_rw (entrypoint platform, PR-6); retirarlos hoy rompe la consola CASE del proceso web (hallazgo F-A10-31).
--   * GRD-RC-09 (cierre solo tras R4 APPLIED o R8) se impone en la base; el dominio TS no lo comprueba (hallazgo F-A10-32).

-- 1. Grants de transition_owner -----------------------------------------------------------------------------------------------------
SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final
SET LOCAL ROLE consent_owner;

GRANT SELECT ON app.rights_case TO transition_owner;
GRANT INSERT (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, revocation_ref, origin) ON app.rights_case TO transition_owner;
GRANT UPDATE (status, revocation_ref, origin) ON app.rights_case TO transition_owner;

-- 2. Policies de app.rights_case ----------------------------------------------------------------------------------------------------
DROP POLICY rights_case_tenant_insert ON app.rights_case;
DROP POLICY rights_case_tenant_update ON app.rights_case;
REVOKE INSERT, UPDATE ON app.rights_case FROM app_rw;
CREATE POLICY rights_case_transition_select ON app.rights_case FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY rights_case_transition_insert ON app.rights_case FOR INSERT TO transition_owner
  WITH CHECK (tenant_id = app.current_tenant_id());
-- USING excluye los terminales: RESOLVED/WITHDRAWN no se actualizan (ni se revierten) por ningun camino; el trigger tambien lo rechaza.
CREATE POLICY rights_case_transition_update ON app.rights_case FOR UPDATE TO transition_owner
  USING (tenant_id = app.current_tenant_id() AND status NOT IN ('RESOLVED', 'WITHDRAWN'))
  WITH CHECK (tenant_id = app.current_tenant_id());

-- 3. DDL sobre integrity.* (integrity_owner) ------------------------------------------------------------------------------------------
-- integrity_owner no tiene USAGE/EXECUTE sobre app (0027): se concede de forma temporal para que ALTER POLICY resuelva app.current_tenant_id().
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
-- INV-DBR-07 (Q-18): solo transition_owner (case_state.ledger_append) escribe eventos de Revocation, RightsCase y CONSENT_REVOKED.
ALTER POLICY audit_event_tenant_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND aggregate_type NOT IN ('Revocation', 'RightsCase')
              AND event_type <> 'CONSENT_REVOKED');
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 4. Funciones (transition_owner) ------------------------------------------------------------------------------------------------------
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Bloqueo de la fila del caso del tenant de la tx (nunca de un parametro). app_rw ya no puede bloquear filas (FOR UPDATE exige UPDATE). Los
-- terminales no se bloquean (inmutables; la policy de UPDATE los excluye): se devuelven tal cual para que el llamador rechace la transicion
-- con RV002 y no con "no encontrada". `p_expected_sequence` (opcional) es el control optimista de la secuencia del agregado RightsCase.
CREATE FUNCTION case_state.lock_rights_case(p_case_ref text, p_expected_sequence integer DEFAULT NULL) RETURNS app.rights_case
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_case app.rights_case;
BEGIN
  SELECT c.* INTO v_case FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
  IF NOT FOUND THEN RAISE EXCEPTION 'caso no encontrado' USING ERRCODE = 'RV001'; END IF; -- ERR-CM-01 uniforme
  IF v_case.status NOT IN ('RESOLVED', 'WITHDRAWN') THEN
    SELECT c.* INTO v_case FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref FOR UPDATE;
    IF NOT FOUND THEN
      -- La fila paso a terminal durante la espera (la policy de UPDATE oculta los terminales al FOR UPDATE): se relee sin bloquear y el
      -- llamador rechaza la transicion con RV002; si sigue sin verse, no existe para este tenant (RV001).
      SELECT c.* INTO v_case FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = p_case_ref;
      IF NOT FOUND OR v_case.status NOT IN ('RESOLVED', 'WITHDRAWN') THEN RAISE EXCEPTION 'caso no encontrado' USING ERRCODE = 'RV001'; END IF;
    END IF;
  END IF;
  IF p_expected_sequence IS NOT NULL THEN PERFORM case_state.assert_sequence(p_case_ref, p_expected_sequence); END IF;
  RETURN v_case;
END
$fn$;

-- FN-RC-01 RC1 fuente BEARER: null -> OPEN. GRD-RC-01 (la cadena y la decision existen en el tenant), GRD-RC-02 (<=1 caso no terminal por
-- (cadena, decision): una segunda apertura devuelve el caso existente sin evento), GRD-RC-04 (origenes del portador: REQUEST_EXPIRED solo lo
-- abre R9 y SCHOOL_REPORTED solo RC0). La carrera entre dos aperturas la resuelve el UNIQUE parcial rights_case_single_open_uq (23505).
-- No implementado aqui (limitacion IT0 documentada en rights-case.ts): FLAG-escalated/REVOCATION_ESCALATED con Revocation abierta.
CREATE FUNCTION case_state.open_rights_case_bearer(p_case_ref text, p_chain_ref text, p_revoked_decision_ref text, p_origin text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_existing app.rights_case;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'open_rights_case_bearer', true);
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  IF p_origin IS NULL OR p_origin NOT IN ('LIMIT_REACHED', 'CHANNEL_UNREACHABLE', 'REQUESTER_ASKED') THEN
    RAISE EXCEPTION 'origen no admitido para la fuente BEARER' USING ERRCODE = 'RC002'; -- ERR-RC-02 (GRD-RC-04)
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.consent_decision d
                  WHERE d.tenant_id = v_tenant AND d.consent_id = p_revoked_decision_ref AND d.chain_ref = p_chain_ref) THEN
    RAISE EXCEPTION 'cadena o decision desconocida en el tenant' USING ERRCODE = 'RC001'; -- ERR-RC-01 uniforme (GRD-RC-01)
  END IF;
  SELECT c.* INTO v_existing FROM app.rights_case c
   WHERE c.tenant_id = v_tenant AND c.chain_ref = p_chain_ref AND c.revoked_decision_ref = p_revoked_decision_ref
     AND c.status NOT IN ('RESOLVED', 'WITHDRAWN')
   ORDER BY c.created_at, c.case_ref LIMIT 1;
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('caseRef', v_existing.case_ref, 'created', false, 'sequence', 0);
  END IF;
  INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin)
  VALUES (v_tenant, p_case_ref, p_chain_ref, p_revoked_decision_ref, 'OPEN', p_origin);
  SELECT * INTO v_ev FROM case_state.ledger_append('RightsCase', p_case_ref, 'RIGHTS_CASE_OPENED', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
    pg_catalog.jsonb_build_object('caseRef', p_case_ref, 'reasonCode', p_origin, 'initiatedVia', 'DECISION_MAKER'),
    v_tenant::text || ':' || p_chain_ref || ':' || p_revoked_decision_ref, 0);
  RETURN pg_catalog.jsonb_build_object('caseRef', p_case_ref, 'created', true, 'sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RC-02 RC2u: OPEN -> CONTACTING solo con origin = CHANNEL_UNREACHABLE (GRD-RC-07; otro origen: ERR-RC-01 uniforme). Idempotente: con el caso
-- ya en CONTACTING no escribe ni emite (idempotencyKey: caseRef). Sin RV0 ni envio.
CREATE FUNCTION case_state.confirm_case_return(p_case_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_case app.rights_case;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'confirm_case_return', true);
  -- Idempotente ANTES del control de secuencia: un RC2u concurrente que esperaba el lock y ve CONTACTING converge sin conflicto (TEST-CNS-847).
  v_case := case_state.lock_rights_case(p_case_ref);
  -- El atajo solo vale para un caso que RC2u ya movio: origin CHANNEL_UNREACHABLE (si no, RC001) y evento con la clave caseRef:contacting.
  IF v_case.status = 'CONTACTING' THEN
    IF v_case.origin IS DISTINCT FROM 'CHANNEL_UNREACHABLE' THEN
      RAISE EXCEPTION 'RC2u solo con origin CHANNEL_UNREACHABLE' USING ERRCODE = 'RC001'; -- ERR-RC-01 uniforme (GRD-RC-07)
    END IF;
    IF EXISTS (SELECT 1 FROM integrity.audit_event e
                WHERE e.tenant_id = v_case.tenant_id AND e.aggregate_id = p_case_ref AND e.event_type = 'RIGHTS_CASE_CONTACTING'
                  AND e.idempotency_key_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_case_ref || ':contacting', 'UTF8')), 'hex')) THEN
      RETURN pg_catalog.jsonb_build_object('sequence', (SELECT pg_catalog.max(e.sequence) FROM integrity.audit_event e
                                                         WHERE e.tenant_id = v_case.tenant_id AND e.aggregate_id = p_case_ref), 'changed', false);
    END IF;
  END IF;
  PERFORM case_state.assert_sequence(p_case_ref, p_expected_sequence);
  IF v_case.status <> 'OPEN' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF; -- ERR-CM-06
  IF v_case.origin IS DISTINCT FROM 'CHANNEL_UNREACHABLE' THEN
    RAISE EXCEPTION 'RC2u solo con origin CHANNEL_UNREACHABLE' USING ERRCODE = 'RC001'; -- ERR-RC-01 uniforme (GRD-RC-07)
  END IF;
  UPDATE app.rights_case SET status = 'CONTACTING' WHERE tenant_id = v_case.tenant_id AND case_ref = v_case.case_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('RightsCase', p_case_ref, 'RIGHTS_CASE_CONTACTING', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
    pg_catalog.jsonb_build_object('caseRef', p_case_ref), p_case_ref || ':contacting', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence, 'changed', true);
END
$fn$;

-- FN-RC-03 / FN-RV-06 (REEMPLAZA la de 0037; mismo nombre y firma, mismo dueno y mismo EXECUTE): lado Revocation Y lado rights_case de RC3 en
-- el mismo lote. p_attach = false (RC3): el caso debe estar CONTACTING y sin Revocation; crea la Revocation REQUESTED (HUMAN_ASSISTED, caseRef
-- 1:1), la liga al caso y lo pasa a IN_VERIFICATION. p_attach = true (R12 sobre la Revocation ya ligada al caso): el caso debe estar
-- IN_VERIFICATION con esa misma Revocation; solo registra el evento (la fila del caso no cambia). El caso debe ser de la cadena y la decision
-- indicadas (GRD-RC-14, ERR-RC-09). No cubre RC3a sobre una Revocation abierta fuera del caso (el dominio no la implementa: F-A10-33).
CREATE OR REPLACE FUNCTION case_state.express_revocation_intent_in_case(
  p_case_ref text, p_chain_ref text, p_revoked_decision_ref text, p_initiated_via text, p_revocation_ref text, p_attach boolean, p_expected_sequence integer)
  RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_case app.rights_case;
  v_rev app.revocation;
  v_ev record;
  v_payload jsonb;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'express_revocation_intent_in_case', true);
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  IF p_initiated_via NOT IN ('DECISION_MAKER', 'SCHOOL_REPORT') THEN RAISE EXCEPTION 'initiatedVia invalido' USING ERRCODE = 'RV002'; END IF;
  v_case := case_state.lock_rights_case(p_case_ref);
  IF v_case.chain_ref IS DISTINCT FROM p_chain_ref OR v_case.revoked_decision_ref IS DISTINCT FROM p_revoked_decision_ref THEN
    RAISE EXCEPTION 'el caso no es de esa cadena/decision' USING ERRCODE = 'RC009'; -- ERR-RC-09 (GRD-RC-14)
  END IF;
  v_payload := pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'revokedDecisionRef', p_revoked_decision_ref, 'scope', 'ALL',
    'authPath', 'RECOVERY', 'recoveryMethod', 'HUMAN_ASSISTED', 'originPurposeRef', 'ALL', 'initiatedVia', p_initiated_via, 'caseRef', p_case_ref);
  IF p_attach THEN
    IF v_case.status <> 'IN_VERIFICATION' OR v_case.revocation_ref IS DISTINCT FROM p_revocation_ref THEN
      RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002';
    END IF;
    v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
    IF v_rev.status IN ('FAILED', 'COMPLETED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
    IF v_rev.chain_ref IS DISTINCT FROM p_chain_ref OR v_rev.revoked_decision_ref IS DISTINCT FROM p_revoked_decision_ref THEN
      RAISE EXCEPTION 'la Revocation no es de esa cadena/decision' USING ERRCODE = 'RV002';
    END IF;
    SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
      v_payload, p_revocation_ref || ':r12:' || p_case_ref, p_expected_sequence);
  ELSE
    IF v_case.status = 'IN_VERIFICATION' AND v_case.revocation_ref IS NOT NULL THEN
      -- Otro RC3 concurrente ya ligo la Revocation mientras esta unidad esperaba el lock: conflicto de secuencia para que el UoW reejecute y converja por R12 (attach).
      RAISE EXCEPTION 'ledger sequence conflict' USING ERRCODE = 'RV409',
        DETAIL = pg_catalog.format('expected=%s actual=%s', p_expected_sequence, (SELECT COALESCE(pg_catalog.max(e.sequence), 0) FROM integrity.audit_event e
                                                                                  WHERE e.tenant_id = v_tenant AND e.aggregate_id = v_case.revocation_ref));
    END IF;
    IF v_case.status <> 'CONTACTING' OR v_case.revocation_ref IS NOT NULL THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
    PERFORM case_state.assert_decision_revocable(p_revoked_decision_ref, p_chain_ref);
    INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, case_ref, status, revoked_decision_ref)
    VALUES (v_tenant, p_revocation_ref, p_chain_ref, p_case_ref, 'REQUESTED', p_revoked_decision_ref);
    UPDATE app.rights_case SET status = 'IN_VERIFICATION', revocation_ref = p_revocation_ref
     WHERE tenant_id = v_case.tenant_id AND case_ref = v_case.case_ref;
    SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
      v_payload, p_revocation_ref || ':rc3', 0);
  END IF;
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RC-06 close_case: RC4.RESOLVED / RC4.WITHDRAWN (desde IN_VERIFICATION) y RC5 / RC6 (desde CONTACTING). GRD-RC-09: RESOLVED solo si la
-- Revocation del caso (la adjunta o la del ciclo: misma cadena y revoked_decision_ref) esta en APPLIED o posterior; WITHDRAWN solo si esa
-- Revocation termino FAILED con WITHDRAWN_BY_REQUESTER; si no, ERR-RC-03 y el caso sigue abierto. Ningun timer cierra un caso (INV-RC-01).
-- GRD-RC-10 (sesion CASE + grant atestado) NO se comprueba aqui: llega con PR-6 (F-A10-26).
CREATE FUNCTION case_state.close_case(p_case_ref text, p_outcome text, p_expected_sequence integer, p_operator_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_case app.rights_case;
  v_ok boolean;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'close_case', true);
  -- Interino F-A10-26: sin sesion CASE ni grant (PR-6) la funcion solo existe en LOCAL; fuera de LOCAL falla cerrado aunque alguien la ejecute.
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN RAISE EXCEPTION 'close_case sin sesion CASE solo existe en LOCAL' USING ERRCODE = '42501'; END IF;
  -- El ledger no atribuye el cierre a un operador anonimo: la ref del operador es obligatoria (recorded_by_ref del evento).
  IF p_operator_ref IS NULL OR pg_catalog.length(p_operator_ref) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'operador no identificado' USING ERRCODE = 'RC010'; END IF; -- ERR-CM-10
  IF p_outcome IS NULL OR p_outcome NOT IN ('RESOLVED', 'WITHDRAWN') THEN RAISE EXCEPTION 'outcome invalido' USING ERRCODE = 'RV002'; END IF;
  v_case := case_state.lock_rights_case(p_case_ref, p_expected_sequence);
  IF v_case.status NOT IN ('CONTACTING', 'IN_VERIFICATION') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF; -- ERR-CM-06
  IF p_outcome = 'RESOLVED' THEN
    SELECT EXISTS (SELECT 1 FROM app.revocation r
                    WHERE r.tenant_id = v_case.tenant_id AND r.chain_ref = v_case.chain_ref AND r.revoked_decision_ref = v_case.revoked_decision_ref
                      AND (v_case.revocation_ref IS NULL OR r.revocation_ref = v_case.revocation_ref)
                      AND r.status IN ('APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED')) INTO v_ok;
  ELSE
    SELECT EXISTS (SELECT 1 FROM app.revocation r
                    WHERE r.tenant_id = v_case.tenant_id AND r.chain_ref = v_case.chain_ref AND r.revoked_decision_ref = v_case.revoked_decision_ref
                      AND (v_case.revocation_ref IS NULL OR r.revocation_ref = v_case.revocation_ref)
                      AND r.status = 'FAILED' AND r.reason_code = 'WITHDRAWN_BY_REQUESTER') INTO v_ok;
  END IF;
  IF NOT v_ok THEN RAISE EXCEPTION 'precondicion de cierre no cumplida' USING ERRCODE = 'RC003'; END IF; -- ERR-RC-03
  UPDATE app.rights_case SET status = p_outcome WHERE tenant_id = v_case.tenant_id AND case_ref = v_case.case_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('RightsCase', p_case_ref, 'RIGHTS_CASE_CLOSED', 'HUMAN', 'RIGHTS_OPERATOR', p_operator_ref, NULL,
    pg_catalog.jsonb_build_object('caseRef', p_case_ref, 'outcome', p_outcome), p_case_ref || ':closed', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- Siembra SOLO LOCAL (contrato `save` del puerto, fixtures de dev y tests). Falla fuera de LOCAL. Upsert por (tenant, case_ref); sobre un terminal falla.
CREATE FUNCTION case_state.seed_local_rights_case(
  p_tenant_id uuid, p_case_ref text, p_chain_ref text, p_revoked_decision_ref text, p_status text, p_revocation_ref text, p_origin text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'seed_local_rights_case', true);
  IF v_tenant IS NULL OR p_tenant_id IS DISTINCT FROM v_tenant THEN RAISE EXCEPTION 'tenant distinto del de la tx' USING ERRCODE = '42501'; END IF;
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN
    RAISE EXCEPTION 'seed_local_rights_case solo existe en LOCAL' USING ERRCODE = '42501';
  END IF;
  -- Un caso terminal es inmutable (policy de UPDATE y trigger): sembrar sobre uno existente es un error (sin upsert sobre terminales).
  IF EXISTS (SELECT 1 FROM app.rights_case c WHERE c.tenant_id = v_tenant AND c.case_ref = p_case_ref AND c.status IN ('RESOLVED', 'WITHDRAWN')) THEN
    RAISE EXCEPTION 'un caso terminal no se siembra de nuevo' USING ERRCODE = '42501';
  END IF;
  INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, revocation_ref, origin)
  VALUES (v_tenant, p_case_ref, p_chain_ref, p_revoked_decision_ref, p_status, p_revocation_ref, p_origin)
  ON CONFLICT (tenant_id, case_ref) DO UPDATE SET status = EXCLUDED.status, revocation_ref = EXCLUDED.revocation_ref, origin = EXCLUDED.origin;
END
$fn$;

-- TRG-RC-01: trigger de grafo y efecto. SECURITY INVOKER a proposito (current_user = el rol que ejecuta la sentencia: dentro de una funcion
-- SECURITY DEFINER de transition_owner es transition_owner). Grafo del spec: null -> OPEN (RC1 BEARER), OPEN -> CONTACTING (RC2u),
-- CONTACTING -> IN_VERIFICATION (RC3), {CONTACTING, IN_VERIFICATION} -> {RESOLVED, WITHDRAWN} (RC4, RC5, RC6). Nada sale de un terminal.
-- Efectos de RC0, RC2 y R9 (FN-RC-07, FN-RC-04, FN-RC-05): sin funcion en PR-5b, el trigger los rechaza.
CREATE FUNCTION case_state.rights_case_transition_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_effect text := NULLIF(pg_catalog.current_setting('case_state.effect', true), '');
  v_pair text;
  v_allowed_pairs text[];
  v_changed text[] := ARRAY[]::text[];
  v_allowed_cols text[];
BEGIN
  -- app.rights_case nunca se borra ni se trunca (los casos cerrados son evidencia); tampoco el superusuario sin desactivar el trigger.
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'app.rights_case no admite DELETE ni TRUNCATE (INV-RC-07)' USING ERRCODE = '42501';
  END IF;
  -- Siembra de fixtures LOCAL como superusuario (admin de los tests): un superusuario ya podria deshabilitar el trigger; no es rol de runtime.
  IF v_effect = 'seed_local_rights_case' AND current_user <> 'transition_owner' AND ops.catalog_environment() = 'LOCAL'
     AND (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RETURN NEW;
  END IF;
  IF current_user <> 'transition_owner' OR v_effect IS NULL THEN
    RAISE EXCEPTION 'app.rights_case solo se escribe por las funciones case_state de transition_owner (INV-RC-07)' USING ERRCODE = '42501';
  END IF;
  IF v_effect = 'seed_local_rights_case' THEN
    IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN RAISE EXCEPTION 'efecto de siembra solo en LOCAL' USING ERRCODE = '42501'; END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF v_effect <> 'open_rights_case_bearer' OR NEW.status <> 'OPEN' OR NEW.revocation_ref IS NOT NULL
       OR NEW.origin IS NULL OR NEW.origin NOT IN ('LIMIT_REACHED', 'CHANNEL_UNREACHABLE', 'REQUESTER_ASKED') THEN
      RAISE EXCEPTION 'INSERT de app.rights_case no admitido para el efecto %', v_effect USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.tenant_id <> OLD.tenant_id OR NEW.case_ref <> OLD.case_ref OR NEW.chain_ref <> OLD.chain_ref
     OR NEW.revoked_decision_ref <> OLD.revoked_decision_ref OR NEW.origin IS DISTINCT FROM OLD.origin
     OR NEW.data_class <> OLD.data_class OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'columnas de identidad de app.rights_case inmutables' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('RESOLVED', 'WITHDRAWN') THEN
    RAISE EXCEPTION 'un caso en estado terminal no se modifica (INV-RC-01)' USING ERRCODE = '42501';
  END IF;

  CASE v_effect
    WHEN 'confirm_case_return' THEN
      v_allowed_pairs := ARRAY['OPEN>CONTACTING']; v_allowed_cols := ARRAY['status'];
    WHEN 'express_revocation_intent_in_case' THEN
      v_allowed_pairs := ARRAY['CONTACTING>IN_VERIFICATION']; v_allowed_cols := ARRAY['status', 'revocation_ref'];
      IF OLD.revocation_ref IS NOT NULL OR NEW.revocation_ref IS NULL THEN
        RAISE EXCEPTION 'RC3 liga la Revocation una sola vez' USING ERRCODE = '42501';
      END IF;
    WHEN 'close_case' THEN
      v_allowed_pairs := ARRAY['CONTACTING>RESOLVED', 'CONTACTING>WITHDRAWN', 'IN_VERIFICATION>RESOLVED', 'IN_VERIFICATION>WITHDRAWN'];
      v_allowed_cols := ARRAY['status'];
    ELSE
      RAISE EXCEPTION 'efecto % sin UPDATE declarado sobre app.rights_case', v_effect USING ERRCODE = '42501';
  END CASE;

  v_pair := OLD.status || '>' || NEW.status;
  IF NOT (v_pair = ANY (v_allowed_pairs)) THEN
    RAISE EXCEPTION 'transicion % no permitida para el efecto %', v_pair, v_effect USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN v_changed := pg_catalog.array_append(v_changed, 'status'::text); END IF;
  IF NEW.revocation_ref IS DISTINCT FROM OLD.revocation_ref THEN v_changed := pg_catalog.array_append(v_changed, 'revocation_ref'::text); END IF;
  IF NOT (v_changed <@ v_allowed_cols) THEN
    RAISE EXCEPTION 'el efecto % no puede modificar las columnas %', v_effect, v_changed USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$fn$;

-- EXECUTE: nadie por defecto; se concede uno por uno. Las auxiliares y el trigger quedan solo para su dueno.
REVOKE ALL ON FUNCTION case_state.lock_rights_case(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.rights_case_transition_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.open_rights_case_bearer(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.confirm_case_return(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.close_case(text, text, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.seed_local_rights_case(uuid, text, text, text, text, text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION case_state.open_rights_case_bearer(text, text, text, text) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.confirm_case_return(text, integer) TO app_rw;
-- Interino IT0 (ver cabecera, F-A10-26): el cierre del caso corre en el proceso web hasta PR-6; solo LOCAL/CI.
GRANT EXECUTE ON FUNCTION case_state.close_case(text, text, integer, text) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.seed_local_rights_case(uuid, text, text, text, text, text, text) TO app_rw;
-- CREATE TRIGGER exige EXECUTE al creador (consent_owner, dueno de la tabla); se revoca enseguida (el disparo no lo comprueba).
GRANT EXECUTE ON FUNCTION case_state.rights_case_transition_guard() TO consent_owner;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
GRANT USAGE ON SCHEMA case_state TO consent_owner; -- temporal: resolver el nombre de la funcion al crear el trigger
SET LOCAL ROLE consent_owner;

CREATE TRIGGER rights_case_transition_guard BEFORE INSERT OR UPDATE ON app.rights_case
  FOR EACH ROW EXECUTE FUNCTION case_state.rights_case_transition_guard();
ALTER TABLE app.rights_case ENABLE ALWAYS TRIGGER rights_case_transition_guard;
CREATE TRIGGER rights_case_no_delete BEFORE DELETE ON app.rights_case
  FOR EACH ROW EXECUTE FUNCTION case_state.rights_case_transition_guard();
CREATE TRIGGER rights_case_no_truncate BEFORE TRUNCATE ON app.rights_case
  FOR EACH STATEMENT EXECUTE FUNCTION case_state.rights_case_transition_guard();
ALTER TABLE app.rights_case ENABLE ALWAYS TRIGGER rights_case_no_delete;
ALTER TABLE app.rights_case ENABLE ALWAYS TRIGGER rights_case_no_truncate;

SET LOCAL ROLE transition_owner;
REVOKE EXECUTE ON FUNCTION case_state.rights_case_transition_guard() FROM consent_owner;
SET LOCAL ROLE case_state_owner;
REVOKE USAGE ON SCHEMA case_state FROM consent_owner;
SET LOCAL ROLE consent_owner;

-- 5. Aserciones: la migracion aborta si algo no quedo como se declara (catalogo por nombre). ----------------------------------------------
DO $assert$
DECLARE
  f record;
  r text;
  rc oid;
  led oid;
  expect_exec jsonb := pg_catalog.jsonb_build_object(
    'request_revocation', ARRAY['app_rw'], 'verify_revocation_otp', ARRAY['app_rw'], 'confirm_revocation', ARRAY['app_rw'],
    'revoke_with_recovery_link', ARRAY['app_rw'], 'withdraw_revocation', ARRAY['app_rw'], 'express_revocation_intent_in_case', ARRAY['app_rw'],
    'propose_case_verification', ARRAY['app_rw'], 'approve_case_verification', ARRAY['app_rw'], 'withdraw_case_verification_proposal', ARRAY['app_rw'],
    'record_case_confirmation', ARRAY['app_rw'], 'cosign_case_confirmation', ARRAY['app_rw'],
    'apply_revocation', ARRAY['app_rw', 'worker'], 'mark_downstream_emitted', ARRAY['app_rw', 'worker'], 'record_downstream_ack', ARRAY['app_rw', 'worker'],
    'record_erasure_attestation', ARRAY['app_rw', 'worker'], 'seed_local_revocation', ARRAY['app_rw'], 'seed_local_revoke_decision', ARRAY['app_rw'],
    'open_rights_case_bearer', ARRAY['app_rw'], 'confirm_case_return', ARRAY['app_rw'], 'close_case', ARRAY['app_rw'], 'seed_local_rights_case', ARRAY['app_rw'],
    'canonical_json', ARRAY[]::text[], 'ledger_append', ARRAY[]::text[], 'lock_revocation', ARRAY[]::text[], 'assert_sequence', ARRAY[]::text[], 'assert_decision_revocable', ARRAY[]::text[],
    'revocation_transition_guard', ARRAY[]::text[], 'lock_rights_case', ARRAY[]::text[], 'rights_case_transition_guard', ARRAY[]::text[]);
BEGIN
  -- Esquema: sin CREATE para nadie (el grant temporal de transition_owner se revoco) y ACL exacta.
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema case_state', r; END IF;
  END LOOP;
  IF pg_catalog.has_schema_privilege('integrity_owner', 'app', 'USAGE') THEN RAISE EXCEPTION 'integrity_owner conserva USAGE sobre app (grant temporal)'; END IF;
  IF pg_catalog.has_function_privilege('integrity_owner', 'app.current_tenant_id()', 'EXECUTE') THEN RAISE EXCEPTION 'integrity_owner conserva EXECUTE de app.current_tenant_id()'; END IF;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'case_state' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'app_rw:USAGE,transition_owner:USAGE,worker:USAGE' THEN
    RAISE EXCEPTION 'la ACL del esquema case_state no es exactamente USAGE para app_rw, transition_owner y worker';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'case_state' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'case_state_owner') THEN
    RAISE EXCEPTION 'el esquema case_state no pertenece a case_state_owner';
  END IF;

  -- Funciones: conjunto exacto, dueno transition_owner, search_path fijo, EXECUTE exacto, sin SQL dinamico.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state') <> 29 THEN
    RAISE EXCEPTION 'case_state debe tener exactamente 29 funciones en PR-5b';
  END IF;
  FOR f IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' LOOP
    IF NOT (expect_exec ? f.proname) THEN RAISE EXCEPTION 'funcion inesperada case_state.%()', f.proname; END IF;
    IF f.owner <> 'transition_owner' THEN RAISE EXCEPTION 'case_state.%() no pertenece a transition_owner', f.proname; END IF;
    IF f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'case_state.%() sin search_path fijo exacto', f.proname; END IF;
    IF f.prosecdef <> (f.proname NOT IN ('canonical_json', 'revocation_transition_guard', 'rights_case_transition_guard')) THEN RAISE EXCEPTION 'case_state.%(): SECURITY DEFINER inesperado', f.proname; END IF;
    IF pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar case_state.%()', f.proname; END IF;
    IF f.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'case_state.%() contiene SQL dinamico', f.proname; END IF;
    IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
          FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner)
       IS DISTINCT FROM (SELECT pg_catalog.string_agg(x, ',' ORDER BY x COLLATE "C") FROM pg_catalog.jsonb_array_elements_text(expect_exec -> f.proname) AS x) THEN
      RAISE EXCEPTION 'la ACL de case_state.%() no es exactamente la declarada', f.proname;
    END IF;
  END LOOP;

  -- Mitigacion F-A10-26: el EXECUTE interino de app_rw sobre close_case y la siembra solo es admisible en LOCAL/CI (catalogo LOCAL).
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'case_state' AND pg_catalog.has_function_privilege('app_rw', p.oid, 'EXECUTE')
          AND p.proname IN ('propose_case_verification', 'approve_case_verification', 'withdraw_case_verification_proposal', 'record_case_confirmation',
                            'cosign_case_confirmation', 'apply_revocation', 'mark_downstream_emitted', 'record_downstream_ack', 'record_erasure_attestation',
                            'seed_local_revocation', 'seed_local_revoke_decision', 'close_case', 'seed_local_rights_case')) THEN
    RAISE EXCEPTION 'F-A10-26: app_rw tiene EXECUTE de funciones de operador/SYSTEM/siembra fuera de LOCAL (interino IT0 solo LOCAL/CI)';
  END IF;

  -- app.rights_case: sin INSERT/UPDATE/DELETE/TRUNCATE para runtime, triggers ENABLE ALWAYS, policies exactas, FORCE RLS.
  SELECT c.oid INTO rc FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'rights_case';
  -- consent_owner no tiene USAGE en integrity (0027): el ledger se consulta por oid de catalogo, nunca por nombre regclass.
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier'] LOOP
    IF pg_catalog.has_any_column_privilege(r, rc, 'INSERT,UPDATE') OR pg_catalog.has_table_privilege(r, rc, 'DELETE,TRUNCATE') THEN
      RAISE EXCEPTION '% conserva INSERT/UPDATE/DELETE/TRUNCATE sobre app.rights_case', r;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_table_privilege('app_rw', rc, 'SELECT') THEN RAISE EXCEPTION 'app_rw perdio SELECT sobre app.rights_case'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = rc AND t.tgname IN ('rights_case_transition_guard', 'rights_case_no_delete', 'rights_case_no_truncate')
        AND t.tgenabled = 'A' AND NOT t.tgisinternal) <> 3
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = rc AND NOT t.tgisinternal) <> 3 THEN
    RAISE EXCEPTION 'app.rights_case debe tener exactamente los triggers rights_case_transition_guard/no_delete/no_truncate, ENABLE ALWAYS';
  END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::text || ':' || p.polcmd::text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = rc)
     IS DISTINCT FROM 'rights_case_tenant_select:r:app_rw rights_case_transition_insert:a:transition_owner rights_case_transition_select:r:transition_owner rights_case_transition_update:w:transition_owner' THEN
    RAISE EXCEPTION 'las policies de app.rights_case no son exactamente las declaradas';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rc AND p.polname = 'rights_case_transition_update'
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polqual, p.polrelid), 'RESOLVED') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polqual, p.polrelid), 'WITHDRAWN') > 0) THEN
    RAISE EXCEPTION 'la policy de UPDATE de transition_owner sobre app.rights_case debe excluir los terminales en USING';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rc AND p.polname LIKE 'rights\_case\_transition\_%'
               AND NOT (pg_catalog.strpos(COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') || COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), ''), 'current_tenant_id()') > 0)) THEN
    RAISE EXCEPTION 'las policies rights_case_transition_* deben filtrar por app.current_tenant_id()';
  END IF;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = rc) THEN RAISE EXCEPTION 'app.rights_case perdio ENABLE/FORCE ROW LEVEL SECURITY'; END IF;

  -- Ledger (INV-DBR-07): la policy de INSERT de app_rw excluye Revocation/RightsCase/CONSENT_REVOKED; transition_owner conserva las suyas.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a'
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'Revocation') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'RightsCase') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'CONSENT_REVOKED') > 0
                   AND (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',') FROM pg_catalog.unnest(p.polroles) AS x) = 'app_rw') THEN
    RAISE EXCEPTION 'la policy de INSERT de app_rw sobre integrity.audit_event debe excluir Revocation, RightsCase y CONSENT_REVOKED (INV-DBR-07)';
  END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::text, ' ' ORDER BY p.polname) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'transition_owner')
     IS DISTINCT FROM 'audit_event_transition_insert audit_event_transition_select' THEN
    RAISE EXCEPTION 'policies de transition_owner sobre integrity.audit_event no son las declaradas';
  END IF;

  -- transition_owner: no es dueno de ninguna tabla ni de objetos fuera de case_state.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE pg_catalog.pg_get_userbyid(c.relowner) = 'transition_owner') THEN
    RAISE EXCEPTION 'transition_owner no debe ser dueno de relaciones';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE pg_catalog.pg_get_userbyid(p.proowner) = 'transition_owner' AND n.nspname <> 'case_state') THEN
    RAISE EXCEPTION 'transition_owner solo es dueno de funciones de case_state';
  END IF;
END
$assert$;
