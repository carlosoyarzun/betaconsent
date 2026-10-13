-- scope: database
-- Gobierna: ADR-010 rev. 4 §4.2 y §7 fila PR-5 (PR-5b, decisiones D1-D6 de Carlos del 2026-10-13); specs/state-machines/rights-case.spec.yaml `dbEnforcement`
-- (FN-RC-06 close_case, GRD-RC-09); specs/db-roles.spec.yaml INV-DBR-07; registers/findings-register-IT0.md F-A10-01, F-A10-30, F-A10-32. 0038 ya esta
-- mergeada y es inmutable (regla de Carlos, 2026-10-01): estos cambios van en migracion nueva y dejan el estado final de la revision de seguridad de #89.
--
-- 1) D6: close_case (CREATE OR REPLACE; mismo dueno, firma y EXECUTE): la Revocation que cierra el caso debe ser de created_at >= created_at del caso (no la
--    de un ciclo anterior de la misma cadena/decision). D1 (GRD-RC-09, RC3 solo desde CONTACTING) ya estaba impuesto por 0038 en la base; aqui se alinea el dominio TS.
-- 2) D5: INV-DBR-07 como ALLOWLIST sobre integrity.audit_event (DDL con SET LOCAL ROLE integrity_owner; allowlist de integrity-owner-checker.ts; antes de PR-7):
--    a) CHECK enum de aggregate_type (validado: si hay filas fuera del enum la migracion aborta);
--    b) la policy de INSERT de app_rw (reemplaza la denylist de 0038) solo admite pares (aggregate_type, event_type) explicitos y ningun aggregate_id de una fila de
--       app.revocation / app.rights_case del tenant;
--    c) trigger audit_event_single_aggregate_type (ENABLE ALWAYS): un aggregate_id no se reutiliza entre aggregate_type distintos; toma el MISMO lock por tenant
--       que case_state.ledger_append (pg_advisory_xact_lock(hashtextextended('ledger-chain:' || tenant, 0))) para que dos tx concurrentes no creen dos tipos para un id.
-- 3) $assert$ completo al final (conjunto de funciones, ACL, F-A10-26, rights_case, ledger: una sola policy de INSERT alcanza a app_rw, roles heredados sin INSERT,
--    allowlist sin REVOCATION_/RIGHTS_CASE_/CONSENT_REVOKED, CHECK y trigger).
-- Idempotente: CREATE OR REPLACE, DROP ... IF EXISTS + CREATE, ALTER POLICY y GRANT/REVOKE repetibles.

-- 1. close_case (transition_owner) --------------------------------------------------------------------------------------------------------
SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final del bloque de funciones
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- FN-RC-06 close_case: RC4.RESOLVED / RC4.WITHDRAWN (desde IN_VERIFICATION) y RC5 / RC6 (desde CONTACTING). GRD-RC-09: RESOLVED solo si la
-- Revocation del caso (la adjunta o la del ciclo: misma cadena y revoked_decision_ref) esta en APPLIED o posterior; WITHDRAWN solo si esa
-- Revocation termino FAILED con WITHDRAWN_BY_REQUESTER; si no, ERR-RC-03 y el caso sigue abierto. Ningun timer cierra un caso (INV-RC-01).
-- GRD-RC-10 (sesion CASE + grant atestado) NO se comprueba aqui: llega con PR-6 (F-A10-26).
CREATE OR REPLACE FUNCTION case_state.close_case(p_case_ref text, p_outcome text, p_expected_sequence integer, p_operator_ref text) RETURNS jsonb
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
                      AND r.created_at >= v_case.created_at -- D6: la Revocation que cierra el caso es posterior a su apertura (no la de un ciclo anterior)
                      AND r.status IN ('APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED')) INTO v_ok;
  ELSE
    SELECT EXISTS (SELECT 1 FROM app.revocation r
                    WHERE r.tenant_id = v_case.tenant_id AND r.chain_ref = v_case.chain_ref AND r.revoked_decision_ref = v_case.revoked_decision_ref
                      AND (v_case.revocation_ref IS NULL OR r.revocation_ref = v_case.revocation_ref)
                      AND r.created_at >= v_case.created_at -- D6: la Revocation que cierra el caso es posterior a su apertura (no la de un ciclo anterior)
                      AND r.status = 'FAILED' AND r.reason_code = 'WITHDRAWN_BY_REQUESTER') INTO v_ok;
  END IF;
  IF NOT v_ok THEN RAISE EXCEPTION 'precondicion de cierre no cumplida' USING ERRCODE = 'RC003'; END IF; -- ERR-RC-03
  UPDATE app.rights_case SET status = p_outcome WHERE tenant_id = v_case.tenant_id AND case_ref = v_case.case_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('RightsCase', p_case_ref, 'RIGHTS_CASE_CLOSED', 'HUMAN', 'RIGHTS_OPERATOR', p_operator_ref, NULL,
    pg_catalog.jsonb_build_object('caseRef', p_case_ref, 'outcome', p_outcome), p_case_ref || ':closed', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;

-- 2. DDL sobre integrity.* (integrity_owner) ------------------------------------------------------------------------------------------
-- integrity_owner no tiene USAGE/EXECUTE sobre app (0027): se concede de forma temporal para que ALTER POLICY resuelva app.current_tenant_id() y las tablas de app.
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
-- INV-DBR-07 como ALLOWLIST (D5, Carlos 2026-10-13): app_rw solo inserta pares (aggregate_type, event_type) explicitos; los eventos de Revocation y
-- RightsCase (y CONSENT_REVOKED) los escribe unicamente transition_owner (case_state.ledger_append). Capas:
--  a) CHECK enum de aggregate_type;
--  b) policy de INSERT de app_rw con la lista de pares permitidos y sin aggregate_id de una fila de app.revocation / app.rights_case del tenant;
--  c) trigger que impide mas de un aggregate_type por (tenant, aggregate_id) (un id no se reutiliza entre agregados).
ALTER TABLE integrity.audit_event DROP CONSTRAINT IF EXISTS audit_event_aggregate_type_enum;
-- Se crea VALIDADA: si hubiera filas con otro aggregate_type, la migracion aborta (fail-closed; en LOCAL/CI se recrea la base).
ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_aggregate_type_enum CHECK (aggregate_type IN (
  'Tenant', 'SchoolParticipation', 'Enrollment', 'Invitation', 'DecisionMakerVerification', 'ConsentDecision', 'Revocation', 'RightsCase'));
ALTER POLICY audit_event_tenant_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND (aggregate_type || ':' || event_type) = ANY (ARRAY[
                'Tenant:TENANT_SEEDED', 'Tenant:TENANT_STATUS_CHANGED',
                'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED', 'SchoolParticipation:SCHOOL_PARTICIPATION_STATUS_CHANGED',
                'Enrollment:ENROLLMENT_STATUS_CHANGED',
                'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_READY', 'Invitation:INVITATION_SENT', 'Invitation:INVITATION_TOKEN_ROTATED',
                'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_VERIFIED', 'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_DECLINED',
                'Invitation:INVITATION_EXPIRED', 'Invitation:INVITATION_CANCELLED',
                'DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED',
                'ConsentDecision:CONTEXT_INFORMATION_VIEWED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED',
                'ConsentDecision:SUBJECT_CONFIRMED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:CONSENT_GRANTED',
                'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:RECEIPT_CREATED'])
              AND NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = aggregate_id)
              AND NOT EXISTS (SELECT 1 FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = aggregate_id));
CREATE OR REPLACE FUNCTION integrity.audit_event_single_aggregate_type() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  -- Misma clave de lock por tenant que case_state.ledger_append (y que el adaptador del ledger): serializa los INSERT concurrentes del tenant; sin ella,
  -- dos transacciones (READ COMMITTED) podrian crear el mismo aggregate_id con dos aggregate_type sin verse. Tras el lock el EXISTS ve lo ya confirmado.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ledger-chain:' || NEW.tenant_id::text, 0));
  IF EXISTS (SELECT 1 FROM integrity.audit_event e
              WHERE e.tenant_id = NEW.tenant_id AND e.aggregate_id = NEW.aggregate_id AND e.aggregate_type <> NEW.aggregate_type) THEN
    RAISE EXCEPTION 'un aggregate_id no se reutiliza entre aggregate_type distintos' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$fn$;
DROP TRIGGER IF EXISTS audit_event_single_aggregate_type ON integrity.audit_event;
CREATE TRIGGER audit_event_single_aggregate_type BEFORE INSERT ON integrity.audit_event
  FOR EACH ROW EXECUTE FUNCTION integrity.audit_event_single_aggregate_type();
ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_single_aggregate_type;
REVOKE ALL ON FUNCTION integrity.audit_event_single_aggregate_type() FROM PUBLIC;

SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 3. Aserciones: la migracion aborta si algo no quedo como se declara (catalogo por nombre). ------------------------------------------------
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

  -- Ledger (INV-DBR-07, allowlist): UNA sola policy de INSERT alcanza a app_rw (ni ALL ni PUBLIC), con la lista de pares y sin los de Revocation/RightsCase/CONSENT_REVOKED.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
         AND (0::oid = ANY (p.polroles) OR (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'app_rw') = ANY (p.polroles))) <> 1 THEN
    RAISE EXCEPTION 'exactamente una policy de INSERT debe alcanzar a app_rw en integrity.audit_event (INV-DBR-07)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a'
                   AND (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',') FROM pg_catalog.unnest(p.polroles) AS x) = 'app_rw'
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'Invitation:INVITATION_CREATED') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'ConsentDecision:RECEIPT_CREATED') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'Revocation') = 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'RightsCase') = 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'CONSENT_REVOKED') = 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'REVOCATION_') = 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'RIGHTS_CASE_') = 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'revocation_ref') > 0
                   AND pg_catalog.strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), 'case_ref') > 0) THEN
    RAISE EXCEPTION 'la policy de INSERT de app_rw sobre integrity.audit_event debe ser la allowlist de pares sin Revocation/RightsCase/CONSENT_REVOKED (INV-DBR-07)';
  END IF;
  -- Ningun rol del que app_rw herede o pueda asumir (USAGE/SET) tiene INSERT sobre el ledger ni una policy de INSERT/ALL propia: seria otra via de escritura.
  FOR r IN SELECT x.rolname::text FROM pg_catalog.pg_roles x
            WHERE x.rolname <> 'app_rw' AND (pg_catalog.pg_has_role('app_rw', x.oid, 'USAGE') OR pg_catalog.pg_has_role('app_rw', x.oid, 'SET')) LOOP
    IF pg_catalog.has_any_column_privilege(r, led, 'INSERT') THEN RAISE EXCEPTION 'app_rw alcanza por membresia a % con INSERT sobre integrity.audit_event', r; END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
                AND (SELECT y.oid FROM pg_catalog.pg_roles y WHERE y.rolname = r) = ANY (p.polroles)) THEN
      RAISE EXCEPTION 'app_rw alcanza por membresia a % con una policy de INSERT sobre integrity.audit_event', r;
    END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = led AND k.conname = 'audit_event_aggregate_type_enum' AND k.convalidated)
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = led AND t.tgname = 'audit_event_single_aggregate_type' AND t.tgenabled = 'A' AND NOT t.tgisinternal) <> 1 THEN
    RAISE EXCEPTION 'faltan el CHECK de aggregate_type o el trigger de un aggregate_type por aggregate_id en integrity.audit_event';
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

-- Aserciones propias de 0039 (D6 y el trigger del ledger).
DO $assert39$
DECLARE
  f record;
BEGIN
  SELECT p.prosrc, p.proowner, p.proconfig, p.prosecdef INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'case_state' AND p.proname = 'close_case';
  IF pg_catalog.strpos(f.prosrc, 'r.created_at >= v_case.created_at') = 0 THEN RAISE EXCEPTION 'close_case no impone D6 (Revocation posterior a la apertura del caso)'; END IF;
  SELECT p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner, p.proconfig, p.prosecdef, p.oid INTO f
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'integrity' AND p.proname = 'audit_event_single_aggregate_type';
  IF f.owner <> 'integrity_owner' OR f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR pg_catalog.strpos(f.prosrc, 'pg_advisory_xact_lock(pg_catalog.hashtextextended(''ledger-chain:'' || NEW.tenant_id::text, 0))') = 0
     OR f.prosrc ~* '\mexecute\M' OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'integrity.audit_event_single_aggregate_type() no es la declarada (dueno, search_path, lock del ledger, sin SQL dinamico, sin EXECUTE PUBLIC)';
  END IF;
END
$assert39$;
