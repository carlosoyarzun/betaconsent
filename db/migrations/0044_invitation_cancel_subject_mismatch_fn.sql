-- scope: database
-- Gobierna: ADR-010 rev. 5 (LG-3 y LG-5 de Carlos, 2026-10-13; F-A10-30) y la opcion A de Carlos (2026-10-14) para I9: la cancelacion de la
-- invitacion por "No es mi estudiante" (invitation.spec.yaml I9, reasonCode SUBJECT_MISMATCH_REPORTED; API-CNS-128, POST /decision/subject-mismatch;
-- D-06) pasa a UNA funcion SECURITY DEFINER por agregado en el esquema case_state, con el mismo patron que las funciones de revocacion y
-- rights-case (0037/0038/0041). 0041 retiro a proposito Invitation:INVITATION_CANCELLED de la allowlist de INSERT de app_rw ("sin productor en
-- src/"): este cambio NO la reabre; el evento lo escribe transition_owner por case_state.ledger_append (policy audit_event_transition_insert, 0037).
-- 0010, 0041 y 0043 estan mergeadas o en el mismo PR y no se editan: todo va en migracion nueva.
--
-- 1) app.invitation: transition_owner recibe SELECT por columnas y UPDATE(state) bajo RLS por tenant; su policy de UPDATE solo ve filas VERIFIED o
--    CANCELLED y solo deja el valor CANCELLED. app_rw ya NO puede insertar ni dejar una invitacion en CANCELLED (policies insert/update
--    con state <> 'CANCELLED', USING incluido: tampoco puede des-cancelar): el unico camino a CANCELLED es la funcion de abajo.
-- 2) case_state.cancel_invitation_subject_mismatch(p_invitation_ref, p_decision_maker_ref, p_expected_sequence) RETURNS jsonb {sequence}:
--    tenant SIEMPRE de app.current_tenant_id() (nunca un parametro); FOR UPDATE de la fila; assert_sequence (RV409) ANTES de los guards de estado;
--    guard GRD-IV-10: el decision_maker_ref pasado debe ser el ligado en I5 (IV009 -> ERR-IV-09; NULL se rechaza siempre) y se comprueba ANTES de la rama idempotente;
--    ya CANCELLED con el mismo DM -> idempotente (no escribe); estado distinto de VERIFIED -> IV009; VERIFIED -> CANCELLED + INVITATION_CANCELLED
--    por case_state.ledger_append (dedupe estricto RV002 de 0041 respetado: clave `<ref>:cancelled:SUBJECT_MISMATCH_REPORTED`). Invitacion inexistente o
--    de otro tenant -> RV001 (404 uniforme). Sin SQL dinamico. Dueno transition_owner, EXECUTE solo app_rw.
-- 3) $assert44$ final con el estado exacto resultante.
-- Idempotente: DROP POLICY IF EXISTS + CREATE, ALTER POLICY, CREATE OR REPLACE FUNCTION, GRANT/REVOKE repetibles.

-- 1. Grants y policies de app.invitation (dueno: consent_owner) ----------------------------------------------------------------------------
GRANT SELECT (tenant_id, invitation_ref, state, bound_decision_maker_ref) ON app.invitation TO transition_owner;
GRANT UPDATE (state) ON app.invitation TO transition_owner;
-- El CHECK invitation_recipient_channel_reserved (0010) se evalua con los privilegios de quien actualiza la fila: sin EXECUTE de esta funcion pura
-- (booleano sobre texto, sin acceso a datos) el UPDATE de transition_owner falla con 42501.
GRANT EXECUTE ON FUNCTION app.is_reserved_email(text) TO transition_owner;
DROP POLICY IF EXISTS invitation_transition_select ON app.invitation;
CREATE POLICY invitation_transition_select ON app.invitation FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
DROP POLICY IF EXISTS invitation_transition_update ON app.invitation;
CREATE POLICY invitation_transition_update ON app.invitation FOR UPDATE TO transition_owner
  USING (tenant_id = app.current_tenant_id() AND state IN ('VERIFIED', 'CANCELLED'))
  WITH CHECK (tenant_id = app.current_tenant_id() AND state = 'CANCELLED');
ALTER POLICY invitation_tenant_insert ON app.invitation
  WITH CHECK (tenant_id = app.current_tenant_id() AND state <> 'CANCELLED');
ALTER POLICY invitation_tenant_update ON app.invitation
  USING (tenant_id = app.current_tenant_id() AND state <> 'CANCELLED')
  WITH CHECK (tenant_id = app.current_tenant_id() AND state <> 'CANCELLED');

-- 2. Funcion (transition_owner) -----------------------------------------------------------------------------------------------------------
SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final del bloque
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION case_state.cancel_invitation_subject_mismatch(p_invitation_ref text, p_decision_maker_ref text, p_expected_sequence integer)
  RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_state text;
  v_bound text;
  v_ev record;
BEGIN
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  SELECT i.state, i.bound_decision_maker_ref INTO v_state, v_bound FROM app.invitation i
   WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref FOR UPDATE;
  IF NOT FOUND THEN
    -- La policy de UPDATE de transition_owner solo expone filas VERIFIED o CANCELLED a FOR UPDATE: una fila del tenant en otro estado se
    -- distingue por una lectura simple (GRD-IV-10 -> IV009); inexistente o de otro tenant -> RV001 (ERR-CM-01 uniforme).
    PERFORM 1 FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref;
    IF FOUND THEN RAISE EXCEPTION 'la invitacion no es cancelable en este estado' USING ERRCODE = 'IV009'; END IF;
    RAISE EXCEPTION 'invitacion no encontrada' USING ERRCODE = 'RV001';
  END IF;
  PERFORM case_state.assert_sequence(p_invitation_ref, p_expected_sequence);
  -- GRD-IV-10 (cancel_reason_and_actor): el actor es el DecisionMaker ligado en I5; va ANTES de la rama idempotente.
  -- Un p_decision_maker_ref NULL nunca es el ligado (aunque la fila tampoco lo tenga): IS DISTINCT FROM trataria NULL = NULL como igual.
  IF p_decision_maker_ref IS NULL OR v_bound IS DISTINCT FROM p_decision_maker_ref THEN RAISE EXCEPTION 'decisionMakerRef no es el ligado a la invitacion' USING ERRCODE = 'IV009'; END IF;
  IF v_state = 'CANCELLED' THEN
    RETURN pg_catalog.jsonb_build_object('sequence', p_expected_sequence); -- idempotente: sin escribir
  END IF;
  IF v_state <> 'VERIFIED' THEN RAISE EXCEPTION 'la invitacion no es cancelable en este estado' USING ERRCODE = 'IV009'; END IF;
  UPDATE app.invitation SET state = 'CANCELLED' WHERE tenant_id = v_tenant AND invitation_ref = p_invitation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Invitation', p_invitation_ref, 'INVITATION_CANCELLED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('invitationRef', p_invitation_ref, 'reasonCode', 'SUBJECT_MISMATCH_REPORTED'),
    p_invitation_ref || ':cancelled:SUBJECT_MISMATCH_REPORTED', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

REVOKE EXECUTE ON FUNCTION case_state.cancel_invitation_subject_mismatch(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION case_state.cancel_invitation_subject_mismatch(text, text, integer) TO app_rw;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;

-- 3. Aserciones del estado resultante -------------------------------------------------------------------------------------------------------
DO $assert44$
DECLARE
  f record;
  inv oid;
  led oid;
  r text;
  v_expr text;
  v_pairs text[];
BEGIN
  SELECT c.oid INTO inv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'invitation';
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';

  -- Funcion: dueno, SECURITY DEFINER, search_path fijo, sin SQL dinamico, EXECUTE solo app_rw.
  SELECT p.oid, p.prosrc, p.prosecdef, p.proconfig, p.proacl, p.proowner, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'case_state' AND p.proname = 'cancel_invitation_subject_mismatch';
  IF f.oid IS NULL THEN RAISE EXCEPTION 'falta case_state.cancel_invitation_subject_mismatch()'; END IF;
  IF f.owner IS DISTINCT FROM 'transition_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR f.prosrc ~* '\mexecute\M' OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'case_state.cancel_invitation_subject_mismatch() no es la declarada (dueno, SECURITY DEFINER, search_path, sin SQL dinamico, sin EXECUTE PUBLIC)';
  END IF;
  IF NOT pg_catalog.has_function_privilege('transition_owner', 'app.is_reserved_email(text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'transition_owner necesita EXECUTE de app.is_reserved_email(text) para el CHECK de app.invitation';
  END IF;
  IF NOT pg_catalog.has_function_privilege('app_rw', f.oid, 'EXECUTE') THEN RAISE EXCEPTION 'app_rw debe poder ejecutar case_state.cancel_invitation_subject_mismatch()'; END IF;
  FOREACH r IN ARRAY ARRAY['worker', 'platform_rw', 'integrity_verifier'] LOOP
    IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar case_state.cancel_invitation_subject_mismatch()', r; END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a
       WHERE a.grantee <> f.proowner AND pg_catalog.pg_get_userbyid(a.grantee) <> 'app_rw') <> 0 THEN
    RAISE EXCEPTION 'la ACL de case_state.cancel_invitation_subject_mismatch() debe ser solo dueno y app_rw';
  END IF;
  IF pg_catalog.strpos(f.prosrc, 'app.current_tenant_id()') = 0 OR pg_catalog.strpos(f.prosrc, 'case_state.ledger_append') = 0
     OR pg_catalog.strpos(f.prosrc, 'case_state.assert_sequence') = 0 OR pg_catalog.strpos(f.prosrc, 'IV009') = 0 THEN
    RAISE EXCEPTION 'case_state.cancel_invitation_subject_mismatch() perdio tenant de la sesion, assert_sequence, ledger_append o el guard IV009';
  END IF;
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema case_state', r; END IF;
  END LOOP;

  -- app.invitation: transition_owner solo SELECT por columnas y UPDATE(state); sus dos policies exactas; app_rw sin camino a CANCELLED.
  IF pg_catalog.has_table_privilege('transition_owner', inv, 'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'transition_owner solo puede leer y actualizar state en app.invitation';
  END IF;
  IF (SELECT pg_catalog.string_agg(a.attname::text, ',' ORDER BY a.attname::text) FROM pg_catalog.pg_attribute a
       WHERE a.attrelid = inv AND a.attnum > 0 AND NOT a.attisdropped AND pg_catalog.has_column_privilege('transition_owner', inv, a.attnum, 'UPDATE')) IS DISTINCT FROM 'state' THEN
    RAISE EXCEPTION 'transition_owner solo debe poder actualizar la columna state de app.invitation';
  END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::text || ':' || p.polcmd::text, ' ' ORDER BY p.polname) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = inv AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'transition_owner') = ANY (p.polroles))
     IS DISTINCT FROM 'invitation_transition_select:r invitation_transition_update:w' THEN
    RAISE EXCEPTION 'las policies de transition_owner sobre app.invitation no son exactamente select y update';
  END IF;
  FOREACH r IN ARRAY ARRAY['invitation_tenant_insert', 'invitation_tenant_update'] LOOP
    SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = inv AND p.polname = r;
    IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'CANCELLED') = 0 THEN RAISE EXCEPTION 'la policy % debe excluir CANCELLED para app_rw', r; END IF;
  END LOOP;
  SELECT pg_catalog.pg_get_expr(p.polqual, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = inv AND p.polname = 'invitation_tenant_update';
  IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'CANCELLED') = 0 THEN RAISE EXCEPTION 'invitation_tenant_update USING debe excluir CANCELLED (sin des-cancelar)'; END IF;

  -- La allowlist de INSERT de app_rw sobre el ledger NO se reabre: sigue sin Invitation:INVITATION_CANCELLED (LG-3/LG-5, 0041) y con 19 pares.
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p
   WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a';
  IF v_expr IS NULL THEN RAISE EXCEPTION 'falta audit_event_tenant_insert'; END IF;
  SELECT pg_catalog.array_agg(m[1]) INTO v_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF pg_catalog.array_length(v_pairs, 1) IS DISTINCT FROM 19 OR 'Invitation:INVITATION_CANCELLED' = ANY (v_pairs) THEN
    RAISE EXCEPTION 'la allowlist de app_rw debe seguir en 19 pares y sin Invitation:INVITATION_CANCELLED (0041)';
  END IF;
END
$assert44$;
