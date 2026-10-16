-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a (R4 sincrono y atomico como excepcion declarada a §4.2/GRD-CM-15; P6-2; G-3, lectura (A) confirmada el 2026-10-15; F-PR6-14, F-PR6-19,
-- F-PR6-25), §10 fila 6d ("R4 compuesta atomica con reintentos acotados, alerta y sin acuse al agotarse"), §15.3 punto 4; specs/state-machines/revocation.spec.yaml (R3, R4, FN-RV-03, FN-RV-12, INV-RV-07);
-- GRD-CM-15 (excepcion), INV-DBR-06; registers/findings-register-IT0.md F-A10-26 (esta migracion es la parte atomica; el REVOKE de EXECUTE va en 0070). 0037 es inmutable: los reemplazos van aqui, con las MISMAS firmas.
--
-- Que cambia (transition_owner, SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico):
--   case_state.r4_apply(revocation_ref, expected_sequence)  NUEVA, INTERNA (sin EXECUTE para ningun rol de runtime). Es R4 + C6 (CONFIRMED -> APPLIED, CONSENT_REVOKED + RECEIPT_CREATED, outbox consent.revoked, decision
--       GRANTED -> REVOKED), con el cuerpo de FN-RV-12 (0037). Actor del ledger: HUMAN / DECISION_MAKER (DEC-BR-017 §8; el ejecutor no cambia el actor). La llaman confirm_revocation (en linea) y apply_revocation (respaldo).
--   case_state.apply_revocation(revocation_ref, expected_sequence)  REEMPLAZADA (misma firma, mismo EXECUTE: app_rw + worker hasta 0070): delega en r4_apply. Es el proceso de RESPALDO del `worker` para una Revocation
--       CONFIRMED sin APPLIED (fila anterior a esta migracion o anomalia); idempotente por expected_sequence y por las claves de idempotencia del ledger.
--   case_state.confirm_revocation(revocation_ref, expected_sequence)  REEMPLAZADA (misma firma, mismo EXECUTE: app_rw): R3 / R3r y R4 + C6 en la MISMA transaccion (excepcion unica a GRD-CM-15). Si R4 falla se revierte la
--       tx completa (R3 + R4 + C6 + ledger): no hay commit parcial ni CONFIRMED visible sin APPLIED (la alternativa SAVEPOINT queda descartada). Concurrencia (P2(c)): toma el lock de la fila de la Revocation y despues
--       SELECT ... FOR UPDATE de la consent_decision afectada ANTES del primer append al ledger (orden revocation -> decision -> ledger, igual que 0037 y 0032:20-21), y acota lock_timeout a 5 s si estaba sin tope o
--       en un valor mayor (valor tecnico, no regulatorio; nunca lo amplia). Devuelve {sequence, applied: true}.
-- NO cambia: revoke_with_recovery_link (R1r/R2r/R10, EXECUTE app_rw). R3r + R4 se componen en la tx del llamador llamando despues a confirm_revocation: un solo POST, una sola tx; si R4 falla no queda Revocation ni token consumido.
-- Reintentos acotados, alerta de agotamiento y commit ambiguo son del llamador (web / platform, ver 0067 y src/server/modules/revocation/apply-guard.ts): la base solo garantiza atomicidad.
-- Idempotente: CREATE OR REPLACE (mismas firmas; la ACL de 0037 se conserva) y GRANT/REVOKE repetibles.

SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final del bloque
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- R4 + C6 interna (sin EXECUTE de runtime).
CREATE FUNCTION case_state.r4_apply(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_dec app.consent_decision;
  v_ev record;
  v_rc record;
  v_effective text;
  v_payload jsonb;
  v_lt bigint;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'apply_revocation', true);
  -- Valor tecnico (no regulatorio): un lock que no se obtiene en 5 s falla con 55P03 (el llamador reintenta la tx completa); nunca se amplia un tope menor.
  SELECT s.setting::bigint INTO v_lt FROM pg_catalog.pg_settings s WHERE s.name = 'lock_timeout';
  IF v_lt = 0 OR v_lt > 5000 THEN PERFORM pg_catalog.set_config('lock_timeout', '5000ms', true); END IF;
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'CONFIRMED' OR v_rev.verified_auth_path IS NULL OR v_rev.revoked_decision_ref IS NULL
     OR (v_rev.verified_auth_path = 'RECOVERY' AND v_rev.verified_recovery_method IS NULL) THEN
    RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002';
  END IF;
  SELECT d.* INTO v_dec FROM app.consent_decision d
   WHERE d.tenant_id = v_rev.tenant_id AND d.consent_id = v_rev.revoked_decision_ref FOR UPDATE;
  IF NOT FOUND OR v_dec.state NOT IN ('GRANTED', 'REVOKED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;

  v_effective := pg_catalog.to_char(pg_catalog.now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload := pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'revokedDecisionRef', v_rev.revoked_decision_ref, 'scope', 'ALL',
    'effectiveAt', v_effective, 'authPath', v_rev.verified_auth_path, 'originPurposeRef', 'ALL');
  IF v_rev.verified_auth_path = 'RECOVERY' THEN
    v_payload := v_payload || pg_catalog.jsonb_build_object('recoveryMethod', v_rev.verified_recovery_method);
  END IF;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'CONSENT_REVOKED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    v_payload, p_revocation_ref || ':r4', p_expected_sequence);
  SELECT * INTO v_rc FROM case_state.ledger_append('Revocation', p_revocation_ref, 'RECEIPT_CREATED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('receiptRef', p_revocation_ref, 'managementLinkIssued', false), p_revocation_ref || ':receipt',
    GREATEST(p_expected_sequence, v_ev.o_sequence));
  v_effective := v_ev.o_payload ->> 'effectiveAt'; -- ante dedupe es el original (un solo reloj)

  INSERT INTO app.outbox (tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, occurred_at, payload)
  VALUES (v_rev.tenant_id, p_revocation_ref || ':consent.revoked', 'consent.revoked', '1.0.0', v_dec.context_ref, v_dec.subject_ref,
          v_effective::timestamptz,
          pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'scope', 'ALL', 'effectiveAt', v_effective))
  ON CONFLICT (tenant_id, dedupe_key) DO NOTHING;

  IF v_dec.state = 'GRANTED' THEN
    UPDATE app.consent_decision SET state = 'REVOKED' WHERE tenant_id = v_dec.tenant_id AND consent_id = v_dec.consent_id;
  END IF;
  UPDATE app.revocation SET status = 'APPLIED' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  RETURN pg_catalog.jsonb_build_object('sequence', v_rc.o_sequence);
END
$fn$;

-- FN-RV-12 (proceso de respaldo del worker): mismo nombre, firma y ACL que en 0037.
CREATE OR REPLACE FUNCTION case_state.apply_revocation(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  RETURN case_state.r4_apply(p_revocation_ref, p_expected_sequence);
END
$fn$;

-- FN-RV-03 R3 / R3r + R4 + C6 en la misma tx. La confirmacion de una verificacion HUMAN_ASSISTED solo es de RH3 (cuatro ojos): nunca por aqui.
CREATE OR REPLACE FUNCTION case_state.confirm_revocation(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_dec_state text;
  v_ev record;
  v_r4 jsonb;
  v_lt bigint;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'confirm_revocation', true);
  SELECT s.setting::bigint INTO v_lt FROM pg_catalog.pg_settings s WHERE s.name = 'lock_timeout';
  IF v_lt = 0 OR v_lt > 5000 THEN PERFORM pg_catalog.set_config('lock_timeout', '5000ms', true); END IF;
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'VERIFIED' OR v_rev.verified_recovery_method IS NOT DISTINCT FROM 'HUMAN_ASSISTED' THEN
    RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002';
  END IF;
  -- P2(c): la decision afectada se bloquea ANTES del primer append al ledger. Si R4 no puede aplicarse (decision ausente o ni GRANTED ni REVOKED) se rechaza AQUI: sin R3 no hay R4 y la tx no deja nada.
  SELECT d.state INTO v_dec_state FROM app.consent_decision d
   WHERE d.tenant_id = v_rev.tenant_id AND d.consent_id = v_rev.revoked_decision_ref FOR UPDATE;
  IF NOT FOUND OR v_dec_state NOT IN ('GRANTED', 'REVOKED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET status = 'CONFIRMED' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_CONFIRMED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref), p_revocation_ref || ':r3', p_expected_sequence);
  -- R4 + C6 en linea (excepcion declarada a GRD-CM-15): si falla, el error revierte tambien R3.
  v_r4 := case_state.r4_apply(p_revocation_ref, v_ev.o_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', (v_r4 ->> 'sequence')::integer, 'applied', true);
END
$fn$;

REVOKE ALL ON FUNCTION case_state.r4_apply(text, integer) FROM PUBLIC;
-- r4_apply: ningun GRANT (interna). apply_revocation y confirm_revocation conservan su ACL de 0037.

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;

DO $assert66$
DECLARE
  f record;
  r text;
  n integer;
  spec text[];
BEGIN
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['r4_apply', ''], ARRAY['apply_revocation', 'app_rw,worker'], ARRAY['confirm_revocation', 'app_rw']] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = spec[1];
    IF n <> 1 THEN RAISE EXCEPTION '0066: case_state.% debe existir exactamente una vez (hay %)', spec[1], n; END IF;
    SELECT p.oid, p.prosrc, p.prosecdef, p.proconfig, p.proacl, p.proowner, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = spec[1];
    IF f.owner <> 'transition_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN
      RAISE EXCEPTION '0066: case_state.%: dueno/SECURITY DEFINER/search_path incorrectos', spec[1];
    END IF;
    IF pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN RAISE EXCEPTION '0066: PUBLIC puede ejecutar case_state.%', spec[1]; END IF;
    IF f.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION '0066: case_state.% contiene SQL dinamico', spec[1]; END IF;
    IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                   FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner), '') IS DISTINCT FROM spec[2] THEN
      RAISE EXCEPTION '0066: la ACL de case_state.% no es exactamente [%]', spec[1], spec[2];
    END IF;
  END LOOP;
  -- La interna no es alcanzable por ningun rol de runtime.
  SELECT p.oid INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'r4_apply';
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'integrity_reconciler'] LOOP
    IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '0066: % puede ejecutar case_state.r4_apply (interna)', r; END IF;
  END LOOP;
  -- Reglas que no se pueden perder: R4 en la misma tx, decision bloqueada antes del primer append, actor DECISION_MAKER, claves de idempotencia.
  SELECT p.prosrc INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'confirm_revocation';
  IF f.prosrc !~ 'case_state\.r4_apply\(' OR f.prosrc !~ 'FOR UPDATE' OR f.prosrc !~ 'lock_timeout' OR f.prosrc !~ 'HUMAN_ASSISTED'
     OR pg_catalog.strpos(f.prosrc, 'FOR UPDATE') > pg_catalog.strpos(f.prosrc, 'ledger_append') THEN
    RAISE EXCEPTION '0066: confirm_revocation perdio R4 en la misma tx, el FOR UPDATE previo al ledger, lock_timeout o la exclusion de HUMAN_ASSISTED';
  END IF;
  SELECT p.prosrc INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'r4_apply';
  IF f.prosrc !~ 'CONSENT_REVOKED' OR f.prosrc !~ 'RECEIPT_CREATED' OR f.prosrc !~ 'DECISION_MAKER' OR f.prosrc !~ ':r4' OR f.prosrc !~ 'consent\.revoked' OR f.prosrc !~ 'FOR UPDATE' THEN
    RAISE EXCEPTION '0066: r4_apply perdio CONSENT_REVOKED, RECEIPT_CREATED, el actor DECISION_MAKER, la clave :r4, el outbox o el FOR UPDATE de la decision';
  END IF;
  SELECT p.prosrc INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'apply_revocation';
  IF f.prosrc !~ 'case_state\.r4_apply\(' THEN RAISE EXCEPTION '0066: apply_revocation debe delegar en r4_apply'; END IF;
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '0066: % conserva CREATE en el esquema case_state', r; END IF;
  END LOOP;
END
$assert66$;
