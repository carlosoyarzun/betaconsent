-- scope: database
-- Gobierna: ADR-010 rev. 5 (propuesta; cierre parcial de F-A10-30, decisiones LG-3 y LG-5 de Carlos del 2026-10-13); ADR-010 rev. 4 §4.2;
-- specs/db-roles.spec.yaml INV-DBR-07; registers/findings-register-IT0.md F-A10-30. 0037 y 0039 estan mergeadas y son inmutables: todo va en migracion nueva.
-- Se publica como 0041 (0040 la usa otro PR en paralelo).
--
-- 1) La allowlist de INSERT de app_rw sobre integrity.audit_event baja de 24 a 19 pares: se quitan los 5 sin productor en src/ (Tenant:TENANT_STATUS_CHANGED,
--    SchoolParticipation:SCHOOL_PARTICIPATION_STATUS_CHANGED, Invitation:INVITATION_TOKEN_ROTATED, Invitation:INVITATION_EXPIRED, Invitation:INVITATION_CANCELLED).
--    Los tipos siguen en el CHECK audit_event_event_type_allowlist (0013/0030): solo app_rw deja de poder forjarlos.
-- 2) Dedupe estricto en case_state.ledger_append (CREATE OR REPLACE; mismo dueno, firma, ACL, SECURITY DEFINER y search_path; sin SQL dinamico): si la
--    clave de idempotencia ya existe, compara agregado, tipo, actor y payload canonico guardados contra los nuevos y aborta con RV002 si difieren.
-- Idempotente en re-deploy: CREATE OR REPLACE, ALTER POLICY, GRANT/REVOKE repetibles.

SET LOCAL ROLE case_state_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner; -- temporal: se revoca al final del bloque
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Append al ledger de las funciones de transicion, ahora con dedupe estricto.
CREATE OR REPLACE FUNCTION case_state.ledger_append(
  p_aggregate_type text, p_aggregate_id text, p_event_type text, p_actor_type text, p_actor_role text,
  p_recorded_by_ref text, p_cosigned_by_ref text, p_payload jsonb, p_idempotency_key text, p_expected_sequence integer,
  OUT o_sequence integer, OUT o_payload jsonb, OUT o_deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_key_hash text;
  v_current integer;
  v_chain_seq bigint;
  v_prev text;
  v_occurred text;
  v_env text;
  v_payload_hash text;
  v_event_hash text;
  v_now timestamptz := pg_catalog.now();
  v_dup_type text;
  v_dup_agg text;
  v_dup_payload jsonb;
  v_dup_actor_type text;
  v_dup_actor_role text;
  v_dup_rec text;
  v_dup_cosign text;
BEGIN
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ledger-chain:' || v_tenant::text, 0));

  IF p_idempotency_key IS NOT NULL THEN
    v_key_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_idempotency_key, 'UTF8')), 'hex');
    SELECT e.sequence, e.payload, e.event_type, e.aggregate_type, e.actor_type, e.actor_role, e.recorded_by_ref, e.cosigned_by_ref
      INTO o_sequence, v_dup_payload, v_dup_type, v_dup_agg, v_dup_actor_type, v_dup_actor_role, v_dup_rec, v_dup_cosign
      FROM integrity.audit_event e
     WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id AND e.idempotency_key_hash = v_key_hash;
    IF FOUND THEN
      -- Dedupe estricto (F-A10-30, ADR-010 rev. 5): una clave de idempotencia solo es un reintento si el evento nuevo es IGUAL al guardado
      -- (agregado, tipo, actor y payload canonico). Cualquier diferencia no es un reintento: aborta sin devolver el evento previo ni escribir.
      IF v_dup_type IS DISTINCT FROM p_event_type OR v_dup_agg IS DISTINCT FROM p_aggregate_type
         OR v_dup_actor_type IS DISTINCT FROM p_actor_type OR v_dup_actor_role IS DISTINCT FROM p_actor_role
         OR v_dup_rec IS DISTINCT FROM p_recorded_by_ref OR v_dup_cosign IS DISTINCT FROM p_cosigned_by_ref
         OR case_state.canonical_json(v_dup_payload) IS DISTINCT FROM case_state.canonical_json(p_payload) THEN
        RAISE EXCEPTION 'clave de idempotencia reutilizada con otro evento (tipo, agregado, actor o payload)' USING ERRCODE = 'RV002';
      END IF;
      o_payload := v_dup_payload;
      o_deduped := true;
      RETURN;
    END IF;
  END IF;

  SELECT COALESCE(pg_catalog.max(e.sequence), 0) INTO v_current
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id;
  IF p_expected_sequence IS DISTINCT FROM v_current THEN
    RAISE EXCEPTION 'ledger sequence conflict' USING ERRCODE = 'RV409', DETAIL = pg_catalog.format('expected=%s actual=%s', p_expected_sequence, v_current);
  END IF;

  SELECT e.chain_seq, e.event_hash INTO v_chain_seq, v_prev
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant AND e.chain_seq IS NOT NULL ORDER BY e.chain_seq DESC LIMIT 1;
  v_chain_seq := COALESCE(v_chain_seq, 0) + 1;
  v_prev := COALESCE(v_prev, pg_catalog.repeat('0', 64));
  v_occurred := pg_catalog.to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  v_env := ops.catalog_environment();
  v_payload_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(case_state.canonical_json(p_payload), 'UTF8')), 'hex');
  v_event_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(case_state.canonical_json(pg_catalog.jsonb_build_object(
    'v', 2, 'tenantId', v_tenant, 'chainSeq', v_chain_seq, 'aggregateType', p_aggregate_type, 'aggregateId', p_aggregate_id,
    'sequence', v_current + 1, 'eventType', p_event_type, 'actorType', p_actor_type, 'actorRole', p_actor_role,
    'recordedByRef', p_recorded_by_ref, 'cosignedByRef', p_cosigned_by_ref, 'idempotencyKeyHash', v_key_hash,
    'occurredAt', v_occurred, 'environment', v_env, 'payloadHash', v_payload_hash, 'previousEventHash', v_prev)), 'UTF8')), 'hex');

  INSERT INTO integrity.audit_event
    (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload,
     idempotency_key_hash, chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  VALUES
    (v_tenant, p_aggregate_type, p_aggregate_id, v_current + 1, p_event_type, p_actor_type, p_actor_role, p_recorded_by_ref, p_cosigned_by_ref, p_payload,
     v_key_hash, v_chain_seq, v_payload_hash, v_prev, v_event_hash, v_now, v_env);
  o_sequence := v_current + 1;
  o_payload := p_payload;
  o_deduped := false;
END
$fn$;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
SET LOCAL ROLE consent_owner;

-- 2. Allowlist de 19 pares (integrity_owner) -------------------------------------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
ALTER POLICY audit_event_tenant_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND (aggregate_type || ':' || event_type) = ANY (ARRAY[
                'Tenant:TENANT_SEEDED',
                'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED',
                'Enrollment:ENROLLMENT_STATUS_CHANGED',
                'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_READY', 'Invitation:INVITATION_SENT',
                'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_VERIFIED', 'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_DECLINED',
                'DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED',
                'ConsentDecision:CONTEXT_INFORMATION_VIEWED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED',
                'ConsentDecision:SUBJECT_CONFIRMED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:CONSENT_GRANTED',
                'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:RECEIPT_CREATED'])
              AND NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = aggregate_id)
              AND NOT EXISTS (SELECT 1 FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = aggregate_id));
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 3. Aserciones ---------------------------------------------------------------------------------------------------------------------------
DO $assert41$
DECLARE
  f record;
  led oid;
  r text;
  v_expr text;
  v_pairs text[];
  expect_pairs text[] := ARRAY[
    'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:CONSENT_GRANTED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:CONTEXT_INFORMATION_VIEWED',
    'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:RECEIPT_CREATED', 'ConsentDecision:SUBJECT_CONFIRMED',
    'DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED', 'Enrollment:ENROLLMENT_STATUS_CHANGED',
    'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_DECLINED', 'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_READY',
    'Invitation:INVITATION_SENT', 'Invitation:INVITATION_VERIFIED',
    'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED', 'Tenant:TENANT_SEEDED'];
BEGIN
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  -- Una sola policy de INSERT alcanza a app_rw (ni ALL ni PUBLIC), es audit_event_tenant_insert y es solo para app_rw.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
         AND (0::oid = ANY (p.polroles) OR (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'app_rw') = ANY (p.polroles))) <> 1 THEN
    RAISE EXCEPTION 'exactamente una policy de INSERT debe alcanzar a app_rw en integrity.audit_event (INV-DBR-07)';
  END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p
   WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a'
     AND (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',') FROM pg_catalog.unnest(p.polroles) AS x) = 'app_rw';
  IF v_expr IS NULL THEN RAISE EXCEPTION 'falta audit_event_tenant_insert (INSERT, solo app_rw)'; END IF;
  -- Allowlist EXACTA de 19 pares (los literales Agregado:Evento de la expresion, sin duplicados).
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO v_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF v_pairs IS DISTINCT FROM expect_pairs THEN RAISE EXCEPTION 'la allowlist de la policy de INSERT de app_rw no es exactamente la de 19 pares (F-A10-30)'; END IF;
  IF pg_catalog.strpos(v_expr, 'revocation_ref') = 0 OR pg_catalog.strpos(v_expr, 'case_ref') = 0 OR pg_catalog.strpos(v_expr, 'current_tenant_id()') = 0 THEN
    RAISE EXCEPTION 'la policy de INSERT de app_rw perdio el filtro de tenant o los NOT EXISTS de revocation/rights_case';
  END IF;
  -- Ningun rol del que app_rw herede o pueda asumir (USAGE/SET) tiene INSERT sobre el ledger ni una policy de INSERT/ALL propia.
  FOR r IN SELECT x.rolname::text FROM pg_catalog.pg_roles x
            WHERE x.rolname <> 'app_rw' AND (pg_catalog.pg_has_role('app_rw', x.oid, 'USAGE') OR pg_catalog.pg_has_role('app_rw', x.oid, 'SET')) LOOP
    IF pg_catalog.has_any_column_privilege(r, led, 'INSERT') THEN RAISE EXCEPTION 'app_rw alcanza por membresia a % con INSERT sobre integrity.audit_event', r; END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
                AND (SELECT y.oid FROM pg_catalog.pg_roles y WHERE y.rolname = r) = ANY (p.polroles)) THEN
      RAISE EXCEPTION 'app_rw alcanza por membresia a % con una policy de INSERT sobre integrity.audit_event', r;
    END IF;
  END LOOP;

  -- case_state.ledger_append: dueno, SECURITY DEFINER, search_path, sin SQL dinamico, ACL sin PUBLIC ni grantees, dedupe estricto, esquema sin CREATE.
  SELECT p.oid, p.prosrc, p.prosecdef, p.proconfig, p.proacl, p.proowner, pg_catalog.pg_get_userbyid(p.proowner) AS owner INTO f
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'ledger_append';
  IF f.owner IS DISTINCT FROM 'transition_owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR f.prosrc ~* '\mexecute\M' OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'case_state.ledger_append() no es la declarada (dueno, SECURITY DEFINER, search_path, sin SQL dinamico, sin EXECUTE PUBLIC)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner) <> 0 THEN
    RAISE EXCEPTION 'la ACL de case_state.ledger_append() debe quedar sin grantees distintos del dueno';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier'] LOOP
    IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar case_state.ledger_append()', r; END IF;
  END LOOP;
  IF pg_catalog.strpos(f.prosrc, 'case_state.canonical_json(v_dup_payload) IS DISTINCT FROM case_state.canonical_json(p_payload)') = 0
     OR pg_catalog.strpos(f.prosrc, 'v_dup_actor_type IS DISTINCT FROM p_actor_type') = 0 OR pg_catalog.strpos(f.prosrc, 'v_dup_rec IS DISTINCT FROM p_recorded_by_ref') = 0
     OR pg_catalog.strpos(f.prosrc, 'v_dup_agg IS DISTINCT FROM p_aggregate_type') = 0 THEN
    RAISE EXCEPTION 'case_state.ledger_append() no impone el dedupe estricto (agregado, tipo, actor y payload)';
  END IF;
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema case_state', r; END IF;
  END LOOP;
  IF pg_catalog.has_schema_privilege('integrity_owner', 'app', 'USAGE') OR pg_catalog.has_function_privilege('integrity_owner', 'app.current_tenant_id()', 'EXECUTE') THEN
    RAISE EXCEPTION 'integrity_owner conserva el grant temporal sobre app';
  END IF;
END
$assert41$;
