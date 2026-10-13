-- scope: database
-- Gobierna: ADR-010 rev. 4 §4.2 y §7 fila PR-5 (primera mitad, PR-5a); specs/state-machines/revocation.spec.yaml `dbEnforcement`
-- (rev. 4i: FN-RV-01..15, TRG-RV-01, newChecks, revokedFromAppRw, INV-RV-12); specs/db-roles.spec.yaml (transition_owner, Q-18; Q-17 a);
-- GRD-RV-05, GRD-RV-26, GRD-RV-29, GRD-RV-10, GRD-CM-15; registers/findings-register-IT0.md F-A10-01 (parte de app.revocation),
-- F-A10-03, F-A10-04, F-A10-05, F-A10-06. Decisiones de Carlos del 2026-10-11 (ADR-010 rev. 4). Regla de Carlos (2026-10-01): 0000-0036
-- no se editan; todo cambio SQL va en migracion nueva.
--
-- Alcance PR-5a: la base impone la maquina de estados de app.revocation. NO incluye (PR-5b): app.rights_case, app.case_session,
-- tipos CASE_* de ops.security_event, ni el retiro del INSERT de app_rw sobre integrity.audit_event (INV-DBR-07), ni FN-RV-16.
--
-- 1) Esquema case_state (dueno case_state_owner); todas las funciones son de transition_owner (Q-18), SECURITY DEFINER,
--    search_path fijo, sin SQL dinamico, sin EXECUTE para PUBLIC. Cada funcion de transicion fija case_state.effect con su propio
--    nombre al entrar (set_config local a la tx); el trigger exige current_user = transition_owner y las columnas/pares que ese
--    efecto declara. Un RCE con app_rw no puede escribir app.revocation ni siquiera con un set_config propio: sin privilegio de tabla
--    ni policy, y el trigger exige el rol dueno de la funcion.
-- 2) DDL sobre integrity.* (SET LOCAL ROLE integrity_owner; allowlist de integrity-owner-checker.ts; antes de PR-7): transition_owner
--    recibe SELECT/INSERT (por columnas, las mismas de app_rw en 0002/0013) y policies por tenant. app_rw CONSERVA su INSERT en el
--    ledger en PR-5a (retiro en PR-5b). El hash de la cadena se calcula en SQL con canonical_json + sha256, identico a
--    src/server/modules/common/ledger-chain.ts (vectores dorados TS<->SQL: TEST-CNS-1371..).
-- 3) Revokes a app_rw: INSERT/UPDATE de app.revocation (0006:113-118, 0016:18-19) y policies; consent_decision con state = REVOKED
--    (F-A10-06; C6 solo por case_state.apply_revocation).
-- 4) CHECKs nuevos: cosigned_by_ref <> recorded_by_ref (GRD-RV-26), verification_ref UNIQUE (GRD-RV-05, por tenant: una restriccion global
--    seria un canal lateral entre tenants), verified_auth_path NOT NULL desde VERIFIED (GRD-RV-29). Se crean VALIDADOS (precedente 0030): una
--    base antigua con filas que los violen aborta la migracion; en LOCAL/CI (sinteticos) se recrea la base.
--
-- Desviaciones DOCUMENTADAS respecto del spec (FINDINGs del PR; ninguna cambia semantica de consentimiento/revocacion/elegibilidad):
--   * EXECUTE: las funciones SYSTEM (FN-RV-12..15) y las de operador (FN-RV-07..11) se conceden a app_rw ademas de su rol de spec
--     (worker), porque en IT0 el codigo de R3->R4, R5-R7 y RH2/RH3 corre en el proceso web (no existen aun los entrypoints
--     worker/platform: PR-6). Se restringe en PR-6. La autorizacion de sesion CASE/PLATFORM y de grants (platform.*) tampoco se
--     comprueba aqui: llega con la integracion de platform (PR-5b/PR-6).
--   * La propuesta RH2 (proposal_*) sigue en app.revocation (0016); en el spec final vive en platform.case_verification.
--   * Las columnas de propuesta se escriben con los efectos propose_/withdraw_/approve_; las de aprobacion solo con approve_.
--   * seed_local_revocation: funcion de fixtures SOLO LOCAL (ops.catalog_environment() = LOCAL) para el contrato `save` del puerto
--     y las siembras de tests/dev; en cualquier otro entorno falla. Es el unico camino no-transicion y no existe fuera de LOCAL.

-- 1. Esquema y grants de uso -------------------------------------------------------------------------------------------------------
CREATE SCHEMA case_state AUTHORIZATION case_state_owner;
SET LOCAL ROLE case_state_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA case_state TO transition_owner;
GRANT USAGE ON SCHEMA case_state TO app_rw, worker;
SET LOCAL ROLE consent_owner;

GRANT USAGE ON SCHEMA app, ops TO transition_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO transition_owner;
GRANT EXECUTE ON FUNCTION ops.catalog_environment() TO transition_owner;
GRANT SELECT ON ops.db_catalog TO transition_owner; -- ops.catalog_environment() es SQL invoker: lee el catalogo con el rol que escribe

-- Tablas de app.*: transition_owner SELECT y escritura por columnas, siempre bajo RLS por tenant.
GRANT SELECT ON app.revocation, app.consent_decision, app.recovery_token, app.outbox TO transition_owner;
GRANT INSERT (tenant_id, revocation_ref, chain_ref, case_ref, status, attested_revocation_ref, attested_case_ref,
              recorded_by_ref, cosigned_by_ref, revoked_decision_ref, verified_auth_path, verified_recovery_method, reason_code,
              proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref)
  ON app.revocation TO transition_owner;
GRANT UPDATE (case_ref, status, attested_revocation_ref, attested_case_ref, recorded_by_ref, cosigned_by_ref,
              verified_auth_path, verified_recovery_method, reason_code,
              proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref)
  ON app.revocation TO transition_owner;
GRANT UPDATE (state) ON app.consent_decision TO transition_owner;
GRANT UPDATE (consumed_at) ON app.recovery_token TO transition_owner;
GRANT INSERT (tenant_id, dedupe_key, event_type, schema_version, context_ref, subject_ref, occurred_at, payload) ON app.outbox TO transition_owner;

-- GRD-RV-05: verification_ref (UNIQUE por tenant). Columna nueva; la escribe solo case_state.verify_revocation_otp.
ALTER TABLE app.revocation
  ADD COLUMN verification_ref text CONSTRAINT revocation_verification_ref_len CHECK (pg_catalog.length(verification_ref) BETWEEN 1 AND 100);
GRANT INSERT (verification_ref) ON app.revocation TO transition_owner;
GRANT UPDATE (verification_ref) ON app.revocation TO transition_owner;

-- 4. CHECKs (GRD-RV-26 / GRD-RV-05 / GRD-RV-29) --------------------------------------------------------------------------------------
ALTER TABLE app.revocation
  ADD CONSTRAINT revocation_cosigned_distinct_recorded
    CHECK (cosigned_by_ref IS NULL OR (recorded_by_ref IS NOT NULL AND cosigned_by_ref <> recorded_by_ref)),
  ADD CONSTRAINT revocation_verified_auth_path_required
    CHECK (status NOT IN ('VERIFIED', 'CONFIRMED', 'APPLIED', 'DOWNSTREAM_PENDING', 'DELIVERED', 'COMPLETED') OR verified_auth_path IS NOT NULL),
  ADD CONSTRAINT revocation_verification_ref_uq UNIQUE (tenant_id, verification_ref);

-- 2. DDL sobre integrity.* (integrity_owner) ------------------------------------------------------------------------------------------
-- integrity_owner no tiene USAGE/EXECUTE sobre app (0027): se concede de forma temporal para crear policies que usan app.current_tenant_id().
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
GRANT USAGE ON SCHEMA integrity TO transition_owner;
GRANT SELECT ON integrity.audit_event TO transition_owner;
GRANT INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role,
              recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
              chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  ON integrity.audit_event TO transition_owner;
CREATE POLICY audit_event_transition_select ON integrity.audit_event FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY audit_event_transition_insert ON integrity.audit_event FOR INSERT TO transition_owner
  WITH CHECK (tenant_id = app.current_tenant_id());
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 3. Policies de tablas de app.* ----------------------------------------------------------------------------------------------------
-- app.revocation: app_rw solo lee. Insert/update son de transition_owner (las funciones FN-RV-*).
DROP POLICY revocation_tenant_insert ON app.revocation;
DROP POLICY revocation_tenant_update ON app.revocation;
REVOKE INSERT, UPDATE ON app.revocation FROM app_rw;
CREATE POLICY revocation_transition_select ON app.revocation FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY revocation_transition_insert ON app.revocation FOR INSERT TO transition_owner
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY revocation_transition_update ON app.revocation FOR UPDATE TO transition_owner
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

-- app.consent_decision (F-A10-06): app_rw no puede dejar una decision en REVOKED (ni insertarla ni actualizarla); C6 solo por
-- case_state.apply_revocation (transition_owner: GRANTED -> REVOKED, nunca otro valor).
ALTER POLICY consent_decision_tenant_insert ON app.consent_decision
  WITH CHECK (tenant_id = app.current_tenant_id() AND state <> 'REVOKED');
-- USING tambien excluye REVOKED: sin esto app_rw podria des-revocar (REVOKED -> GRANTED) con un UPDATE.
ALTER POLICY consent_decision_tenant_update ON app.consent_decision
  USING (tenant_id = app.current_tenant_id() AND state <> 'REVOKED')
  WITH CHECK (tenant_id = app.current_tenant_id() AND state <> 'REVOKED');
CREATE POLICY consent_decision_transition_select ON app.consent_decision FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY consent_decision_transition_update ON app.consent_decision FOR UPDATE TO transition_owner
  USING (tenant_id = app.current_tenant_id() AND state IN ('GRANTED', 'REVOKED'))
  WITH CHECK (tenant_id = app.current_tenant_id() AND state = 'REVOKED');

CREATE POLICY recovery_token_transition_select ON app.recovery_token FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY recovery_token_transition_update ON app.recovery_token FOR UPDATE TO transition_owner
  USING (tenant_id = app.current_tenant_id() AND consumed_at IS NULL)
  WITH CHECK (tenant_id = app.current_tenant_id());

CREATE POLICY outbox_transition_select ON app.outbox FOR SELECT TO transition_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY outbox_transition_insert ON app.outbox FOR INSERT TO transition_owner
  WITH CHECK (tenant_id = app.current_tenant_id() AND status = 'PENDING' AND attempts = 0);

-- 5. Funciones (transition_owner) ------------------------------------------------------------------------------------------------------
SET LOCAL ROLE transition_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- JSON canonico identico a canonicalJson de ledger-chain.ts: claves ordenadas por punto de codigo (COLLATE "C"), sin espacios; los
-- escalares usan la salida de jsonb (mismo escapado que JSON.stringify para cadenas; enteros sin decimales).
CREATE FUNCTION case_state.canonical_json(p_value jsonb) RETURNS text
  LANGUAGE plpgsql IMMUTABLE
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  t text := pg_catalog.jsonb_typeof(p_value);
BEGIN
  IF t = 'object' THEN
    -- Divergencia documentada TS<->SQL: JS ordena las claves por unidad UTF-16 y COLLATE "C" por punto de codigo; difieren para claves con
    -- caracteres fuera del BMP (U+10000..). Esas claves se PROHIBEN (el contrato de payloads solo usa claves ASCII).
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_value) k WHERE k ~ '[\U00010000-\U0010FFFF]') THEN
      RAISE EXCEPTION 'canonical_json: claves fuera del BMP no admitidas (orden TS<->SQL divergente)' USING ERRCODE = '22023';
    END IF;
    RETURN '{' || COALESCE((SELECT pg_catalog.string_agg(pg_catalog.to_jsonb(e.key)::text || ':' || case_state.canonical_json(e.value), ',' ORDER BY e.key COLLATE "C")
                              FROM pg_catalog.jsonb_each(p_value) e), '') || '}';
  ELSIF t = 'array' THEN
    RETURN '[' || COALESCE((SELECT pg_catalog.string_agg(case_state.canonical_json(a.v), ',' ORDER BY a.ord)
                              FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY AS a(v, ord)), '') || ']';
  END IF;
  RETURN p_value::text;
END
$fn$;

-- Append al ledger en la misma tx (P1-9): replica LedgerPort.append de ledger.adapter.ts (lock por tenant, idempotencia por hash de
-- clave, control optimista de secuencia, eslabon de la cadena SHA-256). Solo la llaman las funciones de transicion (mismo dueno).
-- Conflicto de secuencia: SQLSTATE RV409 (DETAIL "expected=<n> actual=<m>").
CREATE FUNCTION case_state.ledger_append(
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
BEGIN
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ledger-chain:' || v_tenant::text, 0));

  IF p_idempotency_key IS NOT NULL THEN
    v_key_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_idempotency_key, 'UTF8')), 'hex');
    SELECT e.sequence, e.payload, e.event_type, e.aggregate_type INTO o_sequence, o_payload, v_dup_type, v_dup_agg
      FROM integrity.audit_event e
     WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id AND e.idempotency_key_hash = v_key_hash;
    IF FOUND THEN
      -- Una clave de idempotencia reutilizada para OTRO tipo de evento o agregado no es un reintento: no devolver el evento ajeno.
      IF v_dup_type IS DISTINCT FROM p_event_type OR v_dup_agg IS DISTINCT FROM p_aggregate_type THEN
        RAISE EXCEPTION 'clave de idempotencia reutilizada con otro event_type o aggregate_type' USING ERRCODE = 'RV002';
      END IF;
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

-- Control optimista de secuencia del agregado (mismo criterio que ledger_append): la ultima sequence por (tenant, aggregate_id) debe ser la
-- que el llamador leyo ANTES del lock. Va ANTES de los guards de estado: un llamador con lectura vieja (otra tx avanzo el agregado) recibe
-- RV409, el UoW reejecuta con estado fresco y converge (idempotente), igual que cuando la fila se bloqueaba desde el dominio (FOR UPDATE).
CREATE FUNCTION case_state.assert_sequence(p_aggregate_id text, p_expected_sequence integer) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_current integer;
BEGIN
  SELECT COALESCE(pg_catalog.max(e.sequence), 0) INTO v_current
    FROM integrity.audit_event e WHERE e.tenant_id = app.current_tenant_id() AND e.aggregate_id = p_aggregate_id;
  IF p_expected_sequence IS DISTINCT FROM v_current THEN
    RAISE EXCEPTION 'ledger sequence conflict' USING ERRCODE = 'RV409', DETAIL = pg_catalog.format('expected=%s actual=%s', p_expected_sequence, v_current);
  END IF;
END
$fn$;

-- Bloqueo de la fila de la Revocation del tenant de la tx (tenant sale de app.current_tenant_id(), nunca de un parametro). app_rw ya no
-- puede bloquear filas (SELECT ... FOR UPDATE exige UPDATE): la serializacion (GRD-RV-23) es esta, bajo lock, mas assert_sequence.
CREATE FUNCTION case_state.lock_revocation(p_revocation_ref text, p_expected_sequence integer DEFAULT NULL) RETURNS app.revocation
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
BEGIN
  SELECT r.* INTO v_rev FROM app.revocation r
   WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = p_revocation_ref FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'revocation no encontrada' USING ERRCODE = 'RV001'; END IF; -- ERR-CM-01 uniforme
  IF p_expected_sequence IS NOT NULL THEN PERFORM case_state.assert_sequence(p_revocation_ref, p_expected_sequence); END IF;
  RETURN v_rev;
END
$fn$;

-- GRD-RV-02 (paridad con el dominio): una decision que existe y no esta GRANTED no se revoca (ERR-RV-02). Ausente: el dominio la admite en R1.
CREATE FUNCTION case_state.assert_decision_revocable(p_revoked_decision_ref text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF EXISTS (SELECT 1 FROM app.consent_decision d
              WHERE d.tenant_id = app.current_tenant_id() AND d.consent_id = p_revoked_decision_ref AND d.state <> 'GRANTED') THEN
    RAISE EXCEPTION 'cadena sin GRANTED vigente' USING ERRCODE = 'RV003'; -- ERR-RV-02
  END IF;
END
$fn$;

-- FN-RV-01 R1
CREATE FUNCTION case_state.request_revocation(p_revocation_ref text, p_chain_ref text, p_revoked_decision_ref text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'request_revocation', true);
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  PERFORM case_state.assert_decision_revocable(p_revoked_decision_ref);
  INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, status, revoked_decision_ref)
  VALUES (v_tenant, p_revocation_ref, p_chain_ref, 'REQUESTED', p_revoked_decision_ref);
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'revokedDecisionRef', p_revoked_decision_ref, 'scope', 'ALL',
      'authPath', 'OTP', 'originPurposeRef', 'ALL', 'initiatedVia', 'DECISION_MAKER'),
    p_revocation_ref || ':r1', 0);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-02 R2 (GRD-RV-05: verification_ref UNIQUE por tenant; el vinculo con la verificacion OTP lo resuelve el proceso web: residual).
CREATE FUNCTION case_state.verify_revocation_otp(p_revocation_ref text, p_verification_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'verify_revocation_otp', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'REQUESTED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF; -- ERR-CM-06
  UPDATE app.revocation SET status = 'VERIFIED', verified_auth_path = 'OTP', verified_recovery_method = NULL, verification_ref = p_verification_ref
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_VERIFIED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'authPath', 'OTP', 'verificationRef', p_verification_ref,
      'assuranceLevel', 'LD-02-PLACEHOLDER-V1'),
    p_revocation_ref || ':r2', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-03 R3 / R3r. La confirmacion de una verificacion HUMAN_ASSISTED solo es de RH3 (cuatro ojos): nunca por aqui.
CREATE FUNCTION case_state.confirm_revocation(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'confirm_revocation', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'VERIFIED' OR v_rev.verified_recovery_method IS NOT DISTINCT FROM 'HUMAN_ASSISTED' THEN
    RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002';
  END IF;
  UPDATE app.revocation SET status = 'CONFIRMED' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_CONFIRMED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref), p_revocation_ref || ':r3', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-04 R1r + R2r (REQUESTED o nueva) / R10 (VERIFIED): consume el token y verifica por enlace (CHANNEL_LINK). R3r la hace
-- case_state.confirm_revocation en la misma tx; R11 (CONFIRMED) es un NOOP sin consumo que no llega aqui (lo resuelve el dominio).
-- GRD-RV-06: token del tenant, no consumido, no vencido, ligado a la GRANTED vigente de su cadena; si no, SQLSTATE RV007 (respuesta uniforme).
CREATE FUNCTION case_state.revoke_with_recovery_link(p_recovery_ref text, p_new_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_tok app.recovery_token;
  v_rev app.revocation;
  v_ref text;
  v_seq integer;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'revoke_with_recovery_link', true);
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  SELECT t.* INTO v_tok FROM app.recovery_token t WHERE t.tenant_id = v_tenant AND t.recovery_ref = p_recovery_ref FOR UPDATE;
  IF NOT FOUND OR v_tok.consumed_at IS NOT NULL OR v_tok.expires_at <= pg_catalog.now() THEN
    RAISE EXCEPTION 'token de recuperacion no elegible' USING ERRCODE = 'RV007'; -- ERR-RV-05
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.consent_decision d
                  WHERE d.tenant_id = v_tenant AND d.consent_id = v_tok.revoked_decision_ref AND d.chain_ref = v_tok.chain_ref AND d.state = 'GRANTED') THEN
    RAISE EXCEPTION 'token de otro ciclo' USING ERRCODE = 'RV007';
  END IF;
  SELECT r.* INTO v_rev FROM app.revocation r
   WHERE r.tenant_id = v_tenant AND r.chain_ref = v_tok.chain_ref AND r.status NOT IN ('FAILED', 'COMPLETED')
   ORDER BY r.created_at, r.revocation_ref LIMIT 1 FOR UPDATE;
  IF FOUND THEN
    IF v_rev.revoked_decision_ref IS DISTINCT FROM v_tok.revoked_decision_ref THEN
      RAISE EXCEPTION 'revocation de otro ciclo' USING ERRCODE = 'RV007';
    END IF;
    PERFORM case_state.assert_sequence(v_rev.revocation_ref, p_expected_sequence);
    IF v_rev.status NOT IN ('REQUESTED', 'VERIFIED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
    v_ref := v_rev.revocation_ref;
    v_seq := p_expected_sequence;
  END IF;

  UPDATE app.recovery_token SET consumed_at = pg_catalog.now() WHERE tenant_id = v_tenant AND recovery_ref = p_recovery_ref AND consumed_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'token de recuperacion no elegible' USING ERRCODE = 'RV007'; END IF;

  IF v_ref IS NULL THEN
    v_ref := p_new_revocation_ref;
    INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, status, revoked_decision_ref)
    VALUES (v_tenant, v_ref, v_tok.chain_ref, 'REQUESTED', v_tok.revoked_decision_ref);
    SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', v_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
      pg_catalog.jsonb_build_object('revocationRef', v_ref, 'revokedDecisionRef', v_tok.revoked_decision_ref, 'scope', 'ALL', 'authPath', 'RECOVERY',
        'recoveryMethod', 'CHANNEL_LINK', 'originPurposeRef', 'ALL', 'initiatedVia', 'DECISION_MAKER', 'recoveryRef', p_recovery_ref),
      v_ref || ':r1r', 0);
    v_seq := v_ev.o_sequence;
  END IF;

  UPDATE app.revocation SET status = 'VERIFIED', verified_auth_path = 'RECOVERY', verified_recovery_method = 'CHANNEL_LINK'
   WHERE tenant_id = v_tenant AND revocation_ref = v_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', v_ref, 'REVOCATION_VERIFIED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', v_ref, 'authPath', 'RECOVERY', 'recoveryMethod', 'CHANNEL_LINK', 'recoveryRef', p_recovery_ref,
      'assuranceLevel', 'LD-02-PLACEHOLDER-V1'),
    v_ref || ':r2r:' || p_recovery_ref, v_seq);
  RETURN pg_catalog.jsonb_build_object('revocationRef', v_ref, 'sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-05 R8: solo REQUESTED, VERIFIED o CONFIRMED (grafo del spec; R4 ya gano si esta APPLIED o posterior).
CREATE FUNCTION case_state.withdraw_revocation(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'withdraw_revocation', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status NOT IN ('REQUESTED', 'VERIFIED', 'CONFIRMED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET status = 'FAILED', reason_code = 'WITHDRAWN_BY_REQUESTER'
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_FAILED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'reasonCode', 'WITHDRAWN_BY_REQUESTER'), p_revocation_ref || ':r8', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-06 (lado Revocation de RC3 / R12; el lado rights_case llega en PR-5b): crea la Revocation REQUESTED del caso (p_attach = false) o
-- registra la intencion sobre la abierta (p_attach = true, la fila no cambia). Actor fijo UNVERIFIED_BEARER (P-v7-3).
CREATE FUNCTION case_state.express_revocation_intent_in_case(
  p_case_ref text, p_chain_ref text, p_revoked_decision_ref text, p_initiated_via text, p_revocation_ref text, p_attach boolean, p_expected_sequence integer)
  RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_rev app.revocation;
  v_ev record;
  v_payload jsonb;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'express_revocation_intent_in_case', true);
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'tenant no resuelto' USING ERRCODE = 'RV001'; END IF;
  IF p_initiated_via NOT IN ('DECISION_MAKER', 'SCHOOL_REPORT') THEN RAISE EXCEPTION 'initiatedVia invalido' USING ERRCODE = 'RV002'; END IF;
  v_payload := pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'revokedDecisionRef', p_revoked_decision_ref, 'scope', 'ALL',
    'authPath', 'RECOVERY', 'recoveryMethod', 'HUMAN_ASSISTED', 'originPurposeRef', 'ALL', 'initiatedVia', p_initiated_via, 'caseRef', p_case_ref);
  IF p_attach THEN
    v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
    IF v_rev.status IN ('FAILED', 'COMPLETED') THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
    IF v_rev.chain_ref IS DISTINCT FROM p_chain_ref OR v_rev.revoked_decision_ref IS DISTINCT FROM p_revoked_decision_ref THEN
      RAISE EXCEPTION 'la Revocation no es de esa cadena/decision' USING ERRCODE = 'RV002';
    END IF;
    SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
      v_payload, p_revocation_ref || ':r12:' || p_case_ref, p_expected_sequence);
  ELSE
    PERFORM case_state.assert_decision_revocable(p_revoked_decision_ref);
    INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, case_ref, status, revoked_decision_ref)
    VALUES (v_tenant, p_revocation_ref, p_chain_ref, p_case_ref, 'REQUESTED', p_revoked_decision_ref);
    SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_REQUESTED', 'HUMAN', 'UNVERIFIED_BEARER', NULL, NULL,
      v_payload, p_revocation_ref || ':rc3', 0);
  END IF;
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-07 RH2 paso 1 (propose): registra la propuesta; sin transicion ni evento.
CREATE FUNCTION case_state.propose_case_verification(
  p_revocation_ref text, p_case_ref text, p_proposal_ref text, p_proposed_by_ref text, p_verification_script_version text, p_expected_sequence integer) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'propose_case_verification', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  IF v_rev.status <> 'REQUESTED' OR v_rev.proposal_ref IS NOT NULL THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET proposal_ref = p_proposal_ref, proposed_by_ref = p_proposed_by_ref, verification_script_version = p_verification_script_version
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
END
$fn$;

-- FN-RV-08 RH2 paso 2 (approve): REQUESTED -> VERIFIED HUMAN_ASSISTED; aprobador distinto del proponente (CHECK 0016 y aqui).
CREATE FUNCTION case_state.approve_case_verification(
  p_revocation_ref text, p_case_ref text, p_proposal_ref text, p_approver_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'approve_case_verification', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref OR v_rev.proposal_ref IS DISTINCT FROM p_proposal_ref THEN
    RAISE EXCEPTION 'propuesta ajena' USING ERRCODE = 'RV001';
  END IF;
  IF p_approver_ref IS NULL OR p_approver_ref = v_rev.proposed_by_ref THEN RAISE EXCEPTION 'aprobador igual al proponente' USING ERRCODE = 'RV004'; END IF; -- ERR-RV-07
  IF v_rev.status <> 'REQUESTED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation
     SET status = 'VERIFIED', attested_revocation_ref = v_rev.revocation_ref, attested_case_ref = v_rev.case_ref,
         verified_auth_path = 'RECOVERY', verified_recovery_method = 'HUMAN_ASSISTED', second_approver_ref = p_approver_ref
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_VERIFIED', 'HUMAN', 'DECISION_MAKER', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'authPath', 'RECOVERY', 'recoveryMethod', 'HUMAN_ASSISTED', 'caseRef', p_case_ref,
      'verifiedByRef', v_rev.proposed_by_ref, 'secondApproverRef', p_approver_ref, 'assuranceLevel', 'LD-02-PLACEHOLDER-V1'),
    p_revocation_ref || ':rh2:' || p_proposal_ref, p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-09 RH2w: solo el proponente retira, solo con la Revocation REQUESTED; la Revocation no cambia de estado (nunca FAILED, INV-6).
CREATE FUNCTION case_state.withdraw_case_verification_proposal(
  p_revocation_ref text, p_case_ref text, p_proposal_ref text, p_actor_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'withdraw_case_verification_proposal', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref OR v_rev.proposal_ref IS DISTINCT FROM p_proposal_ref THEN
    RAISE EXCEPTION 'propuesta ajena' USING ERRCODE = 'RV001';
  END IF;
  IF p_actor_ref IS DISTINCT FROM v_rev.proposed_by_ref THEN RAISE EXCEPTION 'solo el proponente retira' USING ERRCODE = 'RV004'; END IF;
  IF v_rev.status <> 'REQUESTED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET proposal_ref = NULL, proposed_by_ref = NULL, verification_script_version = NULL
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_PROPOSAL_WITHDRAWN', 'HUMAN', 'RIGHTS_OPERATOR', NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'caseRef', p_case_ref, 'proposalRef', p_proposal_ref,
      'verificationScriptVersion', v_rev.verification_script_version, 'withdrawnByRef', p_actor_ref),
    p_revocation_ref || ':rh2w:' || p_proposal_ref, p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-10 RH3 paso 1 (record): GRD-RV-10 (par atestado = (revocation, case)); registra recorded_by_ref sin transicion ni evento.
CREATE FUNCTION case_state.record_case_confirmation(p_revocation_ref text, p_case_ref text, p_recorded_by_ref text, p_expected_sequence integer) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'record_case_confirmation', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  IF v_rev.status <> 'VERIFIED' OR v_rev.attested_revocation_ref IS DISTINCT FROM v_rev.revocation_ref
     OR v_rev.attested_case_ref IS DISTINCT FROM p_case_ref THEN
    RAISE EXCEPTION 'RH3 sin RH2 atestada' USING ERRCODE = 'RV006'; -- ERR-RV-20
  END IF;
  UPDATE app.revocation SET recorded_by_ref = p_recorded_by_ref WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
END
$fn$;

-- FN-RV-11 RH3 paso 2 (cosign): cuatro ojos GRD-RV-26 (co-firmante distinto del registrador; CHECK de la tabla como red de seguridad).
CREATE FUNCTION case_state.cosign_case_confirmation(p_revocation_ref text, p_case_ref text, p_cosigned_by_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'cosign_case_confirmation', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.case_ref IS DISTINCT FROM p_case_ref THEN RAISE EXCEPTION 'caso ajeno' USING ERRCODE = 'RV001'; END IF;
  IF v_rev.status <> 'VERIFIED' OR v_rev.attested_revocation_ref IS DISTINCT FROM v_rev.revocation_ref
     OR v_rev.attested_case_ref IS DISTINCT FROM p_case_ref THEN
    RAISE EXCEPTION 'RH3 sin RH2 atestada' USING ERRCODE = 'RV006'; -- ERR-RV-20
  END IF;
  IF v_rev.recorded_by_ref IS NULL OR p_cosigned_by_ref IS NULL OR p_cosigned_by_ref = v_rev.recorded_by_ref THEN
    RAISE EXCEPTION 'RH3 exige cuatro ojos' USING ERRCODE = 'RV005'; -- ERR-RV-18
  END IF;
  UPDATE app.revocation SET status = 'CONFIRMED', cosigned_by_ref = p_cosigned_by_ref
   WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_CONFIRMED', 'HUMAN', 'DECISION_MAKER',
    v_rev.recorded_by_ref, p_cosigned_by_ref,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'recordedByRef', v_rev.recorded_by_ref, 'cosignedByRef', p_cosigned_by_ref),
    p_revocation_ref || ':rh3', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-12 R4 + C6 (mismo lote): CONFIRMED -> APPLIED, CONSENT_REVOKED + RECEIPT_CREATED, outbox consent.revoked y decision GRANTED -> REVOKED.
-- authPath/recoveryMethod se DERIVAN de la fila (GRD-RV-29); nunca rechaza por integridad (INV-RV-07).
CREATE FUNCTION case_state.apply_revocation(p_revocation_ref text, p_expected_sequence integer) RETURNS jsonb
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
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'apply_revocation', true);
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

-- FN-RV-13 R5: APPLIED -> DOWNSTREAM_PENDING; congela el conjunto de destinos (GRD-RV-12) en el ledger.
CREATE FUNCTION case_state.mark_downstream_emitted(p_revocation_ref text, p_subscription_refs text[], p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'mark_downstream_emitted', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'APPLIED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  IF p_subscription_refs IS NULL OR pg_catalog.cardinality(p_subscription_refs) = 0 OR pg_catalog.array_position(p_subscription_refs, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'sin destinos downstream' USING ERRCODE = 'RV002';
  END IF;
  UPDATE app.revocation SET status = 'DOWNSTREAM_PENDING' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_DOWNSTREAM_EMITTED', 'SYSTEM_GUARD', NULL, NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref,
      'subscriptionRefs', (SELECT pg_catalog.jsonb_agg(x ORDER BY x COLLATE "C") FROM pg_catalog.unnest(p_subscription_refs) AS x)),
    p_revocation_ref || ':r5', p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-14 R6: DOWNSTREAM_PENDING -> DELIVERED. La firma de la evidencia (GRD-RV-13) se verifica en el stub del dominio: residual.
CREATE FUNCTION case_state.record_downstream_ack(p_revocation_ref text, p_ack_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'record_downstream_ack', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'DOWNSTREAM_PENDING' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  UPDATE app.revocation SET status = 'DELIVERED' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'REVOCATION_DELIVERED', 'SYSTEM_GUARD', NULL, NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref, 'ackRef', p_ack_ref), p_revocation_ref || ':r6:' || p_ack_ref, p_expected_sequence);
  RETURN pg_catalog.jsonb_build_object('sequence', v_ev.o_sequence);
END
$fn$;

-- FN-RV-15 R7: DELIVERED -> COMPLETED (GRD-RV-14: la reconciliacion nunca fija COMPLETED; DELIVERED no lo implica).
CREATE FUNCTION case_state.record_erasure_attestation(p_revocation_ref text, p_attestation_ref text, p_expected_sequence integer) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_rev app.revocation;
  v_ev record;
  v_rc record;
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'record_erasure_attestation', true);
  v_rev := case_state.lock_revocation(p_revocation_ref, p_expected_sequence);
  IF v_rev.status <> 'DELIVERED' THEN RAISE EXCEPTION 'transicion invalida' USING ERRCODE = 'RV002'; END IF;
  SELECT * INTO v_ev FROM case_state.ledger_append('Revocation', p_revocation_ref, 'DOWNSTREAM_ERASURE_ATTESTED', 'SYSTEM_GUARD', NULL, NULL, NULL,
    pg_catalog.jsonb_build_object('revocationRef', p_revocation_ref), p_revocation_ref || ':r7:' || p_attestation_ref, p_expected_sequence);
  SELECT * INTO v_rc FROM case_state.ledger_append('Revocation', p_revocation_ref, 'RECEIPT_CREATED', 'SYSTEM_GUARD', NULL, NULL, NULL,
    pg_catalog.jsonb_build_object('receiptRef', p_revocation_ref, 'managementLinkIssued', false), p_revocation_ref || ':receipt-final',
    GREATEST(p_expected_sequence, v_ev.o_sequence));
  UPDATE app.revocation SET status = 'COMPLETED' WHERE tenant_id = v_rev.tenant_id AND revocation_ref = v_rev.revocation_ref;
  RETURN pg_catalog.jsonb_build_object('sequence', v_rc.o_sequence);
END
$fn$;

-- Siembra SOLO LOCAL (contrato `save` del puerto, fixtures de dev y tests). Falla fuera de LOCAL. Upsert por (tenant, revocation_ref).
CREATE FUNCTION case_state.seed_local_revocation(
  p_tenant_id uuid, p_revocation_ref text, p_chain_ref text, p_case_ref text, p_status text, p_attested_revocation_ref text, p_attested_case_ref text,
  p_recorded_by_ref text, p_cosigned_by_ref text, p_revoked_decision_ref text, p_verified_auth_path text, p_verified_recovery_method text,
  p_reason_code text, p_proposal_ref text, p_proposed_by_ref text, p_verification_script_version text, p_second_approver_ref text,
  p_verification_ref text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'seed_local_revocation', true);
  IF v_tenant IS NULL OR p_tenant_id IS DISTINCT FROM v_tenant THEN RAISE EXCEPTION 'tenant distinto del de la tx' USING ERRCODE = '42501'; END IF;
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN
    RAISE EXCEPTION 'seed_local_revocation solo existe en LOCAL' USING ERRCODE = '42501';
  END IF;
  INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, case_ref, status, attested_revocation_ref, attested_case_ref, recorded_by_ref,
    cosigned_by_ref, revoked_decision_ref, verified_auth_path, verified_recovery_method, reason_code, proposal_ref, proposed_by_ref,
    verification_script_version, second_approver_ref, verification_ref)
  VALUES (v_tenant, p_revocation_ref, p_chain_ref, p_case_ref, p_status, p_attested_revocation_ref, p_attested_case_ref, p_recorded_by_ref,
    p_cosigned_by_ref, p_revoked_decision_ref, p_verified_auth_path, p_verified_recovery_method, p_reason_code, p_proposal_ref, p_proposed_by_ref,
    p_verification_script_version, p_second_approver_ref, p_verification_ref)
  ON CONFLICT (tenant_id, revocation_ref) DO UPDATE SET
    case_ref = EXCLUDED.case_ref, status = EXCLUDED.status, attested_revocation_ref = EXCLUDED.attested_revocation_ref,
    attested_case_ref = EXCLUDED.attested_case_ref, recorded_by_ref = EXCLUDED.recorded_by_ref, cosigned_by_ref = EXCLUDED.cosigned_by_ref,
    verified_auth_path = EXCLUDED.verified_auth_path, verified_recovery_method = EXCLUDED.verified_recovery_method,
    reason_code = EXCLUDED.reason_code, proposal_ref = EXCLUDED.proposal_ref, proposed_by_ref = EXCLUDED.proposed_by_ref,
    verification_script_version = EXCLUDED.verification_script_version, second_approver_ref = EXCLUDED.second_approver_ref,
    verification_ref = EXCLUDED.verification_ref;
END
$fn$;

-- Siembra SOLO LOCAL del contrato `save` de consent_decision con state = REVOKED (F-A10-06: app_rw ya no puede escribirlo): GRANTED -> REVOKED.
CREATE FUNCTION case_state.seed_local_revoke_decision(p_tenant_id uuid, p_consent_id text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  PERFORM pg_catalog.set_config('case_state.effect', 'seed_local_revoke_decision', true);
  IF app.current_tenant_id() IS NULL OR p_tenant_id IS DISTINCT FROM app.current_tenant_id() THEN
    RAISE EXCEPTION 'tenant distinto del de la tx' USING ERRCODE = '42501';
  END IF;
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN RAISE EXCEPTION 'seed_local_revoke_decision solo existe en LOCAL' USING ERRCODE = '42501'; END IF;
  UPDATE app.consent_decision SET state = 'REVOKED' WHERE tenant_id = p_tenant_id AND consent_id = p_consent_id AND state = 'GRANTED';
END
$fn$;

-- TRG-RV-01: trigger de grafo y efecto. SECURITY INVOKER a proposito: current_user es el rol que ejecuta la sentencia (dentro de una
-- funcion SECURITY DEFINER de transition_owner es transition_owner; para cualquier otro rol, el rol real).
CREATE FUNCTION case_state.revocation_transition_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_effect text := NULLIF(pg_catalog.current_setting('case_state.effect', true), '');
  v_pair text;
  v_allowed_pairs text[];
  v_allowed_cols text[];
  v_changed text[] := ARRAY[]::text[];
BEGIN
  -- app.revocation nunca se borra ni se trunca (igual que el ledger, 0002:56-64); tampoco el superusuario sin desactivar el trigger.
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'app.revocation no admite DELETE ni TRUNCATE (INV-RV-12)' USING ERRCODE = '42501';
  END IF;
  -- Siembra de fixtures LOCAL como superusuario (admin de los tests): un superusuario ya podria deshabilitar el trigger; no es rol de runtime.
  IF v_effect = 'seed_local_revocation' AND current_user <> 'transition_owner' AND ops.catalog_environment() = 'LOCAL'
     AND (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RETURN NEW;
  END IF;
  IF current_user <> 'transition_owner' OR v_effect IS NULL THEN
    RAISE EXCEPTION 'app.revocation solo se escribe por las funciones case_state de transition_owner (INV-RV-12)' USING ERRCODE = '42501';
  END IF;
  IF v_effect = 'seed_local_revocation' THEN
    IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN RAISE EXCEPTION 'efecto de siembra solo en LOCAL' USING ERRCODE = '42501'; END IF;
    RETURN NEW;
  END IF;
  IF NEW.attested_revocation_ref IS NOT NULL AND (NEW.attested_revocation_ref <> NEW.revocation_ref OR NEW.attested_case_ref IS DISTINCT FROM NEW.case_ref) THEN
    RAISE EXCEPTION 'el par atestado debe ser (revocationRef, caseRef) de la propia Revocation (GRD-RV-10)' USING ERRCODE = '42501';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF v_effect NOT IN ('request_revocation', 'revoke_with_recovery_link', 'express_revocation_intent_in_case') OR NEW.status <> 'REQUESTED'
       OR NEW.attested_revocation_ref IS NOT NULL OR NEW.attested_case_ref IS NOT NULL OR NEW.recorded_by_ref IS NOT NULL
       OR NEW.cosigned_by_ref IS NOT NULL OR NEW.verified_auth_path IS NOT NULL OR NEW.verified_recovery_method IS NOT NULL
       OR NEW.reason_code IS NOT NULL OR NEW.proposal_ref IS NOT NULL OR NEW.proposed_by_ref IS NOT NULL
       OR NEW.verification_script_version IS NOT NULL OR NEW.second_approver_ref IS NOT NULL OR NEW.verification_ref IS NOT NULL THEN
      RAISE EXCEPTION 'INSERT de app.revocation no admitido para el efecto %', v_effect USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.tenant_id <> OLD.tenant_id OR NEW.revocation_ref <> OLD.revocation_ref OR NEW.chain_ref <> OLD.chain_ref
     OR NEW.revoked_decision_ref IS DISTINCT FROM OLD.revoked_decision_ref OR NEW.data_class <> OLD.data_class OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'columnas de identidad de app.revocation inmutables' USING ERRCODE = '42501';
  END IF;

  -- Pares (from>to) y columnas que cada funcion de efecto puede tocar (grafo del spec; INV-RV-12).
  CASE v_effect
    WHEN 'verify_revocation_otp' THEN
      v_allowed_pairs := ARRAY['REQUESTED>VERIFIED']; v_allowed_cols := ARRAY['status', 'verified_auth_path', 'verified_recovery_method', 'verification_ref'];
      IF NEW.verified_auth_path IS DISTINCT FROM 'OTP' OR NEW.verified_recovery_method IS NOT NULL THEN
        RAISE EXCEPTION 'R2 fija authPath OTP' USING ERRCODE = '42501';
      END IF;
    WHEN 'confirm_revocation' THEN
      v_allowed_pairs := ARRAY['VERIFIED>CONFIRMED']; v_allowed_cols := ARRAY['status'];
    WHEN 'revoke_with_recovery_link' THEN
      v_allowed_pairs := ARRAY['REQUESTED>VERIFIED', 'VERIFIED>VERIFIED']; v_allowed_cols := ARRAY['status', 'verified_auth_path', 'verified_recovery_method'];
      IF NEW.verified_auth_path IS DISTINCT FROM 'RECOVERY' OR NEW.verified_recovery_method IS DISTINCT FROM 'CHANNEL_LINK' THEN
        RAISE EXCEPTION 'R1r/R2r/R10 fijan RECOVERY/CHANNEL_LINK' USING ERRCODE = '42501';
      END IF;
    WHEN 'withdraw_revocation' THEN
      v_allowed_pairs := ARRAY['REQUESTED>FAILED', 'VERIFIED>FAILED', 'CONFIRMED>FAILED']; v_allowed_cols := ARRAY['status', 'reason_code'];
    WHEN 'propose_case_verification' THEN
      v_allowed_pairs := ARRAY['REQUESTED>REQUESTED']; v_allowed_cols := ARRAY['proposal_ref', 'proposed_by_ref', 'verification_script_version'];
    WHEN 'withdraw_case_verification_proposal' THEN
      v_allowed_pairs := ARRAY['REQUESTED>REQUESTED']; v_allowed_cols := ARRAY['proposal_ref', 'proposed_by_ref', 'verification_script_version'];
    WHEN 'approve_case_verification' THEN
      v_allowed_pairs := ARRAY['REQUESTED>VERIFIED']; v_allowed_cols := ARRAY['status', 'attested_revocation_ref', 'attested_case_ref', 'verified_auth_path', 'verified_recovery_method', 'second_approver_ref'];
      IF NEW.verified_auth_path IS DISTINCT FROM 'RECOVERY' OR NEW.verified_recovery_method IS DISTINCT FROM 'HUMAN_ASSISTED' THEN
        RAISE EXCEPTION 'RH2 fija RECOVERY/HUMAN_ASSISTED' USING ERRCODE = '42501';
      END IF;
    WHEN 'record_case_confirmation' THEN
      v_allowed_pairs := ARRAY['VERIFIED>VERIFIED']; v_allowed_cols := ARRAY['recorded_by_ref'];
    WHEN 'cosign_case_confirmation' THEN
      v_allowed_pairs := ARRAY['VERIFIED>CONFIRMED']; v_allowed_cols := ARRAY['status', 'cosigned_by_ref'];
    WHEN 'apply_revocation' THEN
      v_allowed_pairs := ARRAY['CONFIRMED>APPLIED']; v_allowed_cols := ARRAY['status'];
    WHEN 'mark_downstream_emitted' THEN
      v_allowed_pairs := ARRAY['APPLIED>DOWNSTREAM_PENDING']; v_allowed_cols := ARRAY['status'];
    WHEN 'record_downstream_ack' THEN
      v_allowed_pairs := ARRAY['DOWNSTREAM_PENDING>DELIVERED']; v_allowed_cols := ARRAY['status'];
    WHEN 'record_erasure_attestation' THEN
      v_allowed_pairs := ARRAY['DELIVERED>COMPLETED']; v_allowed_cols := ARRAY['status'];
    ELSE
      RAISE EXCEPTION 'efecto % sin UPDATE declarado sobre app.revocation', v_effect USING ERRCODE = '42501';
  END CASE;

  v_pair := OLD.status || '>' || NEW.status;
  IF NOT (v_pair = ANY (v_allowed_pairs)) THEN
    RAISE EXCEPTION 'transicion % no permitida para el efecto %', v_pair, v_effect USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN v_changed := pg_catalog.array_append(v_changed, 'status'::text); END IF;
  IF NEW.case_ref IS DISTINCT FROM OLD.case_ref THEN v_changed := pg_catalog.array_append(v_changed, 'case_ref'::text); END IF;
  IF NEW.attested_revocation_ref IS DISTINCT FROM OLD.attested_revocation_ref THEN v_changed := pg_catalog.array_append(v_changed, 'attested_revocation_ref'::text); END IF;
  IF NEW.attested_case_ref IS DISTINCT FROM OLD.attested_case_ref THEN v_changed := pg_catalog.array_append(v_changed, 'attested_case_ref'::text); END IF;
  IF NEW.recorded_by_ref IS DISTINCT FROM OLD.recorded_by_ref THEN v_changed := pg_catalog.array_append(v_changed, 'recorded_by_ref'::text); END IF;
  IF NEW.cosigned_by_ref IS DISTINCT FROM OLD.cosigned_by_ref THEN v_changed := pg_catalog.array_append(v_changed, 'cosigned_by_ref'::text); END IF;
  IF NEW.verified_auth_path IS DISTINCT FROM OLD.verified_auth_path THEN v_changed := pg_catalog.array_append(v_changed, 'verified_auth_path'::text); END IF;
  IF NEW.verified_recovery_method IS DISTINCT FROM OLD.verified_recovery_method THEN v_changed := pg_catalog.array_append(v_changed, 'verified_recovery_method'::text); END IF;
  IF NEW.reason_code IS DISTINCT FROM OLD.reason_code THEN v_changed := pg_catalog.array_append(v_changed, 'reason_code'::text); END IF;
  IF NEW.proposal_ref IS DISTINCT FROM OLD.proposal_ref THEN v_changed := pg_catalog.array_append(v_changed, 'proposal_ref'::text); END IF;
  IF NEW.proposed_by_ref IS DISTINCT FROM OLD.proposed_by_ref THEN v_changed := pg_catalog.array_append(v_changed, 'proposed_by_ref'::text); END IF;
  IF NEW.verification_script_version IS DISTINCT FROM OLD.verification_script_version THEN v_changed := pg_catalog.array_append(v_changed, 'verification_script_version'::text); END IF;
  IF NEW.second_approver_ref IS DISTINCT FROM OLD.second_approver_ref THEN v_changed := pg_catalog.array_append(v_changed, 'second_approver_ref'::text); END IF;
  IF NEW.verification_ref IS DISTINCT FROM OLD.verification_ref THEN v_changed := pg_catalog.array_append(v_changed, 'verification_ref'::text); END IF;
  IF NOT (v_changed <@ v_allowed_cols) THEN
    RAISE EXCEPTION 'el efecto % no puede modificar las columnas %', v_effect, v_changed USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$fn$;

-- EXECUTE: nadie por defecto (ALTER DEFAULT PRIVILEGES); se concede uno por uno. Las auxiliares y el trigger quedan solo para su dueno.
REVOKE ALL ON FUNCTION case_state.canonical_json(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.ledger_append(text, text, text, text, text, text, text, jsonb, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.assert_sequence(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.lock_revocation(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.assert_decision_revocable(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.revocation_transition_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.request_revocation(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.verify_revocation_otp(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.confirm_revocation(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.revoke_with_recovery_link(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.withdraw_revocation(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.express_revocation_intent_in_case(text, text, text, text, text, boolean, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.propose_case_verification(text, text, text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.approve_case_verification(text, text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.withdraw_case_verification_proposal(text, text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.record_case_confirmation(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.cosign_case_confirmation(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.apply_revocation(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.mark_downstream_emitted(text, text[], integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.record_downstream_ack(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.record_erasure_attestation(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.seed_local_revoke_decision(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION case_state.seed_local_revocation(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION case_state.request_revocation(text, text, text) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.verify_revocation_otp(text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.confirm_revocation(text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.revoke_with_recovery_link(text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.withdraw_revocation(text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.express_revocation_intent_in_case(text, text, text, text, text, boolean, integer) TO app_rw;
-- Interino IT0 (ver cabecera): operador y SYSTEM corren en el proceso web hasta PR-6.
GRANT EXECUTE ON FUNCTION case_state.propose_case_verification(text, text, text, text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.approve_case_verification(text, text, text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.withdraw_case_verification_proposal(text, text, text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.record_case_confirmation(text, text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.cosign_case_confirmation(text, text, text, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.apply_revocation(text, integer) TO app_rw, worker;
GRANT EXECUTE ON FUNCTION case_state.mark_downstream_emitted(text, text[], integer) TO app_rw, worker;
GRANT EXECUTE ON FUNCTION case_state.record_downstream_ack(text, text, integer) TO app_rw, worker;
GRANT EXECUTE ON FUNCTION case_state.record_erasure_attestation(text, text, integer) TO app_rw, worker;
GRANT EXECUTE ON FUNCTION case_state.seed_local_revoke_decision(uuid, text) TO app_rw;
GRANT EXECUTE ON FUNCTION case_state.seed_local_revocation(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text) TO app_rw;
-- CREATE TRIGGER exige EXECUTE al creador (consent_owner, dueno de la tabla); se revoca enseguida (el disparo no lo comprueba).
GRANT EXECUTE ON FUNCTION case_state.revocation_transition_guard() TO consent_owner;

SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;
GRANT USAGE ON SCHEMA case_state TO consent_owner; -- temporal: resolver el nombre de la funcion al crear el trigger
SET LOCAL ROLE consent_owner;

CREATE TRIGGER revocation_transition_guard BEFORE INSERT OR UPDATE ON app.revocation
  FOR EACH ROW EXECUTE FUNCTION case_state.revocation_transition_guard();
ALTER TABLE app.revocation ENABLE ALWAYS TRIGGER revocation_transition_guard;
CREATE TRIGGER revocation_no_delete BEFORE DELETE ON app.revocation
  FOR EACH ROW EXECUTE FUNCTION case_state.revocation_transition_guard();
CREATE TRIGGER revocation_no_truncate BEFORE TRUNCATE ON app.revocation
  FOR EACH STATEMENT EXECUTE FUNCTION case_state.revocation_transition_guard();
ALTER TABLE app.revocation ENABLE ALWAYS TRIGGER revocation_no_delete;
ALTER TABLE app.revocation ENABLE ALWAYS TRIGGER revocation_no_truncate;

SET LOCAL ROLE transition_owner;
REVOKE EXECUTE ON FUNCTION case_state.revocation_transition_guard() FROM consent_owner;
SET LOCAL ROLE case_state_owner;
REVOKE USAGE ON SCHEMA case_state FROM consent_owner;
SET LOCAL ROLE consent_owner;

-- 6. Aserciones: la migracion aborta si algo no quedo como se declara (catalogo por nombre). ----------------------------------------------
DO $assert$
DECLARE
  f record;
  r text;
  rv oid;
  led oid;
  expect_exec jsonb := pg_catalog.jsonb_build_object(
    'request_revocation', ARRAY['app_rw'], 'verify_revocation_otp', ARRAY['app_rw'], 'confirm_revocation', ARRAY['app_rw'],
    'revoke_with_recovery_link', ARRAY['app_rw'], 'withdraw_revocation', ARRAY['app_rw'], 'express_revocation_intent_in_case', ARRAY['app_rw'],
    'propose_case_verification', ARRAY['app_rw'], 'approve_case_verification', ARRAY['app_rw'], 'withdraw_case_verification_proposal', ARRAY['app_rw'],
    'record_case_confirmation', ARRAY['app_rw'], 'cosign_case_confirmation', ARRAY['app_rw'],
    'apply_revocation', ARRAY['app_rw', 'worker'], 'mark_downstream_emitted', ARRAY['app_rw', 'worker'], 'record_downstream_ack', ARRAY['app_rw', 'worker'],
    'record_erasure_attestation', ARRAY['app_rw', 'worker'], 'seed_local_revocation', ARRAY['app_rw'], 'seed_local_revoke_decision', ARRAY['app_rw'],
    'canonical_json', ARRAY[]::text[], 'ledger_append', ARRAY[]::text[], 'lock_revocation', ARRAY[]::text[], 'assert_sequence', ARRAY[]::text[], 'assert_decision_revocable', ARRAY[]::text[],
    'revocation_transition_guard', ARRAY[]::text[]);
BEGIN
  -- Esquema.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'case_state' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'case_state_owner') THEN
    RAISE EXCEPTION 'el esquema case_state no pertenece a case_state_owner';
  END IF;
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

  -- Funciones: conjunto exacto, dueno transition_owner, search_path fijo, EXECUTE exacto, sin SQL dinamico.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state') <> 23 THEN
    RAISE EXCEPTION 'case_state debe tener exactamente 23 funciones en PR-5a';
  END IF;
  FOR f IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' LOOP
    IF NOT (expect_exec ? f.proname) THEN RAISE EXCEPTION 'funcion inesperada case_state.%()', f.proname; END IF;
    IF f.owner <> 'transition_owner' THEN RAISE EXCEPTION 'case_state.%() no pertenece a transition_owner', f.proname; END IF;
    IF f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'case_state.%() sin search_path fijo exacto', f.proname; END IF;
    IF f.prosecdef <> (f.proname NOT IN ('canonical_json', 'revocation_transition_guard')) THEN RAISE EXCEPTION 'case_state.%(): SECURITY DEFINER inesperado', f.proname; END IF;
    IF pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar case_state.%()', f.proname; END IF;
    IF f.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'case_state.%() contiene SQL dinamico', f.proname; END IF;
    IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
          FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner)
       IS DISTINCT FROM (SELECT pg_catalog.string_agg(x, ',' ORDER BY x COLLATE "C") FROM pg_catalog.jsonb_array_elements_text(expect_exec -> f.proname) AS x) THEN
      RAISE EXCEPTION 'la ACL de case_state.%() no es exactamente la declarada', f.proname;
    END IF;
  END LOOP;

  -- Mitigacion F-A10-26: el EXECUTE interino de app_rw sobre las funciones de operador (FN-RV-07..11), SYSTEM (FN-RV-12..15) y de siembra solo es
  -- admisible en LOCAL/CI (catalogo LOCAL). En DEV/STAGING la migracion aborta (fail-closed) hasta PR-6/PR-5b (mover EXECUTE a worker/platform_rw).
  IF ops.catalog_environment() IS DISTINCT FROM 'LOCAL' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'case_state' AND pg_catalog.has_function_privilege('app_rw', p.oid, 'EXECUTE')
          AND p.proname IN ('propose_case_verification', 'approve_case_verification', 'withdraw_case_verification_proposal', 'record_case_confirmation',
                            'cosign_case_confirmation', 'apply_revocation', 'mark_downstream_emitted', 'record_downstream_ack', 'record_erasure_attestation',
                            'seed_local_revocation', 'seed_local_revoke_decision')) THEN
    RAISE EXCEPTION 'F-A10-26: app_rw tiene EXECUTE de funciones de operador/SYSTEM fuera de LOCAL (interino IT0 solo LOCAL/CI)';
  END IF;

  -- app.revocation: sin INSERT/UPDATE para runtime, trigger ENABLE ALWAYS, policies exactas.
  SELECT c.oid INTO rv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'revocation';
  -- consent_owner no tiene USAGE en integrity (0027): el ledger se consulta por oid de catalogo, nunca por nombre regclass.
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier'] LOOP
    IF pg_catalog.has_any_column_privilege(r, rv, 'INSERT,UPDATE') OR pg_catalog.has_table_privilege(r, rv, 'DELETE,TRUNCATE') THEN
      RAISE EXCEPTION '% conserva INSERT/UPDATE/DELETE/TRUNCATE sobre app.revocation', r;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_table_privilege('app_rw', rv, 'SELECT') THEN RAISE EXCEPTION 'app_rw perdio SELECT sobre app.revocation'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = rv AND t.tgname IN ('revocation_transition_guard', 'revocation_no_delete', 'revocation_no_truncate')
        AND t.tgenabled = 'A' AND NOT t.tgisinternal) <> 3
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = rv AND NOT t.tgisinternal) <> 3 THEN
    RAISE EXCEPTION 'app.revocation debe tener exactamente los triggers revocation_transition_guard/no_delete/no_truncate, ENABLE ALWAYS';
  END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::text || ':' || p.polcmd::text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = rv)
     IS DISTINCT FROM 'revocation_tenant_select:r:app_rw revocation_transition_insert:a:transition_owner revocation_transition_select:r:transition_owner revocation_transition_update:w:transition_owner' THEN
    RAISE EXCEPTION 'las policies de app.revocation no son exactamente las declaradas';
  END IF;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = rv) THEN RAISE EXCEPTION 'app.revocation perdio ENABLE/FORCE ROW LEVEL SECURITY'; END IF;

  -- consent_decision: app_rw no puede dejar REVOKED (policies INSERT/UPDATE) y transition_owner solo GRANTED -> REVOKED.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = 'app.consent_decision'::pg_catalog.regclass AND p.polname = 'consent_decision_tenant_update'
                   AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%REVOKED%' AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%REVOKED%')
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = 'app.consent_decision'::pg_catalog.regclass AND p.polname = 'consent_decision_tenant_insert'
                      AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%REVOKED%') THEN
    RAISE EXCEPTION 'las policies INSERT/UPDATE de app_rw sobre app.consent_decision deben excluir state = REVOKED (USING y WITH CHECK del UPDATE: sin des-revocar)';
  END IF;

  -- Ledger: transition_owner con policies de tenant; app_rw conserva su INSERT en PR-5a.
  IF (SELECT pg_catalog.string_agg(p.polname::text, ' ' ORDER BY p.polname) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'transition_owner')
     IS DISTINCT FROM 'audit_event_transition_insert audit_event_transition_select' THEN
    RAISE EXCEPTION 'policies de transition_owner sobre integrity.audit_event no son las declaradas';
  END IF;
  IF pg_catalog.has_table_privilege('transition_owner', led, 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'transition_owner no puede mutar integrity.audit_event (append-only)';
  END IF;
  IF pg_catalog.has_any_column_privilege('transition_owner', led, 'UPDATE') THEN
    RAISE EXCEPTION 'transition_owner no puede mutar integrity.audit_event (append-only, columnas)';
  END IF;

  -- transition_owner: no es dueno de ninguna tabla ni de objetos fuera de case_state.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE pg_catalog.pg_get_userbyid(c.relowner) = 'transition_owner') THEN
    RAISE EXCEPTION 'transition_owner no debe ser dueno de relaciones';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE pg_catalog.pg_get_userbyid(p.proowner) = 'transition_owner' AND n.nspname <> 'case_state') THEN
    RAISE EXCEPTION 'transition_owner solo es dueno de funciones de case_state';
  END IF;

  -- Nuevos CHECKs.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint k WHERE k.conrelid = rv AND k.convalidated
        AND k.conname IN ('revocation_cosigned_distinct_recorded', 'revocation_verified_auth_path_required', 'revocation_verification_ref_uq')) <> 3 THEN
    RAISE EXCEPTION 'faltan CHECK/UNIQUE de GRD-RV-26/GRD-RV-05/GRD-RV-29 o no estan validados';
  END IF;
END
$assert$;
