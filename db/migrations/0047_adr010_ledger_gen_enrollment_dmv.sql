-- scope: database
-- Gobierna: ADR-010 rev. 5 §4.2.b (capa 1, LG-1..LG-10; aceptada por Carlos el 2026-10-15 para IT0b), condiciones de F-PR6-22/23/28/30; specs/ledger-derivation.spec.yaml (tabla OLD->NEW,
-- unica fuente de la emision); specs/db-roles.spec.yaml (ledger_writer, ledger_gen_owner, INV-DBR-07). 0010, 0013, 0037, 0039, 0041, 0044 estan mergeadas y son inmutables: todo va en migracion nueva.
-- Primera de las migraciones de PR-b (0046 roles de cluster; 0047 esquema + Enrollment + DecisionMakerVerification; 0048 Invitation; 0049 ConsentDecision + siembra LOCAL + retiro del INSERT de app_rw).
-- Cada agregado cambia ATOMICAMENTE con el retiro de sus pares de la allowlist de app_rw y del append en el dominio (mismo commit).
--
-- Que hace:
--  1) esquema ledger_gen (dueno ledger_gen_owner) y funciones de ledger_writer: canonical_json (copia de case_state.canonical_json; vectores dorados TS<->SQL), ledger_append (cadena SHA-256
--     identica a case_state.ledger_append, dedupe estricto, lock por tenant SOLO al emitir, secuencia = max+1 del agregado: es la misma que calcula case_state.ledger_append, F-PR6-30),
--     guard_*/emit_* de Enrollment y de otp_verification (DecisionMakerVerification). Guardas BEFORE (SECURITY INVOKER, sin lock de ledger: estado inicial fijo, grafo, inmutables, 42501 uniforme sin valores);
--     emision AFTER ROW (SECURITY DEFINER de ledger_writer, ENABLE ALWAYS) solo por la tabla OLD->NEW, sin depender de current_user ni de case_state.effect, con NEW.tenant_id = app.current_tenant_id().
--  2) ledger_writer: SELECT/INSERT por columnas sobre integrity.audit_event bajo policies por tenant; la de INSERT admite SOLO los 19 pares derivados (17 + las 2 siembras LOCAL de 0049).
--     Sin SELECT/UPDATE sobre tablas de app (las guardas son INVOKER; las emisiones leen OLD/NEW).
--  3) Particion real de pares en la base (F-PR6-22, seguridad rev. c punto 3): audit_event_transition_insert (0037:90-91) restringe su WITH CHECK a los 14 pares de transition_owner
--     (Revocation, RightsCase, CONSENT_REVOKED y Invitation:INVITATION_CANCELLED de I9). Los conjuntos de ledger_writer y transition_owner son disjuntos (assert).
--  4) app_rw pierde de su allowlist los pares de Enrollment y DecisionMakerVerification (19 -> 17).
--  5) app.otp_verification gana decision_maker_ref y dm_ref_key_version (LG-9): decision_maker_ref es un SEUDONIMO, es decir DATO PERSONAL; su encuadre es LEGAL DECISION (sin UNIQUE ni indice, CHECK 2..1000
--     en dm_ref_key_version, bajo la purga de retencion de 0031/0033 porque son columnas de la misma fila). La escribe web (capa 1; F-A10-30-S0, cierre solo con la capa 2 / opcion C antes de datos reales).
--  6) Enrollment ACTIVE -> CLOSED NO es una arista de la tabla: ENROLLMENT_STATUS_CHANGED con toStatus CLOSED exige closeReason (x-pending OPEN-TC-03 / Q-28), no hay columna ni productor (EN1 no implementado);
--     la guarda la rechaza con 42501 hasta que exista (FINDING F-PRB-03).
--  7) $assert47$ final fail-closed.
-- Idempotente al re-ejecutar: CREATE ... IF NOT EXISTS / CREATE OR REPLACE / DROP ... IF EXISTS + CREATE / GRANT y REVOKE repetibles.

-- 1. Columnas del seudonimo del apoderado en otp_verification (LG-9) ----------------------------------------------------------------------------
ALTER TABLE app.otp_verification
  ADD COLUMN IF NOT EXISTS decision_maker_ref text CONSTRAINT otp_dm_ref_len CHECK (pg_catalog.length(decision_maker_ref) BETWEEN 1 AND 100),
  ADD COLUMN IF NOT EXISTS dm_ref_key_version integer CONSTRAINT otp_dm_key_version_range CHECK (dm_ref_key_version BETWEEN 2 AND 1000);
ALTER TABLE app.otp_verification DROP CONSTRAINT IF EXISTS otp_dm_ref_pair;
ALTER TABLE app.otp_verification ADD CONSTRAINT otp_dm_ref_pair CHECK ((decision_maker_ref IS NULL) = (dm_ref_key_version IS NULL));
-- NOT VALID: las filas VERIFIED previas (sinteticas, de antes de PR-b) no llevan el seudonimo; la guarda BEFORE lo exige en toda transicion nueva a VERIFIED.
ALTER TABLE app.otp_verification DROP CONSTRAINT IF EXISTS otp_verified_has_dm_ref;
ALTER TABLE app.otp_verification ADD CONSTRAINT otp_verified_has_dm_ref CHECK (state <> 'VERIFIED' OR decision_maker_ref IS NOT NULL) NOT VALID;
-- Solo UPDATE (se fijan en la transicion a VERIFIED); el INSERT no las escribe (la guarda exige NULL al crear).
GRANT UPDATE (decision_maker_ref, dm_ref_key_version) ON app.otp_verification TO app_rw;

-- 2. Esquema ledger_gen y grants de uso -------------------------------------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS ledger_gen AUTHORIZATION ledger_gen_owner;
SET LOCAL ROLE ledger_gen_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA ledger_gen TO ledger_writer; -- CREATE es temporal: se revoca al final del bloque de funciones
SET LOCAL ROLE consent_owner;

GRANT USAGE ON SCHEMA app, ops TO ledger_writer;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO ledger_writer;
GRANT EXECUTE ON FUNCTION ops.catalog_environment() TO ledger_writer;
GRANT SELECT ON ops.db_catalog TO ledger_writer; -- ops.catalog_environment() es SQL invoker: lee el catalogo con el rol que escribe

-- 3. DDL sobre integrity.* (integrity_owner; allowlist de integrity-owner-checker.ts; antes de PR-7) -----------------------------------------------
-- integrity_owner no tiene USAGE/EXECUTE sobre app (0027): se concede de forma temporal para que CREATE/ALTER POLICY resuelva app.current_tenant_id().
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
GRANT USAGE ON SCHEMA integrity TO ledger_writer;
GRANT SELECT ON integrity.audit_event TO ledger_writer;
GRANT INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role,
              recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
              chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  ON integrity.audit_event TO ledger_writer;
DROP POLICY IF EXISTS audit_event_ledger_select ON integrity.audit_event;
CREATE POLICY audit_event_ledger_select ON integrity.audit_event FOR SELECT TO ledger_writer
  USING (tenant_id = app.current_tenant_id());
-- Pares de ledger_writer (19): los 17 derivados de las filas de estado y las 2 siembras LOCAL (seed_local_catalog_event, 0049). Sin Revocation, RightsCase, CONSENT_REVOKED ni
-- Invitation:INVITATION_CANCELLED (esos son de transition_owner).
DROP POLICY IF EXISTS audit_event_ledger_insert ON integrity.audit_event;
CREATE POLICY audit_event_ledger_insert ON integrity.audit_event FOR INSERT TO ledger_writer
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
                'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:RECEIPT_CREATED']));
-- Pares de transition_owner (14): antes solo filtraba por tenant (0037:90-91). Ahora la particion es real en la base.
ALTER POLICY audit_event_transition_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND (aggregate_type || ':' || event_type) = ANY (ARRAY[
                'Revocation:REVOCATION_REQUESTED', 'Revocation:REVOCATION_VERIFIED', 'Revocation:REVOCATION_CONFIRMED', 'Revocation:CONSENT_REVOKED',
                'Revocation:RECEIPT_CREATED', 'Revocation:REVOCATION_DOWNSTREAM_EMITTED', 'Revocation:REVOCATION_DELIVERED',
                'Revocation:DOWNSTREAM_ERASURE_ATTESTED', 'Revocation:REVOCATION_FAILED', 'Revocation:REVOCATION_PROPOSAL_WITHDRAWN',
                'RightsCase:RIGHTS_CASE_OPENED', 'RightsCase:RIGHTS_CASE_CONTACTING', 'RightsCase:RIGHTS_CASE_CLOSED',
                'Invitation:INVITATION_CANCELLED']));
-- app_rw pierde los pares de Enrollment y DecisionMakerVerification (los emite ledger_writer desde esta migracion): 19 -> 17.
ALTER POLICY audit_event_tenant_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND (aggregate_type || ':' || event_type) = ANY (ARRAY[
                'Tenant:TENANT_SEEDED',
                'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED',
                'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_READY', 'Invitation:INVITATION_SENT',
                'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_VERIFIED', 'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_DECLINED',
                'ConsentDecision:CONTEXT_INFORMATION_VIEWED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED',
                'ConsentDecision:SUBJECT_CONFIRMED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:CONSENT_GRANTED',
                'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:RECEIPT_CREATED'])
              AND NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = aggregate_id)
              AND NOT EXISTS (SELECT 1 FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = aggregate_id));
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 4. Funciones (ledger_writer) -----------------------------------------------------------------------------------------------------------------
SET LOCAL ROLE ledger_writer;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- JSON canonico identico a canonicalJson de ledger-chain.ts y a case_state.canonical_json (0037): claves ordenadas por punto de codigo (COLLATE "C"), sin espacios.
-- Copia propia: ledger_writer no tiene USAGE en case_state. Los vectores dorados TS<->SQL (TEST-CNS-1456) comparan ambas copias.
CREATE OR REPLACE FUNCTION ledger_gen.canonical_json(p_value jsonb) RETURNS text
  LANGUAGE plpgsql IMMUTABLE
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  t text := pg_catalog.jsonb_typeof(p_value);
BEGIN
  IF t = 'object' THEN
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_value) k WHERE k ~ '[\U00010000-\U0010FFFF]') THEN
      RAISE EXCEPTION 'canonical_json: claves fuera del BMP no admitidas (orden TS<->SQL divergente)' USING ERRCODE = '22023';
    END IF;
    RETURN '{' || COALESCE((SELECT pg_catalog.string_agg(pg_catalog.to_jsonb(e.key)::text || ':' || ledger_gen.canonical_json(e.value), ',' ORDER BY e.key COLLATE "C")
                              FROM pg_catalog.jsonb_each(p_value) e), '') || '}';
  ELSIF t = 'array' THEN
    RETURN '[' || COALESCE((SELECT pg_catalog.string_agg(ledger_gen.canonical_json(a.v), ',' ORDER BY a.ord)
                              FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY AS a(v, ord)), '') || ']';
  END IF;
  RETURN p_value::text;
END
$fn$;

-- Append del ledger derivado (tenant SIEMPRE de app.current_tenant_id(); recorded_by/cosigned NULL; sin secuencia esperada: la secuencia del agregado es max+1 bajo el lock por tenant,
-- la misma que calcula case_state.ledger_append, asi la secuencia por agregado es unica entre ambos emisores, F-PR6-30). El lock se toma aqui y solo porque hay evento (LG-6).
-- Dedupe estricto: la misma clave solo es un reintento si agregado, tipo, actor y payload canonico son IGUALES (RV002 si difieren).
CREATE OR REPLACE FUNCTION ledger_gen.ledger_append(
  p_aggregate_type text, p_aggregate_id text, p_event_type text, p_actor_type text, p_actor_role text,
  p_payload jsonb, p_idempotency_key text,
  OUT o_sequence integer, OUT o_deduped boolean)
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
    SELECT e.sequence, e.event_type, e.aggregate_type, e.payload, e.actor_type, e.actor_role, e.recorded_by_ref, e.cosigned_by_ref
      INTO o_sequence, v_dup_type, v_dup_agg, v_dup_payload, v_dup_actor_type, v_dup_actor_role, v_dup_rec, v_dup_cosign
      FROM integrity.audit_event e
     WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id AND e.idempotency_key_hash = v_key_hash;
    IF FOUND THEN
      IF v_dup_type IS DISTINCT FROM p_event_type OR v_dup_agg IS DISTINCT FROM p_aggregate_type
         OR v_dup_actor_type IS DISTINCT FROM p_actor_type OR v_dup_actor_role IS DISTINCT FROM p_actor_role
         OR v_dup_rec IS NOT NULL OR v_dup_cosign IS NOT NULL
         OR ledger_gen.canonical_json(v_dup_payload) IS DISTINCT FROM ledger_gen.canonical_json(p_payload) THEN
        RAISE EXCEPTION 'clave de idempotencia reutilizada con otro evento (tipo, agregado, actor o payload)' USING ERRCODE = 'RV002';
      END IF;
      o_deduped := true;
      RETURN;
    END IF;
  END IF;

  SELECT COALESCE(pg_catalog.max(e.sequence), 0) INTO v_current
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant AND e.aggregate_id = p_aggregate_id;

  SELECT e.chain_seq, e.event_hash INTO v_chain_seq, v_prev
    FROM integrity.audit_event e WHERE e.tenant_id = v_tenant AND e.chain_seq IS NOT NULL ORDER BY e.chain_seq DESC LIMIT 1;
  v_chain_seq := COALESCE(v_chain_seq, 0) + 1;
  v_prev := COALESCE(v_prev, pg_catalog.repeat('0', 64));
  v_occurred := pg_catalog.to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  v_env := ops.catalog_environment();
  v_payload_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(ledger_gen.canonical_json(p_payload), 'UTF8')), 'hex');
  v_event_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(ledger_gen.canonical_json(pg_catalog.jsonb_build_object(
    'v', 2, 'tenantId', v_tenant, 'chainSeq', v_chain_seq, 'aggregateType', p_aggregate_type, 'aggregateId', p_aggregate_id,
    'sequence', v_current + 1, 'eventType', p_event_type, 'actorType', p_actor_type, 'actorRole', p_actor_role,
    'recordedByRef', NULL::text, 'cosignedByRef', NULL::text, 'idempotencyKeyHash', v_key_hash,
    'occurredAt', v_occurred, 'environment', v_env, 'payloadHash', v_payload_hash, 'previousEventHash', v_prev)), 'UTF8')), 'hex');

  INSERT INTO integrity.audit_event
    (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload,
     idempotency_key_hash, chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  VALUES
    (v_tenant, p_aggregate_type, p_aggregate_id, v_current + 1, p_event_type, p_actor_type, p_actor_role, NULL, NULL, p_payload,
     v_key_hash, v_chain_seq, v_payload_hash, v_prev, v_event_hash, v_now, v_env);
  o_sequence := v_current + 1;
  o_deduped := false;
END
$fn$;

-- Enrollment ----------------------------------------------------------------------------------------------------------------------------------
-- Guarda (INVOKER): INSERT solo ACTIVE. UPDATE: sin cambios (no-op) o rechazo; ACTIVE -> CLOSED no es una arista (EN1 no implementado; F-PRB-03).
CREATE OR REPLACE FUNCTION ledger_gen.guard_enrollment() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'ACTIVE' THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
    RETURN NEW;
  END IF;
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  RETURN NEW;
END
$fn$;

-- Emision (SECURITY DEFINER de ledger_writer): EN0 (INSERT ACTIVE) -> ENROLLMENT_STATUS_CHANGED (actor HUMAN/INVITER; clave y payload como el dominio de PR-a).
CREATE OR REPLACE FUNCTION ledger_gen.emit_enrollment() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' AND NEW.state = 'ACTIVE' THEN
    PERFORM ledger_gen.ledger_append('Enrollment', NEW.enrollment_ref, 'ENROLLMENT_STATUS_CHANGED', 'HUMAN', 'INVITER',
      pg_catalog.jsonb_build_object('enrollmentRef', NEW.enrollment_ref, 'participationRef', NEW.participation_ref, 'subjectRef', NEW.subject_ref, 'toStatus', 'ACTIVE'),
      NEW.tenant_id::text || ':' || NEW.subject_ref || ':' || NEW.participation_ref || ':en0');
  END IF;
  RETURN NULL;
END
$fn$;

-- OTP / DecisionMakerVerification ---------------------------------------------------------------------------------------------------------------
-- Guarda (INVOKER). Grafo: NOT_STARTED -> CODE_SENT|EXPIRED; CODE_SENT -> CODE_SENT (intento fallido o reenvio V2r, nunca ambos) |VERIFIED|LOCKED|EXPIRED|FAILED; el resto es terminal.
-- Inmutables: tenant, ref, scope, padre, canal y expires_at. VERIFIED exige now() < expires_at, attempts + 1, consumed_at en esa misma transicion y el seudonimo con su version.
-- El maximo de intentos (P-03) es parametro del dominio (OtpPolicy, override solo LOCAL): la base impone que attempts sea monotono y avance de a uno.
CREATE OR REPLACE FUNCTION ledger_gen.guard_otp() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_pair text;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state NOT IN ('NOT_STARTED', 'CODE_SENT') OR NEW.attempts <> 0 OR NEW.consumed_at IS NOT NULL
       OR NEW.decision_maker_ref IS NOT NULL OR NEW.dm_ref_key_version IS NOT NULL THEN
      RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.verification_ref <> OLD.verification_ref OR NEW.scope <> OLD.scope OR NEW.parent_ref <> OLD.parent_ref
     OR NEW.channel_ref <> OLD.channel_ref OR NEW.expires_at <> OLD.expires_at OR NEW.data_class <> OLD.data_class OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
  END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  v_pair := OLD.state || '>' || NEW.state;
  IF v_pair NOT IN ('NOT_STARTED>CODE_SENT', 'NOT_STARTED>EXPIRED', 'CODE_SENT>CODE_SENT', 'CODE_SENT>VERIFIED', 'CODE_SENT>LOCKED', 'CODE_SENT>EXPIRED', 'CODE_SENT>FAILED') THEN
    RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
  END IF;
  -- consumed_at y el seudonimo del apoderado solo existen desde VERIFIED, y se fijan en esa misma transicion.
  IF (NEW.state = 'VERIFIED') <> (NEW.consumed_at IS NOT NULL)
     OR (NEW.state = 'VERIFIED') <> (NEW.decision_maker_ref IS NOT NULL AND NEW.dm_ref_key_version IS NOT NULL) THEN
    RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
  END IF;
  IF v_pair IN ('CODE_SENT>VERIFIED', 'CODE_SENT>LOCKED') THEN
    IF NEW.attempts <> OLD.attempts + 1 THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'CODE_SENT>CODE_SENT' THEN
    IF NEW.code_hash IS DISTINCT FROM OLD.code_hash THEN
      -- Reenvio (V2r): no reinicia ni suma intentos (GRD-OT-06); cuenta un reenvio.
      IF NEW.attempts <> OLD.attempts OR NEW.resend_count <> OLD.resend_count + 1 THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
    ELSE
      -- Intento fallido (V2): un intento mas, el codigo y las marcas de envio no cambian.
      IF NEW.attempts <> OLD.attempts + 1 OR NEW.resend_count <> OLD.resend_count THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
    END IF;
  ELSE
    IF NEW.attempts <> OLD.attempts THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  END IF;
  IF v_pair = 'CODE_SENT>VERIFIED' THEN
    IF pg_catalog.now() >= OLD.expires_at OR NEW.code_hash <> OLD.code_hash OR NEW.resend_count <> OLD.resend_count THEN
      RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
    END IF;
  END IF;
  -- Salvo en el envio inicial y el reenvio, el codigo y las marcas de envio (P-06) no cambian.
  IF v_pair <> 'NOT_STARTED>CODE_SENT' AND NOT (v_pair = 'CODE_SENT>CODE_SENT' AND NEW.code_hash IS DISTINCT FROM OLD.code_hash) THEN
    IF NEW.code_hash <> OLD.code_hash OR NEW.resend_count <> OLD.resend_count OR NEW.last_sent_at IS DISTINCT FROM OLD.last_sent_at
       OR NEW.sends_window_start IS DISTINCT FROM OLD.sends_window_start OR NEW.sends_in_window <> OLD.sends_in_window THEN
      RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

-- Emision: CODE_SENT -> VERIFIED (todos los scopes) -> DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED (actor HUMAN/DECISION_MAKER). method y bindingResult son constantes
-- (OPEN-CT-03: marcador pendiente, igual a BINDING_RESULT_PLACEHOLDER_OPEN_CT03 de opaque-ref.ts).
CREATE OR REPLACE FUNCTION ledger_gen.emit_otp() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'UPDATE' AND OLD.state = 'CODE_SENT' AND NEW.state = 'VERIFIED' THEN
    PERFORM ledger_gen.ledger_append('DecisionMakerVerification', NEW.verification_ref, 'DECISION_MAKER_CHANNEL_VERIFIED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('verificationRef', NEW.verification_ref, 'parentRef', NEW.parent_ref, 'decisionMakerRef', NEW.decision_maker_ref,
        'decisionMakerRefKeyVersion', NEW.dm_ref_key_version, 'scope', NEW.scope, 'method', 'EMAIL_OTP', 'bindingResult', 'OPEN_CT_PENDING'),
      NEW.verification_ref || ':verified');
  END IF;
  RETURN NULL;
END
$fn$;

REVOKE ALL ON FUNCTION ledger_gen.canonical_json(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.ledger_append(text, text, text, text, text, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.guard_enrollment() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.emit_enrollment() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.guard_otp() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.emit_otp() FROM PUBLIC;
-- CREATE TRIGGER exige EXECUTE al creador (consent_owner, dueno de las tablas); se revoca enseguida (el disparo no lo comprueba).
GRANT EXECUTE ON FUNCTION ledger_gen.guard_enrollment(), ledger_gen.emit_enrollment(), ledger_gen.guard_otp(), ledger_gen.emit_otp() TO consent_owner;

SET LOCAL ROLE ledger_gen_owner;
REVOKE CREATE ON SCHEMA ledger_gen FROM ledger_writer;
GRANT USAGE ON SCHEMA ledger_gen TO consent_owner; -- temporal: resolver el nombre de la funcion al crear el trigger
SET LOCAL ROLE consent_owner;

-- 5. Triggers (ENABLE ALWAYS: tambien disparan para el dueno, el migrador y el superusuario) ---------------------------------------------------------
DROP TRIGGER IF EXISTS enrollment_ledger_guard ON app.enrollment;
CREATE TRIGGER enrollment_ledger_guard BEFORE INSERT OR UPDATE ON app.enrollment
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_enrollment();
DROP TRIGGER IF EXISTS enrollment_ledger_emit ON app.enrollment;
CREATE TRIGGER enrollment_ledger_emit AFTER INSERT OR UPDATE ON app.enrollment
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_enrollment();
ALTER TABLE app.enrollment ENABLE ALWAYS TRIGGER enrollment_ledger_guard;
ALTER TABLE app.enrollment ENABLE ALWAYS TRIGGER enrollment_ledger_emit;

DROP TRIGGER IF EXISTS otp_verification_ledger_guard ON app.otp_verification;
CREATE TRIGGER otp_verification_ledger_guard BEFORE INSERT OR UPDATE ON app.otp_verification
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_otp();
DROP TRIGGER IF EXISTS otp_verification_ledger_emit ON app.otp_verification;
CREATE TRIGGER otp_verification_ledger_emit AFTER INSERT OR UPDATE ON app.otp_verification
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_otp();
ALTER TABLE app.otp_verification ENABLE ALWAYS TRIGGER otp_verification_ledger_guard;
ALTER TABLE app.otp_verification ENABLE ALWAYS TRIGGER otp_verification_ledger_emit;

SET LOCAL ROLE ledger_writer;
REVOKE EXECUTE ON FUNCTION ledger_gen.guard_enrollment(), ledger_gen.emit_enrollment(), ledger_gen.guard_otp(), ledger_gen.emit_otp() FROM consent_owner;
SET LOCAL ROLE ledger_gen_owner;
REVOKE USAGE ON SCHEMA ledger_gen FROM consent_owner;
SET LOCAL ROLE consent_owner;

-- 6. Aserciones del estado resultante (fail-closed) ----------------------------------------------------------------------------------------------
DO $assert47$
DECLARE
  f record;
  led oid;
  r text;
  v_expr text;
  v_pairs text[];
  t_pairs text[];
  w_pairs text[];
  w_expect text[] := ARRAY[
    'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:CONSENT_GRANTED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:CONTEXT_INFORMATION_VIEWED',
    'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:RECEIPT_CREATED', 'ConsentDecision:SUBJECT_CONFIRMED',
    'DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED', 'Enrollment:ENROLLMENT_STATUS_CHANGED',
    'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_DECLINED', 'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_READY',
    'Invitation:INVITATION_SENT', 'Invitation:INVITATION_VERIFIED',
    'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED', 'Tenant:TENANT_SEEDED'];
  t_expect text[] := ARRAY[
    'Invitation:INVITATION_CANCELLED',
    'Revocation:CONSENT_REVOKED', 'Revocation:DOWNSTREAM_ERASURE_ATTESTED', 'Revocation:RECEIPT_CREATED', 'Revocation:REVOCATION_CONFIRMED', 'Revocation:REVOCATION_DELIVERED',
    'Revocation:REVOCATION_DOWNSTREAM_EMITTED', 'Revocation:REVOCATION_FAILED', 'Revocation:REVOCATION_PROPOSAL_WITHDRAWN', 'Revocation:REVOCATION_REQUESTED', 'Revocation:REVOCATION_VERIFIED',
    'RightsCase:RIGHTS_CASE_CLOSED', 'RightsCase:RIGHTS_CASE_CONTACTING', 'RightsCase:RIGHTS_CASE_OPENED'];
  a_expect text[] := ARRAY[
    'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:CONSENT_GRANTED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:CONTEXT_INFORMATION_VIEWED',
    'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:RECEIPT_CREATED', 'ConsentDecision:SUBJECT_CONFIRMED',
    'Invitation:INVITATION_COMPLETED', 'Invitation:INVITATION_CREATED', 'Invitation:INVITATION_DECLINED', 'Invitation:INVITATION_OPENED', 'Invitation:INVITATION_READY',
    'Invitation:INVITATION_SENT', 'Invitation:INVITATION_VERIFIED',
    'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED', 'Tenant:TENANT_SEEDED'];
  expect_fn text[] := ARRAY['canonical_json', 'emit_enrollment', 'emit_otp', 'guard_enrollment', 'guard_otp', 'ledger_append'];
BEGIN
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';

  -- Esquema ledger_gen: dueno ledger_gen_owner; ACL exacta (USAGE para ledger_writer); nadie con CREATE.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'ledger_gen' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'ledger_gen_owner') THEN
    RAISE EXCEPTION 'el esquema ledger_gen no pertenece a ledger_gen_owner';
  END IF;
  FOREACH r IN ARRAY ARRAY['ledger_writer', 'ledger_gen_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'transition_owner'] LOOP
    IF r <> 'ledger_gen_owner' AND pg_catalog.has_schema_privilege(r, 'ledger_gen', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema ledger_gen', r; END IF;
  END LOOP;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'ledger_gen' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'ledger_writer:USAGE' THEN
    RAISE EXCEPTION 'la ACL del esquema ledger_gen no es exactamente USAGE para ledger_writer';
  END IF;

  -- Funciones: conjunto exacto, dueno ledger_writer, search_path fijo, sin SQL dinamico, SECURITY DEFINER solo ledger_append/emit_*, sin EXECUTE para nadie mas.
  IF (SELECT pg_catalog.array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen')
     IS DISTINCT FROM expect_fn THEN
    RAISE EXCEPTION 'ledger_gen debe tener exactamente las funciones declaradas en 0047';
  END IF;
  FOR f IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen' LOOP
    IF f.owner <> 'ledger_writer' THEN RAISE EXCEPTION 'ledger_gen.%() no pertenece a ledger_writer', f.proname; END IF;
    IF f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'ledger_gen.%() sin search_path fijo exacto', f.proname; END IF;
    IF f.prosecdef <> (f.proname = 'ledger_append' OR f.proname LIKE 'emit\_%') THEN RAISE EXCEPTION 'ledger_gen.%(): SECURITY DEFINER inesperado', f.proname; END IF;
    IF f.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'ledger_gen.%() contiene SQL dinamico', f.proname; END IF;
    IF pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar ledger_gen.%()', f.proname; END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner) <> 0 THEN
      RAISE EXCEPTION 'la ACL de ledger_gen.%() debe quedar sin grantees distintos del dueno', f.proname;
    END IF;
    FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'transition_owner', 'consent_owner'] LOOP
      IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar ledger_gen.%()', r, f.proname; END IF;
    END LOOP;
    IF f.proname LIKE 'emit\_%' AND (pg_catalog.strpos(f.prosrc, 'app.current_tenant_id()') = 0 OR pg_catalog.strpos(f.prosrc, 'NEW.tenant_id IS DISTINCT FROM') = 0) THEN
      RAISE EXCEPTION 'ledger_gen.%() perdio la exigencia NEW.tenant_id = app.current_tenant_id()', f.proname;
    END IF;
    -- La emision no depende de current_user ni de case_state.effect (F-A10-30: un GUC/rol elegible por el llamador no puede abrir la emision).
    IF f.prosrc ~* 'current_user|session_user|case_state\.effect|current_setting' THEN RAISE EXCEPTION 'ledger_gen.%() depende de current_user o de un GUC', f.proname; END IF;
  END LOOP;

  -- ledger_writer: sin privilegios sobre tablas de app ni duenio de relaciones; INSERT/SELECT solo sobre el ledger.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'app' AND c.relkind IN ('r', 'v', 'p') AND (pg_catalog.has_any_column_privilege('ledger_writer', c.oid, 'SELECT,INSERT,UPDATE')
                    OR pg_catalog.has_table_privilege('ledger_writer', c.oid, 'DELETE,TRUNCATE,REFERENCES,TRIGGER'))) THEN
    RAISE EXCEPTION 'ledger_writer no puede tener privilegios sobre tablas de app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE pg_catalog.pg_get_userbyid(c.relowner) IN ('ledger_writer', 'ledger_gen_owner')) THEN
    RAISE EXCEPTION 'ledger_writer y ledger_gen_owner no deben ser duenos de relaciones';
  END IF;
  IF pg_catalog.has_table_privilege('ledger_writer', led, 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('ledger_writer', led, 'UPDATE') THEN
    RAISE EXCEPTION 'ledger_writer no puede mutar integrity.audit_event (append-only)';
  END IF;
  IF pg_catalog.has_schema_privilege('integrity_owner', 'app', 'USAGE') OR pg_catalog.has_function_privilege('integrity_owner', 'app.current_tenant_id()', 'EXECUTE') THEN
    RAISE EXCEPTION 'integrity_owner conserva el grant temporal sobre app';
  END IF;
  IF pg_catalog.has_schema_privilege('consent_owner', 'ledger_gen', 'USAGE') THEN RAISE EXCEPTION 'consent_owner conserva USAGE sobre ledger_gen (grant temporal)'; END IF;

  -- Policies del ledger: pares exactos y particion disjunta (F-PR6-22). app_rw conserva solo lo aun no migrado.
  IF (SELECT pg_catalog.string_agg(p.polname::text || ':' || p.polcmd::text, ' ' ORDER BY p.polname) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'ledger_writer') = ANY (p.polroles))
     IS DISTINCT FROM 'audit_event_ledger_insert:a audit_event_ledger_select:r' THEN
    RAISE EXCEPTION 'las policies de ledger_writer sobre integrity.audit_event no son exactamente select e insert';
  END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_ledger_insert';
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO w_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF w_pairs IS DISTINCT FROM w_expect THEN RAISE EXCEPTION 'los pares de audit_event_ledger_insert no son exactamente los 19 de ledger_writer'; END IF;
  IF pg_catalog.strpos(v_expr, 'current_tenant_id()') = 0 THEN RAISE EXCEPTION 'audit_event_ledger_insert perdio el filtro de tenant'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_transition_insert';
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO t_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF t_pairs IS DISTINCT FROM t_expect THEN RAISE EXCEPTION 'los pares de audit_event_transition_insert no son exactamente los 14 de transition_owner'; END IF;
  IF pg_catalog.strpos(v_expr, 'current_tenant_id()') = 0 THEN RAISE EXCEPTION 'audit_event_transition_insert perdio el filtro de tenant'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.unnest(w_pairs) x WHERE x = ANY (t_pairs)) THEN RAISE EXCEPTION 'los pares de ledger_writer y transition_owner no son disjuntos'; END IF;
  IF (SELECT pg_catalog.count(DISTINCT x) FROM pg_catalog.unnest(w_pairs || t_pairs) x) <> 33 THEN RAISE EXCEPTION 'la union de pares de ledger_writer y transition_owner no es la esperada (33)'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a';
  IF v_expr IS NULL THEN RAISE EXCEPTION 'falta audit_event_tenant_insert (app_rw sigue emitiendo los agregados aun no migrados)'; END IF;
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO v_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF v_pairs IS DISTINCT FROM a_expect THEN RAISE EXCEPTION 'la allowlist de app_rw no es exactamente la de 17 pares (sin Enrollment ni DecisionMakerVerification)'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.unnest(v_pairs) x WHERE x = ANY (t_pairs)) THEN RAISE EXCEPTION 'app_rw comparte pares con transition_owner'; END IF;
  -- Una sola policy de INSERT alcanza a app_rw (ni ALL ni PUBLIC).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
         AND (0::oid = ANY (p.polroles) OR (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'app_rw') = ANY (p.polroles))) <> 1 THEN
    RAISE EXCEPTION 'exactamente una policy de INSERT debe alcanzar a app_rw en integrity.audit_event (INV-DBR-07)';
  END IF;

  -- Triggers: exactos, ENABLE ALWAYS.
  FOREACH r IN ARRAY ARRAY['enrollment', 'otp_verification'] LOOP
    IF (SELECT pg_catalog.string_agg(t.tgname::text || ':' || t.tgenabled::text, ' ' ORDER BY t.tgname::text) FROM pg_catalog.pg_trigger t
         WHERE t.tgrelid = (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = r)
           AND NOT t.tgisinternal)
       IS DISTINCT FROM (r || '_ledger_emit:A ' || r || '_ledger_guard:A') THEN
      RAISE EXCEPTION 'los triggers de app.% no son exactamente guard y emit, ENABLE ALWAYS', r;
    END IF;
  END LOOP;

  -- Columnas nuevas de otp_verification: solo UPDATE para app_rw (LG-9); sin indice ni UNIQUE.
  IF pg_catalog.has_column_privilege('app_rw', 'app.otp_verification', 'decision_maker_ref', 'INSERT') OR NOT pg_catalog.has_column_privilege('app_rw', 'app.otp_verification', 'decision_maker_ref', 'UPDATE') THEN
    RAISE EXCEPTION 'app_rw debe poder solo ACTUALIZAR (no insertar) decision_maker_ref en otp_verification';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
              WHERE i.indrelid = 'app.otp_verification'::pg_catalog.regclass AND a.attname IN ('decision_maker_ref', 'dm_ref_key_version')) THEN
    RAISE EXCEPTION 'decision_maker_ref no lleva UNIQUE ni indice (LG-9)';
  END IF;
END
$assert47$;
