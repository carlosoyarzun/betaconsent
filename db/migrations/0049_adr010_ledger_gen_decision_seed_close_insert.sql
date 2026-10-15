-- scope: database
-- Gobierna: ADR-010 rev. 5 §4.2.b (capa 1; LG-1..LG-10; aceptada por Carlos el 2026-10-15), LG-4 (siembra LOCAL de payload fijo), LG-2 (a), F-PR6-10 (C6 sin emision con su guarda), F-PR6-28,
-- dictamen de arquitectura 2026-10-15 sobre F-PRB-01 (managementLinkIssued derivado de tenant_resolve.handle) y F-PRB-02 (retiro de case_state.seed_local_revoke_decision, adelanta F-A10-28);
-- specs/ledger-derivation.spec.yaml. 0006, 0010, 0037, 0047 y 0048 son inmutables: todo va en migracion nueva.
-- Ultima migracion de PR-b: agregado ConsentDecision + siembra LOCAL + retiro total del INSERT de app_rw sobre integrity.audit_event (INV-DBR-07).
--
-- Que hace:
--  1) app.consent_decision gana relationship_ref y las columnas de version (consent_version, consent_text_hash, privacy_notice_version): LG-2 (a), las escribe web con la semantica de hoy (en el paso
--     CONSENT_VERSION_VIEWED y de nuevo al decidir; la opcion (c) "version vista en el paso" NO se implementa: gate de Carlos + LD-06). Solo UPDATE para app_rw.
--  2) guard_consent_decision (BEFORE, INVOKER): INSERT solo PENDING sobre una invitacion VERIFIED con el mismo seudonimo (y mismo sujeto/contexto/producto), con steps y purposes vacios y sin recibo.
--     C2 (PENDING->PENDING): steps_recorded crece de a UN stepKind conocido y nuevo, con las columnas que ese paso escribe; prior_steps_complete se recalcula. C3/C5 (PENDING->GRANTED|DECLINED):
--     3 pasos de GRD-CD-05, purposes no vacio y sin finalidades duplicadas; GRANTED exige todas GRANT, DECLINED al menos un DECLINE; recibo y version obligatorios. C6 (GRANTED->REVOKED) NO emite
--     (la emite transition_owner por apply_revocation, F-PR6-10) y la guarda la admite SOLO si existe en el tenant una app.revocation CONFIRMED con revoked_decision_ref = consent_id; sin otra salida:
--     REVOKED/GRANTED/DECLINED son terminales (sin exencion por rol ni por GUC; F-PRB-02). El privilegio cierra la via: policies de 0037 (app_rw nunca deja REVOKED).
--     purpose ~ ^[A-Z_]{1,64}$ (el catalogo de finalidades requeridas en la base, LG-10, sigue pendiente antes de datos reales). C2/C3/C5 exigen ademas la invitacion VERIFIED del mismo seudonimo.
--  3) emit_consent_decision (AFTER, SECURITY DEFINER de ledger_writer): un evento por paso nuevo; en C3/C5 PURPOSE_DECISION_RECORDED por finalidad (en orden), CONSENT_GRANTED|DECLINED y
--     RECEIPT_CREATED. managementLinkIssued (F-PRB-01) NO lo escribe web: lo deriva la base de la existencia en tenant_resolve.handle de una fila NO rotada con el mismo tenant y
--     revoked_decision_ref = consent_id (el dominio registra el handle ANTES del UPDATE a GRANTED, en la misma tx). Significa "registrado", no "entregado". ledger_writer recibe SELECT SOLO de
--     tenant_id, revoked_decision_ref y rotated_at de tenant_resolve.handle (nunca handle_hash); esta ampliacion va a revision de seguridad.
--  4) ledger_gen.seed_local_catalog_event (LG-4, F-PR6-28): unica funcion de ledger_gen con EXECUTE de app_rw; entorno LOCAL leido de ops.db_catalog (no de un GUC), actor FIXTURE, payload constante `{}`,
--     solo TENANT_SEEDED (aggregate_id = tenant de la tx) y SCHOOL_PARTICIPATION_SEEDED.
--  5) F-PRB-02: DROP de case_state.seed_local_revoke_decision (adelanta F-A10-28). Un REVOKED sembrado pasa por seed_local_revocation hasta CONFIRMED y luego R4/C6.
--  6) DROP POLICY audit_event_tenant_insert y REVOKE de todo INSERT de app_rw sobre integrity.audit_event. Aserciones: sin INSERT ni policy de INSERT alcanzable por app_rw; particion disjunta ledger_writer /
--     transition_owner (19 + 14 = 33); y ninguna funcion alcanzable por app_rw hace append con un payload libre salvo el conjunto declarado de funciones case_state (payload fijo o derivado de filas) y la
--     siembra LOCAL de payload constante.
-- Idempotente al re-ejecutar: ADD COLUMN IF NOT EXISTS, CREATE OR REPLACE, DROP ... IF EXISTS, GRANT/REVOKE repetibles.

-- 1. Columnas (dueno: consent_owner) ----------------------------------------------------------------------------------------------------------
ALTER TABLE app.consent_decision
  ADD COLUMN IF NOT EXISTS relationship_ref text CONSTRAINT consent_decision_relationship_shape CHECK (relationship_ref ~ '^[A-Z_]{1,40}$'),
  ADD COLUMN IF NOT EXISTS consent_version text CONSTRAINT consent_decision_version_len CHECK (pg_catalog.length(consent_version) BETWEEN 1 AND 100),
  ADD COLUMN IF NOT EXISTS consent_text_hash text CONSTRAINT consent_decision_text_hash_shape CHECK (consent_text_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN IF NOT EXISTS privacy_notice_version text CONSTRAINT consent_decision_privacy_version_len CHECK (pg_catalog.length(privacy_notice_version) BETWEEN 1 AND 100);
GRANT UPDATE (relationship_ref, consent_version, consent_text_hash, privacy_notice_version) ON app.consent_decision TO app_rw;

-- 2. Lectura minima de tenant_resolve.handle para ledger_writer (F-PRB-01; tenant_resolve_owner) --------------------------------------------------
SET LOCAL ROLE tenant_resolve_owner;
GRANT USAGE ON SCHEMA tenant_resolve TO ledger_writer;
GRANT SELECT (tenant_id, revoked_decision_ref, rotated_at) ON tenant_resolve.handle TO ledger_writer;
SET LOCAL ROLE consent_owner;

-- 3. integrity: DROP POLICY y REVOKE INSERT de app_rw (integrity_owner) -------------------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
DROP POLICY IF EXISTS audit_event_tenant_insert ON integrity.audit_event;
REVOKE INSERT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, payload, idempotency_key_hash,
               chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
  ON integrity.audit_event FROM app_rw;
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 4. F-PRB-02: retiro de la siembra LOCAL de decisiones REVOKED (transition_owner) -------------------------------------------------------------------
SET LOCAL ROLE transition_owner;
DROP FUNCTION IF EXISTS case_state.seed_local_revoke_decision(uuid, text);
SET LOCAL ROLE consent_owner;

-- 5. Funciones (ledger_writer) -----------------------------------------------------------------------------------------------------------------
SET LOCAL ROLE ledger_gen_owner;
GRANT CREATE ON SCHEMA ledger_gen TO ledger_writer; -- temporal: se revoca al final del bloque
SET LOCAL ROLE ledger_writer;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION ledger_gen.guard_consent_decision() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_pair text;
  v_free text[];
  v_n integer;
  v_step text;
  v_deny constant text := 'transicion no admitida por la derivacion del ledger';
  v_required constant text[] := ARRAY['CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED'];
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'PENDING' OR NEW.purposes <> '[]'::jsonb OR NEW.steps_recorded <> ARRAY[]::text[] OR NEW.prior_steps_complete OR NEW.receipt_ref IS NOT NULL
       OR NEW.relationship_ref IS NOT NULL OR NEW.consent_version IS NOT NULL OR NEW.consent_text_hash IS NOT NULL OR NEW.privacy_notice_version IS NOT NULL
       OR NOT EXISTS (SELECT 1 FROM app.invitation i
                       WHERE i.tenant_id = NEW.tenant_id AND i.invitation_ref = NEW.invitation_ref AND i.state = 'VERIFIED'
                         AND i.bound_decision_maker_ref = NEW.decision_maker_ref AND i.subject_ref = NEW.subject_ref
                         AND i.context_ref = NEW.context_ref AND i.product_ref = NEW.product_ref) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.consent_id <> OLD.consent_id OR NEW.context_ref <> OLD.context_ref OR NEW.product_ref <> OLD.product_ref OR NEW.subject_ref <> OLD.subject_ref
     OR NEW.decision_maker_ref <> OLD.decision_maker_ref OR NEW.invitation_ref <> OLD.invitation_ref OR NEW.verification_ref <> OLD.verification_ref OR NEW.chain_ref <> OLD.chain_ref
     OR NEW.data_class <> OLD.data_class OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  v_pair := OLD.state || '>' || NEW.state;
  -- Toda arista que sale de PENDING (C2/C3/C5) exige que la invitacion de la decision siga VERIFIED en el tenant (P2 de seguridad de PR #98): tras I9 (CANCELLED) o un cierre, la decision
  -- queda congelada y ni los pasos ni GRANTED/DECLINED avanzan (ni emiten).
  IF OLD.state = 'PENDING' AND NOT EXISTS (SELECT 1 FROM app.invitation i
                                            WHERE i.tenant_id = NEW.tenant_id AND i.invitation_ref = NEW.invitation_ref AND i.state = 'VERIFIED'
                                              AND i.bound_decision_maker_ref = NEW.decision_maker_ref) THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF v_pair = 'PENDING>PENDING' THEN
    -- C2: un paso nuevo y conocido; purposes y recibo no cambian.
    v_n := pg_catalog.cardinality(OLD.steps_recorded);
    IF pg_catalog.cardinality(NEW.steps_recorded) <> v_n + 1 OR NEW.steps_recorded[1:v_n] IS DISTINCT FROM OLD.steps_recorded THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
    v_step := NEW.steps_recorded[v_n + 1];
    IF v_step NOT IN ('CONTEXT_INFORMATION_VIEWED', 'CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED') OR v_step = ANY (OLD.steps_recorded) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    v_free := ARRAY['steps_recorded', 'prior_steps_complete']
              || CASE v_step WHEN 'CONSENT_VERSION_VIEWED' THEN ARRAY['consent_version', 'consent_text_hash', 'privacy_notice_version']
                             WHEN 'DECISION_MAKER_AUTHORITY_DECLARED' THEN ARRAY['relationship_ref'] ELSE ARRAY[]::text[] END;
    IF (pg_catalog.to_jsonb(NEW) - v_free) IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - v_free)
       OR NEW.prior_steps_complete IS DISTINCT FROM (NEW.steps_recorded @> v_required)
       OR (v_step = 'CONSENT_VERSION_VIEWED' AND (NEW.consent_version IS NULL OR NEW.consent_text_hash IS NULL OR NEW.privacy_notice_version IS NULL))
       OR (v_step = 'DECISION_MAKER_AUTHORITY_DECLARED' AND NEW.relationship_ref IS NULL) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  ELSIF v_pair IN ('PENDING>GRANTED', 'PENDING>DECLINED') THEN
    v_free := ARRAY['state', 'purposes', 'receipt_ref', 'consent_version', 'consent_text_hash', 'privacy_notice_version'];
    IF (pg_catalog.to_jsonb(NEW) - v_free) IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - v_free)
       OR NOT (NEW.steps_recorded @> v_required) OR NOT NEW.prior_steps_complete
       OR NEW.receipt_ref IS NULL OR NEW.consent_version IS NULL OR NEW.consent_text_hash IS NULL OR NEW.privacy_notice_version IS NULL
       OR pg_catalog.jsonb_typeof(NEW.purposes) <> 'array' OR pg_catalog.jsonb_array_length(NEW.purposes) = 0
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(NEW.purposes) e
                   WHERE pg_catalog.jsonb_typeof(e) <> 'object' OR NOT (e ? 'purpose') OR NOT (e ? 'choice') OR pg_catalog.jsonb_typeof(e -> 'purpose') <> 'string' OR (e ->> 'purpose') !~ '^[A-Z_]{1,64}$'
                      OR (e ->> 'choice') NOT IN ('GRANT', 'DECLINE')
                      OR CASE WHEN pg_catalog.jsonb_typeof(e) = 'object' THEN (e - 'purpose' - 'choice') <> '{}'::jsonb ELSE true END)
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_array_elements(NEW.purposes)) <> (SELECT pg_catalog.count(DISTINCT e ->> 'purpose') FROM pg_catalog.jsonb_array_elements(NEW.purposes) e)
       OR (NEW.state = 'GRANTED' AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(NEW.purposes) e WHERE (e ->> 'choice') <> 'GRANT'))
       OR (NEW.state = 'DECLINED' AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(NEW.purposes) e WHERE (e ->> 'choice') = 'DECLINE')) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  ELSIF v_pair = 'GRANTED>REVOKED' THEN
    -- C6: sin emision de ledger_writer. Solo con una Revocation CONFIRMED del tenant sobre esta decision; el resto de la fila no cambia. Sin exencion por rol, GUC ni entorno.
    IF (pg_catalog.to_jsonb(NEW) - 'state') IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'state')
       OR NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = NEW.tenant_id AND r.revoked_decision_ref = NEW.consent_id AND r.status = 'CONFIRMED') THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
END
$fn$;

CREATE OR REPLACE FUNCTION ledger_gen.emit_consent_decision() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_id text := NEW.consent_id;
  v_step text;
  v_payload jsonb;
  v_link boolean;
  p record;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN RETURN NULL; END IF; -- C1: sin evento
  IF OLD.state = 'PENDING' AND NEW.state = 'PENDING' AND pg_catalog.cardinality(NEW.steps_recorded) = pg_catalog.cardinality(OLD.steps_recorded) + 1 THEN
    v_step := NEW.steps_recorded[pg_catalog.cardinality(NEW.steps_recorded)];
    v_payload := pg_catalog.jsonb_build_object('consentId', v_id);
    IF v_step = 'CONSENT_VERSION_VIEWED' THEN
      v_payload := v_payload || pg_catalog.jsonb_build_object('consentVersion', NEW.consent_version, 'consentTextHash', NEW.consent_text_hash, 'privacyNoticeVersion', NEW.privacy_notice_version);
    ELSIF v_step = 'DECISION_MAKER_AUTHORITY_DECLARED' THEN
      v_payload := v_payload || pg_catalog.jsonb_build_object('relationshipRef', NEW.relationship_ref);
    ELSIF v_step = 'SUBJECT_CONFIRMED' THEN
      v_payload := v_payload || pg_catalog.jsonb_build_object('subjectRef', NEW.subject_ref);
    END IF;
    PERFORM ledger_gen.ledger_append('ConsentDecision', v_id, v_step, 'HUMAN', 'DECISION_MAKER', v_payload, v_id || ':' || v_step);
  ELSIF OLD.state = 'PENDING' AND NEW.state IN ('GRANTED', 'DECLINED') THEN
    FOR p IN SELECT e ->> 'purpose' AS purpose, e ->> 'choice' AS choice FROM pg_catalog.jsonb_array_elements(NEW.purposes) WITH ORDINALITY AS t(e, ord) ORDER BY t.ord LOOP
      PERFORM ledger_gen.ledger_append('ConsentDecision', v_id, 'PURPOSE_DECISION_RECORDED', 'HUMAN', 'DECISION_MAKER',
        pg_catalog.jsonb_build_object('consentId', v_id, 'purpose', p.purpose, 'choice', p.choice), v_id || ':purpose:' || p.purpose);
    END LOOP;
    -- managementLinkIssued = "registrado" (no "entregado"): existe un handle de gestion no rotado de esta decision (F-PRB-01). Solo GRANTED puede emitir enlace (C5 no).
    v_link := NEW.state = 'GRANTED' AND EXISTS (SELECT 1 FROM tenant_resolve.handle h WHERE h.tenant_id = NEW.tenant_id AND h.revoked_decision_ref = v_id AND h.rotated_at IS NULL);
    PERFORM ledger_gen.ledger_append('ConsentDecision', v_id, CASE WHEN NEW.state = 'GRANTED' THEN 'CONSENT_GRANTED' ELSE 'CONSENT_DECLINED' END, 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('consentId', v_id, 'chainRef', NEW.chain_ref, 'consentVersion', NEW.consent_version, 'consentTextHash', NEW.consent_text_hash),
      v_id || CASE WHEN NEW.state = 'GRANTED' THEN ':granted' ELSE ':declined' END);
    PERFORM ledger_gen.ledger_append('ConsentDecision', v_id, 'RECEIPT_CREATED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('receiptRef', NEW.receipt_ref, 'managementLinkIssued', v_link), v_id || ':receipt');
  END IF;
  -- GRANTED -> REVOKED (C6) NO emite aqui: CONSENT_REVOKED lo escribe transition_owner por apply_revocation.
  RETURN NULL;
END
$fn$;

-- Siembra LOCAL de payload fijo (LG-4, F-PR6-28). Entorno de la fila de ops.db_catalog (no de un GUC); actor FIXTURE; payload constante {}.
CREATE OR REPLACE FUNCTION ledger_gen.seed_local_catalog_event(p_event_type text, p_aggregate_id text) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_agg text;
  v_key text;
  v_seq integer;
BEGIN
  IF v_tenant IS NULL OR ops.catalog_environment() IS DISTINCT FROM 'LOCAL' THEN RAISE EXCEPTION 'la siembra de catalogo solo existe en LOCAL' USING ERRCODE = '42501'; END IF;
  IF p_event_type = 'TENANT_SEEDED' AND p_aggregate_id = v_tenant::text THEN
    v_agg := 'Tenant'; v_key := p_aggregate_id || ':tn1';
  ELSIF p_event_type = 'SCHOOL_PARTICIPATION_SEEDED' AND p_aggregate_id IS NOT NULL THEN
    v_agg := 'SchoolParticipation'; v_key := p_aggregate_id || ':sp1';
  ELSE
    RAISE EXCEPTION 'siembra no admitida' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_sequence INTO v_seq FROM ledger_gen.ledger_append(v_agg, p_aggregate_id, p_event_type, 'FIXTURE', NULL, '{}'::jsonb, v_key) a;
  RETURN v_seq;
END
$fn$;

REVOKE ALL ON FUNCTION ledger_gen.guard_consent_decision() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.emit_consent_decision() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.seed_local_catalog_event(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ledger_gen.seed_local_catalog_event(text, text) TO app_rw;
GRANT EXECUTE ON FUNCTION ledger_gen.guard_consent_decision(), ledger_gen.emit_consent_decision() TO consent_owner; -- CREATE TRIGGER lo exige; se revoca enseguida
SET LOCAL ROLE ledger_gen_owner;
REVOKE CREATE ON SCHEMA ledger_gen FROM ledger_writer;
GRANT USAGE ON SCHEMA ledger_gen TO app_rw; -- para la siembra LOCAL (seed_local_catalog_event); sin EXECUTE de ninguna otra funcion
GRANT USAGE ON SCHEMA ledger_gen TO consent_owner; -- temporal
SET LOCAL ROLE consent_owner;

DROP TRIGGER IF EXISTS consent_decision_ledger_guard ON app.consent_decision;
CREATE TRIGGER consent_decision_ledger_guard BEFORE INSERT OR UPDATE ON app.consent_decision
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_consent_decision();
DROP TRIGGER IF EXISTS consent_decision_ledger_emit ON app.consent_decision;
CREATE TRIGGER consent_decision_ledger_emit AFTER INSERT OR UPDATE ON app.consent_decision
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_consent_decision();
ALTER TABLE app.consent_decision ENABLE ALWAYS TRIGGER consent_decision_ledger_guard;
ALTER TABLE app.consent_decision ENABLE ALWAYS TRIGGER consent_decision_ledger_emit;

SET LOCAL ROLE ledger_writer;
REVOKE EXECUTE ON FUNCTION ledger_gen.guard_consent_decision(), ledger_gen.emit_consent_decision() FROM consent_owner;
SET LOCAL ROLE ledger_gen_owner;
REVOKE USAGE ON SCHEMA ledger_gen FROM consent_owner;
SET LOCAL ROLE consent_owner;

-- 6. Aserciones ---------------------------------------------------------------------------------------------------------------------------------
DO $assert49$
DECLARE
  f record;
  led oid;
  cd oid;
  hd oid;
  r text;
  v_expr text;
  w_pairs text[];
  t_pairs text[];
  reach text[];
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
  -- Funciones alcanzables por app_rw que llaman a un append de ledger: funciones case_state de transicion (payload fijo o derivado de filas; Q-18, Q-18-I9) y la siembra LOCAL de payload constante.
  reach_expect text[] := ARRAY[
    'case_state.apply_revocation', 'case_state.approve_case_verification', 'case_state.cancel_invitation_subject_mismatch', 'case_state.close_case', 'case_state.confirm_case_return',
    'case_state.confirm_revocation', 'case_state.cosign_case_confirmation', 'case_state.express_revocation_intent_in_case', 'case_state.open_rights_case_bearer',
    'case_state.request_revocation', 'case_state.revoke_with_recovery_link', 'case_state.verify_revocation_otp', 'case_state.withdraw_case_verification_proposal',
    'case_state.withdraw_revocation', 'ledger_gen.seed_local_catalog_event'];
  expect_fn text[] := ARRAY['canonical_json', 'emit_consent_decision', 'emit_enrollment', 'emit_invitation', 'emit_otp', 'guard_consent_decision', 'guard_enrollment', 'guard_invitation',
                            'guard_otp', 'ledger_append', 'seed_local_catalog_event'];
BEGIN
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  SELECT c.oid INTO cd FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'consent_decision';
  -- consent_owner no tiene USAGE en tenant_resolve: la tabla se resuelve por catalogo (oid), nunca por nombre regclass.
  SELECT c.oid INTO hd FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'tenant_resolve' AND c.relname = 'handle';

  -- Retiro total del INSERT de app_rw (INV-DBR-07): sin policy de INSERT/ALL alcanzable, sin privilegio de INSERT, ni por membresia.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polcmd IN ('a', '*')
              AND (0::oid = ANY (p.polroles) OR (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'app_rw') = ANY (p.polroles))) THEN
    RAISE EXCEPTION 'una policy de INSERT alcanza a app_rw en integrity.audit_event (INV-DBR-07)';
  END IF;
  IF pg_catalog.has_any_column_privilege('app_rw', led, 'INSERT') THEN RAISE EXCEPTION 'app_rw conserva INSERT sobre integrity.audit_event'; END IF;
  FOR r IN SELECT x.rolname::text FROM pg_catalog.pg_roles x WHERE x.rolname <> 'app_rw' AND (pg_catalog.pg_has_role('app_rw', x.oid, 'USAGE') OR pg_catalog.pg_has_role('app_rw', x.oid, 'SET')) LOOP
    IF pg_catalog.has_any_column_privilege(r, led, 'INSERT') THEN RAISE EXCEPTION 'app_rw alcanza por membresia a % con INSERT sobre integrity.audit_event', r; END IF;
  END LOOP;

  -- Particion de pares: ledger_writer (19) y transition_owner (14), disjuntos, union 33.
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_ledger_insert';
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO w_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF w_pairs IS DISTINCT FROM w_expect THEN RAISE EXCEPTION 'los pares de audit_event_ledger_insert no son exactamente los 19 de ledger_writer'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_transition_insert';
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO t_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF t_pairs IS DISTINCT FROM t_expect THEN RAISE EXCEPTION 'los pares de audit_event_transition_insert no son exactamente los 14 de transition_owner'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.unnest(w_pairs) x WHERE x = ANY (t_pairs)) THEN RAISE EXCEPTION 'los pares de ledger_writer y transition_owner no son disjuntos'; END IF;
  IF (SELECT pg_catalog.count(DISTINCT x) FROM pg_catalog.unnest(w_pairs || t_pairs) x) <> 33 THEN RAISE EXCEPTION 'la union de pares no es la esperada (33)'; END IF;

  -- ledger_gen: funciones exactas; solo seed_local_catalog_event con EXECUTE (solo app_rw); ACL del esquema.
  IF (SELECT pg_catalog.array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen')
     IS DISTINCT FROM expect_fn THEN
    RAISE EXCEPTION 'ledger_gen debe tener exactamente las 11 funciones declaradas tras 0049';
  END IF;
  FOR f IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen' LOOP
    IF f.owner <> 'ledger_writer' OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] OR f.prosrc ~* '\mexecute\M' OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'ledger_gen.%() no es la declarada (dueno, search_path, sin SQL dinamico, sin EXECUTE PUBLIC)', f.proname;
    END IF;
    IF f.prosecdef <> (f.proname = 'ledger_append' OR f.proname LIKE 'emit\_%' OR f.proname = 'seed_local_catalog_event') THEN RAISE EXCEPTION 'ledger_gen.%(): SECURITY DEFINER inesperado', f.proname; END IF;
    IF f.prosrc ~* 'current_user|session_user|case_state\.effect|current_setting' THEN RAISE EXCEPTION 'ledger_gen.%() depende de current_user o de un GUC', f.proname; END IF;
    IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text, ',') FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner)
       IS DISTINCT FROM (CASE WHEN f.proname = 'seed_local_catalog_event' THEN 'app_rw' ELSE NULL END) THEN
      RAISE EXCEPTION 'la ACL de ledger_gen.%() no es exactamente la declarada', f.proname;
    END IF;
    FOREACH r IN ARRAY ARRAY['worker', 'platform_rw', 'integrity_verifier', 'transition_owner', 'consent_owner'] LOOP
      IF pg_catalog.has_function_privilege(r, f.oid, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar ledger_gen.%()', r, f.proname; END IF;
    END LOOP;
    IF f.proname = 'seed_local_catalog_event' AND (pg_catalog.strpos(f.prosrc, 'ops.catalog_environment()') = 0 OR pg_catalog.strpos(f.prosrc, '''{}''::jsonb') = 0
         OR pg_catalog.strpos(f.prosrc, '''FIXTURE''') = 0) THEN
      RAISE EXCEPTION 'seed_local_catalog_event perdio entorno del catalogo, actor FIXTURE o payload constante';
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'ledger_gen' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'app_rw:USAGE,ledger_writer:USAGE' THEN
    RAISE EXCEPTION 'la ACL del esquema ledger_gen no es exactamente USAGE para app_rw y ledger_writer';
  END IF;
  IF pg_catalog.has_schema_privilege('ledger_writer', 'ledger_gen', 'CREATE') OR pg_catalog.has_schema_privilege('consent_owner', 'ledger_gen', 'USAGE') THEN RAISE EXCEPTION 'quedo un grant temporal sobre ledger_gen'; END IF;

  -- Ninguna funcion alcanzable por app_rw llega a un append con payload libre fuera del conjunto declarado.
  SELECT pg_catalog.array_agg(n.nspname::text || '.' || p.proname::text ORDER BY n.nspname::text || '.' || p.proname::text COLLATE "C") INTO reach
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE p.prosrc ~ 'ledger_append' AND (pg_catalog.has_function_privilege('app_rw', p.oid, 'EXECUTE') OR pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE'));
  IF reach IS DISTINCT FROM reach_expect THEN RAISE EXCEPTION 'las funciones alcanzables por app_rw que hacen append no son exactamente las declaradas: %', reach; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'seed_local_revoke_decision') THEN
    RAISE EXCEPTION 'case_state.seed_local_revoke_decision debe estar retirada (F-PRB-02)';
  END IF;

  -- Triggers de consent_decision: exactos, ENABLE ALWAYS. C6: policies de 0037 intactas (app_rw nunca deja REVOKED).
  IF (SELECT pg_catalog.string_agg(t.tgname::text || ':' || t.tgenabled::text, ' ' ORDER BY t.tgname::text) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = cd AND NOT t.tgisinternal)
     IS DISTINCT FROM 'consent_decision_ledger_emit:A consent_decision_ledger_guard:A' THEN
    RAISE EXCEPTION 'los triggers de app.consent_decision no son exactamente guard y emit, ENABLE ALWAYS';
  END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = cd AND p.polname = 'consent_decision_tenant_update';
  IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'REVOKED') = 0 THEN RAISE EXCEPTION 'consent_decision_tenant_update debe excluir REVOKED para app_rw (FN-10)'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polqual, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = cd AND p.polname = 'consent_decision_tenant_update';
  IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'REVOKED') = 0 THEN RAISE EXCEPTION 'consent_decision_tenant_update USING debe excluir REVOKED'; END IF;
  IF pg_catalog.has_column_privilege('app_rw', cd, 'relationship_ref', 'INSERT') THEN RAISE EXCEPTION 'app_rw solo puede ACTUALIZAR las columnas nuevas de app.consent_decision'; END IF;
  IF pg_catalog.has_any_column_privilege('ledger_writer', cd, 'SELECT,INSERT,UPDATE') THEN RAISE EXCEPTION 'ledger_writer no puede tener privilegios sobre app.consent_decision'; END IF;

  -- tenant_resolve.handle: ledger_writer lee SOLO tenant_id, revoked_decision_ref y rotated_at (nunca handle_hash).
  IF (SELECT pg_catalog.string_agg(a.attname::text, ',' ORDER BY a.attname::text) FROM pg_catalog.pg_attribute a
       WHERE a.attrelid = hd AND a.attnum > 0 AND NOT a.attisdropped
         AND pg_catalog.has_column_privilege('ledger_writer', a.attrelid, a.attnum, 'SELECT'))
     IS DISTINCT FROM 'revoked_decision_ref,rotated_at,tenant_id' THEN
    RAISE EXCEPTION 'ledger_writer solo puede leer tenant_id, revoked_decision_ref y rotated_at de tenant_resolve.handle';
  END IF;
  IF pg_catalog.has_table_privilege('ledger_writer', hd, 'INSERT,UPDATE,DELETE,TRUNCATE') THEN RAISE EXCEPTION 'ledger_writer no puede escribir tenant_resolve.handle'; END IF;
END
$assert49$;
