-- scope: database
-- Gobierna: ADR-010 rev. 5 §4.2.b (capa 1; LG-1..LG-10; aceptada por Carlos el 2026-10-15 para IT0b), §4.2.b(14) (encaje de I9 / Q-18-I9 con ledger_writer, F-PR6-22), F-PR6-23, F-PR6-30;
-- specs/ledger-derivation.spec.yaml. 0010, 0043, 0044 y 0047 estan mergeadas o en este PR y son inmutables: todo va en migracion nueva.
-- Segunda migracion de PR-b (agregado Invitation). Cambia ATOMICAMENTE con el retiro de los 7 pares de Invitation de la allowlist de app_rw (17 -> 10) y del append en el dominio.
--
-- Que hace:
--  1) app.invitation gana delivery_channel, verified_by_ref, dm_ref_key_version y closed_by_consent_id (datos que antes solo vivian en el payload del evento). Solo UPDATE para app_rw (se fijan en
--     la transicion que corresponde; el INSERT exige NULL). El seudonimo bound_decision_maker_ref es DATO PERSONAL (LEGAL DECISION, LG-9); sin UNIQUE ni indice.
--  2) guard_invitation (BEFORE, INVOKER, sin lock de ledger): INSERT solo DRAFT con columnas de cierre NULL y enrollment/participation obligatorios. Aristas permitidas (OLD->NEW) con las columnas que
--     cada una puede tocar (el resto debe quedar identico):
--       DRAFT->READY, READY->SENT, SENT->OPENED, OPENED->VERIFIED (I5), VERIFIED->COMPLETED|DECLINED (I6/I7), y {DRAFT,READY,SENT,OPENED,VERIFIED}->CANCELLED (I9, sin emision de ledger_writer).
--     recipient_channel_ref y token_hash son inmutables desde SENT. CANCELLED, COMPLETED y DECLINED son terminales. bound_decision_maker_ref SOLO se escribe en la arista I5 y es inmutable desde
--     VERIFIED, tambien para I9 y los terminales (F-PR6-23). Cruces (consistencia, NO autenticidad: los dos valores los escribe web): I5 exige un OTP VERIFIED de esa invitacion (scope DECISION,
--     mismo seudonimo y version); el cierre COMPLETED/DECLINED exige una decision GRANTED/DECLINED de esa invitacion con el mismo seudonimo (CANCELLED queda excluido: I9 cierra sin decision).
--     La guarda de ->CANCELLED usa SOLO OLD/NEW (corre como transition_owner: sin grants nuevos). Todo rechazo es 42501 sin valores. Un cambio unicamente de otp_exhausted (V6a) se admite.
--  3) emit_invitation (AFTER ROW, SECURITY DEFINER de ledger_writer, ENABLE ALWAYS): INVITATION_CREATED/READY/SENT/OPENED/VERIFIED/COMPLETED/DECLINED por la tabla OLD->NEW; la arista ->CANCELLED
--     NO emite (el unico emisor de Invitation:INVITATION_CANCELLED es transition_owner por case_state.cancel_invitation_subject_mismatch; sin duplicado).
--  4) app_rw pierde los 7 pares de Invitation de su allowlist. I9 sigue intacta: policies de 0044 (app_rw sin CANCELLED, USING incluido) y ACL de la funcion, reafirmadas en el assert.
-- Idempotente al re-ejecutar: ADD COLUMN IF NOT EXISTS, CREATE OR REPLACE, DROP TRIGGER IF EXISTS + CREATE, ALTER POLICY, GRANT/REVOKE repetibles.

-- 1. Columnas (dueno: consent_owner) ---------------------------------------------------------------------------------------------------------
ALTER TABLE app.invitation
  ADD COLUMN IF NOT EXISTS delivery_channel text CONSTRAINT invitation_delivery_channel_enum CHECK (delivery_channel IN ('SCHOOL_CHANNEL', 'CONSENT_APP_EMAIL')),
  ADD COLUMN IF NOT EXISTS verified_by_ref text CONSTRAINT invitation_verified_by_len CHECK (pg_catalog.length(verified_by_ref) BETWEEN 1 AND 100),
  ADD COLUMN IF NOT EXISTS dm_ref_key_version integer CONSTRAINT invitation_dm_key_version_range CHECK (dm_ref_key_version BETWEEN 2 AND 1000),
  ADD COLUMN IF NOT EXISTS closed_by_consent_id text CONSTRAINT invitation_closed_by_len CHECK (pg_catalog.length(closed_by_consent_id) BETWEEN 1 AND 100);
GRANT UPDATE (delivery_channel, verified_by_ref, dm_ref_key_version, closed_by_consent_id) ON app.invitation TO app_rw;

-- 2. Retiro de los pares de Invitation de la allowlist de app_rw (integrity_owner) ------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
ALTER POLICY audit_event_tenant_insert ON integrity.audit_event
  WITH CHECK (tenant_id = app.current_tenant_id()
              AND (aggregate_type || ':' || event_type) = ANY (ARRAY[
                'Tenant:TENANT_SEEDED',
                'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED',
                'ConsentDecision:CONTEXT_INFORMATION_VIEWED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED',
                'ConsentDecision:SUBJECT_CONFIRMED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:CONSENT_GRANTED',
                'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:RECEIPT_CREATED'])
              AND NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = app.current_tenant_id() AND r.revocation_ref = aggregate_id)
              AND NOT EXISTS (SELECT 1 FROM app.rights_case c WHERE c.tenant_id = app.current_tenant_id() AND c.case_ref = aggregate_id));
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 3. Funciones (ledger_writer) ---------------------------------------------------------------------------------------------------------------
SET LOCAL ROLE ledger_gen_owner;
GRANT CREATE ON SCHEMA ledger_gen TO ledger_writer; -- temporal: se revoca al final del bloque
SET LOCAL ROLE ledger_writer;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION ledger_gen.guard_invitation() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_pair text;
  v_free text[];
  v_deny constant text := 'transicion no admitida por la derivacion del ledger';
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'DRAFT' OR NEW.enrollment_ref IS NULL OR NEW.participation_ref IS NULL
       OR NEW.consent_version IS NOT NULL OR NEW.expires_at IS NOT NULL OR NEW.recipient_channel_ref IS NOT NULL OR NEW.recipient_binding IS NOT NULL
       OR NEW.token_hash IS NOT NULL OR NEW.bound_decision_maker_ref IS NOT NULL OR NEW.delivery_channel IS NOT NULL
       OR NEW.verified_by_ref IS NOT NULL OR NEW.dm_ref_key_version IS NOT NULL OR NEW.closed_by_consent_id IS NOT NULL OR NEW.otp_exhausted THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.invitation_ref <> OLD.invitation_ref OR NEW.context_ref <> OLD.context_ref OR NEW.product_ref <> OLD.product_ref
     OR NEW.subject_ref <> OLD.subject_ref OR NEW.enrollment_ref IS DISTINCT FROM OLD.enrollment_ref OR NEW.participation_ref IS DISTINCT FROM OLD.participation_ref
     OR NEW.reissue_of_ref IS DISTINCT FROM OLD.reissue_of_ref OR NEW.data_class <> OLD.data_class OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF NEW.state = OLD.state THEN
    -- Sin cambio de estado: solo otp_exhausted (V6a) puede cambiar; todo lo demas queda identico (bound_decision_maker_ref inmutable desde VERIFIED y fuera de I5).
    IF (pg_catalog.to_jsonb(NEW) - 'otp_exhausted') IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'otp_exhausted') THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
    RETURN NEW;
  END IF;
  v_pair := OLD.state || '>' || NEW.state;
  IF NEW.otp_exhausted IS DISTINCT FROM OLD.otp_exhausted THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  v_free := CASE v_pair
    WHEN 'DRAFT>READY' THEN ARRAY['state', 'consent_version', 'expires_at', 'recipient_binding', 'recipient_channel_ref']
    WHEN 'READY>SENT' THEN ARRAY['state', 'token_hash', 'delivery_channel', 'expires_at']
    WHEN 'SENT>OPENED' THEN ARRAY['state']
    WHEN 'OPENED>VERIFIED' THEN ARRAY['state', 'bound_decision_maker_ref', 'verified_by_ref', 'dm_ref_key_version']
    WHEN 'VERIFIED>COMPLETED' THEN ARRAY['state', 'closed_by_consent_id']
    WHEN 'VERIFIED>DECLINED' THEN ARRAY['state', 'closed_by_consent_id']
    WHEN 'DRAFT>CANCELLED' THEN ARRAY['state']
    WHEN 'READY>CANCELLED' THEN ARRAY['state']
    WHEN 'SENT>CANCELLED' THEN ARRAY['state']
    WHEN 'OPENED>CANCELLED' THEN ARRAY['state']
    WHEN 'VERIFIED>CANCELLED' THEN ARRAY['state']
    ELSE NULL END;
  IF v_free IS NULL THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF (pg_catalog.to_jsonb(NEW) - v_free) IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - v_free) THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF NEW.state = 'CANCELLED' THEN RETURN NEW; END IF; -- I9: solo OLD/NEW; sin emision de ledger_writer
  IF v_pair = 'DRAFT>READY' THEN
    IF NEW.consent_version IS NULL OR NEW.expires_at IS NULL OR NEW.recipient_binding IS NULL
       OR (NEW.recipient_binding = 'RECIPIENT_CHANNEL') <> (NEW.recipient_channel_ref IS NOT NULL) THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'READY>SENT' THEN
    IF NEW.token_hash IS NULL OR NEW.delivery_channel IS NULL OR NEW.expires_at IS NULL THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'OPENED>VERIFIED' THEN
    IF NEW.bound_decision_maker_ref IS NULL OR NEW.verified_by_ref IS NULL OR NEW.dm_ref_key_version IS NULL
       OR NOT EXISTS (SELECT 1 FROM app.otp_verification o
                       WHERE o.tenant_id = NEW.tenant_id AND o.verification_ref = NEW.verified_by_ref AND o.scope = 'DECISION' AND o.parent_ref = NEW.invitation_ref
                         AND o.state = 'VERIFIED' AND o.decision_maker_ref = NEW.bound_decision_maker_ref AND o.dm_ref_key_version = NEW.dm_ref_key_version) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
  ELSIF v_pair IN ('VERIFIED>COMPLETED', 'VERIFIED>DECLINED') THEN
    IF NEW.closed_by_consent_id IS NULL
       OR NOT EXISTS (SELECT 1 FROM app.consent_decision d
                       WHERE d.tenant_id = NEW.tenant_id AND d.consent_id = NEW.closed_by_consent_id AND d.invitation_ref = NEW.invitation_ref
                         AND d.decision_maker_ref = NEW.bound_decision_maker_ref
                         AND d.state = CASE WHEN NEW.state = 'COMPLETED' THEN 'GRANTED' ELSE 'DECLINED' END) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION ledger_gen.emit_invitation() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_ref text := NEW.invitation_ref;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION 'transicion no admitida por la derivacion del ledger' USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_CREATED', 'HUMAN', 'INVITER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'participationRef', NEW.participation_ref, 'enrollmentRef', NEW.enrollment_ref,
        'subjectRef', NEW.subject_ref, 'reissueOfRef', NEW.reissue_of_ref), v_ref);
  ELSIF OLD.state = 'DRAFT' AND NEW.state = 'READY' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_READY', 'HUMAN', 'INVITER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'consentVersion', NEW.consent_version,
        'expiresAt', pg_catalog.to_char(NEW.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'recipientBinding', NEW.recipient_binding), v_ref || ':ready');
  ELSIF OLD.state = 'READY' AND NEW.state = 'SENT' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_SENT', 'HUMAN', 'INVITER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'deliveryChannel', NEW.delivery_channel,
        'expiresAt', pg_catalog.to_char(NEW.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')), v_ref || ':sent');
  ELSIF OLD.state = 'SENT' AND NEW.state = 'OPENED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_OPENED', 'HUMAN', 'UNVERIFIED_BEARER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref), v_ref || ':opened');
  ELSIF OLD.state = 'OPENED' AND NEW.state = 'VERIFIED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_VERIFIED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'verificationRef', NEW.verified_by_ref, 'decisionMakerRef', NEW.bound_decision_maker_ref,
        'decisionMakerRefKeyVersion', NEW.dm_ref_key_version, 'bindingResult', 'OPEN_CT_PENDING'), v_ref || ':' || NEW.verified_by_ref);
  ELSIF OLD.state = 'VERIFIED' AND NEW.state = 'COMPLETED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_COMPLETED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'consentId', NEW.closed_by_consent_id), v_ref || ':completed');
  ELSIF OLD.state = 'VERIFIED' AND NEW.state = 'DECLINED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_DECLINED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'consentId', NEW.closed_by_consent_id), v_ref || ':declined');
  END IF;
  -- Cualquier arista ->CANCELLED (I9) NO emite aqui: el emisor es transition_owner (Q-18-I9), sin INVITATION_CANCELLED duplicado.
  RETURN NULL;
END
$fn$;

REVOKE ALL ON FUNCTION ledger_gen.guard_invitation() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger_gen.emit_invitation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ledger_gen.guard_invitation(), ledger_gen.emit_invitation() TO consent_owner; -- CREATE TRIGGER lo exige; se revoca enseguida
SET LOCAL ROLE ledger_gen_owner;
REVOKE CREATE ON SCHEMA ledger_gen FROM ledger_writer;
GRANT USAGE ON SCHEMA ledger_gen TO consent_owner; -- temporal
SET LOCAL ROLE consent_owner;

DROP TRIGGER IF EXISTS invitation_ledger_guard ON app.invitation;
CREATE TRIGGER invitation_ledger_guard BEFORE INSERT OR UPDATE ON app.invitation
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_invitation();
DROP TRIGGER IF EXISTS invitation_ledger_emit ON app.invitation;
CREATE TRIGGER invitation_ledger_emit AFTER INSERT OR UPDATE ON app.invitation
  FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_invitation();
ALTER TABLE app.invitation ENABLE ALWAYS TRIGGER invitation_ledger_guard;
ALTER TABLE app.invitation ENABLE ALWAYS TRIGGER invitation_ledger_emit;

SET LOCAL ROLE ledger_writer;
REVOKE EXECUTE ON FUNCTION ledger_gen.guard_invitation(), ledger_gen.emit_invitation() FROM consent_owner;
SET LOCAL ROLE ledger_gen_owner;
REVOKE USAGE ON SCHEMA ledger_gen FROM consent_owner;
SET LOCAL ROLE consent_owner;

-- 4. Aserciones ---------------------------------------------------------------------------------------------------------------------------------
DO $assert48$
DECLARE
  f record;
  led oid;
  inv oid;
  r text;
  v_expr text;
  v_pairs text[];
  a_expect text[] := ARRAY[
    'ConsentDecision:CONSENT_DECLINED', 'ConsentDecision:CONSENT_GRANTED', 'ConsentDecision:CONSENT_VERSION_VIEWED', 'ConsentDecision:CONTEXT_INFORMATION_VIEWED',
    'ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED', 'ConsentDecision:PURPOSE_DECISION_RECORDED', 'ConsentDecision:RECEIPT_CREATED', 'ConsentDecision:SUBJECT_CONFIRMED',
    'SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED', 'Tenant:TENANT_SEEDED'];
BEGIN
  SELECT c.oid INTO inv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'invitation';
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';

  FOR f IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen' AND p.proname IN ('guard_invitation', 'emit_invitation') LOOP
    IF f.owner <> 'ledger_writer' OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] OR f.prosecdef <> (f.proname = 'emit_invitation')
       OR f.prosrc ~* '\mexecute\M' OR pg_catalog.has_function_privilege('public', f.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'ledger_gen.%() no es la declarada', f.proname;
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(COALESCE(f.proacl, pg_catalog.acldefault('f', f.proowner))) a WHERE a.grantee <> f.proowner) <> 0 THEN
      RAISE EXCEPTION 'la ACL de ledger_gen.%() debe quedar sin grantees distintos del dueno', f.proname;
    END IF;
    IF f.prosrc ~* 'current_user|session_user|case_state\.effect|current_setting' THEN RAISE EXCEPTION 'ledger_gen.%() depende de current_user o de un GUC', f.proname; END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen') <> 8 THEN
    RAISE EXCEPTION 'ledger_gen debe tener exactamente 8 funciones tras 0048';
  END IF;
  -- La guarda de ->CANCELLED (I9) usa solo OLD/NEW: el RETURN de CANCELLED va antes de toda lectura de otp_verification/consent_decision.
  SELECT p.prosrc INTO v_expr FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen' AND p.proname = 'guard_invitation';
  IF pg_catalog.strpos(v_expr, 'IF NEW.state = ''CANCELLED'' THEN RETURN NEW; END IF;') = 0
     OR pg_catalog.strpos(v_expr, 'IF NEW.state = ''CANCELLED'' THEN RETURN NEW;') > pg_catalog.strpos(v_expr, 'app.otp_verification')
     OR pg_catalog.strpos(v_expr, 'IF NEW.state = ''CANCELLED'' THEN RETURN NEW;') > pg_catalog.strpos(v_expr, 'app.consent_decision') THEN
    RAISE EXCEPTION 'la guarda de ->CANCELLED (I9) debe usar solo OLD/NEW';
  END IF;

  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = inv AND NOT t.tgisinternal AND t.tgenabled = 'A'
        AND t.tgname IN ('invitation_ledger_guard', 'invitation_ledger_emit')) <> 2 THEN
    RAISE EXCEPTION 'faltan invitation_ledger_guard / invitation_ledger_emit ENABLE ALWAYS';
  END IF;

  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_tenant_insert' AND p.polcmd = 'a';
  SELECT pg_catalog.array_agg(m[1] ORDER BY m[1] COLLATE "C") INTO v_pairs FROM pg_catalog.regexp_matches(v_expr, '''([A-Za-z]+:[A-Z_]+)''', 'g') AS m;
  IF v_pairs IS DISTINCT FROM a_expect THEN RAISE EXCEPTION 'la allowlist de app_rw no es exactamente la de 10 pares (sin Invitation)'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_ledger_insert';
  IF pg_catalog.strpos(v_expr, 'INVITATION_CANCELLED') <> 0 THEN RAISE EXCEPTION 'ledger_writer no puede emitir Invitation:INVITATION_CANCELLED'; END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_transition_insert';
  IF pg_catalog.strpos(v_expr, 'Invitation:INVITATION_CANCELLED') = 0 OR pg_catalog.strpos(v_expr, 'Invitation:INVITATION_CREATED') <> 0 THEN
    RAISE EXCEPTION 'transition_owner solo emite Invitation:INVITATION_CANCELLED entre los pares de Invitation';
  END IF;

  -- I9 intacta (0044).
  FOREACH r IN ARRAY ARRAY['invitation_tenant_insert', 'invitation_tenant_update'] LOOP
    SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = inv AND p.polname = r;
    IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'CANCELLED') = 0 THEN RAISE EXCEPTION 'la policy % debe excluir CANCELLED para app_rw', r; END IF;
  END LOOP;
  SELECT pg_catalog.pg_get_expr(p.polqual, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = inv AND p.polname = 'invitation_tenant_update';
  IF v_expr IS NULL OR pg_catalog.strpos(v_expr, 'CANCELLED') = 0 THEN RAISE EXCEPTION 'invitation_tenant_update USING debe excluir CANCELLED'; END IF;
  IF (SELECT pg_catalog.string_agg(p.polname::text || ':' || p.polcmd::text, ' ' ORDER BY p.polname) FROM pg_catalog.pg_policy p
       WHERE p.polrelid = inv AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'transition_owner') = ANY (p.polroles))
     IS DISTINCT FROM 'invitation_transition_select:r invitation_transition_update:w' THEN
    RAISE EXCEPTION 'las policies de transition_owner sobre app.invitation cambiaron';
  END IF;
  -- consent_owner no tiene USAGE en case_state: la funcion se resuelve por catalogo (oid), nunca por nombre regprocedure.
  SELECT p.oid INTO f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'cancel_invitation_subject_mismatch';
  IF f.oid IS NULL OR NOT pg_catalog.has_function_privilege('app_rw', f.oid, 'EXECUTE') OR pg_catalog.has_function_privilege('worker', f.oid, 'EXECUTE')
     OR pg_catalog.has_function_privilege('platform_rw', f.oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'la ACL de case_state.cancel_invitation_subject_mismatch() cambio';
  END IF;
  IF pg_catalog.has_any_column_privilege('ledger_writer', inv, 'SELECT,INSERT,UPDATE') THEN RAISE EXCEPTION 'ledger_writer no puede tener privilegios sobre app.invitation'; END IF;
  IF pg_catalog.has_schema_privilege('ledger_writer', 'ledger_gen', 'CREATE') OR pg_catalog.has_schema_privilege('consent_owner', 'ledger_gen', 'USAGE') THEN
    RAISE EXCEPTION 'quedo un grant temporal sobre ledger_gen';
  END IF;
  IF pg_catalog.has_column_privilege('app_rw', inv, 'verified_by_ref', 'INSERT') THEN RAISE EXCEPTION 'app_rw solo puede ACTUALIZAR las columnas nuevas de app.invitation'; END IF;
END
$assert48$;
