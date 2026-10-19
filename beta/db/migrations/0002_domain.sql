-- Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-02
-- (rebuild-plan.md §3 modelo de datos mínimo, rebuild-plan-v2.md §5).
-- origen (DDL adaptado a UN dueño consent_owner, sin owners múltiples ni tenant_resolve):
--   db/migrations/0010_invitation_otp_rights_case_enrollment.sql:24-74@9345b78, 0006_revocation_consent_recovery.sql:16-80@9345b78,
--   0032_otp_budget_p06_v6a.sql@9345b78 (presupuesto, recortado), 0003_outbox.sql@9345b78 (patrón de outbox),
--   0048_adr010_ledger_gen_invitation.sql:53-176@9345b78 y 0049_adr010_ledger_gen_decision_seed_close_insert.sql:65-230@9345b78
--   (triggers guard INVOKER + emit SECURITY DEFINER), 0047_adr010_ledger_gen_enrollment_dmv.sql:209-348@9345b78 (guard/emit OTP).
--
-- Diferencias deliberadas respecto del repo anterior:
--   * sin RUT; sin app.is_reserved_email; sin CHECK data_class='SYNTHETIC' por tabla (el gate es ops.db_catalog);
--   * decisión simplificada: se inserta ya GRANTED|DECLINED (sin PENDING ni pasos); su INSERT emite CONSENT_GRANTED|CONSENT_DECLINED;
--     el recibo (RECEIPT_CREATED) y CONSENT_REVOKED los emitirán las funciones de H1-03;
--   * las transiciones de OTP, decisión y revocación NO se conceden a consent_app: serán funciones SECURITY DEFINER en H1-03.

-- Tablas -----------------------------------------------------------------------------------------------------------------------------
CREATE TABLE app.invitation (
  tenant_id            uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  invitation_ref       text        NOT NULL CONSTRAINT invitation_ref_len CHECK (pg_catalog.length(invitation_ref) BETWEEN 1 AND 100),
  -- Ref opaca acordada con LectorPro (SUPUESTO del plan); nunca RUT.
  student_ref          text        NOT NULL CONSTRAINT invitation_student_ref_len CHECK (pg_catalog.length(student_ref) BETWEEN 1 AND 100),
  student_first_name   text        NOT NULL CONSTRAINT invitation_first_name_len CHECK (pg_catalog.length(student_first_name) BETWEEN 1 AND 60),
  guardian_email       text        NOT NULL CONSTRAINT invitation_email_shape CHECK (
                         guardian_email = pg_catalog.lower(guardian_email) AND pg_catalog.length(guardian_email) <= 254
                         AND guardian_email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
  state                text        NOT NULL DEFAULT 'READY' CONSTRAINT invitation_state_enum CHECK (state IN ('READY', 'SENT', 'OPENED', 'VERIFIED', 'COMPLETED', 'DECLINED', 'CANCELLED')),
  -- Solo el hash SHA-256 del token persiste. token_consumed_at lo marca la decisión o el cierre, nunca el GET (F-RB-02).
  token_hash           char(64)    CONSTRAINT invitation_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  token_expires_at     timestamptz,
  token_consumed_at    timestamptz,
  consent_version      text        CONSTRAINT invitation_consent_version_len CHECK (pg_catalog.length(consent_version) BETWEEN 1 AND 100),
  import_batch_ref     text        CONSTRAINT invitation_batch_ref_len CHECK (pg_catalog.length(import_batch_ref) BETWEEN 1 AND 100),
  reissue_of_ref       text        CONSTRAINT invitation_reissue_len CHECK (pg_catalog.length(reissue_of_ref) BETWEEN 1 AND 100),
  created_at           timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT invitation_pkey PRIMARY KEY (tenant_id, invitation_ref),
  CONSTRAINT invitation_token_hash_unique UNIQUE (token_hash),
  CONSTRAINT invitation_token_pair CHECK ((token_hash IS NULL) = (token_expires_at IS NULL)),
  CONSTRAINT invitation_consumed_needs_token CHECK (token_consumed_at IS NULL OR token_hash IS NOT NULL)
);
-- Una invitación viva por student_ref (estados no terminales).
CREATE UNIQUE INDEX invitation_single_live_per_student_uq ON app.invitation (tenant_id, student_ref)
  WHERE state IN ('READY', 'SENT', 'OPENED', 'VERIFIED');

CREATE TABLE app.otp_challenge (
  tenant_id          uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  verification_ref   text        NOT NULL CONSTRAINT otp_ref_len CHECK (pg_catalog.length(verification_ref) BETWEEN 1 AND 100),
  scope              text        NOT NULL CONSTRAINT otp_scope_enum CHECK (scope IN ('DECISION', 'REVOCATION', 'MANAGE')),
  -- DECISION: invitation_ref; REVOCATION/MANAGE: ref opaca de la decisión. Nunca un correo.
  parent_ref         text        NOT NULL CONSTRAINT otp_parent_len CHECK (pg_catalog.length(parent_ref) BETWEEN 1 AND 255),
  -- HMAC-SHA256 hex del código; el código en claro nunca persiste. Lo compara verify_otp dentro de la BD (H1-03).
  code_hmac          char(64)    NOT NULL CONSTRAINT otp_code_hmac_shape CHECK (code_hmac ~ '^[0-9a-f]{64}$'),
  attempts           integer     NOT NULL DEFAULT 0 CONSTRAINT otp_attempts_nonneg CHECK (attempts >= 0),
  state              text        NOT NULL DEFAULT 'CODE_SENT' CONSTRAINT otp_state_enum CHECK (state IN ('CODE_SENT', 'VERIFIED', 'EXPIRED', 'LOCKED')),
  expires_at         timestamptz NOT NULL,
  consumed_at        timestamptz,
  decision_maker_ref text        CONSTRAINT otp_dm_ref_len CHECK (pg_catalog.length(decision_maker_ref) BETWEEN 1 AND 100),
  send_count         integer     NOT NULL DEFAULT 1 CONSTRAINT otp_send_count_pos CHECK (send_count >= 1),
  send_window_start  timestamptz NOT NULL DEFAULT pg_catalog.now(),
  last_sent_at       timestamptz NOT NULL DEFAULT pg_catalog.now(),
  created_at         timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT otp_challenge_pkey PRIMARY KEY (tenant_id, verification_ref),
  CONSTRAINT otp_verified_shape CHECK ((state = 'VERIFIED') = (consumed_at IS NOT NULL AND decision_maker_ref IS NOT NULL)),
  CONSTRAINT otp_send_window_order CHECK (send_window_start <= last_sent_at)
);
-- Un OTP vivo por (padre, scope): para DECISION, uno por invitación.
CREATE UNIQUE INDEX otp_single_live_uq ON app.otp_challenge (tenant_id, parent_ref, scope) WHERE state = 'CODE_SENT';

-- Presupuesto de fallos de OTP (P-04: 10 fallos / 24 h por clave HMAC). Lo escriben solo las funciones de H1-03.
CREATE TABLE app.otp_budget (
  tenant_id    uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  key_kind     text        NOT NULL CONSTRAINT otp_budget_key_kind_enum CHECK (key_kind IN ('CHANNEL', 'INVITATION')),
  key_hmac     char(64)    NOT NULL CONSTRAINT otp_budget_key_hmac_shape CHECK (key_hmac ~ '^[0-9a-f]{64}$'),
  window_start timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  failures     integer     NOT NULL DEFAULT 0 CONSTRAINT otp_budget_failures_nonneg CHECK (failures >= 0),
  CONSTRAINT otp_budget_pkey PRIMARY KEY (tenant_id, key_kind, key_hmac),
  CONSTRAINT otp_budget_window_order CHECK (expires_at > window_start)
);
CREATE INDEX otp_budget_expires_idx ON app.otp_budget (expires_at);

CREATE TABLE app.consent_decision (
  tenant_id             uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  consent_id            text        NOT NULL CONSTRAINT consent_decision_id_len CHECK (pg_catalog.length(consent_id) BETWEEN 1 AND 100),
  invitation_ref        text        NOT NULL,
  student_ref           text        NOT NULL CONSTRAINT consent_decision_student_len CHECK (pg_catalog.length(student_ref) BETWEEN 1 AND 100),
  decision_maker_ref    text        NOT NULL CONSTRAINT consent_decision_dm_len CHECK (pg_catalog.length(decision_maker_ref) BETWEEN 1 AND 100),
  verification_ref      text        NOT NULL,
  state                 text        NOT NULL CONSTRAINT consent_decision_state_enum CHECK (state IN ('GRANTED', 'DECLINED', 'REVOKED')),
  purposes              jsonb       NOT NULL CONSTRAINT consent_decision_purposes_array CHECK (pg_catalog.jsonb_typeof(purposes) = 'array'),
  consent_version       text        NOT NULL CONSTRAINT consent_decision_version_len CHECK (pg_catalog.length(consent_version) BETWEEN 1 AND 100),
  consent_text_sha256   char(64)    NOT NULL CONSTRAINT consent_decision_text_hash_shape CHECK (consent_text_sha256 ~ '^[0-9a-f]{64}$'),
  idempotency_key_hash  char(64)    NOT NULL CONSTRAINT consent_decision_idem_shape CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
  decided_at            timestamptz NOT NULL DEFAULT pg_catalog.now(),
  revoked_at            timestamptz,
  CONSTRAINT consent_decision_pkey PRIMARY KEY (tenant_id, consent_id),
  CONSTRAINT consent_decision_invitation_fk FOREIGN KEY (tenant_id, invitation_ref) REFERENCES app.invitation (tenant_id, invitation_ref),
  CONSTRAINT consent_decision_verification_fk FOREIGN KEY (tenant_id, verification_ref) REFERENCES app.otp_challenge (tenant_id, verification_ref),
  -- Una decisión por invitación; la clave de idempotencia es única.
  CONSTRAINT consent_decision_one_per_invitation UNIQUE (tenant_id, invitation_ref),
  CONSTRAINT consent_decision_idem_unique UNIQUE (tenant_id, idempotency_key_hash),
  CONSTRAINT consent_decision_revoked_shape CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);
-- A lo más una autorización vigente por estudiante.
CREATE UNIQUE INDEX consent_decision_one_granted_per_student_uq ON app.consent_decision (tenant_id, student_ref) WHERE state = 'GRANTED';

CREATE TABLE app.revocation (
  tenant_id             uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  revocation_ref        text        NOT NULL CONSTRAINT revocation_ref_len CHECK (pg_catalog.length(revocation_ref) BETWEEN 1 AND 100),
  consent_id            text        NOT NULL,
  verification_ref      text,
  via                   text        NOT NULL CONSTRAINT revocation_via_enum CHECK (via IN ('OTP_EMAIL', 'RECOVERY_LINK', 'ALT_PATH')),
  status                text        NOT NULL DEFAULT 'REQUESTED' CONSTRAINT revocation_status_enum CHECK (status IN ('REQUESTED', 'VERIFIED', 'WITHDRAWN', 'PENDING', 'APPLIED', 'HELD')),
  idempotency_key_hash  char(64)    NOT NULL CONSTRAINT revocation_idem_shape CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
  requested_at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  manifested_at         timestamptz,
  applied_at            timestamptz,
  attempts              integer     NOT NULL DEFAULT 0 CONSTRAINT revocation_attempts_nonneg CHECK (attempts >= 0),
  last_error_code       text        CONSTRAINT revocation_error_code_len CHECK (pg_catalog.length(last_error_code) BETWEEN 1 AND 60),
  CONSTRAINT revocation_pkey PRIMARY KEY (tenant_id, revocation_ref),
  CONSTRAINT revocation_consent_fk FOREIGN KEY (tenant_id, consent_id) REFERENCES app.consent_decision (tenant_id, consent_id),
  CONSTRAINT revocation_idem_unique UNIQUE (tenant_id, idempotency_key_hash),
  CONSTRAINT revocation_manifested_shape CHECK ((status IN ('PENDING', 'APPLIED', 'HELD')) = (manifested_at IS NOT NULL))
);
-- Una revocación efectiva por decisión (la autorización deja de valer desde que existe una en PENDING/APPLIED/HELD).
CREATE UNIQUE INDEX revocation_one_effective_per_consent_uq ON app.revocation (tenant_id, consent_id) WHERE status IN ('PENDING', 'APPLIED', 'HELD');

CREATE TABLE app.email_outbox (
  tenant_id           uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  email_id            uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  kind                text        NOT NULL CONSTRAINT email_outbox_kind_enum CHECK (kind IN ('INVITATION', 'DECISION_RECEIPT', 'REVOCATION_RECEIPT', 'RECOVERY_LINK', 'EMAIL_REPLACED_NOTICE', 'OPERATOR_ALERT')),
  -- El destinatario se resuelve al enviar desde la invitación: el correo no se copia aquí.
  invitation_ref      text        NOT NULL,
  dedupe_key          text        NOT NULL CONSTRAINT email_outbox_dedupe_len CHECK (pg_catalog.length(dedupe_key) BETWEEN 1 AND 200),
  status              text        NOT NULL DEFAULT 'PENDING' CONSTRAINT email_outbox_status_enum CHECK (status IN ('PENDING', 'SENDING', 'SENT', 'FAILED')),
  attempts            integer     NOT NULL DEFAULT 0 CONSTRAINT email_outbox_attempts_nonneg CHECK (attempts >= 0),
  next_attempt_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  provider_message_id text        CONSTRAINT email_outbox_msgid_len CHECK (pg_catalog.length(provider_message_id) BETWEEN 1 AND 255),
  last_error_code     text        CONSTRAINT email_outbox_error_len CHECK (pg_catalog.length(last_error_code) BETWEEN 1 AND 60),
  -- Sin token ni OTP ni correo: solo refs y parámetros de plantilla.
  payload             jsonb       NOT NULL DEFAULT '{}'::jsonb CONSTRAINT email_outbox_payload_object CHECK (pg_catalog.jsonb_typeof(payload) = 'object'),
  created_at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT email_outbox_pkey PRIMARY KEY (tenant_id, email_id),
  CONSTRAINT email_outbox_dedupe_unique UNIQUE (tenant_id, dedupe_key),
  CONSTRAINT email_outbox_invitation_fk FOREIGN KEY (tenant_id, invitation_ref) REFERENCES app.invitation (tenant_id, invitation_ref)
);
CREATE INDEX email_outbox_claimable_idx ON app.email_outbox (next_attempt_at) WHERE status IN ('PENDING', 'FAILED');

CREATE TABLE app.api_nonce (
  tenant_id uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  key_id    text        NOT NULL CONSTRAINT api_nonce_key_id_len CHECK (pg_catalog.length(key_id) BETWEEN 1 AND 40),
  nonce     text        NOT NULL CONSTRAINT api_nonce_len CHECK (pg_catalog.length(nonce) BETWEEN 8 AND 128),
  seen_at   timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT api_nonce_pkey PRIMARY KEY (tenant_id, key_id, nonce)
);
CREATE INDEX api_nonce_seen_idx ON app.api_nonce (seen_at);

CREATE TABLE app.api_access_log (
  tenant_id   uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  access_id   bigint      GENERATED ALWAYS AS IDENTITY,
  at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  key_id      text        CONSTRAINT api_access_key_id_len CHECK (pg_catalog.length(key_id) BETWEEN 1 AND 40),
  student_ref text        CONSTRAINT api_access_student_len CHECK (pg_catalog.length(student_ref) BETWEEN 1 AND 100),
  result      text        NOT NULL CONSTRAINT api_access_result_enum CHECK (result IN ('AUTHORIZED', 'NOT_AUTHORIZED', 'UNAUTHENTICATED', 'ERROR')),
  status_code smallint    NOT NULL CONSTRAINT api_access_status_range CHECK (status_code BETWEEN 100 AND 599),
  CONSTRAINT api_access_log_pkey PRIMARY KEY (tenant_id, access_id)
);

-- RLS FORCE con política por tenant_id (patrón de 0010/0006) -------------------------------------------------------------------------
DO $rls$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['invitation', 'otp_challenge', 'otp_budget', 'consent_decision', 'revocation', 'email_outbox', 'api_nonce', 'api_access_log'] LOOP
    EXECUTE pg_catalog.format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE pg_catalog.format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE pg_catalog.format('CREATE POLICY %I ON app.%I FOR ALL TO consent_app, consent_owner USING (tenant_id = app.current_tenant_id()) WITH CHECK (tenant_id = app.current_tenant_id())', t || '_tenant', t);
    EXECUTE pg_catalog.format('REVOKE ALL ON app.%I FROM PUBLIC', t);
  END LOOP;
END
$rls$;

-- Triggers del ledger: guard (INVOKER, valida la arista) + emit (SECURITY DEFINER del dueño, escribe el evento) ------------------------
-- Ambos ENABLE ALWAYS: disparan también para el dueño, el migrador y el superusuario.

-- Invitación. Grafo: READY>SENT; SENT>SENT (rotación de token); SENT>OPENED; OPENED>VERIFIED; VERIFIED>COMPLETED|DECLINED; no terminal>CANCELLED.
CREATE FUNCTION ledger_gen.guard_invitation() RETURNS trigger
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
    IF NEW.state <> 'READY' OR NEW.token_hash IS NOT NULL OR NEW.token_consumed_at IS NOT NULL OR NEW.consent_version IS NOT NULL THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.invitation_ref <> OLD.invitation_ref OR NEW.student_ref <> OLD.student_ref
     OR NEW.student_first_name <> OLD.student_first_name OR NEW.guardian_email <> OLD.guardian_email
     OR NEW.import_batch_ref IS DISTINCT FROM OLD.import_batch_ref OR NEW.reissue_of_ref IS DISTINCT FROM OLD.reissue_of_ref
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  v_pair := OLD.state || '>' || NEW.state;
  v_free := CASE v_pair
    WHEN 'READY>SENT' THEN ARRAY['state', 'token_hash', 'token_expires_at', 'consent_version']
    WHEN 'SENT>SENT' THEN ARRAY['token_hash', 'token_expires_at']
    WHEN 'SENT>OPENED' THEN ARRAY['state']
    WHEN 'OPENED>VERIFIED' THEN ARRAY['state']
    WHEN 'VERIFIED>COMPLETED' THEN ARRAY['state', 'token_consumed_at']
    WHEN 'VERIFIED>DECLINED' THEN ARRAY['state', 'token_consumed_at']
    WHEN 'READY>CANCELLED' THEN ARRAY['state']
    WHEN 'SENT>CANCELLED' THEN ARRAY['state']
    WHEN 'OPENED>CANCELLED' THEN ARRAY['state']
    WHEN 'VERIFIED>CANCELLED' THEN ARRAY['state']
    ELSE NULL END;
  IF v_free IS NULL THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF (pg_catalog.to_jsonb(NEW) - v_free) IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - v_free) THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF v_pair = 'READY>SENT' THEN
    IF NEW.token_hash IS NULL OR NEW.consent_version IS NULL THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'SENT>SENT' THEN
    -- Rotación: el token anterior queda muerto; el nuevo no puede estar consumido.
    IF NEW.token_hash IS NULL OR NEW.token_hash = OLD.token_hash OR NEW.token_consumed_at IS NOT NULL THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'SENT>OPENED' THEN
    IF NEW.token_expires_at <= pg_catalog.now() THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'OPENED>VERIFIED' THEN
    IF NOT EXISTS (SELECT 1 FROM app.otp_challenge o
                    WHERE o.tenant_id = NEW.tenant_id AND o.parent_ref = NEW.invitation_ref AND o.scope = 'DECISION' AND o.state = 'VERIFIED') THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
  ELSIF v_pair IN ('VERIFIED>COMPLETED', 'VERIFIED>DECLINED') THEN
    IF NEW.token_consumed_at IS NULL
       OR NOT EXISTS (SELECT 1 FROM app.consent_decision d
                       WHERE d.tenant_id = NEW.tenant_id AND d.invitation_ref = NEW.invitation_ref
                         AND d.state = CASE WHEN NEW.state = 'COMPLETED' THEN 'GRANTED' ELSE 'DECLINED' END) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

CREATE FUNCTION ledger_gen.emit_invitation() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_ref text := NEW.invitation_ref;
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_CREATED', 'HUMAN', 'OPERATOR',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'studentRef', NEW.student_ref, 'importBatchRef', NEW.import_batch_ref, 'reissueOfRef', NEW.reissue_of_ref), v_ref);
  ELSIF OLD.state = 'READY' AND NEW.state = 'SENT' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_SENT', 'HUMAN', 'OPERATOR',
      pg_catalog.jsonb_build_object('invitationRef', v_ref, 'consentVersion', NEW.consent_version,
        'expiresAt', pg_catalog.to_char(NEW.token_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')), v_ref || ':sent');
  ELSIF OLD.state = 'SENT' AND NEW.state = 'SENT' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_TOKEN_ROTATED', 'HUMAN', 'OPERATOR',
      pg_catalog.jsonb_build_object('invitationRef', v_ref,
        'expiresAt', pg_catalog.to_char(NEW.token_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')), v_ref || ':rotated:' || NEW.token_hash);
  ELSIF OLD.state = 'SENT' AND NEW.state = 'OPENED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_OPENED', 'HUMAN', 'UNVERIFIED_BEARER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref), v_ref || ':opened');
  ELSIF OLD.state = 'OPENED' AND NEW.state = 'VERIFIED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_VERIFIED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref), v_ref || ':verified');
  ELSIF OLD.state = 'VERIFIED' AND NEW.state IN ('COMPLETED', 'DECLINED') THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, CASE WHEN NEW.state = 'COMPLETED' THEN 'INVITATION_COMPLETED' ELSE 'INVITATION_DECLINED' END, 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('invitationRef', v_ref), v_ref || CASE WHEN NEW.state = 'COMPLETED' THEN ':completed' ELSE ':declined' END);
  ELSIF NEW.state = 'CANCELLED' AND OLD.state <> 'CANCELLED' THEN
    PERFORM ledger_gen.ledger_append('Invitation', v_ref, 'INVITATION_CANCELLED', 'HUMAN', 'OPERATOR',
      pg_catalog.jsonb_build_object('invitationRef', v_ref), v_ref || ':cancelled');
  END IF;
  RETURN NULL;
END
$fn$;

-- OTP. Grafo: CODE_SENT>CODE_SENT (intento fallido o reenvío, nunca ambos) | VERIFIED | LOCKED | EXPIRED; el resto es terminal.
-- VERIFIED exige now() < expires_at, attempts + 1, consumed_at y decision_maker_ref en esa misma transición. El máximo de intentos lo aplica verify_otp (H1-03).
CREATE FUNCTION ledger_gen.guard_otp() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_pair text;
  v_deny constant text := 'transicion no admitida por la derivacion del ledger';
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'CODE_SENT' OR NEW.attempts <> 0 OR NEW.consumed_at IS NOT NULL OR NEW.decision_maker_ref IS NOT NULL OR NEW.send_count <> 1 THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.verification_ref <> OLD.verification_ref OR NEW.scope <> OLD.scope OR NEW.parent_ref <> OLD.parent_ref
     OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  v_pair := OLD.state || '>' || NEW.state;
  IF v_pair NOT IN ('CODE_SENT>CODE_SENT', 'CODE_SENT>VERIFIED', 'CODE_SENT>LOCKED', 'CODE_SENT>EXPIRED') THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  IF v_pair IN ('CODE_SENT>VERIFIED', 'CODE_SENT>LOCKED') THEN
    IF NEW.attempts <> OLD.attempts + 1 THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  ELSIF v_pair = 'CODE_SENT>CODE_SENT' THEN
    IF NEW.code_hmac IS DISTINCT FROM OLD.code_hmac THEN
      -- Reenvío: no reinicia ni suma intentos; cuenta un envío.
      IF NEW.attempts <> OLD.attempts OR NEW.send_count <> OLD.send_count + 1 THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
    ELSE
      -- Intento fallido: un intento más; código y marcas de envío intactos.
      IF NEW.attempts <> OLD.attempts + 1 OR NEW.send_count <> OLD.send_count
         OR NEW.send_window_start <> OLD.send_window_start OR NEW.last_sent_at <> OLD.last_sent_at THEN
        RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
      END IF;
    END IF;
  ELSE
    IF NEW.attempts <> OLD.attempts THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  END IF;
  IF v_pair = 'CODE_SENT>VERIFIED' THEN
    IF pg_catalog.now() >= OLD.expires_at OR NEW.code_hmac <> OLD.code_hmac OR NEW.send_count <> OLD.send_count THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
  END IF;
  -- consumed_at y decision_maker_ref solo existen desde VERIFIED (lo refuerza también el CHECK otp_verified_shape).
  IF v_pair <> 'CODE_SENT>VERIFIED' AND (NEW.consumed_at IS NOT NULL OR NEW.decision_maker_ref IS NOT NULL) THEN
    RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE FUNCTION ledger_gen.emit_otp() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.state = 'CODE_SENT' AND NEW.state = 'VERIFIED' THEN
    PERFORM ledger_gen.ledger_append('DecisionMakerVerification', NEW.verification_ref, 'DECISION_MAKER_CHANNEL_VERIFIED', 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('verificationRef', NEW.verification_ref, 'parentRef', NEW.parent_ref, 'decisionMakerRef', NEW.decision_maker_ref,
        'scope', NEW.scope, 'method', 'EMAIL_OTP'), NEW.verification_ref || ':verified');
  ELSIF TG_OP = 'UPDATE' AND OLD.state = 'CODE_SENT' AND NEW.state = 'LOCKED' THEN
    PERFORM ledger_gen.ledger_append('DecisionMakerVerification', NEW.verification_ref, 'OTP_LOCKED', 'HUMAN', 'SYSTEM',
      pg_catalog.jsonb_build_object('verificationRef', NEW.verification_ref, 'parentRef', NEW.parent_ref, 'scope', NEW.scope), NEW.verification_ref || ':locked');
  END IF;
  RETURN NULL;
END
$fn$;

-- Decisión. INSERT solo GRANTED|DECLINED con la invitación VERIFIED y el OTP DECISION VERIFIED del mismo apoderado.
-- UPDATE solo GRANTED>REVOKED con una revocación PENDING/APPLIED de esa decisión.
CREATE FUNCTION ledger_gen.guard_consent_decision() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_deny constant text := 'transicion no admitida por la derivacion del ledger';
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM app.current_tenant_id() THEN RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state NOT IN ('GRANTED', 'DECLINED') OR NEW.revoked_at IS NOT NULL
       OR NOT EXISTS (SELECT 1 FROM app.invitation i
                       WHERE i.tenant_id = NEW.tenant_id AND i.invitation_ref = NEW.invitation_ref AND i.state = 'VERIFIED' AND i.student_ref = NEW.student_ref)
       OR NOT EXISTS (SELECT 1 FROM app.otp_challenge o
                       WHERE o.tenant_id = NEW.tenant_id AND o.verification_ref = NEW.verification_ref AND o.scope = 'DECISION'
                         AND o.parent_ref = NEW.invitation_ref AND o.state = 'VERIFIED' AND o.decision_maker_ref = NEW.decision_maker_ref) THEN
      RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF OLD.state = 'GRANTED' AND NEW.state = 'REVOKED'
     AND (pg_catalog.to_jsonb(NEW) - 'state' - 'revoked_at') IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'state' - 'revoked_at')
     AND EXISTS (SELECT 1 FROM app.revocation r
                  WHERE r.tenant_id = NEW.tenant_id AND r.consent_id = NEW.consent_id AND r.status IN ('PENDING', 'APPLIED')) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION '%', v_deny USING ERRCODE = '42501';
END
$fn$;

CREATE FUNCTION ledger_gen.emit_consent_decision() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM ledger_gen.ledger_append('ConsentDecision', NEW.consent_id,
      CASE WHEN NEW.state = 'GRANTED' THEN 'CONSENT_GRANTED' ELSE 'CONSENT_DECLINED' END, 'HUMAN', 'DECISION_MAKER',
      pg_catalog.jsonb_build_object('consentId', NEW.consent_id, 'invitationRef', NEW.invitation_ref, 'consentVersion', NEW.consent_version,
        'consentTextSha256', NEW.consent_text_sha256, 'purposes', NEW.purposes),
      NEW.consent_id || CASE WHEN NEW.state = 'GRANTED' THEN ':granted' ELSE ':declined' END);
  END IF;
  -- GRANTED>REVOKED no emite aquí: CONSENT_REVOKED lo escribe la función de revocación de H1-03 (TODO H1-03).
  RETURN NULL;
END
$fn$;

-- CREATE TRIGGER exige EXECUTE al creador (el dueño); el disparo no lo comprueba, así que consent_app no necesita ningún EXECUTE.
REVOKE ALL ON FUNCTION ledger_gen.guard_invitation(), ledger_gen.emit_invitation(), ledger_gen.guard_otp(), ledger_gen.emit_otp(),
  ledger_gen.guard_consent_decision(), ledger_gen.emit_consent_decision() FROM PUBLIC;

CREATE TRIGGER invitation_ledger_guard BEFORE INSERT OR UPDATE ON app.invitation FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_invitation();
CREATE TRIGGER invitation_ledger_emit AFTER INSERT OR UPDATE ON app.invitation FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_invitation();
CREATE TRIGGER otp_challenge_ledger_guard BEFORE INSERT OR UPDATE ON app.otp_challenge FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_otp();
CREATE TRIGGER otp_challenge_ledger_emit AFTER INSERT OR UPDATE ON app.otp_challenge FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_otp();
CREATE TRIGGER consent_decision_ledger_guard BEFORE INSERT OR UPDATE ON app.consent_decision FOR EACH ROW EXECUTE FUNCTION ledger_gen.guard_consent_decision();
CREATE TRIGGER consent_decision_ledger_emit AFTER INSERT OR UPDATE ON app.consent_decision FOR EACH ROW EXECUTE FUNCTION ledger_gen.emit_consent_decision();
ALTER TABLE app.invitation ENABLE ALWAYS TRIGGER invitation_ledger_guard;
ALTER TABLE app.invitation ENABLE ALWAYS TRIGGER invitation_ledger_emit;
ALTER TABLE app.otp_challenge ENABLE ALWAYS TRIGGER otp_challenge_ledger_guard;
ALTER TABLE app.otp_challenge ENABLE ALWAYS TRIGGER otp_challenge_ledger_emit;
ALTER TABLE app.consent_decision ENABLE ALWAYS TRIGGER consent_decision_ledger_guard;
ALTER TABLE app.consent_decision ENABLE ALWAYS TRIGGER consent_decision_ledger_emit;

-- Grants mínimos a consent_app -------------------------------------------------------------------------------------------------------
-- TODO H1-03: import_invitation / arm_invitation_token / open_invitation / issue_otp / verify_otp / record_decision / *_revocation / claim_emails /
-- record_api_nonce serán funciones SECURITY DEFINER (dueño consent_owner, EXECUTE solo para consent_app); entonces se retiran los INSERT/UPDATE directos de abajo.
GRANT SELECT ON app.invitation TO consent_app;
GRANT INSERT (invitation_ref, student_ref, student_first_name, guardian_email, import_batch_ref, reissue_of_ref) ON app.invitation TO consent_app; -- TODO H1-03: pasa a import_invitation()

-- Sin SELECT de code_hmac: el código jamás sale de la BD; lo compara verify_otp.
GRANT SELECT (tenant_id, verification_ref, scope, parent_ref, attempts, state, expires_at, consumed_at, decision_maker_ref, send_count, send_window_start, last_sent_at, created_at)
  ON app.otp_challenge TO consent_app;
-- Sin INSERT ni UPDATE sobre otp_challenge (state, code_hmac, attempts): TODO H1-03 issue_otp() / verify_otp().

-- Sin INSERT ni UPDATE sobre consent_decision ni revocation: TODO H1-03 record_decision() / request_revocation() / confirm_revocation() / apply_revocation().
GRANT SELECT ON app.consent_decision, app.revocation TO consent_app;

-- app.otp_budget: sin grants (solo las funciones de H1-03).

GRANT SELECT, INSERT (kind, invitation_ref, dedupe_key, payload, next_attempt_at) ON app.email_outbox TO consent_app;
GRANT UPDATE (status, attempts, next_attempt_at, provider_message_id, last_error_code) ON app.email_outbox TO consent_app; -- TODO H1-03: pasa a claim_emails()/mark_email_*()
GRANT SELECT ON app.email_outbox TO consent_app;

GRANT SELECT, INSERT (key_id, nonce) ON app.api_nonce TO consent_app; -- TODO H1-03: pasa a record_api_nonce()
GRANT SELECT ON app.api_nonce TO consent_app;
GRANT SELECT, INSERT (key_id, student_ref, result, status_code) ON app.api_access_log TO consent_app;
GRANT SELECT ON app.api_access_log TO consent_app;

-- Aserciones de privilegios (patrón de 0047:404-480): la migración aborta si el modelo de roles no se cumple ------------------------------
DO $assert$
DECLARE
  t text;
BEGIN
  IF pg_catalog.pg_has_role('consent_app', 'consent_owner', 'MEMBER') THEN RAISE EXCEPTION 'consent_app no puede ser miembro de consent_owner'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consent_app' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole)) THEN
    RAISE EXCEPTION 'consent_app tiene atributos de rol no permitidos';
  END IF;
  FOREACH t IN ARRAY ARRAY['integrity.audit_event'] LOOP
    IF pg_catalog.has_table_privilege('consent_app', t, 'UPDATE') OR pg_catalog.has_table_privilege('consent_app', t, 'DELETE')
       OR pg_catalog.has_table_privilege('consent_app', t, 'TRUNCATE') OR pg_catalog.has_table_privilege('consent_app', t, 'INSERT')
       OR pg_catalog.has_table_privilege('consent_owner', t, 'UPDATE') OR pg_catalog.has_table_privilege('consent_owner', t, 'DELETE')
       OR pg_catalog.has_table_privilege('consent_owner', t, 'TRUNCATE') THEN
      RAISE EXCEPTION 'privilegios indebidos sobre %', t;
    END IF;
  END LOOP;
  IF pg_catalog.has_table_privilege('consent_app', 'app.consent_decision', 'UPDATE') OR pg_catalog.has_table_privilege('consent_app', 'app.consent_decision', 'INSERT')
     OR pg_catalog.has_any_column_privilege('consent_app', 'app.otp_challenge', 'UPDATE')
     OR pg_catalog.has_column_privilege('consent_app', 'app.otp_challenge', 'code_hmac', 'SELECT') THEN
    RAISE EXCEPTION 'consent_app no puede escribir otp_challenge/consent_decision ni leer code_hmac';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class c ON c.oid = tg.tgrelid
              WHERE c.oid IN ('integrity.audit_event'::regclass, 'app.invitation'::regclass, 'app.otp_challenge'::regclass, 'app.consent_decision'::regclass, 'ops.db_catalog'::regclass)
                AND NOT tg.tgisinternal AND tg.tgenabled <> 'A') THEN
    RAISE EXCEPTION 'todos los triggers del ledger y del catalogo deben ser ENABLE ALWAYS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname IN ('app', 'integrity', 'ops', 'ledger_gen') AND c.relkind IN ('r', 'p', 'v', 'S', 'f') AND pg_catalog.pg_get_userbyid(c.relowner) <> 'consent_owner') THEN
    RAISE EXCEPTION 'todos los objetos deben pertenecer a consent_owner';
  END IF;
END
$assert$;
