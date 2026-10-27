-- Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-05/H1-07; SEC-CNS-024-V1 (verificación PR #121, V2 punto 5).
-- Decisión técnica del Supervisor: el enlace de gestión (/m/<token>) deja de ser un token firmado sin estado de 30 días y pasa a ser un secreto CON ESTADO en la base,
-- invalidable y rotable como el de invitación (P-10: 7 días; F-RB-02: abrir no consume).
--   1. ledger: se amplía la lista blanca de tipos de evento con MANAGE_LINK_ISSUED (espejo en src/ledger/ledger-event-types.ts).
--   2. app.manage_link (RLS FORCE, sin grants a consent_app ni consent_mailer: solo las funciones del dueño la tocan).
--   3. issue_manage_link (EXECUTE solo consent_mailer: devuelve el token en claro, una vez) / open_manage_link (EXECUTE consent_app: solo hash; no consume).
--   4. cancel_invitation (EXECUTE consent_app): "no es mi estudiante" -> CANCELLED con reasonCode en el ledger.
--   5. Cierre del P2 de la verificación: consent_app deja de insertar en app.email_outbox. El encolado vive en funciones del dueño: record_decision (recibo + enlace de
--      gestión), revoke_decision (recibo), enqueue_invitation_email (consent_app, solo la primera invitación) y request_invitation_resend (consent_mailer: reenvío de operador
--      con motivo). El worker solo rota el token de invitación por OUTBOX_RETRY o por un motivo escrito por esas funciones; la app ya no puede escribir el payload.
--   6. Los recibos llevan el payload completo (versión, fecha, finalidades, receiptRef): consent_mailer no lee consent_decision, así que el worker no los puede enriquecer.

-- 1. Lista blanca del ledger ---------------------------------------------------------------------------------------------------------
ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_event_type_allowlist;
ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_event_type_allowlist CHECK (event_type IN (
  'INVITATION_CREATED', 'INVITATION_SENT', 'INVITATION_TOKEN_ROTATED', 'INVITATION_LINK_REISSUED', 'INVITATION_OPENED', 'INVITATION_VERIFIED',
  'INVITATION_COMPLETED', 'INVITATION_DECLINED', 'INVITATION_CANCELLED',
  'DECISION_MAKER_CHANNEL_VERIFIED', 'OTP_LOCKED',
  'CONSENT_GRANTED', 'CONSENT_DECLINED', 'RECEIPT_CREATED', 'CONSENT_REVOKED',
  'REVOCATION_REQUESTED', 'REVOCATION_VERIFIED', 'REVOCATION_CONFIRMED', 'REVOCATION_APPLIED', 'REVOCATION_HELD',
  'MANAGE_LINK_ISSUED'
));

-- 2. Tabla del enlace de gestión -----------------------------------------------------------------------------------------------------
CREATE TABLE app.manage_link (
  tenant_id           uuid        NOT NULL DEFAULT app.current_tenant_id() REFERENCES app.school (tenant_id),
  manage_link_id      uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  consent_decision_id text        NOT NULL,
  -- sha256 del token (32 bytes). El token en claro nunca persiste: lo genera issue_manage_link y se devuelve una vez al worker.
  token_hash          bytea       NOT NULL CONSTRAINT manage_link_token_hash_len CHECK (pg_catalog.length(token_hash) = 32),
  expires_at          timestamptz NOT NULL,
  consumed_at         timestamptz,
  revoked_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT manage_link_pkey PRIMARY KEY (tenant_id, manage_link_id),
  CONSTRAINT manage_link_token_hash_unique UNIQUE (token_hash),
  CONSTRAINT manage_link_decision_fk FOREIGN KEY (tenant_id, consent_decision_id) REFERENCES app.consent_decision (tenant_id, consent_id),
  CONSTRAINT manage_link_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE INDEX manage_link_live_idx ON app.manage_link (tenant_id, consent_decision_id) WHERE consumed_at IS NULL AND revoked_at IS NULL;
ALTER TABLE app.manage_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.manage_link FORCE ROW LEVEL SECURITY;
CREATE POLICY manage_link_tenant ON app.manage_link FOR ALL TO consent_owner USING (tenant_id = app.current_tenant_id()) WITH CHECK (tenant_id = app.current_tenant_id());
REVOKE ALL ON app.manage_link FROM PUBLIC;

-- 3. Funciones reemplazadas (misma firma y mismos grants; CREATE OR REPLACE conserva el ACL de 0003/0002) ----------------------------------

-- record_decision: recibo con payload completo + encolado del enlace de gestión en la misma tx.
CREATE OR REPLACE FUNCTION app.record_decision(p_invitation_ref text, p_verification_ref text, p_outcome text, p_consent_version text, p_consent_text_hash text,
                                    p_idempotency_key text, p_purposes jsonb DEFAULT '[]'::jsonb)
  RETURNS TABLE (consent_id text, state text, deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_window constant interval := interval '10 minutes';
  v_tenant uuid := app.current_tenant_id();
  v_idem text;
  v_inv app.invitation%ROWTYPE;
  v_ch app.otp_challenge%ROWTYPE;
  v_dec app.consent_decision%ROWTYPE;
  v_id text := 'con-' || pg_catalog.gen_random_uuid()::text;
BEGIN
  IF p_outcome NOT IN ('GRANTED', 'DECLINED') THEN RAISE EXCEPTION 'INVALID_OUTCOME'; END IF;
  -- F-SB-05: purposes entra al ledger inmutable. Solo un arreglo (sin duplicados) de códigos de la lista cerrada de beta/src/mail/guest-purposes.ts; cualquier otro tipo se rechaza.
  IF p_purposes IS NULL OR pg_catalog.jsonb_typeof(p_purposes) <> 'array' OR pg_catalog.jsonb_array_length(p_purposes) > 4
     OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_purposes) e
                 WHERE pg_catalog.jsonb_typeof(e) <> 'string' OR (e #>> '{}') NOT IN ('STUDY_PARTICIPATION', 'AUDIO_RECORDING', 'AUTOMATED_ANALYSIS', 'HUMAN_REVIEW'))
     OR (SELECT pg_catalog.count(DISTINCT e) FROM pg_catalog.jsonb_array_elements(p_purposes) e) <> pg_catalog.jsonb_array_length(p_purposes) THEN
    RAISE EXCEPTION 'INVALID_PURPOSES';
  END IF;
  IF p_consent_version IS NULL OR p_consent_version !~ '^[A-Za-z0-9_.-]{1,64}$' THEN RAISE EXCEPTION 'INVALID_CONSENT_VERSION'; END IF;
  IF p_idempotency_key IS NULL OR pg_catalog.length(p_idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'INVALID_IDEMPOTENCY_KEY'; END IF;
  v_idem := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_idempotency_key, 'UTF8')), 'hex');

  SELECT * INTO v_inv FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVITATION_NOT_FOUND'; END IF;

  SELECT * INTO v_dec FROM app.consent_decision d WHERE d.tenant_id = v_tenant AND d.invitation_ref = p_invitation_ref;
  IF FOUND THEN
    IF v_dec.idempotency_key_hash = v_idem THEN RETURN QUERY SELECT v_dec.consent_id, v_dec.state, true; RETURN; END IF;
    RAISE EXCEPTION 'ALREADY_DECIDED';
  END IF;
  IF EXISTS (SELECT 1 FROM app.consent_decision d WHERE d.tenant_id = v_tenant AND d.idempotency_key_hash = v_idem) THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED'; END IF;

  SELECT * INTO v_ch FROM app.otp_challenge o
   WHERE o.tenant_id = v_tenant AND o.verification_ref = p_verification_ref AND o.scope = 'DECISION' AND o.parent_ref = p_invitation_ref AND o.state = 'VERIFIED'
     AND o.consumed_at > pg_catalog.now() - c_window FOR UPDATE;
  IF NOT FOUND OR v_inv.state <> 'VERIFIED' OR v_inv.token_consumed_at IS NOT NULL OR v_inv.token_expires_at IS NULL THEN RAISE EXCEPTION 'VERIFICATION_REQUIRED'; END IF;

  INSERT INTO app.consent_decision (consent_id, invitation_ref, student_ref, decision_maker_ref, verification_ref, state, purposes, consent_version, consent_text_sha256, idempotency_key_hash)
  VALUES (v_id, p_invitation_ref, v_inv.student_ref, v_ch.decision_maker_ref, p_verification_ref, p_outcome, p_purposes, p_consent_version, p_consent_text_hash, v_idem); -- emite CONSENT_GRANTED|DECLINED
  UPDATE app.invitation SET state = CASE WHEN p_outcome = 'GRANTED' THEN 'COMPLETED' ELSE 'DECLINED' END, token_consumed_at = pg_catalog.now()
   WHERE tenant_id = v_tenant AND invitation_ref = p_invitation_ref; -- emite INVITATION_COMPLETED|DECLINED
  INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
  VALUES ('DECISION_RECEIPT', p_invitation_ref, 'receipt:' || v_id, pg_catalog.jsonb_build_object('consentId', v_id, 'outcome', p_outcome, 'decision', p_outcome,
    'consentVersion', p_consent_version, 'decidedAt', pg_catalog.to_char(pg_catalog.now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'receiptRef', 'rcp-' || pg_catalog.substr(pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_id, 'UTF8')), 'hex'), 1, 24),
    'purposes', (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('purpose', u.p, 'choice', CASE WHEN pg_catalog.jsonb_exists(p_purposes, u.p) THEN 'GRANT' ELSE 'DECLINE' END) ORDER BY u.ord)
                  FROM pg_catalog.unnest(ARRAY['STUDY_PARTICIPATION', 'AUDIO_RECORDING', 'AUTOMATED_ANALYSIS', 'HUMAN_REVIEW']) WITH ORDINALITY AS u(p, ord)))); -- payload completo: consent_mailer no lee consent_decision, así que el recibo no se "enriquece" en el worker
  IF p_outcome = 'GRANTED' THEN
    -- Enlace de gestión: se encola en la MISMA tx que la decisión (si el proceso muere después, la fila ya existe). Sin token: lo emite el worker con issue_manage_link.
    INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
    VALUES ('RECOVERY_LINK', p_invitation_ref, 'mgmt-link:' || v_id, pg_catalog.jsonb_build_object('consentId', v_id, 'purpose', 'MANAGE'));
  END IF;
  RETURN QUERY SELECT v_id, p_outcome, false;
END
$fn$;

-- revoke_decision: consume los enlaces de gestión de la decisión; recibo con payload completo.
CREATE OR REPLACE FUNCTION app.revoke_decision(p_consent_id text, p_verification_ref text, p_idempotency_key text)
  RETURNS TABLE (revocation_ref text, deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_window constant interval := interval '10 minutes';
  v_tenant uuid := app.current_tenant_id();
  v_idem text;
  v_dec app.consent_decision%ROWTYPE;
  v_rev app.revocation%ROWTYPE;
  v_ch app.otp_challenge%ROWTYPE;
  v_ref text := 'rev-' || pg_catalog.gen_random_uuid()::text;
BEGIN
  IF p_idempotency_key IS NULL OR pg_catalog.length(p_idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'INVALID_IDEMPOTENCY_KEY'; END IF;
  v_idem := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_idempotency_key, 'UTF8')), 'hex');

  SELECT * INTO v_dec FROM app.consent_decision d WHERE d.tenant_id = v_tenant AND d.consent_id = p_consent_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'DECISION_NOT_FOUND'; END IF;

  SELECT * INTO v_rev FROM app.revocation r WHERE r.tenant_id = v_tenant AND r.idempotency_key_hash = v_idem;
  IF FOUND THEN
    IF v_rev.consent_id = p_consent_id THEN RETURN QUERY SELECT v_rev.revocation_ref, true; RETURN; END IF;
    RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED';
  END IF;
  IF v_dec.state = 'DECLINED' THEN RAISE EXCEPTION 'NOT_REVOCABLE_DECLINED'; END IF;
  IF v_dec.state = 'REVOKED' THEN RAISE EXCEPTION 'ALREADY_REVOKED'; END IF;

  SELECT * INTO v_ch FROM app.otp_challenge o
   WHERE o.tenant_id = v_tenant AND o.verification_ref = p_verification_ref AND o.scope IN ('REVOCATION', 'MANAGE') AND o.parent_ref = p_consent_id
     AND o.state = 'VERIFIED' AND o.decision_maker_ref = v_dec.decision_maker_ref AND o.consumed_at > pg_catalog.now() - c_window FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'VERIFICATION_REQUIRED'; END IF;

  INSERT INTO app.revocation (revocation_ref, consent_id, verification_ref, via, status, idempotency_key_hash, manifested_at, applied_at)
  VALUES (v_ref, p_consent_id, p_verification_ref, 'OTP_EMAIL', 'APPLIED', v_idem, pg_catalog.now(), pg_catalog.now());
  UPDATE app.consent_decision SET state = 'REVOKED', revoked_at = pg_catalog.now() WHERE tenant_id = v_tenant AND consent_id = p_consent_id;
  -- Los enlaces de gestión de la decisión quedan consumidos (siguen resolviendo solo para mostrar "ya revocado", ver open_manage_link).
  UPDATE app.manage_link SET consumed_at = pg_catalog.now() WHERE tenant_id = v_tenant AND consent_decision_id = p_consent_id AND consumed_at IS NULL AND revoked_at IS NULL;
  PERFORM ledger_gen.ledger_append('ConsentDecision', p_consent_id, 'CONSENT_REVOKED', 'HUMAN', 'DECISION_MAKER',
    pg_catalog.jsonb_build_object('consentId', p_consent_id, 'revocationRef', v_ref), p_consent_id || ':revoked');
  INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
  VALUES ('REVOCATION_RECEIPT', v_dec.invitation_ref, 'receipt-rev:' || p_consent_id, pg_catalog.jsonb_build_object('consentId', p_consent_id, 'revocationRef', v_ref, 'decision', 'REVOKED',
    'consentVersion', v_dec.consent_version, 'decidedAt', pg_catalog.to_char(pg_catalog.now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'receiptRef', v_ref, 'purposes', (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('purpose', u.p, 'choice', CASE WHEN pg_catalog.jsonb_exists(v_dec.purposes, u.p) THEN 'GRANT' ELSE 'DECLINE' END) ORDER BY u.ord)
                  FROM pg_catalog.unnest(ARRAY['STUDY_PARTICIPATION', 'AUDIO_RECORDING', 'AUTOMATED_ANALYSIS', 'HUMAN_REVIEW']) WITH ORDINALITY AS u(p, ord))));
  RETURN QUERY SELECT v_ref, false;
END
$fn$;

-- emit_invitation: INVITATION_CANCELLED lleva reasonCode cuando cancel_invitation lo fija (GUC local a la transacción); sin él, payload idéntico al de 0002.
CREATE OR REPLACE FUNCTION ledger_gen.emit_invitation() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_ref text := NEW.invitation_ref;
  v_reason text := NULLIF(pg_catalog.current_setting('app.cancel_reason', true), '');
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
      CASE WHEN v_reason IS NULL THEN pg_catalog.jsonb_build_object('invitationRef', v_ref)
           ELSE pg_catalog.jsonb_build_object('invitationRef', v_ref, 'reasonCode', v_reason) END, v_ref || ':cancelled');
  END IF;
  RETURN NULL;
END
$fn$;

-- 4. Funciones nuevas ----------------------------------------------------------------------------------------------------------------

-- issue_manage_link: SOLO consent_mailer. Decisión GRANTED; genera el token (CSPRNG de pgcrypto, 32 bytes, base64url sin relleno), guarda su sha256, vigencia 7 días (P-10),
-- invalida (revoked_at) los enlaces vigentes anteriores de la misma decisión y emite MANAGE_LINK_ISSUED (sin token ni hash en el payload). Devuelve el token en claro una vez.
CREATE FUNCTION app.issue_manage_link(p_consent_decision_id text)
  RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_ttl constant interval := interval '7 days'; -- P-10
  v_tenant uuid := app.current_tenant_id();
  v_state text;
  v_id uuid := pg_catalog.gen_random_uuid();
  v_token text;
  v_expires timestamptz := pg_catalog.now() + c_ttl;
BEGIN
  SELECT d.state INTO v_state FROM app.consent_decision d WHERE d.tenant_id = v_tenant AND d.consent_id = p_consent_decision_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'DECISION_NOT_FOUND'; END IF;
  IF v_state <> 'GRANTED' THEN RAISE EXCEPTION 'DECISION_NOT_GRANTED'; END IF;
  v_token := pg_catalog.translate(pg_catalog.rtrim(pg_catalog.encode(ext.gen_random_bytes(32), 'base64'), '='), '+/', '-_');
  UPDATE app.manage_link SET revoked_at = pg_catalog.now()
   WHERE tenant_id = v_tenant AND consent_decision_id = p_consent_decision_id AND consumed_at IS NULL AND revoked_at IS NULL;
  INSERT INTO app.manage_link (manage_link_id, consent_decision_id, token_hash, expires_at)
  VALUES (v_id, p_consent_decision_id, pg_catalog.sha256(pg_catalog.convert_to(v_token, 'UTF8')), v_expires);
  PERFORM ledger_gen.ledger_append('ConsentDecision', p_consent_decision_id, 'MANAGE_LINK_ISSUED', 'HUMAN', 'SYSTEM',
    pg_catalog.jsonb_build_object('consentId', p_consent_decision_id, 'manageLinkId', v_id::text,
      'expiresAt', pg_catalog.to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
    p_consent_decision_id || ':manage-link:' || v_id::text);
  RETURN v_token;
END
$fn$;

-- open_manage_link: consent_app. Recibe SOLO el hash. Devuelve refs opacas si el enlace no está invalidado ni vencido y la decisión sigue GRANTED; si la decisión ya está
-- REVOKED devuelve state = 'REVOKED' (la UI muestra "ya revocado"; el enlace consumido por la revocación sigue resolviendo solo para eso). No consume (F-RB-02).
CREATE FUNCTION app.open_manage_link(p_token_hash bytea)
  RETURNS TABLE (consent_id text, invitation_ref text, state text)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_dec_id text;
  v_inv text;
  v_state text;
  v_consumed timestamptz;
BEGIN
  SELECT l.consent_decision_id, d.invitation_ref, d.state, l.consumed_at INTO v_dec_id, v_inv, v_state, v_consumed
    FROM app.manage_link l JOIN app.consent_decision d ON d.tenant_id = l.tenant_id AND d.consent_id = l.consent_decision_id
   WHERE l.tenant_id = v_tenant AND l.token_hash = p_token_hash AND l.revoked_at IS NULL AND l.expires_at > pg_catalog.now();
  IF NOT FOUND THEN RETURN; END IF;
  IF (v_state = 'GRANTED' AND v_consumed IS NULL) OR v_state = 'REVOKED' THEN
    RETURN QUERY SELECT v_dec_id, v_inv, v_state;
  END IF;
END
$fn$;

-- cancel_invitation: "no es mi estudiante" (SUBJECT_MISMATCH_REPORTED). Decisión técnica (más simple compatible con la SPA): la base acepta OPENED o VERIFIED (el contrato dice VERIFIED,
-- pero la SPA lo declara también antes del OTP y la sesión HTTP ya exige OTP verificado); la ligadura con el decisionMakerRef de GRD-IV-10 NO se aplica aquí (consent_app no lo lee) y
-- queda como desviación. Idempotente: ya CANCELLED => no hace nada. reason_code cerrado (sin texto libre) y queda en el payload de INVITATION_CANCELLED. No toca ninguna decisión.
CREATE FUNCTION app.cancel_invitation(p_invitation_ref text, p_reason_code text)
  RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_state text;
BEGIN
  IF p_reason_code IS NULL OR p_reason_code NOT IN ('SUBJECT_MISMATCH_REPORTED') THEN RAISE EXCEPTION 'INVALID_REASON_CODE'; END IF;
  SELECT i.state INTO v_state FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVITATION_NOT_FOUND'; END IF;
  IF v_state = 'CANCELLED' THEN RETURN; END IF;
  IF v_state NOT IN ('OPENED', 'VERIFIED') THEN RAISE EXCEPTION 'INVITATION_NOT_CANCELLABLE'; END IF;
  PERFORM pg_catalog.set_config('app.cancel_reason', p_reason_code, true);
  UPDATE app.invitation SET state = 'CANCELLED' WHERE tenant_id = v_tenant AND invitation_ref = p_invitation_ref; -- emite INVITATION_CANCELLED con reasonCode
  PERFORM pg_catalog.set_config('app.cancel_reason', '', true);
END
$fn$;

-- enqueue_invitation_email: consent_app (el CLI de H1-09 "send"). Encola UNA fila INVITATION por invitación (dedupe) con la versión de consentimiento; solo READY|SENT. Nunca lleva
-- motivo de reemisión: el worker no puede rotar un token vigente por esta vía (TOKEN_STILL_VALID => FAILED).
CREATE FUNCTION app.enqueue_invitation_email(p_invitation_ref text, p_consent_version text)
  RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_state text;
BEGIN
  IF p_consent_version IS NULL OR p_consent_version !~ '^[A-Za-z0-9_.-]{1,64}$' THEN RAISE EXCEPTION 'INVALID_CONSENT_VERSION'; END IF;
  SELECT i.state INTO v_state FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVITATION_NOT_FOUND'; END IF;
  IF v_state NOT IN ('READY', 'SENT') THEN RAISE EXCEPTION 'INVITATION_NOT_ARMABLE'; END IF;
  INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
  VALUES ('INVITATION', p_invitation_ref, 'invitation:' || p_invitation_ref, pg_catalog.jsonb_build_object('consentVersion', p_consent_version))
  ON CONFLICT (tenant_id, dedupe_key) DO NOTHING;
  RETURN FOUND;
END
$fn$;

-- request_invitation_resend: SOLO consent_mailer (comando de operador, H1-09). Encola un reenvío CON motivo (queda en el ledger como INVITATION_LINK_REISSUED al rotar el token).
-- El motivo solo puede salir de aquí: la app no escribe el payload del outbox.
CREATE FUNCTION app.request_invitation_resend(p_invitation_ref text, p_reason text)
  RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_state text;
  v_version text;
BEGIN
  IF p_reason IS NULL OR p_reason !~ '^[A-Z][A-Z0-9_]{2,39}$' THEN RAISE EXCEPTION 'INVALID_REISSUE_REASON'; END IF;
  SELECT i.state, i.consent_version INTO v_state, v_version FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_invitation_ref;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVITATION_NOT_FOUND'; END IF;
  IF v_state <> 'SENT' OR v_version IS NULL THEN RAISE EXCEPTION 'INVITATION_NOT_ARMABLE'; END IF;
  INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
  VALUES ('INVITATION', p_invitation_ref, 'invitation-resend:' || p_invitation_ref || ':' || pg_catalog.gen_random_uuid()::text,
          pg_catalog.jsonb_build_object('consentVersion', v_version, 'reissueReason', p_reason));
END
$fn$;

REVOKE ALL ON FUNCTION app.issue_manage_link(text), app.open_manage_link(bytea), app.cancel_invitation(text, text), app.enqueue_invitation_email(text, text),
  app.request_invitation_resend(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.open_manage_link(bytea), app.cancel_invitation(text, text), app.enqueue_invitation_email(text, text) TO consent_app;
GRANT EXECUTE ON FUNCTION app.issue_manage_link(text), app.request_invitation_resend(text, text) TO consent_mailer;

-- 5. consent_app deja de insertar en el outbox (P2 de la verificación): el INSERT directo era un canal para forzar rotaciones y reenvíos. -------------------
REVOKE INSERT ON app.email_outbox FROM consent_app; -- revoca también los privilegios por columna

-- 6. Tabla de verdad (se suma a la de 0003) -------------------------------------------------------------------------------------------------------------
DO $truth$
DECLARE
  r record;
  v boolean;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    ('consent_app', 'app.manage_link', 'SELECT', false), ('consent_app', 'app.manage_link', 'INSERT', false), ('consent_app', 'app.manage_link', 'UPDATE', false),
    ('consent_app', 'app.manage_link', 'DELETE', false), ('consent_app', 'app.manage_link', 'TRUNCATE', false),
    ('consent_mailer', 'app.manage_link', 'SELECT', false), ('consent_mailer', 'app.manage_link', 'INSERT', false), ('consent_mailer', 'app.manage_link', 'UPDATE', false),
    ('consent_mailer', 'app.manage_link', 'DELETE', false), ('consent_mailer', 'app.manage_link', 'TRUNCATE', false),
    ('consent_app', 'app.email_outbox', 'INSERT', false), ('consent_app', 'app.email_outbox', 'SELECT', true), ('consent_app', 'app.email_outbox', 'UPDATE', false),
    ('consent_mailer', 'app.email_outbox', 'INSERT', false)
  ) AS t(rol, obj, priv, expected) LOOP
    v := pg_catalog.has_table_privilege(r.rol, r.obj, r.priv);
    IF v IS DISTINCT FROM r.expected THEN RAISE EXCEPTION 'tabla de verdad 0004: % % % = % (esperado %)', r.rol, r.obj, r.priv, v, r.expected; END IF;
  END LOOP;
  IF pg_catalog.has_any_column_privilege('consent_app', 'app.manage_link', 'SELECT') OR pg_catalog.has_any_column_privilege('consent_app', 'app.manage_link', 'INSERT')
     OR pg_catalog.has_any_column_privilege('consent_app', 'app.manage_link', 'UPDATE') OR pg_catalog.has_any_column_privilege('consent_mailer', 'app.manage_link', 'SELECT')
     OR pg_catalog.has_any_column_privilege('consent_mailer', 'app.manage_link', 'INSERT') OR pg_catalog.has_any_column_privilege('consent_mailer', 'app.manage_link', 'UPDATE') THEN
    RAISE EXCEPTION 'tabla de verdad 0004: ni consent_app ni consent_mailer tocan app.manage_link (ni por columnas)';
  END IF;
  IF pg_catalog.has_any_column_privilege('consent_app', 'app.email_outbox', 'INSERT') OR pg_catalog.has_any_column_privilege('consent_app', 'app.email_outbox', 'UPDATE')
     OR pg_catalog.has_any_column_privilege('consent_mailer', 'app.email_outbox', 'INSERT') THEN
    RAISE EXCEPTION 'tabla de verdad 0004: consent_app no inserta ni actualiza el outbox (ni por columnas); consent_mailer solo actualiza marcas';
  END IF;
  -- Todas las funciones de app/ledger_gen/ops/integrity: dueño consent_owner y no ejecutables por PUBLIC (misma regla de 0003, ahora con las funciones nuevas).
  FOR r IN SELECT p.oid, p.oid::regprocedure::text AS sig FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname IN ('app', 'ledger_gen', 'ops', 'integrity') AND p.prokind = 'f' LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p2, pg_catalog.aclexplode(COALESCE(p2.proacl, pg_catalog.acldefault('f', p2.proowner))) a WHERE p2.oid = r.oid AND a.grantee = 0) THEN
      RAISE EXCEPTION 'tabla de verdad 0004: % es ejecutable por PUBLIC', r.sig;
    END IF;
    IF pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid = r.oid)) <> 'consent_owner' THEN RAISE EXCEPTION 'tabla de verdad 0004: % no es de consent_owner', r.sig; END IF;
  END LOOP;
  FOR r IN SELECT * FROM (VALUES
    -- función, EXECUTE de consent_app, EXECUTE de consent_mailer
    ('app.issue_manage_link(text)', false, true), ('app.request_invitation_resend(text,text)', false, true),
    ('app.open_manage_link(bytea)', true, false), ('app.cancel_invitation(text,text)', true, false), ('app.enqueue_invitation_email(text,text)', true, false),
    -- las reemplazadas conservan su ACL
    ('app.record_decision(text,text,text,text,text,text,jsonb)', true, false), ('app.revoke_decision(text,text,text)', true, false),
    ('app.issue_otp(text,text)', false, true), ('app.arm_invitation_token(text,text,timestamptz,text,text)', false, true), ('ledger_gen.emit_invitation()', false, false)
  ) AS t(fn, app_expected, mailer_expected) LOOP
    IF pg_catalog.has_function_privilege('consent_app', r.fn, 'EXECUTE') IS DISTINCT FROM r.app_expected THEN RAISE EXCEPTION 'tabla de verdad 0004: EXECUTE de consent_app sobre % (esperado %)', r.fn, r.app_expected; END IF;
    IF pg_catalog.has_function_privilege('consent_mailer', r.fn, 'EXECUTE') IS DISTINCT FROM r.mailer_expected THEN RAISE EXCEPTION 'tabla de verdad 0004: EXECUTE de consent_mailer sobre % (esperado %)', r.fn, r.mailer_expected; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'app' AND p.prokind = 'f' AND p.proname <> 'current_tenant_id' AND (NOT p.prosecdef OR p.proconfig IS NULL OR NOT ('search_path=pg_catalog, pg_temp' = ANY (p.proconfig)))) THEN
    RAISE EXCEPTION 'tabla de verdad 0004: toda función de app debe ser SECURITY DEFINER con search_path fijo';
  END IF;
END
$truth$;
