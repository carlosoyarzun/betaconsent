-- Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-03 (rebuild-plan.md §3 "funciones").
-- origen (lógica adaptada a UN dueño, sin RH2 ni HELD): db/migrations/0037_adr010_case_state_revocation.sql:286-413,594-644@9345b78;
-- parámetros OTP de src/server/modules/common/approved-parameters.ts:39-72@9345b78 (espejo en beta/src/otp/approved-parameters.ts).
--
-- Funciones SECURITY DEFINER (dueño consent_owner, search_path fijo, EXECUTE solo para consent_app). Son la ÚNICA vía de escritura de consent_app sobre
-- invitation, otp_challenge, otp_budget, consent_decision y revocation: la verificación del OTP y la decisión viven en la base (cierra RES-OTP-WEB-PRB).
-- Las fallas "esperables" de verify_otp NO lanzan excepción (revertiría el conteo de intentos): devuelven un código. Las demás lanzan SQLSTATE P0001 con
-- un mensaje estable (ALREADY_DECIDED, VERIFICATION_REQUIRED, ...).
-- Los eventos los emiten los triggers de 0002 (INVITATION_*, OTP verificado/LOCKED, CONSENT_GRANTED|DECLINED) y revoke_decision (CONSENT_REVOKED).

-- 0. Importación y armado del token (el CLI de H1-09 y el outbox de H1-06 los usan; sin ellos no habría cómo crear invitaciones al retirar el INSERT) ----------
CREATE FUNCTION app.import_invitation(p_student_ref text, p_first_name text, p_email text, p_batch_ref text)
  RETURNS TABLE (invitation_ref text, created boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_ref text := 'inv-' || pg_catalog.gen_random_uuid()::text;
BEGIN
  INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email, import_batch_ref)
  VALUES (v_ref, p_student_ref, p_first_name, p_email, p_batch_ref)
  ON CONFLICT (tenant_id, student_ref) WHERE state IN ('READY', 'SENT', 'OPENED', 'VERIFIED') DO NOTHING;
  IF FOUND THEN
    RETURN QUERY SELECT v_ref, true;
  ELSE
    -- Reimport idempotente: devuelve la invitación viva existente.
    RETURN QUERY SELECT i.invitation_ref, false FROM app.invitation i
      WHERE i.tenant_id = app.current_tenant_id() AND i.student_ref = p_student_ref AND i.state IN ('READY', 'SENT', 'OPENED', 'VERIFIED');
  END IF;
END
$fn$;

-- READY>SENT (primer token) o SENT>SENT (rotación: el token anterior queda muerto). El hash lo calcula el llamador; el token en claro nunca llega a la base.
CREATE FUNCTION app.arm_invitation_token(p_invitation_ref text, p_token_hash text, p_expires_at timestamptz, p_consent_version text)
  RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_state text;
BEGIN
  SELECT i.state INTO v_state FROM app.invitation i WHERE i.tenant_id = app.current_tenant_id() AND i.invitation_ref = p_invitation_ref FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVITATION_NOT_FOUND'; END IF;
  IF p_expires_at <= pg_catalog.now() THEN RAISE EXCEPTION 'TOKEN_EXPIRY_IN_PAST'; END IF;
  IF v_state = 'READY' THEN
    UPDATE app.invitation SET state = 'SENT', token_hash = p_token_hash, token_expires_at = p_expires_at, consent_version = p_consent_version
     WHERE tenant_id = app.current_tenant_id() AND invitation_ref = p_invitation_ref;
  ELSIF v_state = 'SENT' THEN
    UPDATE app.invitation SET token_hash = p_token_hash, token_expires_at = p_expires_at
     WHERE tenant_id = app.current_tenant_id() AND invitation_ref = p_invitation_ref;
  ELSE
    RAISE EXCEPTION 'INVITATION_NOT_ARMABLE';
  END IF;
END
$fn$;

-- 1. open_invitation: valida vigencia y devuelve refs opacas. NO consume el token (los escáneres de buzón lo abren primero, F-RB-02). Sin fila = token inválido,
-- vencido, consumido o invitación cancelada/terminal: respuesta uniforme.
CREATE FUNCTION app.open_invitation(p_token_hash text)
  RETURNS TABLE (invitation_ref text, student_ref text, consent_version text, state text)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_inv app.invitation%ROWTYPE;
BEGIN
  SELECT * INTO v_inv FROM app.invitation i
   WHERE i.tenant_id = app.current_tenant_id() AND i.token_hash = p_token_hash
     AND i.token_consumed_at IS NULL AND i.token_expires_at > pg_catalog.now() AND i.state IN ('SENT', 'OPENED', 'VERIFIED')
   FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  IF v_inv.state = 'SENT' THEN
    UPDATE app.invitation SET state = 'OPENED' WHERE tenant_id = v_inv.tenant_id AND invitation_ref = v_inv.invitation_ref; -- emite INVITATION_OPENED
    v_inv.state := 'OPENED';
  END IF;
  RETURN QUERY SELECT v_inv.invitation_ref, v_inv.student_ref, v_inv.consent_version, v_inv.state;
END
$fn$;

-- 2. issue_otp: un OTP vivo por (padre, scope). Padre DECISION = invitación OPENED; REVOCATION|MANAGE = decisión GRANTED. Un nuevo envío expira el anterior
-- (P-06: >= 60 s entre envíos, <= 3 por hora, contados sobre los challenges del padre) y respeta el presupuesto P-04 (10 fallos / 24 h).
-- p_expires_at lo fija el llamador, acotado a (now, now + 10 min] (P-02).
CREATE FUNCTION app.issue_otp(p_parent_ref text, p_code_hmac text, p_expires_at timestamptz, p_scope text DEFAULT 'DECISION')
  RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_ttl constant interval := interval '10 minutes';            -- P-02
  c_budget_max constant integer := 10;                          -- P-04
  c_min_resend constant interval := interval '60 seconds';      -- P-06
  c_max_sends constant integer := 3;                            -- P-06
  v_tenant uuid := app.current_tenant_id();
  v_ref text := 'ver-' || pg_catalog.gen_random_uuid()::text;
  v_budget_key text := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_parent_ref, 'UTF8')), 'hex');
  v_failures integer;
  v_last timestamptz;
  v_sends integer;
BEGIN
  IF p_scope NOT IN ('DECISION', 'REVOCATION', 'MANAGE') THEN RAISE EXCEPTION 'INVALID_SCOPE'; END IF;
  IF p_expires_at <= pg_catalog.now() OR p_expires_at > pg_catalog.now() + c_ttl + interval '5 seconds' THEN RAISE EXCEPTION 'INVALID_EXPIRY'; END IF;
  IF p_scope = 'DECISION' THEN
    PERFORM 1 FROM app.invitation i WHERE i.tenant_id = v_tenant AND i.invitation_ref = p_parent_ref AND i.state = 'OPENED' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PARENT_NOT_ELIGIBLE'; END IF;
  ELSE
    PERFORM 1 FROM app.consent_decision d WHERE d.tenant_id = v_tenant AND d.consent_id = p_parent_ref AND d.state = 'GRANTED' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PARENT_NOT_ELIGIBLE'; END IF;
  END IF;

  SELECT b.failures INTO v_failures FROM app.otp_budget b
   WHERE b.tenant_id = v_tenant AND b.key_kind = 'INVITATION' AND b.key_hmac = v_budget_key AND b.expires_at > pg_catalog.now();
  IF COALESCE(v_failures, 0) >= c_budget_max THEN RAISE EXCEPTION 'OTP_BUDGET_EXHAUSTED'; END IF;

  SELECT pg_catalog.max(o.created_at), pg_catalog.count(*) FILTER (WHERE o.created_at > pg_catalog.now() - interval '1 hour') INTO v_last, v_sends
    FROM app.otp_challenge o WHERE o.tenant_id = v_tenant AND o.parent_ref = p_parent_ref AND o.scope = p_scope;
  IF v_last IS NOT NULL AND v_last > pg_catalog.now() - c_min_resend THEN RAISE EXCEPTION 'OTP_RESEND_TOO_SOON'; END IF;
  IF v_sends >= c_max_sends THEN RAISE EXCEPTION 'OTP_SEND_LIMIT'; END IF;

  UPDATE app.otp_challenge SET state = 'EXPIRED'
   WHERE tenant_id = v_tenant AND parent_ref = p_parent_ref AND scope = p_scope AND state = 'CODE_SENT';
  INSERT INTO app.otp_challenge (verification_ref, scope, parent_ref, code_hmac, expires_at)
  VALUES (v_ref, p_scope, p_parent_ref, p_code_hmac, p_expires_at);
  RETURN v_ref;
END
$fn$;

-- 3. verify_otp: compara DENTRO de la base (bytea del HMAC), con FOR UPDATE del challenge: dos llamadas concurrentes con el código correcto dan 1 solo VERIFIED.
-- Devuelve (outcome, verification_ref, attempts_left). outcome: VERIFIED | WRONG_CODE | LOCKED | EXPIRED | NOT_ACTIVE | BUDGET_EXHAUSTED.
-- p_decision_maker_ref (seudónimo HKDF del canal verificado) lo calcula el servidor y queda en el OTP y luego en la decisión.
CREATE FUNCTION app.verify_otp(p_verification_ref text, p_code_hmac_attempt text, p_decision_maker_ref text)
  RETURNS TABLE (outcome text, verification_ref text, attempts_left integer)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_max_attempts constant integer := 5;                         -- P-03
  c_budget_max constant integer := 10;                          -- P-04
  c_budget_window constant interval := interval '24 hours';     -- P-04 (ventana fija desde el primer fallo)
  v_tenant uuid := app.current_tenant_id();
  v_ch app.otp_challenge%ROWTYPE;
  v_budget_key text;
  v_failures integer;
BEGIN
  IF p_code_hmac_attempt !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'INVALID_CODE_HMAC'; END IF;
  SELECT * INTO v_ch FROM app.otp_challenge o WHERE o.tenant_id = v_tenant AND o.verification_ref = p_verification_ref FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT 'NOT_ACTIVE'::text, NULL::text, 0; RETURN; END IF;
  IF v_ch.state <> 'CODE_SENT' THEN RETURN QUERY SELECT 'NOT_ACTIVE'::text, NULL::text, 0; RETURN; END IF;
  IF pg_catalog.now() >= v_ch.expires_at THEN
    UPDATE app.otp_challenge SET state = 'EXPIRED' WHERE tenant_id = v_tenant AND verification_ref = p_verification_ref;
    RETURN QUERY SELECT 'EXPIRED'::text, NULL::text, 0; RETURN;
  END IF;

  v_budget_key := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_ch.parent_ref, 'UTF8')), 'hex');
  SELECT b.failures INTO v_failures FROM app.otp_budget b
   WHERE b.tenant_id = v_tenant AND b.key_kind = 'INVITATION' AND b.key_hmac = v_budget_key AND b.expires_at > pg_catalog.now();
  IF COALESCE(v_failures, 0) >= c_budget_max THEN RETURN QUERY SELECT 'BUDGET_EXHAUSTED'::text, NULL::text, 0; RETURN; END IF;

  -- Igualdad sobre bytea de 32 bytes (HMAC-SHA256): no depende de la longitud ni del texto hex.
  IF pg_catalog.decode(p_code_hmac_attempt, 'hex') = pg_catalog.decode(v_ch.code_hmac, 'hex') THEN
    IF p_decision_maker_ref IS NULL OR pg_catalog.length(p_decision_maker_ref) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'INVALID_DECISION_MAKER_REF'; END IF;
    UPDATE app.otp_challenge SET attempts = v_ch.attempts + 1, state = 'VERIFIED', consumed_at = pg_catalog.now(), decision_maker_ref = p_decision_maker_ref
     WHERE tenant_id = v_tenant AND verification_ref = p_verification_ref; -- emite DECISION_MAKER_CHANNEL_VERIFIED
    IF v_ch.scope = 'DECISION' THEN
      UPDATE app.invitation SET state = 'VERIFIED' WHERE tenant_id = v_tenant AND invitation_ref = v_ch.parent_ref AND state = 'OPENED'; -- emite INVITATION_VERIFIED
    END IF;
    RETURN QUERY SELECT 'VERIFIED'::text, p_verification_ref, c_max_attempts - (v_ch.attempts + 1);
    RETURN;
  END IF;

  INSERT INTO app.otp_budget (key_kind, key_hmac, window_start, expires_at, failures)
  VALUES ('INVITATION', v_budget_key, pg_catalog.now(), pg_catalog.now() + c_budget_window, 1)
  ON CONFLICT (tenant_id, key_kind, key_hmac) DO UPDATE
    SET failures = CASE WHEN app.otp_budget.expires_at > pg_catalog.now() THEN app.otp_budget.failures + 1 ELSE 1 END,
        window_start = CASE WHEN app.otp_budget.expires_at > pg_catalog.now() THEN app.otp_budget.window_start ELSE pg_catalog.now() END,
        expires_at = CASE WHEN app.otp_budget.expires_at > pg_catalog.now() THEN app.otp_budget.expires_at ELSE pg_catalog.now() + c_budget_window END;
  IF v_ch.attempts + 1 >= c_max_attempts THEN
    UPDATE app.otp_challenge SET attempts = v_ch.attempts + 1, state = 'LOCKED' WHERE tenant_id = v_tenant AND verification_ref = p_verification_ref; -- emite OTP_LOCKED
    RETURN QUERY SELECT 'LOCKED'::text, NULL::text, 0;
  ELSE
    UPDATE app.otp_challenge SET attempts = v_ch.attempts + 1 WHERE tenant_id = v_tenant AND verification_ref = p_verification_ref;
    RETURN QUERY SELECT 'WRONG_CODE'::text, NULL::text, c_max_attempts - (v_ch.attempts + 1);
  END IF;
END
$fn$;

-- 4. record_decision: exige OTP DECISION VERIFIED (de esta invitación, dentro de la ventana de sesión de 30 min, SUPUESTO de beta), inserta la decisión
-- (1 por invitación), marca token_consumed_at y cierra la invitación, y encola el recibo en la misma tx. Idempotente por clave: misma clave => misma decisión sin
-- evento nuevo (deduped = true); otra clave sobre una invitación ya decidida => ALREADY_DECIDED. El FOR UPDATE de la invitación serializa los reintentos paralelos.
CREATE FUNCTION app.record_decision(p_invitation_ref text, p_verification_ref text, p_outcome text, p_consent_version text, p_consent_text_hash text,
                                    p_idempotency_key text, p_purposes jsonb DEFAULT '[]'::jsonb)
  RETURNS TABLE (consent_id text, state text, deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_window constant interval := interval '30 minutes';
  v_tenant uuid := app.current_tenant_id();
  v_idem text;
  v_inv app.invitation%ROWTYPE;
  v_ch app.otp_challenge%ROWTYPE;
  v_dec app.consent_decision%ROWTYPE;
  v_id text := 'con-' || pg_catalog.gen_random_uuid()::text;
BEGIN
  IF p_outcome NOT IN ('GRANTED', 'DECLINED') THEN RAISE EXCEPTION 'INVALID_OUTCOME'; END IF;
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
  VALUES ('DECISION_RECEIPT', p_invitation_ref, 'receipt:' || v_id, pg_catalog.jsonb_build_object('consentId', v_id, 'outcome', p_outcome));
  RETURN QUERY SELECT v_id, p_outcome, false;
END
$fn$;

-- 5. revoke_decision: UNA tx: exige OTP (REVOCATION|MANAGE) VERIFIED sobre esta decisión, inserta la revocación ya APPLIED (manifestada y aplicada en el mismo commit,
-- sin PENDING/HELD), pasa GRANTED>REVOKED, emite CONSENT_REVOKED y encola el recibo. Idempotente por clave; DECLINED o ya REVOKED con otra clave => error claro.
CREATE FUNCTION app.revoke_decision(p_consent_id text, p_verification_ref text, p_idempotency_key text)
  RETURNS TABLE (revocation_ref text, deduped boolean)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  c_window constant interval := interval '30 minutes';
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
  PERFORM ledger_gen.ledger_append('ConsentDecision', p_consent_id, 'CONSENT_REVOKED', 'HUMAN', 'DECISION_MAKER',
    pg_catalog.jsonb_build_object('consentId', p_consent_id, 'revocationRef', v_ref), p_consent_id || ':revoked');
  INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload)
  VALUES ('REVOCATION_RECEIPT', v_dec.invitation_ref, 'receipt-rev:' || p_consent_id, pg_catalog.jsonb_build_object('consentId', p_consent_id, 'revocationRef', v_ref));
  RETURN QUERY SELECT v_ref, false;
END
$fn$;

-- 6. authorization_status: AUTHORIZED solo con una decisión GRANTED no revocada; todo lo demás (sin invitación, DECLINED, REVOKED) es NOT_AUTHORIZED.
-- Lee la misma BD que revoke_decision: la lectura posterior al commit ya ve REVOKED.
CREATE FUNCTION app.authorization_status(p_student_ref text)
  RETURNS TABLE (status text, as_of timestamptz, decision_ref text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE WHEN d.consent_id IS NULL THEN 'NOT_AUTHORIZED' ELSE 'AUTHORIZED' END, pg_catalog.now(), d.consent_id
    FROM (SELECT 1) one
    LEFT JOIN LATERAL (SELECT x.consent_id FROM app.consent_decision x
                        WHERE x.tenant_id = app.current_tenant_id() AND x.student_ref = p_student_ref AND x.state = 'GRANTED'
                          AND NOT EXISTS (SELECT 1 FROM app.revocation r WHERE r.tenant_id = x.tenant_id AND r.consent_id = x.consent_id AND r.status IN ('PENDING', 'APPLIED', 'HELD'))
                        LIMIT 1) d ON true
$fn$;

REVOKE ALL ON FUNCTION app.import_invitation(text, text, text, text), app.arm_invitation_token(text, text, timestamptz, text), app.open_invitation(text),
  app.issue_otp(text, text, timestamptz, text), app.verify_otp(text, text, text),
  app.record_decision(text, text, text, text, text, text, jsonb), app.revoke_decision(text, text, text), app.authorization_status(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.import_invitation(text, text, text, text), app.arm_invitation_token(text, text, timestamptz, text), app.open_invitation(text),
  app.issue_otp(text, text, timestamptz, text), app.verify_otp(text, text, text),
  app.record_decision(text, text, text, text, text, text, jsonb), app.revoke_decision(text, text, text), app.authorization_status(text) TO consent_app;

-- Retiro de los grants directos marcados TODO H1-03 ---------------------------------------------------------------------------------------------------------
REVOKE INSERT ON app.invitation FROM consent_app;
-- consent_app queda con SELECT en invitation, otp_challenge (sin code_hmac), consent_decision y revocation; ningún INSERT/UPDATE/DELETE en ellas ni en otp_budget.
-- Se CONSERVAN, porque ninguna función de H1-03 los cubre: email_outbox (SELECT, INSERT acotado, UPDATE acotado de status/attempts/next_attempt_at/provider_message_id/
-- last_error_code: el outbox en proceso y su reintento son de H1-06; ahí pasa a claim_emails()/mark_email_*()), api_nonce (INSERT para la verificación de replay, H1-08)
-- y api_access_log (INSERT append-only, H1-08).

-- Tabla de verdad rol x objeto x privilegio ------------------------------------------------------------------------------------------------------------------
DO $truth$
DECLARE
  r record;
  v boolean;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    -- rol, objeto, privilegio, esperado
    ('consent_app', 'app.invitation', 'SELECT', true), ('consent_app', 'app.invitation', 'INSERT', false), ('consent_app', 'app.invitation', 'UPDATE', false),
    ('consent_app', 'app.invitation', 'DELETE', false), ('consent_app', 'app.invitation', 'TRUNCATE', false),
    ('consent_app', 'app.otp_challenge', 'INSERT', false), ('consent_app', 'app.otp_challenge', 'UPDATE', false),
    ('consent_app', 'app.otp_challenge', 'DELETE', false),
    ('consent_app', 'app.otp_budget', 'SELECT', false), ('consent_app', 'app.otp_budget', 'INSERT', false), ('consent_app', 'app.otp_budget', 'UPDATE', false),
    ('consent_app', 'app.consent_decision', 'SELECT', true), ('consent_app', 'app.consent_decision', 'INSERT', false), ('consent_app', 'app.consent_decision', 'UPDATE', false),
    ('consent_app', 'app.consent_decision', 'DELETE', false),
    ('consent_app', 'app.revocation', 'SELECT', true), ('consent_app', 'app.revocation', 'INSERT', false), ('consent_app', 'app.revocation', 'UPDATE', false),
    ('consent_app', 'app.revocation', 'DELETE', false),
    ('consent_app', 'app.email_outbox', 'SELECT', true), ('consent_app', 'app.email_outbox', 'DELETE', false),
    ('consent_app', 'app.api_nonce', 'SELECT', true), ('consent_app', 'app.api_nonce', 'UPDATE', false), ('consent_app', 'app.api_nonce', 'DELETE', false),
    ('consent_app', 'app.api_access_log', 'SELECT', true), ('consent_app', 'app.api_access_log', 'UPDATE', false), ('consent_app', 'app.api_access_log', 'DELETE', false),
    ('consent_app', 'integrity.audit_event', 'SELECT', true), ('consent_app', 'integrity.audit_event', 'INSERT', false), ('consent_app', 'integrity.audit_event', 'UPDATE', false),
    ('consent_app', 'integrity.audit_event', 'DELETE', false), ('consent_app', 'integrity.audit_event', 'TRUNCATE', false),
    ('consent_owner', 'integrity.audit_event', 'UPDATE', false), ('consent_owner', 'integrity.audit_event', 'DELETE', false), ('consent_owner', 'integrity.audit_event', 'TRUNCATE', false),
    ('consent_app', 'ops.db_catalog', 'SELECT', true), ('consent_app', 'ops.db_catalog', 'UPDATE', false), ('consent_app', 'ops.db_catalog', 'INSERT', false),
    ('consent_app', 'app.school', 'SELECT', true), ('consent_app', 'app.school', 'UPDATE', false)
  ) AS t(rol, obj, priv, expected) LOOP
    v := pg_catalog.has_table_privilege(r.rol, r.obj, r.priv);
    IF v IS DISTINCT FROM r.expected THEN RAISE EXCEPTION 'tabla de verdad: % % % = % (esperado %)', r.rol, r.obj, r.priv, v, r.expected; END IF;
  END LOOP;

  -- Columnas sensibles (otp_challenge se lee por columnas, sin code_hmac).
  IF NOT pg_catalog.has_column_privilege('consent_app', 'app.otp_challenge', 'state', 'SELECT') THEN RAISE EXCEPTION 'tabla de verdad: consent_app debe leer otp_challenge.state'; END IF;
  IF pg_catalog.has_column_privilege('consent_app', 'app.otp_challenge', 'code_hmac', 'SELECT') OR pg_catalog.has_any_column_privilege('consent_app', 'app.otp_challenge', 'UPDATE')
     OR pg_catalog.has_any_column_privilege('consent_app', 'app.consent_decision', 'UPDATE') OR pg_catalog.has_any_column_privilege('consent_app', 'app.invitation', 'INSERT')
     OR pg_catalog.has_any_column_privilege('consent_app', 'app.invitation', 'UPDATE') THEN
    RAISE EXCEPTION 'tabla de verdad: privilegios de columna indebidos para consent_app';
  END IF;

  -- EXECUTE: solo consent_app (y el dueño); nadie por PUBLIC; ledger_gen.* no es ejecutable por consent_app.
  FOR r IN SELECT p.oid, p.oid::regprocedure::text AS sig FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname IN ('app', 'ledger_gen', 'ops', 'integrity') AND p.prokind = 'f' LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p2, pg_catalog.aclexplode(COALESCE(p2.proacl, pg_catalog.acldefault('f', p2.proowner))) a WHERE p2.oid = r.oid AND a.grantee = 0) THEN
      RAISE EXCEPTION 'tabla de verdad: % es ejecutable por PUBLIC', r.sig;
    END IF;
    IF pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid = r.oid)) <> 'consent_owner' THEN RAISE EXCEPTION 'tabla de verdad: % no es de consent_owner', r.sig; END IF;
  END LOOP;
  FOR r IN SELECT * FROM (VALUES
    ('app.import_invitation(text,text,text,text)', true), ('app.arm_invitation_token(text,text,timestamptz,text)', true), ('app.open_invitation(text)', true),
    ('app.issue_otp(text,text,timestamptz,text)', true), ('app.verify_otp(text,text,text)', true),
    ('app.record_decision(text,text,text,text,text,text,jsonb)', true), ('app.revoke_decision(text,text,text)', true), ('app.authorization_status(text)', true),
    ('ledger_gen.ledger_append(text,text,text,text,text,jsonb,text)', false), ('ledger_gen.canonical_json(jsonb)', false), ('ledger_gen.emit_invitation()', false)
  ) AS t(fn, expected) LOOP
    IF pg_catalog.has_function_privilege('consent_app', r.fn, 'EXECUTE') IS DISTINCT FROM r.expected THEN RAISE EXCEPTION 'tabla de verdad: EXECUTE de consent_app sobre % (esperado %)', r.fn, r.expected; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'app' AND p.prokind = 'f' AND p.proname <> 'current_tenant_id' AND (NOT p.prosecdef OR p.proconfig IS NULL OR NOT ('search_path=pg_catalog, pg_temp' = ANY (p.proconfig)))) THEN
    RAISE EXCEPTION 'tabla de verdad: toda función de app debe ser SECURITY DEFINER con search_path fijo';
  END IF;
END
$truth$;
