-- scope: database
-- Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4: oidc_exchange, canje en el verifier, aserciones), §4.4 (identidad, doble control), §4.6, §7 fila PR-4
-- ("proceso verifier, oidc_exchange, grant_assertion; JWKS sintetico en LOCAL"; DF-4, F-X8-15); specs/db-roles.spec.yaml (integrity_verifier, platform_rw, worker,
-- grant_owner, membership_owner; INV-DBR-01/03); contracts/openapi/consent-platform.openapi.yaml; registers/findings-register-IT0.md F-A10-12, F-A10-15 (parcial).
-- Decisiones de Carlos del 2026-10-11: (6) nadie aprueba su propio acceso (approved_by_ref <> principal_ref, CHECK y authorize_target); (2) enums de rol fijos.
-- Regla de Carlos (2026-10-01): 0000-0035 no se editan; esta migracion es nueva. Corre como consent_owner (SET TRUE sobre los owners, Q-15 c).
--
-- Que agrega:
--   membership_owner : platform.principal_identity (UNIQUE sub_hmac <-> principal_ref, F-A10-12; solo el HMAC del sub del IdP, nunca el sub en claro); CHECK
--                      no_self_approval en tenant_membership y platform_role_assignment; principal_ref pasa a UUIDv4 estricto (se quita la forma staff-synthetic-,
--                      F-A10-12: el spec pide un UUIDv4 opaco).
--   grant_owner      : platform.oidc_exchange (cola del canje: code + PKCE son secretos operativos N4, se anulan al consumirse, sin SELECT para nadie),
--                      platform.grant_assertion (aserciones ATTESTED|REJECTED, append-only, solo claims minimos), y las funciones SECURITY DEFINER
--                      enqueue_oidc_exchange (platform_rw), claim_oidc_exchange y record_assertion (integrity_verifier), purge_expired_oidc_exchange (worker).
--                      platform.record_assertion es la UNICA forma de fijar action_nonce.attested_at y habilita el step-up.
-- Los roles de runtime siguen SIN privilegios sobre ninguna tabla de platform (aqui TAMPOCO el verifier: lee y cierra el canje solo por funciones; es mas estricto
-- que las columnas que listaba el spec, ver specs/db-roles.spec.yaml rev. 0.3). platform no tiene egress: el verifier canjea el code (en LOCAL contra un IdP sintetico).
-- Todas las funciones nuevas: SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico, EXECUTE revocado a PUBLIC. Ante un DENY no lanzan excepcion:
-- devuelven NULL/false/0 filas para que la evidencia de authorization_check se confirme (el adapter hace COMMIT, F-A10-13).
-- Decision de modelo (N6): record_assertion degrada a REJECTED/SUB_MISMATCH si el sub_hmac informado no es el mapeado a principal_ref en platform.principal_identity;
-- el vinculo se crea fuera de las funciones de runtime (LOCAL: fixture sintetico db/fixtures/local; STAGING/datos reales: ceremonia de break-glass de PR-7, Q10).

-- 0. Precondiciones: USAGE para los dos roles de runtime nuevos; CREATE temporal para los owners de objetos (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT USAGE ON SCHEMA platform TO worker, integrity_verifier;
GRANT CREATE ON SCHEMA platform TO membership_owner, grant_owner;

-- 1. membership_owner: forma de principal_ref, identidad (sub_hmac), no_self_approval y funciones de solicitud.
SET LOCAL ROLE membership_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER TABLE platform.tenant_membership
  DROP CONSTRAINT tenant_membership_principal_shape,
  DROP CONSTRAINT tenant_membership_requested_by_shape,
  DROP CONSTRAINT tenant_membership_approved_by_shape;
ALTER TABLE platform.tenant_membership
  ADD CONSTRAINT tenant_membership_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT tenant_membership_requested_by_shape CHECK (requested_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT tenant_membership_approved_by_shape CHECK (approved_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  -- Decision 6 de Carlos (2026-10-11): nadie aprueba su propio acceso. Aparte del solicitante <> aprobador (tenant_membership_double_control).
  ADD CONSTRAINT tenant_membership_no_self_approval CHECK (approved_by_ref IS NULL OR approved_by_ref <> principal_ref);

ALTER TABLE platform.platform_role_assignment
  DROP CONSTRAINT platform_role_assignment_principal_shape,
  DROP CONSTRAINT platform_role_assignment_requested_by_shape,
  DROP CONSTRAINT platform_role_assignment_approved_by_shape;
ALTER TABLE platform.platform_role_assignment
  ADD CONSTRAINT platform_role_assignment_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT platform_role_assignment_requested_by_shape CHECK (requested_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT platform_role_assignment_approved_by_shape CHECK (approved_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT platform_role_assignment_no_self_approval CHECK (approved_by_ref IS NULL OR approved_by_ref <> principal_ref);

-- Identidad (F-A10-12): un principal_ref <-> un sub_hmac (HMAC(K_sub, iss||sub) hex). UNIQUE en ambos sentidos: un mismo humano (mismo sub) no puede tener dos
-- principal_ref para cumplir el doble control con dos identidades, ni un principal_ref dos sub. Solo INSERT por el dueno; nada se actualiza ni se borra.
CREATE TABLE platform.principal_identity (
  principal_ref text        NOT NULL CONSTRAINT principal_identity_pkey PRIMARY KEY
                            CONSTRAINT principal_identity_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  sub_hmac      text        NOT NULL CONSTRAINT principal_identity_sub_hmac_unique UNIQUE
                            CONSTRAINT principal_identity_sub_hmac_shape CHECK (sub_hmac ~ '^[0-9a-f]{64}$'),
  created_at    timestamptz NOT NULL DEFAULT pg_catalog.now(),
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT principal_identity_data_class_synthetic CHECK (data_class = 'SYNTHETIC')
);

CREATE FUNCTION platform.identity_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'platform.principal_identity es append-only (ADR-010 §4.4, F-A10-12)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.identity_guard() FROM PUBLIC;
CREATE TRIGGER principal_identity_guard BEFORE UPDATE OR DELETE ON platform.principal_identity
  FOR EACH ROW EXECUTE FUNCTION platform.identity_guard();
CREATE TRIGGER principal_identity_no_truncate BEFORE TRUNCATE ON platform.principal_identity
  FOR EACH STATEMENT EXECUTE FUNCTION platform.membership_no_truncate();
ALTER TABLE platform.principal_identity ENABLE ALWAYS TRIGGER principal_identity_guard;
ALTER TABLE platform.principal_identity ENABLE ALWAYS TRIGGER principal_identity_no_truncate;
ALTER TABLE platform.principal_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.principal_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY principal_identity_owner_select ON platform.principal_identity FOR SELECT TO membership_owner USING (true);
CREATE POLICY principal_identity_owner_insert ON platform.principal_identity FOR INSERT TO membership_owner WITH CHECK (true);
CREATE POLICY principal_identity_authorize_select ON platform.principal_identity FOR SELECT TO grant_owner USING (true);
REVOKE ALL ON platform.principal_identity FROM PUBLIC;
-- grant_owner (platform.record_assertion) lee solo las dos columnas que decide.
GRANT SELECT (principal_ref, sub_hmac) ON platform.principal_identity TO grant_owner;

-- Solicitudes: igual que 0035, con principal_ref UUIDv4 estricto (sin staff-synthetic-).
CREATE OR REPLACE FUNCTION platform.request_membership(p_tenant_id uuid, p_principal_ref text, p_membership_role text)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_requester text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_ref uuid;
  v_res text := CASE WHEN p_principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                      AND p_membership_role IN ('TENANT_ADMIN', 'INVITER') THEN pg_catalog.concat(p_principal_ref, ':', p_membership_role) END;
BEGIN
  -- Entrada invalida => v_res NULL => authorize_target deja un DENY INVALID_RESOURCE (evidencia) y no se inserta nada.
  IF NOT platform.authorize_target('REQUEST_MEMBERSHIP', v_res, p_tenant_id, true) THEN
    RETURN NULL;
  END IF;
  INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref)
  VALUES (p_tenant_id, p_principal_ref, p_membership_role, 'PENDING', v_requester)
  ON CONFLICT ON CONSTRAINT tenant_membership_unique DO NOTHING
  RETURNING request_ref INTO v_ref;
  RETURN v_ref;
END
$$;

CREATE OR REPLACE FUNCTION platform.request_role_assignment(p_principal_ref text, p_platform_role text, p_approver_class text)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_requester text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_ref uuid;
  v_res text := CASE WHEN p_principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                      AND p_platform_role IN ('PLATFORM', 'RIGHTS_OPERATOR', 'APPROVER', 'CONTEXT_OWNER')
                      AND ((p_platform_role = 'APPROVER' AND p_approver_class IN ('PRIVACY_LEGAL', 'SECURITY')) OR (p_platform_role <> 'APPROVER' AND p_approver_class IS NULL))
                      THEN pg_catalog.concat_ws(':', p_principal_ref, p_platform_role, p_approver_class) END;
BEGIN
  IF NOT platform.authorize_target('REQUEST_ROLE_ASSIGNMENT', v_res, NULL, true) THEN
    RETURN NULL;
  END IF;
  INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, approver_class, status, requested_by_ref)
  VALUES (p_principal_ref, p_platform_role, p_approver_class, 'PENDING', v_requester)
  ON CONFLICT (principal_ref, platform_role, (COALESCE(approver_class, ''))) DO NOTHING
  RETURNING request_ref INTO v_ref;
  RETURN v_ref;
END
$$;

-- 2. grant_owner: formas, enums de evidencia, oidc_exchange, grant_assertion y funciones.
SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER TABLE platform.action_nonce
  DROP CONSTRAINT action_nonce_principal_shape;
ALTER TABLE platform.action_nonce
  ADD CONSTRAINT action_nonce_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

ALTER TABLE platform.authorization_check
  DROP CONSTRAINT authorization_check_principal_shape,
  DROP CONSTRAINT authorization_check_resource_shape,
  DROP CONSTRAINT authorization_check_kind_enum,
  DROP CONSTRAINT authorization_check_reason_enum;
ALTER TABLE platform.authorization_check
  ADD CONSTRAINT authorization_check_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT authorization_check_resource_shape CHECK (
    resource_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    OR resource_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:(TENANT_ADMIN|INVITER)$'
    OR resource_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:(PLATFORM|RIGHTS_OPERATOR|APPROVER|CONTEXT_OWNER)(:(PRIVACY_LEGAL|SECURITY))?$'),
  ADD CONSTRAINT authorization_check_kind_enum CHECK (check_kind IN ('AUTHORIZE', 'ISSUE_NONCE', 'ENQUEUE_EXCHANGE', 'RECORD_ASSERTION')),
  ADD CONSTRAINT authorization_check_reason_enum CHECK (reason_code IN
    ('OK', 'UNKNOWN_ACTION', 'NO_PRINCIPAL', 'INVALID_RESOURCE', 'TENANT_SCOPE', 'CALLER_ROLE', 'NO_ROLE', 'TENANT_MISMATCH', 'REQUEST_NOT_FOUND', 'SELF_APPROVAL', 'STEP_UP_MISSING', 'INVALID_TTL',
     'SELF_ACCESS', 'INVALID_INPUT', 'NONCE_NOT_FOUND', 'DUPLICATE_EXCHANGE', 'EXCHANGE_NOT_FOUND', 'SUB_MISMATCH', 'INVALID_CLAIMS', 'EXCHANGE_FAILED'));

-- Cola del canje OIDC (ADR-010 §4.3.2). code y pkce_verifier son secretos operativos (N4): ningun runtime hace SELECT; se anulan en la misma transaccion en que se
-- consumen o rechazan (record_assertion) y el worker borra las filas vencidas. NO son datos de retencion LD-15. binding = sha256 hex del action nonce en claro,
-- que viaja como claim `nonce` del ID token.
CREATE TABLE platform.oidc_exchange (
  exchange_ref  uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT oidc_exchange_pkey PRIMARY KEY,
  binding       text        NOT NULL CONSTRAINT oidc_exchange_binding_shape CHECK (binding ~ '^[0-9a-f]{64}$'),
  principal_ref text        NOT NULL CONSTRAINT oidc_exchange_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  code          text        CONSTRAINT oidc_exchange_code_shape CHECK (pg_catalog.length(code) BETWEEN 1 AND 512 AND code ~ '^[!-~]+$'),
  pkce_verifier text        CONSTRAINT oidc_exchange_pkce_shape CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
  status        text        NOT NULL DEFAULT 'PENDING' CONSTRAINT oidc_exchange_status_enum CHECK (status IN ('PENDING', 'ATTESTED', 'REJECTED')),
  created_at    timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at    timestamptz NOT NULL,
  claimed_until timestamptz,
  decided_at    timestamptz,
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT oidc_exchange_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- Vida del code acotada tecnicamente a 10 min (el IdP real emite codes de decenas de segundos; el parametro fino llega con APR-IDP).
  CONSTRAINT oidc_exchange_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  -- Secretos presentes solo mientras PENDING; decididas => anulados (N4) y con decided_at.
  CONSTRAINT oidc_exchange_secrets_iff_pending CHECK (
    (status = 'PENDING' AND code IS NOT NULL AND pkce_verifier IS NOT NULL AND decided_at IS NULL)
    OR (status <> 'PENDING' AND code IS NULL AND pkce_verifier IS NULL AND decided_at IS NOT NULL))
);
CREATE UNIQUE INDEX oidc_exchange_pending_binding ON platform.oidc_exchange (binding) WHERE status = 'PENDING';
CREATE INDEX oidc_exchange_expires_idx ON platform.oidc_exchange (expires_at);

-- Aserciones del verifier: solo claims minimos (sub_hmac, auth_time, acr, amr) y el hash del ID token. Sin ID token crudo, sin email, sin sub en claro.
-- Append-only. Retencion: LD-15/P-34 pendiente (F-A10-15); sin purga en PR-4.
CREATE TABLE platform.grant_assertion (
  assertion_ref  uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT grant_assertion_pkey PRIMARY KEY,
  exchange_ref   uuid        NOT NULL CONSTRAINT grant_assertion_exchange_unique UNIQUE,
  binding        text        NOT NULL CONSTRAINT grant_assertion_binding_shape CHECK (binding ~ '^[0-9a-f]{64}$'),
  principal_ref  text        NOT NULL CONSTRAINT grant_assertion_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  decision       text        NOT NULL CONSTRAINT grant_assertion_decision_enum CHECK (decision IN ('ATTESTED', 'REJECTED')),
  reason_code    text        CONSTRAINT grant_assertion_reason_enum CHECK (reason_code IN ('SUB_MISMATCH', 'INVALID_CLAIMS', 'EXCHANGE_FAILED', 'NONCE_NOT_FOUND')),
  sub_hmac       text        CONSTRAINT grant_assertion_sub_hmac_shape CHECK (sub_hmac ~ '^[0-9a-f]{64}$'),
  assertion_hash text        CONSTRAINT grant_assertion_hash_shape CHECK (assertion_hash ~ '^[0-9a-f]{64}$'),
  auth_time      timestamptz,
  acr            text        CONSTRAINT grant_assertion_acr_shape CHECK (acr ~ '^[A-Za-z0-9:._-]{1,128}$'),
  amr            text[]      CONSTRAINT grant_assertion_amr_shape CHECK (pg_catalog.array_to_string(amr, ',') ~ '^[A-Za-z0-9:._-]{1,64}(,[A-Za-z0-9:._-]{1,64}){0,7}$'),
  recorded_at    timestamptz NOT NULL DEFAULT pg_catalog.now(),
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT grant_assertion_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT grant_assertion_reason_iff_rejected CHECK ((decision = 'REJECTED') = (reason_code IS NOT NULL)),
  CONSTRAINT grant_assertion_attested_claims CHECK (decision <> 'ATTESTED' OR (sub_hmac IS NOT NULL AND assertion_hash IS NOT NULL AND auth_time IS NOT NULL))
);

CREATE FUNCTION platform.oidc_exchange_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- DELETE solo de filas ya vencidas (purga del worker). UPDATE: PENDING -> PENDING solo fija claimed_until (lease); PENDING -> ATTESTED|REJECTED cierra y anula secretos.
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at <= pg_catalog.now() THEN RETURN OLD; END IF;
  ELSIF TG_OP = 'UPDATE' AND OLD.status = 'PENDING'
        AND (NEW.exchange_ref, NEW.binding, NEW.principal_ref, NEW.created_at, NEW.expires_at, NEW.data_class)
            IS NOT DISTINCT FROM (OLD.exchange_ref, OLD.binding, OLD.principal_ref, OLD.created_at, OLD.expires_at, OLD.data_class) THEN
    IF NEW.status = 'PENDING' AND (NEW.code, NEW.pkce_verifier, NEW.decided_at) IS NOT DISTINCT FROM (OLD.code, OLD.pkce_verifier, OLD.decided_at) THEN RETURN NEW; END IF;
    IF NEW.status IN ('ATTESTED', 'REJECTED') AND NEW.code IS NULL AND NEW.pkce_verifier IS NULL AND NEW.decided_at IS NOT NULL THEN RETURN NEW; END IF;
  END IF;
  RAISE EXCEPTION 'platform.oidc_exchange: solo lease, cierre PENDING -> ATTESTED|REJECTED con secretos anulados, y borrado de filas vencidas (ADR-010 §4.3)'
    USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.oidc_exchange_guard() FROM PUBLIC;

CREATE FUNCTION platform.deny_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'platform.%: operacion % no permitida (append-only, ADR-010 §4.3)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.deny_guard() FROM PUBLIC;

CREATE TRIGGER oidc_exchange_guard BEFORE UPDATE OR DELETE ON platform.oidc_exchange
  FOR EACH ROW EXECUTE FUNCTION platform.oidc_exchange_guard();
CREATE TRIGGER oidc_exchange_no_truncate BEFORE TRUNCATE ON platform.oidc_exchange
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
CREATE TRIGGER grant_assertion_immutable BEFORE UPDATE OR DELETE ON platform.grant_assertion
  FOR EACH ROW EXECUTE FUNCTION platform.deny_guard();
CREATE TRIGGER grant_assertion_no_truncate BEFORE TRUNCATE ON platform.grant_assertion
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
ALTER TABLE platform.oidc_exchange ENABLE ALWAYS TRIGGER oidc_exchange_guard;
ALTER TABLE platform.oidc_exchange ENABLE ALWAYS TRIGGER oidc_exchange_no_truncate;
ALTER TABLE platform.grant_assertion ENABLE ALWAYS TRIGGER grant_assertion_immutable;
ALTER TABLE platform.grant_assertion ENABLE ALWAYS TRIGGER grant_assertion_no_truncate;

ALTER TABLE platform.oidc_exchange ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.oidc_exchange FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_exchange_owner_select ON platform.oidc_exchange FOR SELECT TO grant_owner USING (true);
CREATE POLICY oidc_exchange_owner_insert ON platform.oidc_exchange FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY oidc_exchange_owner_update ON platform.oidc_exchange FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
CREATE POLICY oidc_exchange_owner_delete ON platform.oidc_exchange FOR DELETE TO grant_owner USING (true);
REVOKE ALL ON platform.oidc_exchange FROM PUBLIC;

ALTER TABLE platform.grant_assertion ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.grant_assertion FORCE ROW LEVEL SECURITY;
CREATE POLICY grant_assertion_owner_select ON platform.grant_assertion FOR SELECT TO grant_owner USING (true);
CREATE POLICY grant_assertion_owner_insert ON platform.grant_assertion FOR INSERT TO grant_owner WITH CHECK (true);
REVOKE ALL ON platform.grant_assertion FROM PUBLIC;

-- platform.authorize_target (v2): principal_ref UUIDv4 estricto; decision 6 de Carlos (aprobar el acceso propio => DENY SELF_ACCESS, aparte de SELF_APPROVAL).
CREATE OR REPLACE FUNCTION platform.authorize_target(p_action text, p_resource_ref text, p_tenant uuid, p_consume boolean)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy      constant text := 'ADR010-PR4-v1';
  c_principal   constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  c_princ       constant text := '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
  c_uuid        constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
  c_member      constant text := '^' || c_princ || ':(TENANT_ADMIN|INVITER)$';
  c_roleas      constant text := '^' || c_princ || ':(PLATFORM|RIGHTS_OPERATOR|APPROVER|CONTEXT_OWNER)(:(PRIVACY_LEGAL|SECURITY))?$';
  v_principal   text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_re          text;
  v_scope       text;
  v_reason      text := NULL;
  v_is_platform boolean := false;
  v_is_tadmin   boolean := false;
  v_req_by      text;
  v_target      text;
  v_nonce       text;
  v_digest      text;
BEGIN
  <<decide>>
  BEGIN
    v_scope := CASE p_action
      WHEN 'REQUEST_MEMBERSHIP' THEN 'TENANT' WHEN 'APPROVE_MEMBERSHIP' THEN 'TENANT'
      WHEN 'REQUEST_ROLE_ASSIGNMENT' THEN 'PLATFORM' WHEN 'APPROVE_ROLE_ASSIGNMENT' THEN 'PLATFORM' END;
    IF v_scope IS NULL THEN v_reason := 'UNKNOWN_ACTION'; EXIT decide; END IF;
    v_re := CASE p_action WHEN 'REQUEST_MEMBERSHIP' THEN c_member WHEN 'REQUEST_ROLE_ASSIGNMENT' THEN c_roleas ELSE c_uuid END;
    IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; EXIT decide; END IF;
    IF p_resource_ref IS NULL OR p_resource_ref !~ v_re THEN v_reason := 'INVALID_RESOURCE'; EXIT decide; END IF;
    -- APPROVE_MEMBERSHIP sin tenant (solicitud inexistente) sigue al lookup y termina en REQUEST_NOT_FOUND.
    IF p_action <> 'APPROVE_MEMBERSHIP' AND (v_scope = 'TENANT') <> (p_tenant IS NOT NULL) THEN v_reason := 'TENANT_SCOPE'; EXIT decide; END IF;

    v_is_platform := session_user = 'platform_rw' AND EXISTS (
      SELECT 1 FROM platform.platform_role_assignment a
       WHERE a.principal_ref = v_principal AND a.platform_role = 'PLATFORM' AND a.status = 'ACTIVE');

    IF p_action = 'REQUEST_MEMBERSHIP' THEN
      -- Via TENANT_ADMIN (consola STAFF en web, Q-17): solo su propio tenant. Q4/§4.4: ambos con step-up ATTESTED, tambien esta via (B2).
      v_is_tadmin := session_user = 'app_rw' AND p_tenant IS NOT DISTINCT FROM app.current_tenant_id() AND EXISTS (
        SELECT 1 FROM platform.tenant_membership m
         WHERE m.tenant_id = p_tenant AND m.principal_ref = v_principal AND m.membership_role = 'TENANT_ADMIN' AND m.status = 'ACTIVE');
      IF NOT v_is_tadmin AND NOT v_is_platform THEN
        IF session_user NOT IN ('app_rw', 'platform_rw') THEN v_reason := 'CALLER_ROLE';
        ELSIF session_user = 'app_rw' AND p_tenant IS DISTINCT FROM app.current_tenant_id() THEN v_reason := 'TENANT_MISMATCH';
        ELSE v_reason := 'NO_ROLE'; END IF;
        EXIT decide;
      END IF;
    ELSE
      -- REQUEST_ROLE_ASSIGNMENT / APPROVE_*: solo el equipo de LectorPro (platform_rw) con rol PLATFORM activo.
      IF session_user <> 'platform_rw' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
      IF NOT v_is_platform THEN v_reason := 'NO_ROLE'; EXIT decide; END IF;
      IF p_action = 'APPROVE_MEMBERSHIP' THEN
        IF p_resource_ref !~ c_uuid THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        SELECT m.requested_by_ref, m.principal_ref INTO v_req_by, v_target FROM platform.tenant_membership m
         WHERE m.request_ref = p_resource_ref::pg_catalog.uuid AND m.tenant_id = p_tenant AND m.status = 'PENDING';
        IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        IF v_req_by = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
        IF v_target = v_principal THEN v_reason := 'SELF_ACCESS'; EXIT decide; END IF;
      ELSIF p_action = 'APPROVE_ROLE_ASSIGNMENT' THEN
        IF p_resource_ref !~ c_uuid THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        SELECT a.requested_by_ref, a.principal_ref INTO v_req_by, v_target FROM platform.platform_role_assignment a
         WHERE a.request_ref = p_resource_ref::pg_catalog.uuid AND a.status = 'PENDING';
        IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        IF v_req_by = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
        IF v_target = v_principal THEN v_reason := 'SELF_ACCESS'; EXIT decide; END IF;
      END IF;
    END IF;

    -- Step-up: nonce ATTESTED (platform.record_assertion, verifier) ligado a (principal, accion, tenant, refs), vigente y no consumido.
    v_digest := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_resource_ref, 'UTF8')), 'hex');
    SELECT n.nonce_hash INTO v_nonce FROM platform.action_nonce n
     WHERE n.principal_ref = v_principal AND n.action = p_action AND n.scope = v_scope AND n.tenant_id IS NOT DISTINCT FROM p_tenant
       AND n.refs_digest = v_digest AND n.attested_at IS NOT NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     ORDER BY n.issued_at LIMIT 1 FOR UPDATE;
    IF v_nonce IS NULL THEN v_reason := 'STEP_UP_MISSING'; EXIT decide; END IF;
    IF p_consume THEN
      UPDATE platform.action_nonce SET consumed_at = pg_catalog.now() WHERE nonce_hash = v_nonce AND consumed_at IS NULL;
      IF NOT FOUND THEN v_reason := 'STEP_UP_MISSING'; EXIT decide; END IF;
    END IF;
  END;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('AUTHORIZE', p_tenant,
          CASE WHEN v_scope IS NOT NULL THEN p_action END,
          CASE WHEN v_principal ~ c_principal THEN v_principal END,
          CASE WHEN v_re IS NOT NULL AND p_resource_ref ~ v_re THEN p_resource_ref END,
          CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  RETURN v_reason IS NULL;
END
$$;

-- platform.issue_action_nonce (v2): principal_ref UUIDv4 estricto; politica ADR010-PR4-v1. Resto igual que 0035.
CREATE OR REPLACE FUNCTION platform.issue_action_nonce(p_action text, p_refs text[], p_tenant_id uuid, p_ttl_seconds integer)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy    constant text := 'ADR010-PR4-v1';
  c_principal constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  c_princ     constant text := '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
  c_uuid      constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
  c_member    constant text := '^' || c_princ || ':(TENANT_ADMIN|INVITER)$';
  c_roleas    constant text := '^' || c_princ || ':(PLATFORM|RIGHTS_OPERATOR|APPROVER|CONTEXT_OWNER)(:(PRIVACY_LEGAL|SECURITY))?$';
  v_principal text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_re        text;
  v_scope     text;
  v_reason    text := NULL;
  v_nonce     text;
  v_digest    text;
BEGIN
  <<decide>>
  BEGIN
    v_scope := CASE p_action
      WHEN 'REQUEST_MEMBERSHIP' THEN 'TENANT' WHEN 'APPROVE_MEMBERSHIP' THEN 'TENANT'
      WHEN 'REQUEST_ROLE_ASSIGNMENT' THEN 'PLATFORM' WHEN 'APPROVE_ROLE_ASSIGNMENT' THEN 'PLATFORM' END;
    IF v_scope IS NULL THEN v_reason := 'UNKNOWN_ACTION'; EXIT decide; END IF;
    v_re := CASE p_action WHEN 'REQUEST_MEMBERSHIP' THEN c_member WHEN 'REQUEST_ROLE_ASSIGNMENT' THEN c_roleas ELSE c_uuid END;
    IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; EXIT decide; END IF;
    IF p_refs IS NULL OR pg_catalog.cardinality(p_refs) <> 1 OR p_refs[1] IS NULL OR p_refs[1] !~ v_re THEN v_reason := 'INVALID_RESOURCE'; EXIT decide; END IF;
    IF (v_scope = 'TENANT') <> (p_tenant_id IS NOT NULL) THEN v_reason := 'TENANT_SCOPE'; EXIT decide; END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 3600 THEN v_reason := 'INVALID_TTL'; EXIT decide; END IF;
    IF session_user <> 'platform_rw' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    IF NOT EXISTS (SELECT 1 FROM platform.platform_role_assignment a
                    WHERE a.principal_ref = v_principal AND a.platform_role = 'PLATFORM' AND a.status = 'ACTIVE') THEN
      v_reason := 'NO_ROLE'; EXIT decide;
    END IF;
    -- 244 bits de aleatoriedad (dos UUIDv4); solo se persiste el hash.
    v_nonce := pg_catalog.replace(pg_catalog.gen_random_uuid()::pg_catalog.text || pg_catalog.gen_random_uuid()::pg_catalog.text, '-', '');
    v_digest := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_refs[1], 'UTF8')), 'hex');
    INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at)
    VALUES (pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_nonce, 'UTF8')), 'hex'), v_scope, p_tenant_id, p_action, v_digest, v_principal,
            pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_seconds));
  END;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('ISSUE_NONCE', p_tenant_id,
          CASE WHEN v_scope IS NOT NULL THEN p_action END,
          CASE WHEN v_principal ~ c_principal THEN v_principal END,
          CASE WHEN p_refs IS NOT NULL AND pg_catalog.cardinality(p_refs) = 1 AND v_re IS NOT NULL AND p_refs[1] ~ v_re THEN p_refs[1] END,
          CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  IF v_reason IS NOT NULL THEN RETURN NULL; END IF;
  RETURN v_nonce;
END
$$;

-- platform.enqueue_oidc_exchange (platform_rw): encola code + PKCE (secretos operativos) ligados al nonce de step-up vigente del principal de la transaccion.
-- platform NO canjea (sin egress): el verifier lo hace. Devuelve exchange_ref o NULL (DENY con evidencia).
CREATE FUNCTION platform.enqueue_oidc_exchange(p_binding text, p_code text, p_pkce_verifier text, p_ttl_seconds integer)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy    constant text := 'ADR010-PR4-v1';
  c_principal constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  v_principal text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_reason    text := NULL;
  v_ref       uuid;
  v_action    text;
  v_tenant    uuid;
BEGIN
  <<decide>>
  BEGIN
    IF v_principal IS NULL OR v_principal !~ c_principal THEN v_reason := 'NO_PRINCIPAL'; EXIT decide; END IF;
    IF session_user <> 'platform_rw' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 600 THEN v_reason := 'INVALID_TTL'; EXIT decide; END IF;
    IF p_binding IS NULL OR p_binding !~ '^[0-9a-f]{64}$' OR p_code IS NULL OR pg_catalog.length(p_code) > 512 OR p_code !~ '^[!-~]+$'
       OR p_pkce_verifier IS NULL OR p_pkce_verifier !~ '^[A-Za-z0-9._~-]{43,128}$' THEN
      v_reason := 'INVALID_INPUT'; EXIT decide;
    END IF;
    SELECT n.action, n.tenant_id INTO v_action, v_tenant FROM platform.action_nonce n
     WHERE n.nonce_hash = p_binding AND n.principal_ref = v_principal AND n.attested_at IS NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now();
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    INSERT INTO platform.oidc_exchange (binding, principal_ref, code, pkce_verifier, expires_at)
    VALUES (p_binding, v_principal, p_code, p_pkce_verifier, pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_seconds))
    ON CONFLICT (binding) WHERE status = 'PENDING' DO NOTHING
    RETURNING exchange_ref INTO v_ref;
    IF v_ref IS NULL THEN v_reason := 'DUPLICATE_EXCHANGE'; EXIT decide; END IF;
  END;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('ENQUEUE_EXCHANGE', v_tenant, v_action, CASE WHEN v_principal ~ c_principal THEN v_principal END, NULL,
          CASE WHEN v_reason IS NULL THEN 'ALLOW' ELSE 'DENY' END, COALESCE(v_reason, 'OK'), c_policy);
  RETURN v_ref;
END
$$;

-- platform.claim_oidc_exchange (integrity_verifier): toma UNA solicitud PENDING vigente y sin lease activo, fija el lease y devuelve los secretos. Sin DENY
-- ruidoso: cualquier otro llamador recibe 0 filas. La transaccion del verifier NO debe quedar abierta durante el canje (lease en vez de FOR UPDATE largo).
CREATE FUNCTION platform.claim_oidc_exchange(p_lease_seconds integer)
  RETURNS TABLE (o_exchange_ref uuid, o_binding text, o_principal_ref text, o_code text, o_pkce_verifier text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF session_user <> 'integrity_verifier' OR p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 120 THEN
    RETURN;
  END IF;
  RETURN QUERY
  WITH pick AS (
    SELECT e.exchange_ref FROM platform.oidc_exchange e
     WHERE e.status = 'PENDING' AND e.expires_at > pg_catalog.now() AND (e.claimed_until IS NULL OR e.claimed_until <= pg_catalog.now())
     ORDER BY e.created_at LIMIT 1 FOR UPDATE SKIP LOCKED),
  upd AS (
    UPDATE platform.oidc_exchange x SET claimed_until = pg_catalog.now() + pg_catalog.make_interval(secs => p_lease_seconds)
      FROM pick WHERE x.exchange_ref = pick.exchange_ref
    RETURNING x.exchange_ref, x.binding, x.principal_ref, x.code, x.pkce_verifier)
  SELECT upd.exchange_ref, upd.binding, upd.principal_ref, upd.code, upd.pkce_verifier FROM upd;
END
$$;

-- platform.record_assertion (integrity_verifier): UNICA forma de fijar action_nonce.attested_at. En una sola transaccion: cierra la solicitud (anula code + PKCE),
-- guarda la asercion (solo claims minimos) y, si es ATTESTED, atesta el nonce del binding. DB-side (N6): el sub_hmac debe ser el mapeado a principal_ref en
-- platform.principal_identity, o se degrada a REJECTED/SUB_MISMATCH aunque el verifier pida ATTESTED. Devuelve true solo si quedo ATTESTED.
CREATE FUNCTION platform.record_assertion(
    p_exchange_ref uuid, p_decision text, p_reason text, p_sub_hmac text, p_assertion_hash text, p_auth_time timestamptz, p_acr text, p_amr text[])
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy   constant text := 'ADR010-PR4-v1';
  c_hex      constant text := '^[0-9a-f]{64}$';
  v_ex       platform.oidc_exchange%ROWTYPE;
  v_found    boolean := false;
  v_reason   text := NULL;
  v_decision text := 'REJECTED';
  v_mapped   text;
  v_action   text;
  v_tenant   uuid;
  v_input_ok boolean;
BEGIN
  <<decide>>
  BEGIN
    IF session_user <> 'integrity_verifier' THEN v_reason := 'CALLER_ROLE'; EXIT decide; END IF;
    SELECT * INTO v_ex FROM platform.oidc_exchange e
     WHERE e.exchange_ref = p_exchange_ref AND e.status = 'PENDING' AND e.expires_at > pg_catalog.now() FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'EXCHANGE_NOT_FOUND'; EXIT decide; END IF;
    v_found := true;
    v_input_ok := COALESCE(p_decision IN ('ATTESTED', 'REJECTED')
      AND (p_sub_hmac IS NULL OR p_sub_hmac ~ c_hex) AND (p_assertion_hash IS NULL OR p_assertion_hash ~ c_hex)
      AND (p_acr IS NULL OR p_acr ~ '^[A-Za-z0-9:._-]{1,128}$')
      AND (p_amr IS NULL OR (pg_catalog.cardinality(p_amr) BETWEEN 1 AND 8 AND pg_catalog.array_to_string(p_amr, ',') ~ '^[A-Za-z0-9:._-]{1,64}(,[A-Za-z0-9:._-]{1,64}){0,7}$'))
      AND (p_decision = 'REJECTED' OR (p_sub_hmac IS NOT NULL AND p_assertion_hash IS NOT NULL AND p_auth_time IS NOT NULL))
      AND (p_decision = 'ATTESTED' OR p_reason IN ('SUB_MISMATCH', 'INVALID_CLAIMS', 'EXCHANGE_FAILED')), false);
    IF NOT v_input_ok THEN
      -- Entrada invalida: la solicitud se cierra REJECTED/INVALID_CLAIMS (y se anulan los secretos); nunca queda un ATTESTED parcial.
      v_reason := 'INVALID_CLAIMS'; EXIT decide;
    END IF;
    IF p_decision = 'REJECTED' THEN v_reason := p_reason; EXIT decide; END IF;

    -- ATTESTED solicitado: N6 (sub_hmac <-> principal_ref), auth_time razonable, nonce vigente del mismo principal y binding.
    SELECT i.sub_hmac INTO v_mapped FROM platform.principal_identity i WHERE i.principal_ref = v_ex.principal_ref;
    IF v_mapped IS NULL OR v_mapped <> p_sub_hmac THEN v_reason := 'SUB_MISMATCH'; EXIT decide; END IF;
    IF p_auth_time > pg_catalog.now() + interval '2 minutes' THEN v_reason := 'INVALID_CLAIMS'; EXIT decide; END IF;
    SELECT n.action, n.tenant_id INTO v_action, v_tenant FROM platform.action_nonce n
     WHERE n.nonce_hash = v_ex.binding AND n.principal_ref = v_ex.principal_ref AND n.attested_at IS NULL AND n.consumed_at IS NULL AND n.expires_at > pg_catalog.now()
     FOR UPDATE;
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    UPDATE platform.action_nonce SET attested_at = pg_catalog.now() WHERE nonce_hash = v_ex.binding AND attested_at IS NULL;
    IF NOT FOUND THEN v_reason := 'NONCE_NOT_FOUND'; EXIT decide; END IF;
    v_decision := 'ATTESTED';
  END;

  IF v_found THEN
    IF v_decision = 'REJECTED' AND v_action IS NULL THEN
      SELECT n.action, n.tenant_id INTO v_action, v_tenant FROM platform.action_nonce n WHERE n.nonce_hash = v_ex.binding AND n.principal_ref = v_ex.principal_ref;
    END IF;
    UPDATE platform.oidc_exchange SET status = v_decision, code = NULL, pkce_verifier = NULL, decided_at = pg_catalog.now() WHERE exchange_ref = v_ex.exchange_ref;
    INSERT INTO platform.grant_assertion (exchange_ref, binding, principal_ref, decision, reason_code, sub_hmac, assertion_hash, auth_time, acr, amr)
    VALUES (v_ex.exchange_ref, v_ex.binding, v_ex.principal_ref, v_decision, CASE WHEN v_decision = 'REJECTED' THEN COALESCE(v_reason, 'INVALID_CLAIMS') END,
            CASE WHEN v_input_ok THEN p_sub_hmac END, CASE WHEN v_input_ok THEN p_assertion_hash END, CASE WHEN v_input_ok THEN p_auth_time END,
            CASE WHEN v_input_ok THEN p_acr END, CASE WHEN v_input_ok THEN p_amr END);
  END IF;

  INSERT INTO platform.authorization_check (check_kind, tenant_id, action, principal_ref, resource_ref, decision, reason_code, policy_version)
  VALUES ('RECORD_ASSERTION', v_tenant, v_action, CASE WHEN v_found THEN v_ex.principal_ref END, NULL,
          CASE WHEN v_decision = 'ATTESTED' THEN 'ALLOW' ELSE 'DENY' END,
          CASE WHEN v_decision = 'ATTESTED' THEN 'OK' ELSE COALESCE(v_reason, 'INVALID_CLAIMS') END, c_policy);
  RETURN v_decision = 'ATTESTED';
END
$$;

-- platform.purge_expired_oidc_exchange (worker): borra las solicitudes vencidas (el guard solo admite DELETE de filas con expires_at <= now()).
CREATE FUNCTION platform.purge_expired_oidc_exchange()
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_n integer;
BEGIN
  IF session_user <> 'worker' THEN RETURN NULL; END IF;
  DELETE FROM platform.oidc_exchange WHERE expires_at <= pg_catalog.now();
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

REVOKE ALL ON FUNCTION platform.enqueue_oidc_exchange(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.claim_oidc_exchange(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.purge_expired_oidc_exchange() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.enqueue_oidc_exchange(text, text, text, integer) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.claim_oidc_exchange(integer) TO integrity_verifier;
GRANT EXECUTE ON FUNCTION platform.record_assertion(uuid, text, text, text, text, timestamptz, text, text[]) TO integrity_verifier;
GRANT EXECUTE ON FUNCTION platform.purge_expired_oidc_exchange() TO worker;

-- 3. Revocar el CREATE temporal; nadie salvo el dueno del esquema lo conserva.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM membership_owner, grant_owner;
SET LOCAL ROLE consent_owner;

-- 4. Aserciones: la migracion aborta si algo no quedo como se declara. Se consulta el catalogo por nombre.
DO $assert$
DECLARE
  t record;
  r text;
  expect_exec jsonb := pg_catalog.jsonb_build_object(
    'request_membership',       ARRAY['app_rw', 'platform_rw'],
    'approve_membership',       ARRAY['platform_rw'],
    'request_role_assignment',  ARRAY['platform_rw'],
    'approve_role_assignment',  ARRAY['platform_rw'],
    'authorize',                ARRAY['platform_rw'],
    'issue_action_nonce',       ARRAY['platform_rw'],
    'authorize_target',         ARRAY['membership_owner'],
    'membership_guard',         ARRAY[]::text[],
    'membership_no_truncate',   ARRAY[]::text[],
    'action_nonce_guard',       ARRAY[]::text[],
    'authorization_check_guard', ARRAY[]::text[],
    'identity_guard',           ARRAY[]::text[],
    'oidc_exchange_guard',      ARRAY[]::text[],
    'deny_guard',               ARRAY[]::text[],
    'enqueue_oidc_exchange',    ARRAY['platform_rw'],
    'claim_oidc_exchange',      ARRAY['integrity_verifier'],
    'record_assertion',         ARRAY['integrity_verifier'],
    'purge_expired_oidc_exchange', ARRAY['worker']);
  expect_owner jsonb := pg_catalog.jsonb_build_object(
    'request_membership', 'membership_owner', 'approve_membership', 'membership_owner', 'request_role_assignment', 'membership_owner',
    'approve_role_assignment', 'membership_owner', 'membership_guard', 'membership_owner', 'membership_no_truncate', 'membership_owner',
    'authorize', 'grant_owner', 'issue_action_nonce', 'grant_owner', 'authorize_target', 'grant_owner', 'action_nonce_guard', 'grant_owner',
    'authorization_check_guard', 'grant_owner', 'identity_guard', 'membership_owner', 'oidc_exchange_guard', 'grant_owner', 'deny_guard', 'grant_owner',
    'enqueue_oidc_exchange', 'grant_owner', 'claim_oidc_exchange', 'grant_owner', 'record_assertion', 'grant_owner', 'purge_expired_oidc_exchange', 'grant_owner');
BEGIN
  -- Esquema: dueno y CREATE.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'platform' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'platform_schema_owner') THEN
    RAISE EXCEPTION 'el esquema platform no pertenece a platform_schema_owner';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'tenant_resolve_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier'] LOOP
    IF NOT pg_catalog.has_schema_privilege(r, 'platform', 'USAGE') THEN RAISE EXCEPTION '% sin USAGE en el esquema platform', r; END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['consent_owner', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'USAGE') THEN RAISE EXCEPTION '% no debe tener USAGE en el esquema platform', r; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a
              WHERE n.nspname = 'platform' AND a.grantee = 0) THEN
    RAISE EXCEPTION 'PUBLIC tiene privilegios sobre el esquema platform';
  END IF;

  -- Relaciones: exactamente 4 tablas, con su dueno, ENABLE + FORCE RLS; indices y secuencias del mismo dueno que su tabla.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND c.relkind NOT IN ('r', 'i')) <> 0 THEN
    RAISE EXCEPTION 'platform solo debe tener tablas e indices en PR-4';
  END IF;
  FOR t IN SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.pg_get_userbyid(c.relowner) AS owner
             FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'platform' AND c.relkind = 'r' LOOP
    IF t.relname NOT IN ('tenant_membership', 'platform_role_assignment', 'principal_identity', 'action_nonce', 'authorization_check', 'oidc_exchange', 'grant_assertion') THEN
      RAISE EXCEPTION 'tabla inesperada platform.%', t.relname;
    END IF;
    IF (t.relname IN ('tenant_membership', 'platform_role_assignment', 'principal_identity') AND t.owner <> 'membership_owner')
       OR (t.relname IN ('action_nonce', 'authorization_check', 'oidc_exchange', 'grant_assertion') AND t.owner <> 'grant_owner') THEN
      RAISE EXCEPTION 'platform.% no pertenece a su dueno declarado', t.relname;
    END IF;
    IF NOT (t.relrowsecurity AND t.relforcerowsecurity) THEN RAISE EXCEPTION 'platform.% sin ENABLE/FORCE ROW LEVEL SECURITY', t.relname; END IF;
    FOREACH r IN ARRAY ARRAY['consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'tenant_resolve_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'] LOOP
      IF pg_catalog.has_table_privilege(r, t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR pg_catalog.has_any_column_privilege(r, t.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
        RAISE EXCEPTION '% tiene privilegios sobre platform.%', r, t.relname;
      END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE((SELECT c2.relacl FROM pg_catalog.pg_class c2 WHERE c2.oid = t.oid), pg_catalog.acldefault('r', (SELECT c3.relowner FROM pg_catalog.pg_class c3 WHERE c3.oid = t.oid)))) a WHERE a.grantee = 0) THEN
      RAISE EXCEPTION 'PUBLIC tiene privilegios sobre platform.%', t.relname;
    END IF;
    -- grant_owner solo SELECT por columnas sobre las tablas de membership; membership_owner nada sobre las de grant_owner.
    IF t.relname IN ('tenant_membership', 'platform_role_assignment', 'principal_identity') THEN
      IF pg_catalog.has_table_privilege('grant_owner', t.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR pg_catalog.has_any_column_privilege('grant_owner', t.oid, 'INSERT,UPDATE,REFERENCES')
         OR pg_catalog.has_table_privilege('grant_owner', t.oid, 'SELECT') THEN
        RAISE EXCEPTION 'grant_owner solo debe tener SELECT por columnas sobre platform.%', t.relname;
      END IF;
    ELSIF pg_catalog.has_any_column_privilege('membership_owner', t.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_table_privilege('membership_owner', t.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
      RAISE EXCEPTION 'membership_owner tiene privilegios sobre platform.%', t.relname;
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relkind = 'r') <> 7 THEN
    RAISE EXCEPTION 'platform debe tener exactamente 7 tablas en PR-4';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_class tbl ON tbl.oid = (SELECT i.indrelid FROM pg_catalog.pg_index i WHERE i.indexrelid = c.oid)
              WHERE n.nspname = 'platform' AND c.relkind = 'i' AND c.relowner <> tbl.relowner) THEN
    RAISE EXCEPTION 'hay indices de platform con dueno distinto del de su tabla';
  END IF;

  -- Policies exactas (nombre, comando, roles). polcmd: a=INSERT, r=SELECT, w=UPDATE, d=DELETE.
  FOR t IN SELECT * FROM (VALUES
      ('tenant_membership', 'tenant_membership_authorize_select:r:grant_owner tenant_membership_owner_insert:a:membership_owner tenant_membership_owner_select:r:membership_owner tenant_membership_owner_update:w:membership_owner'),
      ('platform_role_assignment', 'platform_role_assignment_authorize_select:r:grant_owner platform_role_assignment_owner_insert:a:membership_owner platform_role_assignment_owner_select:r:membership_owner platform_role_assignment_owner_update:w:membership_owner'),
      ('principal_identity', 'principal_identity_authorize_select:r:grant_owner principal_identity_owner_insert:a:membership_owner principal_identity_owner_select:r:membership_owner'),
      ('oidc_exchange', 'oidc_exchange_owner_delete:d:grant_owner oidc_exchange_owner_insert:a:grant_owner oidc_exchange_owner_select:r:grant_owner oidc_exchange_owner_update:w:grant_owner'),
      ('grant_assertion', 'grant_assertion_owner_insert:a:grant_owner grant_assertion_owner_select:r:grant_owner'),
      ('action_nonce', 'action_nonce_owner_insert:a:grant_owner action_nonce_owner_select:r:grant_owner action_nonce_owner_update:w:grant_owner'),
      ('authorization_check', 'authorization_check_owner_insert:a:grant_owner authorization_check_owner_select:r:grant_owner')
    ) AS v(tbl, expected) LOOP
    IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
          FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'platform' AND c.relname = t.tbl) IS DISTINCT FROM t.expected THEN
      RAISE EXCEPTION 'las policies de platform.% no son exactamente las declaradas (rol y comando)', t.tbl;
    END IF;
  END LOOP;

  -- Triggers: 14, ENABLE ALWAYS (guardas por fila UPDATE/DELETE y TRUNCATE por sentencia).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND NOT g.tgisinternal AND g.tgenabled = 'A') <> 14
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'platform' AND NOT g.tgisinternal) <> 14
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'platform' AND NOT g.tgisinternal AND (g.tgtype & 2) = 2 AND (((g.tgtype & 1) = 1 AND (g.tgtype & 8) = 8 AND (g.tgtype & 16) = 16) OR ((g.tgtype & 1) = 0 AND (g.tgtype & 32) = 32))) <> 14 THEN
    RAISE EXCEPTION 'los triggers de platform deben ser 14, BEFORE y ENABLE ALWAYS (UPDATE/DELETE por fila o TRUNCATE por sentencia)';
  END IF;

  -- Funciones: conjunto exacto, dueno, SECURITY DEFINER donde corresponde, search_path fijo, EXECUTE exacto.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform') <> 18 THEN
    RAISE EXCEPTION 'platform debe tener exactamente 18 funciones en PR-4';
  END IF;
  FOR t IN SELECT p.oid, p.proname, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc, pg_catalog.pg_get_userbyid(p.proowner) AS owner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' LOOP
    IF NOT (expect_exec ? t.proname) THEN RAISE EXCEPTION 'funcion inesperada platform.%()', t.proname; END IF;
    IF t.owner <> (expect_owner ->> t.proname) THEN RAISE EXCEPTION 'platform.%() no pertenece a %', t.proname, expect_owner ->> t.proname; END IF;
    IF t.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION 'platform.%() sin search_path fijo exacto', t.proname; END IF;
    IF t.prosecdef <> (t.proname NOT LIKE '%guard' AND t.proname <> 'membership_no_truncate') THEN RAISE EXCEPTION 'platform.%(): SECURITY DEFINER inesperado', t.proname; END IF;
    IF pg_catalog.has_function_privilege('public', t.oid, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar platform.%()', t.proname; END IF;
    -- P2-8: sin SQL dinamico y ACL cerrada: el conjunto de grantees (distintos del dueno) es EXACTAMENTE el declarado, de cualquier rol.
    IF t.prosrc ~* '\mexecute\M' THEN RAISE EXCEPTION 'platform.%() contiene EXECUTE (SQL dinamico prohibido)', t.proname; END IF;
    IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
          FROM pg_catalog.aclexplode(COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))) a WHERE a.grantee <> t.proowner)
       IS DISTINCT FROM (SELECT pg_catalog.string_agg(x, ',' ORDER BY x COLLATE "C") FROM pg_catalog.jsonb_array_elements_text(expect_exec -> t.proname) AS x) THEN
      RAISE EXCEPTION 'la ACL de platform.%() no es exactamente la declarada', t.proname;
    END IF;
    FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'grant_owner', 'transition_owner', 'platform_schema_owner'] LOOP
      IF r <> t.owner AND pg_catalog.has_function_privilege(r, t.oid, 'EXECUTE') <> COALESCE((expect_exec -> t.proname) ? r, false) THEN
        RAISE EXCEPTION 'EXECUTE de platform.%() para % distinto del declarado', t.proname, r;
      END IF;
    END LOOP;
  END LOOP;

  -- P2-8: ACL de tablas, columnas, esquema y triggers cerradas frente a cualquier rol (no solo los nombrados arriba).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                    pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
              WHERE n.nspname = 'platform' AND c.relkind = 'r' AND a.grantee <> c.relowner) THEN
    RAISE EXCEPTION 'las tablas de platform solo pueden tener ACL de su dueno (cualquier otro grantee, incluido PUBLIC, esta prohibido)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid = att.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                    pg_catalog.aclexplode(att.attacl) a
              WHERE n.nspname = 'platform' AND att.attacl IS NOT NULL
                AND (pg_catalog.pg_get_userbyid(a.grantee) <> 'grant_owner' OR a.privilege_type <> 'SELECT' OR c.relname NOT IN ('tenant_membership', 'platform_role_assignment', 'principal_identity'))) THEN
    RAISE EXCEPTION 'las ACL de columnas de platform solo admiten SELECT para grant_owner sobre las tablas de membership';
  END IF;
  IF (SELECT pg_catalog.string_agg(c.relname::pg_catalog.text || '.' || att.attname::pg_catalog.text, ',' ORDER BY (c.relname::pg_catalog.text || '.' || att.attname::pg_catalog.text) COLLATE "C")
        FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid = att.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND att.attnum > 0 AND NOT att.attisdropped AND att.attacl IS NOT NULL)
     IS DISTINCT FROM 'platform_role_assignment.platform_role,platform_role_assignment.principal_ref,platform_role_assignment.request_ref,platform_role_assignment.requested_by_ref,platform_role_assignment.status,principal_identity.principal_ref,principal_identity.sub_hmac,tenant_membership.membership_role,tenant_membership.principal_ref,tenant_membership.request_ref,tenant_membership.requested_by_ref,tenant_membership.status,tenant_membership.tenant_id' THEN
    RAISE EXCEPTION 'las columnas con SELECT de grant_owner no son exactamente las que usa authorize_target';
  END IF;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'platform' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'app_rw:USAGE,grant_owner:USAGE,integrity_verifier:USAGE,membership_owner:USAGE,platform_rw:USAGE,worker:USAGE' THEN
    RAISE EXCEPTION 'la ACL del esquema platform no es exactamente USAGE para app_rw, platform_rw, worker, integrity_verifier, membership_owner y grant_owner';
  END IF;
  IF (SELECT pg_catalog.string_agg(g.tgname::pg_catalog.text || ':' || p.proname::pg_catalog.text, ',' ORDER BY g.tgname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid = g.tgfoid
       WHERE n.nspname = 'platform' AND NOT g.tgisinternal)
     IS DISTINCT FROM 'action_nonce_guard:action_nonce_guard,action_nonce_no_truncate:authorization_check_guard,authorization_check_append_only:authorization_check_guard,authorization_check_no_truncate:authorization_check_guard,grant_assertion_immutable:deny_guard,grant_assertion_no_truncate:deny_guard,oidc_exchange_guard:oidc_exchange_guard,oidc_exchange_no_truncate:deny_guard,platform_role_assignment_guard:membership_guard,platform_role_assignment_no_truncate:membership_no_truncate,principal_identity_guard:identity_guard,principal_identity_no_truncate:membership_no_truncate,tenant_membership_guard:membership_guard,tenant_membership_no_truncate:membership_no_truncate' THEN
    RAISE EXCEPTION 'el mapeo trigger -> funcion de platform no es el declarado';
  END IF;
  -- PR-4: principal_ref UUIDv4 estricto (sin staff-synthetic-) en TODA constraint y funcion de platform; no_self_approval; secretos del canje solo PENDING.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_namespace n ON n.oid = k.connamespace
              WHERE n.nspname = 'platform' AND pg_catalog.pg_get_constraintdef(k.oid) ~* 'staff-synthetic') THEN
    RAISE EXCEPTION 'hay constraints de platform que aun admiten la forma staff-synthetic- (F-A10-12)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.prosrc ~* 'staff-synthetic') THEN
    RAISE EXCEPTION 'hay funciones de platform que aun admiten la forma staff-synthetic- (F-A10-12)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_namespace n ON n.oid = k.connamespace
       WHERE n.nspname = 'platform' AND k.contype = 'c' AND k.conname IN ('tenant_membership_no_self_approval', 'platform_role_assignment_no_self_approval')
         AND pg_catalog.pg_get_constraintdef(k.oid) ~ 'approved_by_ref <> principal_ref') <> 2 THEN
    RAISE EXCEPTION 'faltan los CHECK no_self_approval (decision 6 de Carlos, 2026-10-11)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_namespace n ON n.oid = k.connamespace
       WHERE n.nspname = 'platform' AND k.conname IN ('oidc_exchange_secrets_iff_pending', 'principal_identity_sub_hmac_unique', 'principal_identity_pkey', 'grant_assertion_exchange_unique')) <> 4 THEN
    RAISE EXCEPTION 'faltan constraints de oidc_exchange / principal_identity / grant_assertion (N4, F-A10-12)';
  END IF;
END
$assert$;
