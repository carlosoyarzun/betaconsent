-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (columnas y estados de oidc_exchange, CHECK de secretos, principal_ref), §5.2 (login sin principal
-- previo), §5.4 (P-48..P-52), §6 (F-PR6-16: principal_identity versionada), §10 fila PR-6b; decisiones G-5, G-6, G-7, G-8 (2026-10-15); FINDINGs F-PR6-01/02/15/16/17/18/26/27/31.
-- Regla de Carlos (2026-10-01): 0000-0045 estan mergeadas y son inmutables; esta migracion es nueva (primera de PR-6b; las funciones llegan en 0051).
--
-- Que cambia (solo esquema `platform`; patron 0036: SET LOCAL ROLE de los owners, CREATE temporal concedido y revocado, $assert$ final):
--   membership_owner : platform.principal_identity pasa a PK (principal_ref, key_version) + UNIQUE (key_version, sub_hmac) (F-PR6-16). key_version arranca en 1 (la rotacion de K_sub,
--                      re-alta con doble HMAC, es PR-7).
--   grant_owner      : * action_nonce.action amplia su enum con PROPOSE_/APPROVE_/WITHDRAW_CASE_VERIFICATION, REQUEST_GRANT y APPROVE_GRANT (§5.1; las funciones que los usan llegan en 6c/6d).
--                      * oidc_exchange gana kind (LOGIN_PLATFORM | LOGIN_CASE | STEP_UP), state_hash (NOT NULL, UNIQUE, sha256 hex del `state` del navegador), target_ref_hash (solo LOGIN_CASE:
--                        hash del case_ref destino; G-7, F-PR6-27) y el estado AWAITING_CALLBACK (code NULL, PKCE NOT NULL). principal_ref pasa a NULL solo en LOGIN_PLATFORM (P6-1).
--                        El CHECK de secretos (0036) se reemplaza: AWAITING_CALLBACK code NULL + PKCE; PENDING ambos; decididas ninguno. El guard admite AWAITING_CALLBACK -> PENDING (solo fija code).
--                      * platform.login_assertion (nueva): la asercion LOGIN (ATTESTED | REJECTED), ligada a exchange_ref, state_hash, kind, principal resuelto por la BASE y target_ref_hash;
--                        vida <= 5 min contada desde auth_time (P-52, G-7; el CHECK fija el techo en 5 min); un solo uso (consumed_at). NUNCA guarda sub_hmac ni claims en claro (P2(f)).
--                        Los rechazos solo guardan motivo en codigo, hora y, si la base lo resolvio, el principal (necesario para contar P-48; no es el sub).
--                      * platform.session_event (nueva): eventos de login rechazado, principal distinto en LOGIN_CASE, limites excedidos (P-48..P-51, P-53) e inicios de step-up (P-51). Sin IP, ni
--                        completa ni truncada (F-PR6-31). Append-only. 6c la extiende con PLATFORM_LOGIN/LOGOUT y CASE_*.
--                      * authorization_check.reason_code suma RATE_LIMITED y AWAITING_CAP (evidencia del inicio de STEP_UP, 0051).
-- Retencion de login_assertion/session_event: LEGAL DECISION LD-15/P-34 (datos del equipo, Ley 21.719): sin purga en esta migracion.
-- Idempotencia: el runner aplica cada migracion una vez (checksum); las sentencias no se repiten.

-- 0. CREATE temporal para los owners de objetos (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO membership_owner, grant_owner;

-- 1. membership_owner: identidad versionada (F-PR6-16).
SET LOCAL ROLE membership_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER TABLE platform.principal_identity
  ADD COLUMN key_version smallint NOT NULL DEFAULT 1
  CONSTRAINT principal_identity_key_version_range CHECK (key_version BETWEEN 1 AND 1000);
ALTER TABLE platform.principal_identity
  DROP CONSTRAINT principal_identity_pkey,
  DROP CONSTRAINT principal_identity_sub_hmac_unique;
ALTER TABLE platform.principal_identity
  ADD CONSTRAINT principal_identity_pkey PRIMARY KEY (principal_ref, key_version),
  ADD CONSTRAINT principal_identity_version_sub_hmac_unique UNIQUE (key_version, sub_hmac);
-- grant_owner (record_login_assertion, 0051) resuelve el principal por (key_version, sub_hmac).
GRANT SELECT (key_version) ON platform.principal_identity TO grant_owner;

-- 2. grant_owner: enums, oidc_exchange, login_assertion y session_event.
SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER TABLE platform.action_nonce DROP CONSTRAINT action_nonce_action_enum;
ALTER TABLE platform.action_nonce
  ADD CONSTRAINT action_nonce_action_enum CHECK (action IN
    ('REQUEST_MEMBERSHIP', 'APPROVE_MEMBERSHIP', 'REQUEST_ROLE_ASSIGNMENT', 'APPROVE_ROLE_ASSIGNMENT',
     'PROPOSE_CASE_VERIFICATION', 'APPROVE_CASE_VERIFICATION', 'WITHDRAW_CASE_VERIFICATION', 'REQUEST_GRANT', 'APPROVE_GRANT'));

ALTER TABLE platform.authorization_check DROP CONSTRAINT authorization_check_reason_enum;
ALTER TABLE platform.authorization_check
  ADD CONSTRAINT authorization_check_reason_enum CHECK (reason_code IN
    ('OK', 'UNKNOWN_ACTION', 'NO_PRINCIPAL', 'INVALID_RESOURCE', 'TENANT_SCOPE', 'CALLER_ROLE', 'NO_ROLE', 'TENANT_MISMATCH', 'REQUEST_NOT_FOUND', 'SELF_APPROVAL', 'STEP_UP_MISSING', 'INVALID_TTL',
     'SELF_ACCESS', 'INVALID_INPUT', 'NONCE_NOT_FOUND', 'DUPLICATE_EXCHANGE', 'EXCHANGE_NOT_FOUND', 'SUB_MISMATCH', 'INVALID_CLAIMS', 'EXCHANGE_FAILED', 'RETRY_LIMIT',
     'RATE_LIMITED', 'AWAITING_CAP'));

-- oidc_exchange: las filas previas (flujo 0036) son STEP_UP; un state_hash aleatorio de relleno las hace unicas (la fila nunca tuvo state). Los DEFAULT se retiran de inmediato.
ALTER TABLE platform.oidc_exchange
  ADD COLUMN kind text NOT NULL DEFAULT 'STEP_UP',
  ADD COLUMN state_hash text NOT NULL DEFAULT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.gen_random_uuid()::pg_catalog.text, 'UTF8')), 'hex'),
  ADD COLUMN target_ref_hash text;
ALTER TABLE platform.oidc_exchange
  ALTER COLUMN kind DROP DEFAULT,
  ALTER COLUMN state_hash DROP DEFAULT,
  ALTER COLUMN principal_ref DROP NOT NULL;
ALTER TABLE platform.oidc_exchange
  ADD CONSTRAINT oidc_exchange_kind_enum CHECK (kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE', 'STEP_UP')),
  ADD CONSTRAINT oidc_exchange_state_hash_shape CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT oidc_exchange_target_ref_hash_shape CHECK (target_ref_hash ~ '^[0-9a-f]{64}$'),
  -- G-7 / F-PR6-27: solo LOGIN_CASE ata la operacion (hash del case_ref destino).
  ADD CONSTRAINT oidc_exchange_target_iff_login_case CHECK ((kind = 'LOGIN_CASE') = (target_ref_hash IS NOT NULL)),
  -- P6-1: LOGIN_PLATFORM nace SIN principal; LOGIN_CASE (el de la sesion PLATFORM) y STEP_UP (el del nonce) lo traen.
  ADD CONSTRAINT oidc_exchange_principal_iff_not_login_platform CHECK ((kind = 'LOGIN_PLATFORM') = (principal_ref IS NULL));
ALTER TABLE platform.oidc_exchange DROP CONSTRAINT oidc_exchange_status_enum;
ALTER TABLE platform.oidc_exchange
  ADD CONSTRAINT oidc_exchange_status_enum CHECK (status IN ('AWAITING_CALLBACK', 'PENDING', 'ATTESTED', 'REJECTED'));
ALTER TABLE platform.oidc_exchange DROP CONSTRAINT oidc_exchange_secrets_iff_pending;
ALTER TABLE platform.oidc_exchange
  ADD CONSTRAINT oidc_exchange_secrets_iff_pending CHECK (
    (status = 'AWAITING_CALLBACK' AND code IS NULL AND pkce_verifier IS NOT NULL AND decided_at IS NULL)
    OR (status = 'PENDING' AND code IS NOT NULL AND pkce_verifier IS NOT NULL AND decided_at IS NULL)
    OR (status IN ('ATTESTED', 'REJECTED') AND code IS NULL AND pkce_verifier IS NULL AND decided_at IS NOT NULL));
-- binding unico mientras la solicitud esta viva (antes solo PENDING); state_hash unico siempre (la fila vive hasta expirar; no se reusa un state).
DROP INDEX platform.oidc_exchange_pending_binding;
CREATE UNIQUE INDEX oidc_exchange_live_binding ON platform.oidc_exchange (binding) WHERE status IN ('AWAITING_CALLBACK', 'PENDING');
CREATE UNIQUE INDEX oidc_exchange_state_hash_unique ON platform.oidc_exchange (state_hash);
CREATE INDEX oidc_exchange_awaiting_idx ON platform.oidc_exchange (expires_at) WHERE status = 'AWAITING_CALLBACK';

CREATE OR REPLACE FUNCTION platform.oidc_exchange_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- DELETE solo de filas ya vencidas (purga del worker). UPDATE (columnas de identidad inmutables):
  --   AWAITING_CALLBACK -> PENDING   solo fija code (el PKCE se conserva) y no toca lease ni decision;
  --   PENDING -> PENDING             solo fija claimed_until (lease);
  --   PENDING -> ATTESTED|REJECTED   cierra y anula secretos.
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at <= pg_catalog.now() THEN RETURN OLD; END IF;
  ELSIF TG_OP = 'UPDATE' AND OLD.status IN ('AWAITING_CALLBACK', 'PENDING')
        AND (NEW.exchange_ref, NEW.binding, NEW.principal_ref, NEW.kind, NEW.state_hash, NEW.target_ref_hash, NEW.created_at, NEW.expires_at, NEW.data_class)
            IS NOT DISTINCT FROM (OLD.exchange_ref, OLD.binding, OLD.principal_ref, OLD.kind, OLD.state_hash, OLD.target_ref_hash, OLD.created_at, OLD.expires_at, OLD.data_class) THEN
    IF OLD.status = 'AWAITING_CALLBACK' THEN
      IF NEW.status = 'PENDING' AND NEW.code IS NOT NULL AND NEW.pkce_verifier IS NOT DISTINCT FROM OLD.pkce_verifier
         AND NEW.claimed_until IS NULL AND NEW.decided_at IS NULL THEN RETURN NEW; END IF;
    ELSE
      IF NEW.status = 'PENDING' AND (NEW.code, NEW.pkce_verifier, NEW.decided_at) IS NOT DISTINCT FROM (OLD.code, OLD.pkce_verifier, OLD.decided_at) THEN RETURN NEW; END IF;
      IF NEW.status IN ('ATTESTED', 'REJECTED') AND NEW.code IS NULL AND NEW.pkce_verifier IS NULL AND NEW.decided_at IS NOT NULL THEN RETURN NEW; END IF;
    END IF;
  END IF;
  RAISE EXCEPTION 'platform.oidc_exchange: solo AWAITING_CALLBACK -> PENDING (code), lease, cierre PENDING -> ATTESTED|REJECTED con secretos anulados, y borrado de filas vencidas (ADR-010 §4.3)'
    USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.oidc_exchange_guard() FROM PUBLIC;

-- Aserciones LOGIN (§5.2 paso 4). Sin sub_hmac ni claims en claro. principal_ref lo fija la BASE (record_login_assertion); en un rechazo solo se guarda si se llego a resolver.
CREATE TABLE platform.login_assertion (
  assertion_ref   uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT login_assertion_pkey PRIMARY KEY,
  exchange_ref    uuid        NOT NULL CONSTRAINT login_assertion_exchange_unique UNIQUE,
  kind            text        NOT NULL CONSTRAINT login_assertion_kind_enum CHECK (kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE')),
  state_hash      text        NOT NULL CONSTRAINT login_assertion_state_hash_shape CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  target_ref_hash text        CONSTRAINT login_assertion_target_ref_hash_shape CHECK (target_ref_hash ~ '^[0-9a-f]{64}$'),
  principal_ref   text        CONSTRAINT login_assertion_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  decision        text        NOT NULL CONSTRAINT login_assertion_decision_enum CHECK (decision IN ('ATTESTED', 'REJECTED')),
  reason_code     text        CONSTRAINT login_assertion_reason_enum CHECK (reason_code IN
    ('NO_MAPPING', 'ROLE_INACTIVE', 'AUTH_TIME_INVALID', 'INVALID_CLAIMS', 'EXCHANGE_FAILED', 'PRINCIPAL_MISMATCH', 'RATE_LIMITED', 'NOT_CONFIGURED')),
  assertion_hash  text        CONSTRAINT login_assertion_hash_shape CHECK (assertion_hash ~ '^[0-9a-f]{64}$'),
  auth_time       timestamptz,
  acr             text        CONSTRAINT login_assertion_acr_shape CHECK (acr ~ '^[A-Za-z0-9:._-]{1,128}$'),
  amr             text[]      CONSTRAINT login_assertion_amr_shape CHECK (pg_catalog.array_to_string(amr, ',') ~ '^[A-Za-z0-9:._-]{1,64}(,[A-Za-z0-9:._-]{1,64}){0,7}$'),
  recorded_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at      timestamptz,
  consumed_at     timestamptz,
  data_class      text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT login_assertion_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT login_assertion_target_iff_login_case CHECK ((kind = 'LOGIN_CASE') = (target_ref_hash IS NOT NULL)),
  CONSTRAINT login_assertion_reason_iff_rejected CHECK ((decision = 'REJECTED') = (reason_code IS NOT NULL)),
  -- ATTESTED: principal resuelto, claims minimos y vida (P-52) contada DESDE auth_time, con techo tecnico de 5 min (valor aprobado, G-7); un solo uso.
  CONSTRAINT login_assertion_attested_shape CHECK (decision <> 'ATTESTED' OR (
    principal_ref IS NOT NULL AND assertion_hash IS NOT NULL AND auth_time IS NOT NULL AND expires_at IS NOT NULL
    AND expires_at > auth_time AND expires_at <= auth_time + interval '5 minutes')),
  -- REJECTED: sin claims, sin vida ni consumo.
  CONSTRAINT login_assertion_rejected_shape CHECK (decision <> 'REJECTED' OR (
    assertion_hash IS NULL AND auth_time IS NULL AND acr IS NULL AND amr IS NULL AND expires_at IS NULL AND consumed_at IS NULL)),
  CONSTRAINT login_assertion_consumed_after_attested CHECK (consumed_at IS NULL OR decision = 'ATTESTED')
);
CREATE INDEX login_assertion_p48_idx ON platform.login_assertion (principal_ref, recorded_at) WHERE decision = 'REJECTED';

CREATE FUNCTION platform.login_assertion_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Unica mutacion: consumir una asercion ATTESTED una vez (consumed_at NULL -> instante, resto identico). Nada se borra.
  IF TG_OP = 'UPDATE' AND OLD.decision = 'ATTESTED' AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL
     AND (NEW.assertion_ref, NEW.exchange_ref, NEW.kind, NEW.state_hash, NEW.target_ref_hash, NEW.principal_ref, NEW.decision, NEW.reason_code, NEW.assertion_hash, NEW.auth_time, NEW.acr, NEW.amr, NEW.recorded_at, NEW.expires_at, NEW.data_class)
         IS NOT DISTINCT FROM (OLD.assertion_ref, OLD.exchange_ref, OLD.kind, OLD.state_hash, OLD.target_ref_hash, OLD.principal_ref, OLD.decision, OLD.reason_code, OLD.assertion_hash, OLD.auth_time, OLD.acr, OLD.amr, OLD.recorded_at, OLD.expires_at, OLD.data_class) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.login_assertion: solo se consume una vez una asercion ATTESTED; no se borra (ADR-010 §5.2, P-52)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.login_assertion_guard() FROM PUBLIC;

-- Eventos de sesion sin tenant (F-PR6-12). Sin IP (F-PR6-31) ni sub_hmac.
CREATE TABLE platform.session_event (
  event_ref          uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT session_event_pkey PRIMARY KEY,
  event_type         text        NOT NULL CONSTRAINT session_event_type_enum CHECK (event_type IN ('LOGIN_REJECTED', 'LOGIN_PRINCIPAL_MISMATCH', 'LIMIT_EXCEEDED', 'STEP_UP_BEGIN')),
  reason_code        text        CONSTRAINT session_event_reason_shape CHECK (reason_code ~ '^[A-Z_]{1,64}$'),
  kind               text        CONSTRAINT session_event_kind_enum CHECK (kind IN ('LOGIN_PLATFORM', 'LOGIN_CASE', 'STEP_UP')),
  principal_ref      text        CONSTRAINT session_event_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  peer_principal_ref text        CONSTRAINT session_event_peer_principal_shape CHECK (peer_principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  limit_kind         text        CONSTRAINT session_event_limit_kind_enum CHECK (limit_kind IN ('P-48', 'P-49', 'P-50', 'P-51', 'P-53')),
  window_seconds     integer     CONSTRAINT session_event_window_range CHECK (window_seconds BETWEEN 1 AND 86400),
  at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
  data_class         text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT session_event_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT session_event_limit_iff_exceeded CHECK ((event_type = 'LIMIT_EXCEEDED') = (limit_kind IS NOT NULL))
);
CREATE INDEX session_event_principal_idx ON platform.session_event (principal_ref, event_type, at);

CREATE TRIGGER login_assertion_guard BEFORE UPDATE OR DELETE ON platform.login_assertion
  FOR EACH ROW EXECUTE FUNCTION platform.login_assertion_guard();
CREATE TRIGGER login_assertion_no_truncate BEFORE TRUNCATE ON platform.login_assertion
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
CREATE TRIGGER session_event_immutable BEFORE UPDATE OR DELETE ON platform.session_event
  FOR EACH ROW EXECUTE FUNCTION platform.deny_guard();
CREATE TRIGGER session_event_no_truncate BEFORE TRUNCATE ON platform.session_event
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
ALTER TABLE platform.login_assertion ENABLE ALWAYS TRIGGER login_assertion_guard;
ALTER TABLE platform.login_assertion ENABLE ALWAYS TRIGGER login_assertion_no_truncate;
ALTER TABLE platform.session_event ENABLE ALWAYS TRIGGER session_event_immutable;
ALTER TABLE platform.session_event ENABLE ALWAYS TRIGGER session_event_no_truncate;

ALTER TABLE platform.login_assertion ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.login_assertion FORCE ROW LEVEL SECURITY;
CREATE POLICY login_assertion_owner_select ON platform.login_assertion FOR SELECT TO grant_owner USING (true);
CREATE POLICY login_assertion_owner_insert ON platform.login_assertion FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY login_assertion_owner_update ON platform.login_assertion FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
REVOKE ALL ON platform.login_assertion FROM PUBLIC;

ALTER TABLE platform.session_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.session_event FORCE ROW LEVEL SECURITY;
CREATE POLICY session_event_owner_select ON platform.session_event FOR SELECT TO grant_owner USING (true);
CREATE POLICY session_event_owner_insert ON platform.session_event FOR INSERT TO grant_owner WITH CHECK (true);
REVOKE ALL ON platform.session_event FROM PUBLIC;

-- 3. Revocar el CREATE temporal; nadie salvo el dueno del esquema lo conserva.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM membership_owner, grant_owner;
SET LOCAL ROLE consent_owner;

-- 4. Aserciones (fail-closed): estado exacto resultante. consent_owner no tiene USAGE en platform: los objetos se resuelven por catalogo (oid), nunca por regclass de texto.
DO $assert$
DECLARE
  r text;
  t text;
  n integer;
  o oid;
  v_pi oid;
  v_ox oid;
  v_an oid;
  rel record;
BEGIN
  SELECT c.oid INTO v_pi FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = 'principal_identity';
  SELECT c.oid INTO v_ox FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = 'oidc_exchange';
  SELECT c.oid INTO v_an FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = 'action_nonce';
  -- principal_identity versionada.
  IF (SELECT pg_catalog.string_agg(k.conname::pg_catalog.text, ',' ORDER BY k.conname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_constraint k WHERE k.conrelid = v_pi AND k.contype IN ('p', 'u'))
     IS DISTINCT FROM 'principal_identity_pkey,principal_identity_version_sub_hmac_unique' THEN
    RAISE EXCEPTION 'principal_identity: PK/UNIQUE no son exactamente (principal_ref, key_version) y (key_version, sub_hmac) (F-PR6-16)';
  END IF;
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k WHERE k.conname = 'principal_identity_pkey' AND k.conrelid = v_pi)
     IS DISTINCT FROM 'PRIMARY KEY (principal_ref, key_version)' THEN
    RAISE EXCEPTION 'principal_identity_pkey no es (principal_ref, key_version)';
  END IF;
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k WHERE k.conname = 'principal_identity_version_sub_hmac_unique' AND k.conrelid = v_pi)
     IS DISTINCT FROM 'UNIQUE (key_version, sub_hmac)' THEN
    RAISE EXCEPTION 'principal_identity_version_sub_hmac_unique no es (key_version, sub_hmac)';
  END IF;
  -- oidc_exchange: columnas y constraints.
  SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_attribute a
   WHERE a.attrelid = v_ox AND a.attnum > 0 AND NOT a.attisdropped
     AND a.attname IN ('kind', 'state_hash', 'target_ref_hash') AND (a.attname = 'target_ref_hash' OR a.attnotnull) AND a.atthasdef = false;
  IF n <> 3 THEN RAISE EXCEPTION 'oidc_exchange: kind/state_hash (NOT NULL, sin DEFAULT) y target_ref_hash deben existir'; END IF;
  IF (SELECT a.attnotnull FROM pg_catalog.pg_attribute a WHERE a.attrelid = v_ox AND a.attname = 'principal_ref') THEN
    RAISE EXCEPTION 'oidc_exchange.principal_ref debe admitir NULL (LOGIN_PLATFORM, P6-1)';
  END IF;
  SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_constraint k
   WHERE k.conrelid = v_ox
     AND k.conname IN ('oidc_exchange_kind_enum', 'oidc_exchange_state_hash_shape', 'oidc_exchange_target_ref_hash_shape', 'oidc_exchange_target_iff_login_case',
                       'oidc_exchange_principal_iff_not_login_platform', 'oidc_exchange_status_enum', 'oidc_exchange_secrets_iff_pending');
  IF n <> 7 THEN RAISE EXCEPTION 'oidc_exchange: faltan constraints (hay %, se esperaban 7)', n; END IF;
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k WHERE k.conname = 'oidc_exchange_status_enum' AND k.conrelid = v_ox)
     NOT LIKE '%AWAITING_CALLBACK%' THEN RAISE EXCEPTION 'oidc_exchange_status_enum no admite AWAITING_CALLBACK'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_indexes i WHERE i.schemaname = 'platform' AND i.tablename = 'oidc_exchange'
        AND i.indexname IN ('oidc_exchange_live_binding', 'oidc_exchange_state_hash_unique')) <> 2
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_indexes i WHERE i.schemaname = 'platform' AND i.indexname = 'oidc_exchange_pending_binding') THEN
    RAISE EXCEPTION 'oidc_exchange: indices de binding/state_hash incorrectos';
  END IF;
  -- action_nonce: el enum incluye las acciones de caso.
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k WHERE k.conname = 'action_nonce_action_enum' AND k.conrelid = v_an)
     NOT LIKE '%APPROVE_GRANT%' THEN RAISE EXCEPTION 'action_nonce_action_enum no incluye las acciones de caso (§5.1)'; END IF;
  -- Tablas nuevas: dueno, RLS forzada, sin privilegios para ningun rol de runtime ni PUBLIC.
  FOREACH t IN ARRAY ARRAY['login_assertion', 'session_event'] LOOP
    SELECT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity, c.relacl INTO rel
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = t;
    IF rel.oid IS NULL THEN RAISE EXCEPTION 'falta platform.%', t; END IF;
    o := rel.oid;
    IF pg_catalog.pg_get_userbyid(rel.relowner) <> 'grant_owner' THEN RAISE EXCEPTION 'platform.% no pertenece a grant_owner', t; END IF;
    IF NOT (rel.relrowsecurity AND rel.relforcerowsecurity) THEN RAISE EXCEPTION 'platform.% sin ENABLE + FORCE RLS', t; END IF;
    FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'] LOOP
      IF pg_catalog.has_table_privilege(r, o, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR pg_catalog.has_any_column_privilege(r, o, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
        RAISE EXCEPTION '% tiene privilegios sobre platform.%', r, t;
      END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(rel.relacl, pg_catalog.acldefault('r', rel.relowner))) a WHERE a.grantee = 0) THEN
      RAISE EXCEPTION 'PUBLIC tiene privilegios sobre platform.%', t;
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.string_agg(g.tgname::pg_catalog.text || ':' || g.tgenabled::pg_catalog.text, ',' ORDER BY g.tgname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE NOT g.tgisinternal AND s.nspname = 'platform' AND c.relname IN ('login_assertion', 'session_event'))
     IS DISTINCT FROM 'login_assertion_guard:A,login_assertion_no_truncate:A,session_event_immutable:A,session_event_no_truncate:A' THEN
    RAISE EXCEPTION 'triggers de login_assertion/session_event: no son exactamente los cuatro ENABLE ALWAYS';
  END IF;
  -- Policies: solo grant_owner.
  -- Incluye TODAS las policies de las dos tablas, tambien las de varios roles o de PUBLIC (polroles = {0}): el texto lista cada rol y una policy ajena rompe la igualdad.
  IF (SELECT pg_catalog.string_agg(c.relname::pg_catalog.text || '/' || p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':'
                                   || (SELECT pg_catalog.string_agg(CASE WHEN r.oid = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(r.oid)::pg_catalog.text END, ',' ORDER BY r.oid)
                                         FROM pg_catalog.unnest(p.polroles) AS r(oid)), ' ' ORDER BY c.relname::pg_catalog.text COLLATE "C", p.polname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname IN ('login_assertion', 'session_event'))
     IS DISTINCT FROM 'login_assertion/login_assertion_owner_insert:a:grant_owner login_assertion/login_assertion_owner_select:r:grant_owner login_assertion/login_assertion_owner_update:w:grant_owner session_event/session_event_owner_insert:a:grant_owner session_event/session_event_owner_select:r:grant_owner' THEN
    RAISE EXCEPTION 'policies de login_assertion/session_event no son exactamente las esperadas (solo grant_owner)';
  END IF;
  -- Nadie conserva CREATE en el esquema platform.
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
