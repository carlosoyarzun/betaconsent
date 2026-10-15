-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7 (sesiones PLATFORM y CASE), §6 (la sesion vive en `platform`), §10 fila PR-6c, §11.3 G-5..G-8;
-- seguridad rev. c (puntos 5 y 6) y revision de seguridad de 6b (F-PR6-32, F-PR6-36, F-PR6-37). Depende de 0050/0051. 0000-0051 estan mergeadas y son inmutables.
--
-- Que agrega (solo esquema `platform`; patron 0050: SET LOCAL ROLE del owner, CREATE temporal concedido y revocado, $assert$ final):
--   grant_owner : * platform.platform_session (nueva): sesiones PLATFORM y CASE de operador. Solo guarda sha256(sid) (el sid lo genera la BASE y solo viaja en la cookie), el principal que fijo la
--                   asercion LOGIN consumida (nunca la request), la asercion consumida (UNIQUE: una asercion abre a lo sumo una sesion), y en CASE el caso, el tenant del grant, el grant y la sesion
--                   PLATFORM de la que cuelga. Vida absoluta <= 4 h e inactividad <= 15 min (P-36 PLATFORM y P-25 CASE, SEC-CNS-006 rev. 5 §1, ACCEPTED 2026-09-26; la sesion CASE ademas vence con su grant). Append-only salvo avanzar last_seen_at y revocar una vez. Nada se borra (retencion = LEGAL DECISION LD-15/P-34).
--                 * platform.rights_case_grant (nueva): lo que open_case_session necesita para exigir un grant atestado y vigente (§5.2 paso 7). Vida <= 4 h (P-23; por defecto 2 h lo fija approve_grant en 6d; renovar = nueva doble aprobacion). SIN camino de escritura de runtime:
--                   request_grant/approve_grant requieren step-up (GRD-RC-12) y son 6d (F-PR6-40); mientras no existan, ningun rol puede abrir una sesion CASE (fail-closed). platform.grant_request (P-37, 1 h) se crea
--                   solo como estructura. Los tests siembran filas con superusuario.
--                 * platform.session_event se extiende: PLATFORM_LOGIN, PLATFORM_LOGOUT, CASE_LOGIN, CASE_LOGOUT, SESSION_ROTATED, con session_kind, session_ref y case_ref (UUIDv4 opaco). Sin IP.
-- Idempotencia: el runner aplica cada migracion una vez (checksum); las sentencias no se repiten.

-- 0. CREATE temporal para grant_owner (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. session_event: tipos de sesion y columnas de sesion (los eventos de 0050 no cambian).
ALTER TABLE platform.session_event DROP CONSTRAINT session_event_type_enum;
ALTER TABLE platform.session_event
  ADD COLUMN session_kind text CONSTRAINT session_event_session_kind_enum CHECK (session_kind IN ('PLATFORM', 'CASE')),
  ADD COLUMN session_ref  uuid,
  ADD COLUMN case_ref     text CONSTRAINT session_event_case_ref_shape CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE platform.session_event
  ADD CONSTRAINT session_event_type_enum CHECK (event_type IN
    ('LOGIN_REJECTED', 'LOGIN_PRINCIPAL_MISMATCH', 'LIMIT_EXCEEDED', 'STEP_UP_BEGIN', 'PLATFORM_LOGIN', 'PLATFORM_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_ROTATED')),
  -- Los eventos de sesion llevan sesion y principal; PLATFORM_* no llevan caso; CASE_* si; SESSION_ROTATED puede ser de cualquier clase.
  ADD CONSTRAINT session_event_session_shape CHECK (
    (event_type IN ('PLATFORM_LOGIN', 'PLATFORM_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_ROTATED')) = (session_ref IS NOT NULL AND session_kind IS NOT NULL AND principal_ref IS NOT NULL)),
  -- case_ref (UUIDv4 opaco): obligatorio en CASE_LOGIN/CASE_LOGOUT; en SESSION_ROTATED solo si la sesion es CASE; opcional en LOGIN_REJECTED (rechazo de open_case_session); nunca en el resto.
  ADD CONSTRAINT session_event_case_shape CHECK (
    (event_type IN ('CASE_LOGIN', 'CASE_LOGOUT') AND case_ref IS NOT NULL)
    OR (event_type = 'SESSION_ROTATED' AND (session_kind = 'CASE') = (case_ref IS NOT NULL))
    OR event_type = 'LOGIN_REJECTED'
    OR (event_type NOT IN ('CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_ROTATED', 'LOGIN_REJECTED') AND case_ref IS NULL)),
  ADD CONSTRAINT session_event_session_kind_matches_type CHECK (
    event_type NOT IN ('PLATFORM_LOGIN', 'PLATFORM_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT') OR session_kind = CASE WHEN event_type LIKE 'PLATFORM\_%' THEN 'PLATFORM' ELSE 'CASE' END);
CREATE INDEX session_event_session_idx ON platform.session_event (session_ref) WHERE session_ref IS NOT NULL;

-- 2. rights_case_grant (minima y provisional; ver cabecera).
CREATE TABLE platform.rights_case_grant (
  grant_ref               uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT rights_case_grant_pkey PRIMARY KEY,
  tenant_id               uuid        NOT NULL,
  case_ref                text        NOT NULL CONSTRAINT rights_case_grant_case_ref_shape CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  operator_principal_ref  text        NOT NULL CONSTRAINT rights_case_grant_principal_shape CHECK (operator_principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  attested_at             timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at              timestamptz NOT NULL,
  revoked_at              timestamptz,
  data_class              text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT rights_case_grant_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- P-23: valid_until - valid_from <= 4 h (attested_at = valid_from, expires_at = valid_until).
  CONSTRAINT rights_case_grant_life CHECK (expires_at > attested_at AND expires_at <= attested_at + interval '4 hours')
);
CREATE INDEX rights_case_grant_lookup_idx ON platform.rights_case_grant (operator_principal_ref, case_ref, expires_at);

CREATE FUNCTION platform.rights_case_grant_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Unica mutacion: revocar una vez (revoked_at NULL -> instante, resto identico). Nada se borra.
  IF TG_OP = 'UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
     AND (NEW.grant_ref, NEW.tenant_id, NEW.case_ref, NEW.operator_principal_ref, NEW.attested_at, NEW.expires_at, NEW.data_class)
         IS NOT DISTINCT FROM (OLD.grant_ref, OLD.tenant_id, OLD.case_ref, OLD.operator_principal_ref, OLD.attested_at, OLD.expires_at, OLD.data_class) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.rights_case_grant: solo se revoca una vez; no se borra ni se edita (ADR-010 §6, GRD-RC-10)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.rights_case_grant_guard() FROM PUBLIC;

-- 2b. grant_request (estructura; P-37, SEC-CNS-006 rev. 5 §1, ACCEPTED 2026-09-26): la solicitud pendiente expira a 1 h sin aprobacion; una vencida NO es aprobable (CHECK approved_at <= expires_at); el
-- aprobador es distinto del solicitante (GRD-RC-10). SIN camino de escritura de runtime: request_grant/approve_grant (con step-up, GRD-RC-12) son 6d. La solicitud vencida se registra al intentar aprobarla (6d).
CREATE TABLE platform.grant_request (
  request_ref            uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT grant_request_pkey PRIMARY KEY,
  tenant_id              uuid        NOT NULL,
  case_ref               text        NOT NULL CONSTRAINT grant_request_case_ref_shape CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  operator_principal_ref text        NOT NULL CONSTRAINT grant_request_operator_shape CHECK (operator_principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  requested_by_ref       text        NOT NULL CONSTRAINT grant_request_requested_by_shape CHECK (requested_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  requested_at           timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at             timestamptz NOT NULL,
  status                 text        NOT NULL DEFAULT 'PENDING' CONSTRAINT grant_request_status_enum CHECK (status IN ('PENDING', 'APPROVED')),
  approved_by_ref        text        CONSTRAINT grant_request_approved_by_shape CHECK (approved_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  approved_at            timestamptz,
  data_class             text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT grant_request_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- P-37: expira a 1 h como maximo.
  CONSTRAINT grant_request_life CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '1 hour'),
  CONSTRAINT grant_request_approved_shape CHECK ((status = 'APPROVED') = (approved_by_ref IS NOT NULL AND approved_at IS NOT NULL)),
  CONSTRAINT grant_request_distinct_approver CHECK (approved_by_ref IS NULL OR approved_by_ref <> requested_by_ref),
  -- Vencida no es aprobable.
  CONSTRAINT grant_request_not_expired_when_approved CHECK (approved_at IS NULL OR (approved_at >= requested_at AND approved_at <= expires_at))
);

CREATE FUNCTION platform.grant_request_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Unica mutacion: PENDING -> APPROVED una vez (resto identico). Nada se borra.
  IF TG_OP = 'UPDATE' AND OLD.status = 'PENDING' AND NEW.status = 'APPROVED'
     AND (NEW.request_ref, NEW.tenant_id, NEW.case_ref, NEW.operator_principal_ref, NEW.requested_by_ref, NEW.requested_at, NEW.expires_at, NEW.data_class)
         IS NOT DISTINCT FROM (OLD.request_ref, OLD.tenant_id, OLD.case_ref, OLD.operator_principal_ref, OLD.requested_by_ref, OLD.requested_at, OLD.expires_at, OLD.data_class) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.grant_request: solo PENDING -> APPROVED una vez; no se borra ni se edita (ADR-010 §6, GRD-RC-10, P-37)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.grant_request_guard() FROM PUBLIC;

-- 3. platform_session.
CREATE TABLE platform.platform_session (
  session_ref        uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT platform_session_pkey PRIMARY KEY,
  sid_hash           text        NOT NULL CONSTRAINT platform_session_sid_hash_shape CHECK (sid_hash ~ '^[0-9a-f]{64}$') CONSTRAINT platform_session_sid_hash_unique UNIQUE,
  session_kind       text        NOT NULL CONSTRAINT platform_session_kind_enum CHECK (session_kind IN ('PLATFORM', 'CASE')),
  principal_ref      text        NOT NULL CONSTRAINT platform_session_principal_shape CHECK (principal_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  assertion_ref      uuid        NOT NULL CONSTRAINT platform_session_assertion_unique UNIQUE CONSTRAINT platform_session_assertion_fk REFERENCES platform.login_assertion (assertion_ref),
  parent_session_ref uuid        CONSTRAINT platform_session_parent_fk REFERENCES platform.platform_session (session_ref),
  tenant_id          uuid,
  case_ref           text        CONSTRAINT platform_session_case_ref_shape CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  grant_ref          uuid        CONSTRAINT platform_session_grant_fk REFERENCES platform.rights_case_grant (grant_ref),
  issued_at          timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at         timestamptz NOT NULL,
  idle_seconds       integer     NOT NULL CONSTRAINT platform_session_idle_range CHECK (idle_seconds BETWEEN 60 AND 900),
  last_seen_at       timestamptz NOT NULL DEFAULT pg_catalog.now(),
  revoked_at         timestamptz,
  revoke_cause       text        CONSTRAINT platform_session_revoke_cause_enum CHECK (revoke_cause IN ('USER_LOGOUT', 'ROTATION', 'PARENT_REVOKED')),
  data_class         text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT platform_session_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- Techo de vida absoluta: 4 h (P-36 PLATFORM, P-25 CASE; aprobados).
  CONSTRAINT platform_session_life CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '4 hours'),
  CONSTRAINT platform_session_last_seen_in_life CHECK (last_seen_at >= issued_at),
  CONSTRAINT platform_session_case_shape CHECK ((session_kind = 'CASE') = (case_ref IS NOT NULL AND tenant_id IS NOT NULL AND grant_ref IS NOT NULL AND parent_session_ref IS NOT NULL)),
  CONSTRAINT platform_session_revoked_shape CHECK ((revoked_at IS NULL) = (revoke_cause IS NULL))
);
CREATE INDEX platform_session_principal_idx ON platform.platform_session (principal_ref) WHERE revoked_at IS NULL;
CREATE INDEX platform_session_parent_idx ON platform.platform_session (parent_session_ref) WHERE parent_session_ref IS NOT NULL;

CREATE FUNCTION platform.platform_session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Mutaciones permitidas (resto de columnas inmutables): avanzar last_seen_at (nunca retroceder) y revocar una vez (revoked_at + revoke_cause). Una sesion revocada no se reactiva. Nada se borra.
  IF TG_OP = 'UPDATE'
     AND (NEW.session_ref, NEW.sid_hash, NEW.session_kind, NEW.principal_ref, NEW.assertion_ref, NEW.parent_session_ref, NEW.tenant_id, NEW.case_ref, NEW.grant_ref, NEW.issued_at, NEW.expires_at, NEW.idle_seconds, NEW.data_class)
         IS NOT DISTINCT FROM (OLD.session_ref, OLD.sid_hash, OLD.session_kind, OLD.principal_ref, OLD.assertion_ref, OLD.parent_session_ref, OLD.tenant_id, OLD.case_ref, OLD.grant_ref, OLD.issued_at, OLD.expires_at, OLD.idle_seconds, OLD.data_class)
     AND NEW.last_seen_at >= OLD.last_seen_at
     AND ((OLD.revoked_at IS NULL AND OLD.revoke_cause IS NULL) OR (NEW.revoked_at, NEW.revoke_cause) IS NOT DISTINCT FROM (OLD.revoked_at, OLD.revoke_cause)) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.platform_session: solo avanza last_seen_at y se revoca una vez; no se edita ni se borra (ADR-010 §5.2)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.platform_session_guard() FROM PUBLIC;

CREATE TRIGGER grant_request_guard BEFORE UPDATE OR DELETE ON platform.grant_request
  FOR EACH ROW EXECUTE FUNCTION platform.grant_request_guard();
CREATE TRIGGER grant_request_no_truncate BEFORE TRUNCATE ON platform.grant_request
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
ALTER TABLE platform.grant_request ENABLE ALWAYS TRIGGER grant_request_guard;
ALTER TABLE platform.grant_request ENABLE ALWAYS TRIGGER grant_request_no_truncate;
ALTER TABLE platform.grant_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.grant_request FORCE ROW LEVEL SECURITY;
CREATE POLICY grant_request_owner_select ON platform.grant_request FOR SELECT TO grant_owner USING (true);
CREATE POLICY grant_request_owner_insert ON platform.grant_request FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY grant_request_owner_update ON platform.grant_request FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
REVOKE ALL ON platform.grant_request FROM PUBLIC;

CREATE TRIGGER platform_session_guard BEFORE UPDATE OR DELETE ON platform.platform_session
  FOR EACH ROW EXECUTE FUNCTION platform.platform_session_guard();
CREATE TRIGGER platform_session_no_truncate BEFORE TRUNCATE ON platform.platform_session
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
CREATE TRIGGER rights_case_grant_guard BEFORE UPDATE OR DELETE ON platform.rights_case_grant
  FOR EACH ROW EXECUTE FUNCTION platform.rights_case_grant_guard();
CREATE TRIGGER rights_case_grant_no_truncate BEFORE TRUNCATE ON platform.rights_case_grant
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_guard();
ALTER TABLE platform.platform_session ENABLE ALWAYS TRIGGER platform_session_guard;
ALTER TABLE platform.platform_session ENABLE ALWAYS TRIGGER platform_session_no_truncate;
ALTER TABLE platform.rights_case_grant ENABLE ALWAYS TRIGGER rights_case_grant_guard;
ALTER TABLE platform.rights_case_grant ENABLE ALWAYS TRIGGER rights_case_grant_no_truncate;

ALTER TABLE platform.platform_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.platform_session FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_session_owner_select ON platform.platform_session FOR SELECT TO grant_owner USING (true);
CREATE POLICY platform_session_owner_insert ON platform.platform_session FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY platform_session_owner_update ON platform.platform_session FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
REVOKE ALL ON platform.platform_session FROM PUBLIC;

ALTER TABLE platform.rights_case_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.rights_case_grant FORCE ROW LEVEL SECURITY;
CREATE POLICY rights_case_grant_owner_select ON platform.rights_case_grant FOR SELECT TO grant_owner USING (true);
CREATE POLICY rights_case_grant_owner_insert ON platform.rights_case_grant FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY rights_case_grant_owner_update ON platform.rights_case_grant FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
REVOKE ALL ON platform.rights_case_grant FROM PUBLIC;

-- 4. Revocar el CREATE temporal.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

-- 5. Aserciones (fail-closed). consent_owner no tiene USAGE en platform: los objetos se resuelven por catalogo (oid).
DO $assert$
DECLARE
  r text;
  t text;
  rel record;
BEGIN
  FOREACH t IN ARRAY ARRAY['platform_session', 'rights_case_grant', 'grant_request'] LOOP
    SELECT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity, c.relacl INTO rel
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = t;
    IF rel.oid IS NULL THEN RAISE EXCEPTION 'falta platform.%', t; END IF;
    IF pg_catalog.pg_get_userbyid(rel.relowner) <> 'grant_owner' THEN RAISE EXCEPTION 'platform.% no pertenece a grant_owner', t; END IF;
    IF NOT (rel.relrowsecurity AND rel.relforcerowsecurity) THEN RAISE EXCEPTION 'platform.% sin ENABLE + FORCE RLS', t; END IF;
    FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'] LOOP
      IF pg_catalog.has_table_privilege(r, rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR pg_catalog.has_any_column_privilege(r, rel.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
        RAISE EXCEPTION '% tiene privilegios sobre platform.%', r, t;
      END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(rel.relacl, pg_catalog.acldefault('r', rel.relowner))) a WHERE a.grantee = 0) THEN
      RAISE EXCEPTION 'PUBLIC tiene privilegios sobre platform.%', t;
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.string_agg(c.relname::pg_catalog.text || '/' || g.tgname::pg_catalog.text || ':' || g.tgenabled::pg_catalog.text, ',' ORDER BY c.relname::pg_catalog.text COLLATE "C", g.tgname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE NOT g.tgisinternal AND s.nspname = 'platform' AND c.relname IN ('platform_session', 'rights_case_grant', 'grant_request'))
     IS DISTINCT FROM 'grant_request/grant_request_guard:A,grant_request/grant_request_no_truncate:A,platform_session/platform_session_guard:A,platform_session/platform_session_no_truncate:A,rights_case_grant/rights_case_grant_guard:A,rights_case_grant/rights_case_grant_no_truncate:A' THEN
    RAISE EXCEPTION 'triggers de platform_session/rights_case_grant: no son exactamente los cuatro ENABLE ALWAYS';
  END IF;
  IF (SELECT pg_catalog.string_agg(c.relname::pg_catalog.text || '/' || p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':'
                                   || (SELECT pg_catalog.string_agg(CASE WHEN x.oid = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x.oid)::pg_catalog.text END, ',' ORDER BY x.oid)
                                         FROM pg_catalog.unnest(p.polroles) AS x(oid)), ' ' ORDER BY c.relname::pg_catalog.text COLLATE "C", p.polname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname IN ('platform_session', 'rights_case_grant', 'grant_request'))
     IS DISTINCT FROM 'grant_request/grant_request_owner_insert:a:grant_owner grant_request/grant_request_owner_select:r:grant_owner grant_request/grant_request_owner_update:w:grant_owner platform_session/platform_session_owner_insert:a:grant_owner platform_session/platform_session_owner_select:r:grant_owner platform_session/platform_session_owner_update:w:grant_owner rights_case_grant/rights_case_grant_owner_insert:a:grant_owner rights_case_grant/rights_case_grant_owner_select:r:grant_owner rights_case_grant/rights_case_grant_owner_update:w:grant_owner' THEN
    RAISE EXCEPTION 'policies de platform_session/rights_case_grant no son exactamente las esperadas (solo grant_owner)';
  END IF;
  -- session_event: tipos y columnas de sesion.
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname = 'session_event' AND k.conname = 'session_event_type_enum') NOT LIKE '%SESSION_ROTATED%' THEN
    RAISE EXCEPTION 'session_event_type_enum no incluye los eventos de sesion (6c)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname = 'session_event' AND a.attname IN ('session_kind', 'session_ref', 'case_ref') AND NOT a.attisdropped) <> 3 THEN
    RAISE EXCEPTION 'session_event: faltan session_kind/session_ref/case_ref';
  END IF;
  -- platform_session: forma de las vidas (techo de 4 h) y del CASE.
  IF (SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname = 'platform_session' AND k.conname = 'platform_session_life') NOT LIKE '%04:00:00%' THEN
    RAISE EXCEPTION 'platform_session_life perdio el techo de 4 h (P-36/P-25)';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
