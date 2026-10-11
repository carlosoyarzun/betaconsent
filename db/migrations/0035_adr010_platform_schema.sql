-- scope: database
-- Gobierna: ADR-010 rev. 4 §4.3 (punto 1, nonce), §4.4 (esquema platform, membership, role_assignment), §4.6 (authorization_check), §7 fila PR-3;
-- specs/db-roles.spec.yaml (platform_schema_owner, membership_owner, grant_owner; INV-DBR-01/03); contracts/openapi/consent-platform.openapi.yaml
-- (API-CNS-TBD-P07, P11..P14); decisiones de Carlos del 2026-10-11: Q-17 (a), Q-18, Q-19. Cierra DF-3, DF-11 y DF-12.
-- Regla de Carlos (2026-10-01): 0000-0034 no se editan; esta migracion es nueva. Corre como consent_owner (SET TRUE sobre los tres owners, Q-15 c).
--
-- Esquema `platform` con dueno propio (patron 0027): `CREATE SCHEMA platform AUTHORIZATION platform_schema_owner`. consent_owner NO es dueno
-- y no conserva privilegios sobre el esquema ni sobre sus objetos. Reparto de objetos (spec db-roles):
--   membership_owner : platform.tenant_membership, platform.platform_role_assignment y sus funciones de aprovisionamiento
--                      (request_membership, approve_membership, request_role_assignment, approve_role_assignment).
--   grant_owner      : platform.action_nonce, platform.authorization_check, platform.issue_action_nonce, platform.authorize,
--                      platform.authorize_target (PR-4/PR-5 agregan aserciones, grants y sesiones).
-- Las tablas tienen ENABLE + FORCE RLS y policies solo para su dueno (y SELECT por columnas para grant_owner sobre membership). NINGUN rol de
-- runtime tiene privilegios sobre ninguna tabla de platform (sin DML, Q4): solo EXECUTE de funciones SECURITY DEFINER.
-- Todas las funciones: SECURITY DEFINER, search_path = pg_catalog, pg_temp, sin SQL dinamico, EXECUTE revocado a PUBLIC.
--
-- Modelo de decision (platform.authorize_target, ADR-010 §4.6, Q6):
--   * El principal sale de la GUC de la transaccion `app.principal_ref` (opaco; nunca de un parametro ni de un email). El tenant del actor STAFF
--     sale de app.current_tenant_id(); el aprovisionamiento PLATFORM recibe el tenant destino como parametro (excepcion F-A10-07, OPEN: choca con
--     API-CNS-100; la revisa lampone-security).
--   * La ruta se liga al proceso con session_user: la via TENANT_ADMIN solo vale con session_user = app_rw (consola STAFF en web, Q-17) y solo para su
--     propio tenant; la via PLATFORM solo con session_user = platform_rw.
--   * Aprobar exige PLATFORM activo, solicitud PENDING, aprobador distinto del solicitante (tambien CHECK de la tabla) y un nonce de step-up
--     ATTESTED, ligado a (tenant, accion, refs, principal), vigente y no consumido. Quien marca ATTESTED es el verifier (PR-4, platform.record_assertion):
--     en PR-3 ninguna funcion lo hace, asi que toda ruta con step-up falla cerrada (STEP_UP_MISSING) hasta PR-4.
--   * Cada decision (ALLOW/DENY) se escribe en platform.authorization_check. Las funciones de aprovisionamiento NO lanzan excepcion ante un DENY:
--     devuelven NULL/false para que la fila de evidencia se confirme con la transaccion.
-- Contrato con el adapter (P2-7): el principal y el tenant se fijan SOLO con set_config('app.principal_ref' | 'app.tenant_id', ..., true) (local a la
-- transaccion). Ninguna GUC app.* puede venir de ALTER ROLE/DATABASE ... SET (startup-checks lo verifica). Ante un DENY el adapter debe hacer COMMIT.
-- resource_ref solo admite formas cerradas por accion (B1): APPROVE_* = UUID; REQUEST_MEMBERSHIP = principal:(TENANT_ADMIN|INVITER);
-- REQUEST_ROLE_ASSIGNMENT = principal:ROL(:CLASE)?. Cualquier otro texto (RUT, nombre, correo) es DENY INVALID_RESOURCE y se guarda NULL.
-- Ningun dato personal: principal_ref y resource_ref son refs opacas (sin '@'), data_class SYNTHETIC.

-- 0. Precondiciones de lectura de grant_owner (tenant de la transaccion): unico objeto de `app` que toca.
GRANT USAGE ON SCHEMA app TO grant_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO grant_owner;

-- 1. Esquema con dueno propio. Los CREATE de los dos owners de objetos son temporales (se revocan al final).
CREATE SCHEMA platform AUTHORIZATION platform_schema_owner;
SET LOCAL ROLE platform_schema_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA platform TO membership_owner, grant_owner;
GRANT USAGE ON SCHEMA platform TO app_rw, platform_rw;

-- 2. membership_owner: tablas, guardas y funciones de aprovisionamiento.
SET LOCAL ROLE membership_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE platform.tenant_membership (
  request_ref      uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT tenant_membership_pkey PRIMARY KEY,
  tenant_id        uuid        NOT NULL,
  principal_ref    text        NOT NULL CONSTRAINT tenant_membership_principal_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  membership_role  text        NOT NULL CONSTRAINT tenant_membership_role_enum CHECK (membership_role IN ('TENANT_ADMIN', 'INVITER')),
  status           text        NOT NULL DEFAULT 'PENDING' CONSTRAINT tenant_membership_status_enum CHECK (status IN ('PENDING', 'ACTIVE')),
  requested_by_ref text        NOT NULL CONSTRAINT tenant_membership_requested_by_shape CHECK (requested_by_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  requested_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  approved_by_ref  text        CONSTRAINT tenant_membership_approved_by_shape CHECK (approved_by_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  approved_at      timestamptz,
  data_class       text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT tenant_membership_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  -- Doble control impuesto por la base (Q4): ACTIVE exige aprobador distinto del solicitante; PENDING no tiene aprobacion.
  CONSTRAINT tenant_membership_double_control CHECK (
    (status = 'PENDING' AND approved_by_ref IS NULL AND approved_at IS NULL)
    OR (status = 'ACTIVE' AND approved_by_ref IS NOT NULL AND approved_at IS NOT NULL AND approved_by_ref <> requested_by_ref)),
  CONSTRAINT tenant_membership_unique UNIQUE (tenant_id, principal_ref, membership_role)
);

CREATE TABLE platform.platform_role_assignment (
  request_ref      uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT platform_role_assignment_pkey PRIMARY KEY,
  principal_ref    text        NOT NULL CONSTRAINT platform_role_assignment_principal_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  platform_role    text        NOT NULL CONSTRAINT platform_role_assignment_role_enum CHECK (platform_role IN ('PLATFORM', 'RIGHTS_OPERATOR', 'APPROVER', 'CONTEXT_OWNER')),
  approver_class   text        CONSTRAINT platform_role_assignment_approver_class_enum CHECK (approver_class IN ('PRIVACY_LEGAL', 'SECURITY')),
  status           text        NOT NULL DEFAULT 'PENDING' CONSTRAINT platform_role_assignment_status_enum CHECK (status IN ('PENDING', 'ACTIVE')),
  requested_by_ref text        NOT NULL CONSTRAINT platform_role_assignment_requested_by_shape CHECK (requested_by_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  requested_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  approved_by_ref  text        CONSTRAINT platform_role_assignment_approved_by_shape CHECK (approved_by_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  approved_at      timestamptz,
  data_class       text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT platform_role_assignment_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT platform_role_assignment_approver_class_iff CHECK ((platform_role = 'APPROVER') = (approver_class IS NOT NULL)),
  CONSTRAINT platform_role_assignment_double_control CHECK (
    (status = 'PENDING' AND approved_by_ref IS NULL AND approved_at IS NULL)
    OR (status = 'ACTIVE' AND approved_by_ref IS NOT NULL AND approved_at IS NOT NULL AND approved_by_ref <> requested_by_ref))
);
CREATE UNIQUE INDEX platform_role_assignment_unique ON platform.platform_role_assignment (principal_ref, platform_role, (COALESCE(approver_class, '')));

-- Guardas: la unica mutacion permitida es PENDING -> ACTIVE fijando approved_*; nada se borra ni se trunca (ENABLE ALWAYS: tampoco el dueno).
CREATE FUNCTION platform.membership_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- P2-4: toda fila nace PENDING (el CHECK de doble control ya exige approved_* nulos); ACTIVE solo por UPDATE.
  IF TG_OP = 'INSERT' THEN
    IF NEW.status = 'PENDING' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'platform.%: toda fila nace PENDING (ADR-010 §4.4)', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.status = 'PENDING' AND NEW.status = 'ACTIVE' THEN
      IF TG_TABLE_NAME = 'tenant_membership' THEN
        IF (NEW.request_ref, NEW.tenant_id, NEW.principal_ref, NEW.membership_role, NEW.requested_by_ref, NEW.requested_at, NEW.data_class)
           IS NOT DISTINCT FROM (OLD.request_ref, OLD.tenant_id, OLD.principal_ref, OLD.membership_role, OLD.requested_by_ref, OLD.requested_at, OLD.data_class) THEN
          RETURN NEW;
        END IF;
      ELSIF (NEW.request_ref, NEW.principal_ref, NEW.platform_role, NEW.approver_class, NEW.requested_by_ref, NEW.requested_at, NEW.data_class)
           IS NOT DISTINCT FROM (OLD.request_ref, OLD.principal_ref, OLD.platform_role, OLD.approver_class, OLD.requested_by_ref, OLD.requested_at, OLD.data_class) THEN
        RETURN NEW;
      END IF;
    END IF;
  END IF;
  RAISE EXCEPTION 'platform.%: solo se admite INSERT PENDING y PENDING -> ACTIVE con approved_*; no se borra ni se reescribe (ADR-010 §4.4)', TG_TABLE_NAME
    USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.membership_guard() FROM PUBLIC;

CREATE FUNCTION platform.membership_no_truncate() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'platform.%: TRUNCATE no permitido (ADR-010 §4.4)', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.membership_no_truncate() FROM PUBLIC;

CREATE TRIGGER tenant_membership_guard BEFORE INSERT OR UPDATE OR DELETE ON platform.tenant_membership
  FOR EACH ROW EXECUTE FUNCTION platform.membership_guard();
CREATE TRIGGER tenant_membership_no_truncate BEFORE TRUNCATE ON platform.tenant_membership
  FOR EACH STATEMENT EXECUTE FUNCTION platform.membership_no_truncate();
CREATE TRIGGER platform_role_assignment_guard BEFORE INSERT OR UPDATE OR DELETE ON platform.platform_role_assignment
  FOR EACH ROW EXECUTE FUNCTION platform.membership_guard();
CREATE TRIGGER platform_role_assignment_no_truncate BEFORE TRUNCATE ON platform.platform_role_assignment
  FOR EACH STATEMENT EXECUTE FUNCTION platform.membership_no_truncate();
ALTER TABLE platform.tenant_membership ENABLE ALWAYS TRIGGER tenant_membership_guard;
ALTER TABLE platform.tenant_membership ENABLE ALWAYS TRIGGER tenant_membership_no_truncate;
ALTER TABLE platform.platform_role_assignment ENABLE ALWAYS TRIGGER platform_role_assignment_guard;
ALTER TABLE platform.platform_role_assignment ENABLE ALWAYS TRIGGER platform_role_assignment_no_truncate;

ALTER TABLE platform.tenant_membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.tenant_membership FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_membership_owner_select ON platform.tenant_membership FOR SELECT TO membership_owner USING (true);
CREATE POLICY tenant_membership_owner_insert ON platform.tenant_membership FOR INSERT TO membership_owner WITH CHECK (true);
CREATE POLICY tenant_membership_owner_update ON platform.tenant_membership FOR UPDATE TO membership_owner USING (true) WITH CHECK (true);
CREATE POLICY tenant_membership_authorize_select ON platform.tenant_membership FOR SELECT TO grant_owner USING (true);
REVOKE ALL ON platform.tenant_membership FROM PUBLIC;

ALTER TABLE platform.platform_role_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.platform_role_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_role_assignment_owner_select ON platform.platform_role_assignment FOR SELECT TO membership_owner USING (true);
CREATE POLICY platform_role_assignment_owner_insert ON platform.platform_role_assignment FOR INSERT TO membership_owner WITH CHECK (true);
CREATE POLICY platform_role_assignment_owner_update ON platform.platform_role_assignment FOR UPDATE TO membership_owner USING (true) WITH CHECK (true);
CREATE POLICY platform_role_assignment_authorize_select ON platform.platform_role_assignment FOR SELECT TO grant_owner USING (true);
REVOKE ALL ON platform.platform_role_assignment FROM PUBLIC;

-- grant_owner (platform.authorize_target) lee solo las columnas que decide; nunca escribe en estas tablas.
GRANT SELECT (request_ref, tenant_id, principal_ref, membership_role, status, requested_by_ref) ON platform.tenant_membership TO grant_owner;
GRANT SELECT (request_ref, principal_ref, platform_role, status, requested_by_ref) ON platform.platform_role_assignment TO grant_owner;

-- Funciones de aprovisionamiento (dueno membership_owner). Reglas: nunca excepcion ante DENY (la evidencia de authorize se confirma);
-- devuelven NULL (solicitar) o false (aprobar). El actor es app.principal_ref (authorize_target); el tenant destino de PLATFORM es parametro.
CREATE FUNCTION platform.request_membership(p_tenant_id uuid, p_principal_ref text, p_membership_role text)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_requester text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_ref uuid;
  v_res text := CASE WHEN p_principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'
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

CREATE FUNCTION platform.approve_membership(p_request_ref uuid)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_approver text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_tenant uuid;
BEGIN
  -- Bloquea la solicitud antes de decidir (P2-2): el perdedor de una carrera ve la fila ya ACTIVE y recibe REQUEST_NOT_FOUND sin consumir su nonce.
  SELECT m.tenant_id INTO v_tenant FROM platform.tenant_membership m WHERE m.request_ref = p_request_ref AND m.status = 'PENDING' FOR UPDATE;
  IF NOT platform.authorize_target('APPROVE_MEMBERSHIP', p_request_ref::pg_catalog.text, v_tenant, true) THEN
    RETURN false;
  END IF;
  UPDATE platform.tenant_membership
     SET status = 'ACTIVE', approved_by_ref = v_approver, approved_at = pg_catalog.now()
   WHERE request_ref = p_request_ref AND status = 'PENDING';
  RETURN FOUND;
END
$$;

CREATE FUNCTION platform.request_role_assignment(p_principal_ref text, p_platform_role text, p_approver_class text)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_requester text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
  v_ref uuid;
  v_res text := CASE WHEN p_principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'
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

CREATE FUNCTION platform.approve_role_assignment(p_request_ref uuid)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_approver text := NULLIF(pg_catalog.current_setting('app.principal_ref', true), '');
BEGIN
  PERFORM 1 FROM platform.platform_role_assignment a WHERE a.request_ref = p_request_ref AND a.status = 'PENDING' FOR UPDATE;
  IF NOT platform.authorize_target('APPROVE_ROLE_ASSIGNMENT', p_request_ref::pg_catalog.text, NULL, true) THEN
    RETURN false;
  END IF;
  UPDATE platform.platform_role_assignment
     SET status = 'ACTIVE', approved_by_ref = v_approver, approved_at = pg_catalog.now()
   WHERE request_ref = p_request_ref AND status = 'PENDING';
  RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION platform.request_membership(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.approve_membership(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.request_role_assignment(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.approve_role_assignment(uuid) FROM PUBLIC;
-- Q-17 + Q4: web (app_rw) solo SOLICITA membership de TENANT_ADMIN; el resto es del equipo de LectorPro (platform_rw).
GRANT EXECUTE ON FUNCTION platform.request_membership(uuid, text, text) TO app_rw, platform_rw;
GRANT EXECUTE ON FUNCTION platform.approve_membership(uuid) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.request_role_assignment(text, text, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.approve_role_assignment(uuid) TO platform_rw;

-- 3. grant_owner: nonce de step-up, authorization_check y la decision.
SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Nonce emitido por la DB (ADR-010 §4.3.1): solo se guarda nonce_hash (sha256 hex); el nonce en claro sale una vez de issue_action_nonce.
CREATE TABLE platform.action_nonce (
  nonce_hash    text        NOT NULL CONSTRAINT action_nonce_pkey PRIMARY KEY CONSTRAINT action_nonce_hash_shape CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  scope         text        NOT NULL CONSTRAINT action_nonce_scope_enum CHECK (scope IN ('TENANT', 'PLATFORM')),
  tenant_id     uuid,
  action        text        NOT NULL CONSTRAINT action_nonce_action_enum CHECK (action IN ('REQUEST_MEMBERSHIP', 'APPROVE_MEMBERSHIP', 'REQUEST_ROLE_ASSIGNMENT', 'APPROVE_ROLE_ASSIGNMENT')),
  refs_digest   text        NOT NULL CONSTRAINT action_nonce_refs_digest_shape CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
  principal_ref text        NOT NULL CONSTRAINT action_nonce_principal_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  issued_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at    timestamptz NOT NULL,
  attested_at   timestamptz,
  consumed_at   timestamptz,
  data_class    text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT action_nonce_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT action_nonce_scope_tenant CHECK ((scope = 'TENANT') = (tenant_id IS NOT NULL)),
  -- Tope tecnico de vida (NO es P-36, que sigue pendiente de parametro): 1 h.
  CONSTRAINT action_nonce_life CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '1 hour'),
  CONSTRAINT action_nonce_consumed_after_attested CHECK (consumed_at IS NULL OR attested_at IS NOT NULL)
);
CREATE INDEX action_nonce_binding_idx ON platform.action_nonce (principal_ref, action, refs_digest);

-- DF-11: append-only; sin PII; ENABLE ALWAYS.
CREATE TABLE platform.authorization_check (
  check_ref      uuid        NOT NULL DEFAULT pg_catalog.gen_random_uuid() CONSTRAINT authorization_check_pkey PRIMARY KEY,
  check_kind     text        NOT NULL CONSTRAINT authorization_check_kind_enum CHECK (check_kind IN ('AUTHORIZE', 'ISSUE_NONCE')),
  tenant_id      uuid,
  action         text        CONSTRAINT authorization_check_action_shape CHECK (action ~ '^[A-Z_]{1,64}$'),
  principal_ref  text        CONSTRAINT authorization_check_principal_shape CHECK (principal_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'),
  resource_ref   text        CONSTRAINT authorization_check_resource_shape CHECK (
    resource_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    OR resource_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}):(TENANT_ADMIN|INVITER)$'
    OR resource_ref ~ '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}):(PLATFORM|RIGHTS_OPERATOR|APPROVER|CONTEXT_OWNER)(:(PRIVACY_LEGAL|SECURITY))?$'),
  decision       text        NOT NULL CONSTRAINT authorization_check_decision_enum CHECK (decision IN ('ALLOW', 'DENY')),
  reason_code    text        NOT NULL CONSTRAINT authorization_check_reason_enum CHECK (reason_code IN
    ('OK', 'UNKNOWN_ACTION', 'NO_PRINCIPAL', 'INVALID_RESOURCE', 'TENANT_SCOPE', 'CALLER_ROLE', 'NO_ROLE', 'TENANT_MISMATCH', 'REQUEST_NOT_FOUND', 'SELF_APPROVAL', 'STEP_UP_MISSING', 'INVALID_TTL')),
  policy_version text        NOT NULL,
  at             timestamptz NOT NULL DEFAULT pg_catalog.now(),
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT authorization_check_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT authorization_check_ok_iff_allow CHECK ((decision = 'ALLOW') = (reason_code = 'OK'))
);
CREATE INDEX authorization_check_tenant_at_idx ON platform.authorization_check (tenant_id, at);

CREATE FUNCTION platform.action_nonce_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Unica mutacion: fijar attested_at (NULL -> instante) y consumed_at (NULL -> instante, ya atestado). Nada se borra.
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.nonce_hash, NEW.scope, NEW.tenant_id, NEW.action, NEW.refs_digest, NEW.principal_ref, NEW.issued_at, NEW.expires_at, NEW.data_class)
         IS NOT DISTINCT FROM (OLD.nonce_hash, OLD.scope, OLD.tenant_id, OLD.action, OLD.refs_digest, OLD.principal_ref, OLD.issued_at, OLD.expires_at, OLD.data_class)
       AND (OLD.attested_at IS NULL OR NEW.attested_at IS NOT DISTINCT FROM OLD.attested_at)
       AND (OLD.consumed_at IS NULL OR NEW.consumed_at IS NOT DISTINCT FROM OLD.consumed_at) THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'platform.action_nonce: solo se fija attested_at y consumed_at una vez; no se borra (ADR-010 §4.3)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.action_nonce_guard() FROM PUBLIC;

CREATE FUNCTION platform.authorization_check_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'platform.authorization_check es append-only (ADR-010 §4.6, INV-CM-01)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.authorization_check_guard() FROM PUBLIC;

CREATE TRIGGER action_nonce_guard BEFORE UPDATE OR DELETE ON platform.action_nonce
  FOR EACH ROW EXECUTE FUNCTION platform.action_nonce_guard();
CREATE TRIGGER action_nonce_no_truncate BEFORE TRUNCATE ON platform.action_nonce
  FOR EACH STATEMENT EXECUTE FUNCTION platform.authorization_check_guard();
CREATE TRIGGER authorization_check_append_only BEFORE UPDATE OR DELETE ON platform.authorization_check
  FOR EACH ROW EXECUTE FUNCTION platform.authorization_check_guard();
CREATE TRIGGER authorization_check_no_truncate BEFORE TRUNCATE ON platform.authorization_check
  FOR EACH STATEMENT EXECUTE FUNCTION platform.authorization_check_guard();
ALTER TABLE platform.action_nonce ENABLE ALWAYS TRIGGER action_nonce_guard;
ALTER TABLE platform.action_nonce ENABLE ALWAYS TRIGGER action_nonce_no_truncate;
ALTER TABLE platform.authorization_check ENABLE ALWAYS TRIGGER authorization_check_append_only;
ALTER TABLE platform.authorization_check ENABLE ALWAYS TRIGGER authorization_check_no_truncate;

ALTER TABLE platform.action_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.action_nonce FORCE ROW LEVEL SECURITY;
CREATE POLICY action_nonce_owner_select ON platform.action_nonce FOR SELECT TO grant_owner USING (true);
CREATE POLICY action_nonce_owner_insert ON platform.action_nonce FOR INSERT TO grant_owner WITH CHECK (true);
CREATE POLICY action_nonce_owner_update ON platform.action_nonce FOR UPDATE TO grant_owner USING (true) WITH CHECK (true);
REVOKE ALL ON platform.action_nonce FROM PUBLIC;

ALTER TABLE platform.authorization_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.authorization_check FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_check_owner_select ON platform.authorization_check FOR SELECT TO grant_owner USING (true);
CREATE POLICY authorization_check_owner_insert ON platform.authorization_check FOR INSERT TO grant_owner WITH CHECK (true);
REVOKE ALL ON platform.authorization_check FROM PUBLIC;

-- platform.authorize_target: la decision. p_consume = true consume el nonce de step-up (una vez) cuando decide ALLOW por esa via.
CREATE FUNCTION platform.authorize_target(p_action text, p_resource_ref text, p_tenant uuid, p_consume boolean)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy      constant text := 'ADR010-PR3-v1';
  c_principal   constant text := '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$';
  c_princ       constant text := '(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})';
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
      -- Via TENANT_ADMIN (consola STAFF en web, Q-17): solo su propio tenant. Q4/§4.4: ambos con step-up ATTESTED, tambien esta via (B2); hasta PR-4 falla cerrado.
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
        IF p_resource_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        SELECT m.requested_by_ref INTO v_req_by FROM platform.tenant_membership m
         WHERE m.request_ref = p_resource_ref::pg_catalog.uuid AND m.tenant_id = p_tenant AND m.status = 'PENDING';
        IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        IF v_req_by = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
      ELSIF p_action = 'APPROVE_ROLE_ASSIGNMENT' THEN
        IF p_resource_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        SELECT a.requested_by_ref INTO v_req_by FROM platform.platform_role_assignment a
         WHERE a.request_ref = p_resource_ref::pg_catalog.uuid AND a.status = 'PENDING';
        IF NOT FOUND THEN v_reason := 'REQUEST_NOT_FOUND'; EXIT decide; END IF;
        IF v_req_by = v_principal THEN v_reason := 'SELF_APPROVAL'; EXIT decide; END IF;
      END IF;
    END IF;

    IF true THEN
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

-- platform.authorize(action, resource_ref): decision sin consumir nonce (dry-run con evidencia); el tenant es el de la transaccion.
CREATE FUNCTION platform.authorize(p_action text, p_resource_ref text)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RETURN platform.authorize_target(p_action, p_resource_ref, CASE WHEN p_action IN ('REQUEST_MEMBERSHIP', 'APPROVE_MEMBERSHIP') THEN app.current_tenant_id() END, false);
END
$$;

-- platform.issue_action_nonce(action, refs): emite el nonce (DB) ligado a (tenant, accion, refs, principal, expira). Solo PLATFORM activo desde
-- platform_rw. El TTL lo fija el llamador desde la configuracion de P-36 (pendiente); la DB solo acota 1..3600 s. Devuelve el nonce en claro una vez.
CREATE FUNCTION platform.issue_action_nonce(p_action text, p_refs text[], p_tenant_id uuid, p_ttl_seconds integer)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  c_policy    constant text := 'ADR010-PR3-v1';
  c_principal constant text := '^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$';
  c_princ     constant text := '(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})';
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

REVOKE ALL ON FUNCTION platform.action_nonce_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.authorize_target(text, text, uuid, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.authorize(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.issue_action_nonce(text, text[], uuid, integer) FROM PUBLIC;
-- authorize_target solo la llaman las funciones de aprovisionamiento (membership_owner) y authorize (mismo dueno); ningun runtime.
GRANT EXECUTE ON FUNCTION platform.authorize_target(text, text, uuid, boolean) TO membership_owner;
GRANT EXECUTE ON FUNCTION platform.authorize(text, text) TO platform_rw;
GRANT EXECUTE ON FUNCTION platform.issue_action_nonce(text, text[], uuid, integer) TO platform_rw;

-- 4. Revocar el CREATE temporal; nadie salvo el dueno del esquema lo conserva.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM membership_owner, grant_owner;
SET LOCAL ROLE consent_owner;

-- 5. Aserciones: la migracion aborta si algo no quedo como se declara. Se consulta el catalogo por nombre.
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
    'authorization_check_guard', ARRAY[]::text[]);
  expect_owner jsonb := pg_catalog.jsonb_build_object(
    'request_membership', 'membership_owner', 'approve_membership', 'membership_owner', 'request_role_assignment', 'membership_owner',
    'approve_role_assignment', 'membership_owner', 'membership_guard', 'membership_owner', 'membership_no_truncate', 'membership_owner',
    'authorize', 'grant_owner', 'issue_action_nonce', 'grant_owner', 'authorize_target', 'grant_owner', 'action_nonce_guard', 'grant_owner',
    'authorization_check_guard', 'grant_owner');
BEGIN
  -- Esquema: dueno y CREATE.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'platform' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'platform_schema_owner') THEN
    RAISE EXCEPTION 'el esquema platform no pertenece a platform_schema_owner';
  END IF;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'tenant_resolve_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '% conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'app_rw', 'platform_rw'] LOOP
    IF NOT pg_catalog.has_schema_privilege(r, 'platform', 'USAGE') THEN RAISE EXCEPTION '% sin USAGE en el esquema platform', r; END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['worker', 'integrity_verifier', 'consent_owner', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'USAGE') THEN RAISE EXCEPTION '% no debe tener USAGE en el esquema platform en PR-3', r; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a
              WHERE n.nspname = 'platform' AND a.grantee = 0) THEN
    RAISE EXCEPTION 'PUBLIC tiene privilegios sobre el esquema platform';
  END IF;

  -- Relaciones: exactamente 4 tablas, con su dueno, ENABLE + FORCE RLS; indices y secuencias del mismo dueno que su tabla.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND c.relkind NOT IN ('r', 'i')) <> 0 THEN
    RAISE EXCEPTION 'platform solo debe tener tablas e indices en PR-3';
  END IF;
  FOR t IN SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.pg_get_userbyid(c.relowner) AS owner
             FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'platform' AND c.relkind = 'r' LOOP
    IF t.relname NOT IN ('tenant_membership', 'platform_role_assignment', 'action_nonce', 'authorization_check') THEN
      RAISE EXCEPTION 'tabla inesperada platform.%', t.relname;
    END IF;
    IF (t.relname IN ('tenant_membership', 'platform_role_assignment') AND t.owner <> 'membership_owner')
       OR (t.relname IN ('action_nonce', 'authorization_check') AND t.owner <> 'grant_owner') THEN
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
    IF t.relname IN ('tenant_membership', 'platform_role_assignment') THEN
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
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relkind = 'r') <> 4 THEN
    RAISE EXCEPTION 'platform debe tener exactamente 4 tablas en PR-3';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_class tbl ON tbl.oid = (SELECT i.indrelid FROM pg_catalog.pg_index i WHERE i.indexrelid = c.oid)
              WHERE n.nspname = 'platform' AND c.relkind = 'i' AND c.relowner <> tbl.relowner) THEN
    RAISE EXCEPTION 'hay indices de platform con dueno distinto del de su tabla';
  END IF;

  -- Policies exactas (nombre, comando, roles). polcmd: a=INSERT, r=SELECT, w=UPDATE, d=DELETE.
  FOR t IN SELECT * FROM (VALUES
      ('tenant_membership', 'tenant_membership_authorize_select:r:grant_owner tenant_membership_owner_insert:a:membership_owner tenant_membership_owner_select:r:membership_owner tenant_membership_owner_update:w:membership_owner'),
      ('platform_role_assignment', 'platform_role_assignment_authorize_select:r:grant_owner platform_role_assignment_owner_insert:a:membership_owner platform_role_assignment_owner_select:r:membership_owner platform_role_assignment_owner_update:w:membership_owner'),
      ('action_nonce', 'action_nonce_owner_insert:a:grant_owner action_nonce_owner_select:r:grant_owner action_nonce_owner_update:w:grant_owner'),
      ('authorization_check', 'authorization_check_owner_insert:a:grant_owner authorization_check_owner_select:r:grant_owner')
    ) AS v(tbl, expected) LOOP
    IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
          FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'platform' AND c.relname = t.tbl) IS DISTINCT FROM t.expected THEN
      RAISE EXCEPTION 'las policies de platform.% no son exactamente las declaradas (rol y comando)', t.tbl;
    END IF;
  END LOOP;

  -- Triggers: 8, ENABLE ALWAYS (guardas por fila UPDATE/DELETE y TRUNCATE por sentencia).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND NOT g.tgisinternal AND g.tgenabled = 'A') <> 8
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'platform' AND NOT g.tgisinternal) <> 8
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'platform' AND NOT g.tgisinternal AND (g.tgtype & 2) = 2 AND (((g.tgtype & 1) = 1 AND (g.tgtype & 8) = 8 AND (g.tgtype & 16) = 16) OR ((g.tgtype & 1) = 0 AND (g.tgtype & 32) = 32))) <> 8 THEN
    RAISE EXCEPTION 'los triggers de platform deben ser 8, BEFORE y ENABLE ALWAYS (UPDATE/DELETE por fila o TRUNCATE por sentencia)';
  END IF;

  -- Funciones: conjunto exacto, dueno, SECURITY DEFINER donde corresponde, search_path fijo, EXECUTE exacto.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform') <> 11 THEN
    RAISE EXCEPTION 'platform debe tener exactamente 11 funciones en PR-3';
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
                AND (pg_catalog.pg_get_userbyid(a.grantee) <> 'grant_owner' OR a.privilege_type <> 'SELECT' OR c.relname NOT IN ('tenant_membership', 'platform_role_assignment'))) THEN
    RAISE EXCEPTION 'las ACL de columnas de platform solo admiten SELECT para grant_owner sobre las tablas de membership';
  END IF;
  IF (SELECT pg_catalog.string_agg(c.relname::pg_catalog.text || '.' || att.attname::pg_catalog.text, ',' ORDER BY (c.relname::pg_catalog.text || '.' || att.attname::pg_catalog.text) COLLATE "C")
        FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid = att.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'platform' AND att.attnum > 0 AND NOT att.attisdropped AND att.attacl IS NOT NULL)
     IS DISTINCT FROM 'platform_role_assignment.platform_role,platform_role_assignment.principal_ref,platform_role_assignment.request_ref,platform_role_assignment.requested_by_ref,platform_role_assignment.status,tenant_membership.membership_role,tenant_membership.principal_ref,tenant_membership.request_ref,tenant_membership.requested_by_ref,tenant_membership.status,tenant_membership.tenant_id' THEN
    RAISE EXCEPTION 'las columnas con SELECT de grant_owner no son exactamente las que usa authorize_target';
  END IF;
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a WHERE n.nspname = 'platform' AND a.grantee <> n.nspowner)
     IS DISTINCT FROM 'app_rw:USAGE,grant_owner:USAGE,membership_owner:USAGE,platform_rw:USAGE' THEN
    RAISE EXCEPTION 'la ACL del esquema platform no es exactamente USAGE para app_rw, platform_rw, membership_owner y grant_owner';
  END IF;
  IF (SELECT pg_catalog.string_agg(g.tgname::pg_catalog.text || ':' || p.proname::pg_catalog.text, ',' ORDER BY g.tgname::pg_catalog.text COLLATE "C")
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid = g.tgfoid
       WHERE n.nspname = 'platform' AND NOT g.tgisinternal)
     IS DISTINCT FROM 'action_nonce_guard:action_nonce_guard,action_nonce_no_truncate:authorization_check_guard,authorization_check_append_only:authorization_check_guard,authorization_check_no_truncate:authorization_check_guard,platform_role_assignment_guard:membership_guard,platform_role_assignment_no_truncate:membership_no_truncate,tenant_membership_guard:membership_guard,tenant_membership_no_truncate:membership_no_truncate' THEN
    RAISE EXCEPTION 'el mapeo trigger -> funcion de platform no es el declarado';
  END IF;
END
$assert$;
