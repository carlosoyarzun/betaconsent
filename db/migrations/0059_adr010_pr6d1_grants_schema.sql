-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (step-up: el principal sale de la sesion validada), §6 (Grants P6-3: grant_request / rights_case_grant completos, P-23, P-37),
-- §10 filas 6c y 6d, §11.3 G-5..G-7; GRD-RC-10 y GRD-RC-12 (specs/state-machines/rights-case.spec.yaml); SEC-CNS-006 rev. 5 §1 (P-23, P-37, P-51, P-52; ACCEPTED 2026-09-26);
-- registers/findings-register-IT0.md F-PR6-39, F-PR6-40 (tenant y case_ref derivados del caso real). Decision de Carlos (2026-10-15, opcion A): lo de 6c no entregado pasa a 6d.
-- Depende de 0050-0054 y del rol de cluster de 0064 (los archivos cluster corren antes que los de database). 0000-0058 estan mergeadas y son inmutables; esta migracion es nueva (primera de PR-6d parte 1; las funciones llegan en 0060-0063).
--
-- Que cambia (patron 0052: SET LOCAL ROLE del owner, CREATE temporal concedido y revocado, $assert$ final):
--   rights_case_lookup_owner (rol NOLOGIN dedicado, creado en 0064 (cluster); sin miembros salvo consent_owner con SET sin herencia, como los demas owners): dueño de app.rights_case_tenant_of(case_ref) (SECURITY DEFINER;
--                   EXECUTE solo grant_owner). Devuelve (tenant_id, status) del caso REAL solo si hay EXACTAMENTE una fila con ese case_ref (inexistente o ambiguo = 0 filas). Tiene SELECT SOLO de (tenant_id,
--                   case_ref, status) de app.rights_case y UNA policy de SELECT `TO rights_case_lookup_owner`. Es la unica via por la que request_grant, approve_grant, open_case_session y validate_session derivan
--                   el tenant (F-PR6-40, F-PR6-45): nunca de un parametro ni de la request. NO hay policy para consent_owner (consent_migrator hereda sus privilegios) ni para grant_owner; grant_owner solo tiene
--                   USAGE sobre app y EXECUTE de EXACTAMENTE dos funciones de app: app.current_tenant_id() (0035:36) y app.rights_case_tenant_of(text) (assert con la lista exacta).
--   grant_owner   : * platform.session_event: tipos nuevos STEP_UP_REJECTED (intento de confirmacion fallido, cuenta para P-51), GRANT_REQUESTED, GRANT_APPROVED y GRANT_REJECTED (incluye la solicitud
--                     vencida, P-37: "vencida no aprobable y se registra"); columna request_ref. Sin IP (F-PR6-31).
--                   * platform.grant_request: UNIQUE (request_ref, tenant_id, case_ref, operator_principal_ref) para que el grant la referencie por FK compuesta.
--                   * platform.rights_case_grant: gana request_ref (UNIQUE: una solicitud, un grant) y approved_by_ref (NOT NULL, distinto del operador), con FK compuesta a grant_request: un grant solo
--                     existe si nace de una solicitud con el MISMO tenant, caso y operador, y un trigger BEFORE INSERT exige que esa solicitud este APPROVED por ese aprobador (doble control en la base,
--                     tambien para el superusuario). Ningun rol tiene INSERT: solo approve_grant (0062). La guarda de UPDATE/DELETE (0052) se reemplaza para incluir las columnas nuevas.
--   La tabla rights_case_grant estaba SIN camino de escritura de runtime desde 0052: la migracion aborta si trae filas (solo podian ser siembras de test; nunca hay datos reales).
-- Idempotencia: el runner aplica cada migracion una vez (checksum); las sentencias no se repiten.

-- 0. app.rights_case_tenant_of (dueño rights_case_lookup_owner; los grants sobre app.rights_case los da consent_owner, dueño de la tabla).
SET LOCAL ROLE consent_owner;
GRANT USAGE ON SCHEMA app TO grant_owner;
GRANT USAGE ON SCHEMA app TO rights_case_lookup_owner;
GRANT CREATE ON SCHEMA app TO rights_case_lookup_owner; -- temporal: se revoca al final
GRANT SELECT (tenant_id, case_ref, status) ON app.rights_case TO rights_case_lookup_owner;
DROP POLICY IF EXISTS rights_case_owner_lookup_select ON app.rights_case;
DROP POLICY IF EXISTS rights_case_lookup_select ON app.rights_case;
CREATE POLICY rights_case_lookup_select ON app.rights_case FOR SELECT TO rights_case_lookup_owner USING (true);

SET LOCAL ROLE rights_case_lookup_owner;
CREATE FUNCTION app.rights_case_tenant_of(p_case_ref text)
  RETURNS TABLE (o_tenant_id uuid, o_status text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_n      integer;
  v_tenant uuid;
  v_status text;
BEGIN
  IF p_case_ref IS NULL THEN RETURN; END IF;
  SELECT pg_catalog.count(*)::integer, (pg_catalog.array_agg(c.tenant_id))[1], (pg_catalog.array_agg(c.status))[1] INTO v_n, v_tenant, v_status
    FROM app.rights_case c WHERE c.case_ref = p_case_ref;
  -- Exactamente una fila: inexistente (0) o ambiguo (>1, el mismo case_ref en dos tenants) deniega.
  IF v_n = 1 THEN RETURN QUERY SELECT v_tenant, v_status; END IF;
END
$$;
REVOKE ALL ON FUNCTION app.rights_case_tenant_of(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.rights_case_tenant_of(text) TO grant_owner;

SET LOCAL ROLE consent_owner;
REVOKE CREATE ON SCHEMA app FROM rights_case_lookup_owner;

-- 1. CREATE temporal para grant_owner (se revoca al final).
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;

SET LOCAL ROLE grant_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

DO $pre$
BEGIN
  IF EXISTS (SELECT 1 FROM platform.rights_case_grant) THEN
    RAISE EXCEPTION '0059: platform.rights_case_grant tiene filas sin solicitud aprobada (siembras de test); recrear la base de LOCAL';
  END IF;
END
$pre$;

-- 2. session_event: eventos de step-up fallido y de grants.
ALTER TABLE platform.session_event DROP CONSTRAINT session_event_type_enum;
ALTER TABLE platform.session_event DROP CONSTRAINT session_event_case_shape;
ALTER TABLE platform.session_event ADD COLUMN request_ref uuid;
ALTER TABLE platform.session_event
  ADD CONSTRAINT session_event_type_enum CHECK (event_type IN
    ('LOGIN_REJECTED', 'LOGIN_PRINCIPAL_MISMATCH', 'LIMIT_EXCEEDED', 'STEP_UP_BEGIN', 'PLATFORM_LOGIN', 'PLATFORM_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_ROTATED',
     'STEP_UP_REJECTED', 'GRANT_REQUESTED', 'GRANT_APPROVED', 'GRANT_REJECTED')),
  -- case_ref (UUIDv4 opaco): obligatorio en CASE_LOGIN/CASE_LOGOUT y GRANT_REQUESTED/GRANT_APPROVED; en SESSION_ROTATED solo si la sesion es CASE; opcional en LOGIN_REJECTED y GRANT_REJECTED;
  -- nunca en el resto.
  ADD CONSTRAINT session_event_case_shape CHECK (
    (event_type IN ('CASE_LOGIN', 'CASE_LOGOUT', 'GRANT_REQUESTED', 'GRANT_APPROVED') AND case_ref IS NOT NULL)
    OR (event_type = 'SESSION_ROTATED' AND (session_kind = 'CASE') = (case_ref IS NOT NULL))
    OR event_type IN ('LOGIN_REJECTED', 'GRANT_REJECTED')
    OR (event_type NOT IN ('CASE_LOGIN', 'CASE_LOGOUT', 'GRANT_REQUESTED', 'GRANT_APPROVED', 'SESSION_ROTATED', 'LOGIN_REJECTED', 'GRANT_REJECTED') AND case_ref IS NULL)),
  -- request_ref (solicitud de grant): obligatorio en GRANT_REQUESTED/GRANT_APPROVED, opcional en GRANT_REJECTED, nunca en el resto. Los eventos de grant llevan siempre principal (de la sesion).
  ADD CONSTRAINT session_event_request_shape CHECK (
    (event_type IN ('GRANT_REQUESTED', 'GRANT_APPROVED') AND request_ref IS NOT NULL)
    OR event_type = 'GRANT_REJECTED'
    OR (event_type NOT IN ('GRANT_REQUESTED', 'GRANT_APPROVED', 'GRANT_REJECTED') AND request_ref IS NULL)),
  ADD CONSTRAINT session_event_grant_principal CHECK (event_type NOT IN ('GRANT_REQUESTED', 'GRANT_APPROVED', 'GRANT_REJECTED', 'STEP_UP_REJECTED') OR principal_ref IS NOT NULL);

-- 3. grant_request: identidad compuesta referenciable.
ALTER TABLE platform.grant_request
  ADD CONSTRAINT grant_request_identity_unique UNIQUE (request_ref, tenant_id, case_ref, operator_principal_ref);

-- 4. rights_case_grant: nace de una solicitud aprobada (FK compuesta + trigger), con el aprobador.
ALTER TABLE platform.rights_case_grant
  ADD COLUMN request_ref     uuid NOT NULL,
  ADD COLUMN approved_by_ref text NOT NULL CONSTRAINT rights_case_grant_approved_by_shape CHECK (approved_by_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE platform.rights_case_grant
  ADD CONSTRAINT rights_case_grant_request_unique UNIQUE (request_ref),
  ADD CONSTRAINT rights_case_grant_request_fk FOREIGN KEY (request_ref, tenant_id, case_ref, operator_principal_ref)
    REFERENCES platform.grant_request (request_ref, tenant_id, case_ref, operator_principal_ref),
  -- GRD-RC-10: el aprobador nunca es el operador receptor.
  ADD CONSTRAINT rights_case_grant_distinct_approver CHECK (approved_by_ref <> operator_principal_ref);

CREATE OR REPLACE FUNCTION platform.rights_case_grant_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  -- Unica mutacion: revocar una vez (revoked_at NULL -> instante, resto identico). Nada se borra.
  IF TG_OP = 'UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
     AND (NEW.grant_ref, NEW.tenant_id, NEW.case_ref, NEW.operator_principal_ref, NEW.attested_at, NEW.expires_at, NEW.data_class, NEW.request_ref, NEW.approved_by_ref)
         IS NOT DISTINCT FROM (OLD.grant_ref, OLD.tenant_id, OLD.case_ref, OLD.operator_principal_ref, OLD.attested_at, OLD.expires_at, OLD.data_class, OLD.request_ref, OLD.approved_by_ref) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.rights_case_grant: solo se revoca una vez; no se borra ni se edita (ADR-010 §6, GRD-RC-10)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

-- BEFORE INSERT: el grant solo nace de una solicitud APPROVED por ese aprobador (doble control en la base). La FK compuesta ya fija tenant, caso y operador.
CREATE FUNCTION platform.rights_case_grant_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM platform.grant_request r
              WHERE r.request_ref = NEW.request_ref AND r.status = 'APPROVED' AND r.approved_by_ref = NEW.approved_by_ref AND r.requested_by_ref <> NEW.approved_by_ref) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform.rights_case_grant: solo nace de una grant_request APPROVED por ese aprobador, distinto del solicitante (ADR-010 §6, GRD-RC-10, P-37)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION platform.rights_case_grant_insert_guard() FROM PUBLIC;

CREATE TRIGGER rights_case_grant_insert_guard BEFORE INSERT ON platform.rights_case_grant
  FOR EACH ROW EXECUTE FUNCTION platform.rights_case_grant_insert_guard();
ALTER TABLE platform.rights_case_grant ENABLE ALWAYS TRIGGER rights_case_grant_insert_guard;

-- 5. Revocar el CREATE temporal.
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;
SET LOCAL ROLE consent_owner;

-- 6. Aserciones (fail-closed). consent_owner no tiene USAGE en platform: los objetos se resuelven por catalogo (oid).
DO $assert$
DECLARE
  r text;
  rel record;
  def text;
BEGIN
  -- app.rights_case: grant_owner NO tiene privilegio de tabla, de columna ni policy; solo USAGE sobre app y EXECUTE de EXACTAMENTE dos funciones de app (P2-a).
  SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'app' AND c.relname = 'rights_case';
  IF NOT pg_catalog.has_schema_privilege('grant_owner', 'app', 'USAGE') THEN RAISE EXCEPTION '0059: grant_owner sin USAGE sobre app'; END IF;
  IF pg_catalog.has_schema_privilege('grant_owner', 'app', 'CREATE') THEN RAISE EXCEPTION '0059: grant_owner tiene CREATE sobre app'; END IF;
  IF pg_catalog.has_table_privilege('grant_owner', rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('grant_owner', rel.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0059: grant_owner tiene privilegios sobre app.rights_case (solo via app.rights_case_tenant_of)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rel.oid AND p.polroles && ARRAY[(SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'grant_owner'), (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner')]::oid[]) THEN
    RAISE EXCEPTION '0059: hay una policy de grant_owner o consent_owner sobre app.rights_case (el dueño y su herencia no leen cross-tenant)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rel.oid AND p.polname = 'rights_case_lookup_select' AND p.polcmd = 'r'
         AND p.polroles = ARRAY[(SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'rights_case_lookup_owner')]::oid[]) <> 1 THEN
    RAISE EXCEPTION '0059: falta la policy de SELECT TO rights_case_lookup_owner en app.rights_case';
  END IF;
  -- rights_case_lookup_owner: solo SELECT por columnas (tenant_id, case_ref, status); ningun otro privilegio; sin CREATE en app; sin membresias salvo consent_owner (SET, sin herencia ni ADMIN).
  IF pg_catalog.has_table_privilege('rights_case_lookup_owner', rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('rights_case_lookup_owner', rel.oid, 'INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0059: rights_case_lookup_owner tiene mas privilegios de los previstos sobre app.rights_case';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped
              AND (a.attname IN ('tenant_id', 'case_ref', 'status')) <> pg_catalog.has_column_privilege('rights_case_lookup_owner', rel.oid, a.attnum, 'SELECT')) THEN
    RAISE EXCEPTION '0059: rights_case_lookup_owner debe leer exactamente (tenant_id, case_ref, status)';
  END IF;
  IF pg_catalog.has_schema_privilege('rights_case_lookup_owner', 'app', 'CREATE') THEN RAISE EXCEPTION '0059: rights_case_lookup_owner conserva CREATE en app'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.roleid WHERE x.rolname = 'rights_case_lookup_owner'
              AND NOT (m.member = (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner') AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
    RAISE EXCEPTION '0059: rights_case_lookup_owner solo puede tener a consent_owner como miembro (SET, sin herencia ni ADMIN)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member WHERE x.rolname = 'rights_case_lookup_owner') THEN
    RAISE EXCEPTION '0059: rights_case_lookup_owner no debe ser miembro de ningun rol';
  END IF;
  -- Lista exacta de EXECUTE de grant_owner en el esquema app.
  SELECT pg_catalog.string_agg(p.proname::pg_catalog.text || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')', ',' ORDER BY p.proname::pg_catalog.text COLLATE "C") INTO def
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'app' AND pg_catalog.has_function_privilege('grant_owner', p.oid, 'EXECUTE');
  IF def IS DISTINCT FROM 'current_tenant_id(),rights_case_tenant_of(p_case_ref text)' THEN
    RAISE EXCEPTION '0059: grant_owner debe ejecutar exactamente app.current_tenant_id() y app.rights_case_tenant_of(text) en app (hay: %)', def;
  END IF;
  SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc INTO rel FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'app' AND p.proname = 'rights_case_tenant_of';
  IF pg_catalog.pg_get_userbyid(rel.proowner) <> 'rights_case_lookup_owner' OR NOT rel.prosecdef OR rel.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR pg_catalog.has_function_privilege('public', rel.oid, 'EXECUTE') OR rel.prosrc ~* '\mexecute\M' THEN
    RAISE EXCEPTION '0059: app.rights_case_tenant_of: dueño/SECURITY DEFINER/search_path/ACL incorrectos';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'integrity_reconciler', 'membership_owner', 'transition_owner', 'consent_owner', 'consent_migrator'] LOOP
    IF pg_catalog.has_function_privilege(r, rel.oid, 'EXECUTE') THEN RAISE EXCEPTION '0059: % puede ejecutar app.rights_case_tenant_of', r; END IF;
  END LOOP;
  -- session_event: tipos y request_ref.
  SELECT pg_catalog.pg_get_constraintdef(k.oid) INTO def FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
   WHERE s.nspname = 'platform' AND c.relname = 'session_event' AND k.conname = 'session_event_type_enum';
  IF def IS NULL OR def NOT LIKE '%GRANT_APPROVED%' OR def NOT LIKE '%STEP_UP_REJECTED%' OR def NOT LIKE '%SESSION_ROTATED%' THEN RAISE EXCEPTION '0059: session_event_type_enum incompleto'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname = 'platform' AND c.relname = 'session_event' AND a.attname = 'request_ref' AND NOT a.attisdropped) <> 1 THEN
    RAISE EXCEPTION '0059: falta session_event.request_ref';
  END IF;
  -- rights_case_grant: FK compuesta, UNIQUE(request_ref), trigger de INSERT ENABLE ALWAYS, sin privilegios de runtime.
  SELECT c.oid, c.relowner INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'platform' AND c.relname = 'rights_case_grant';
  IF pg_catalog.pg_get_userbyid(rel.relowner) <> 'grant_owner' THEN RAISE EXCEPTION '0059: rights_case_grant no pertenece a grant_owner'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint k WHERE k.conrelid = rel.oid AND k.contype = 'f' AND k.conname = 'rights_case_grant_request_fk' AND pg_catalog.array_length(k.conkey, 1) = 4) <> 1 THEN
    RAISE EXCEPTION '0059: falta la FK compuesta rights_case_grant -> grant_request';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger g WHERE g.tgrelid = rel.oid AND NOT g.tgisinternal AND g.tgname = 'rights_case_grant_insert_guard' AND g.tgenabled = 'A') <> 1 THEN
    RAISE EXCEPTION '0059: falta el trigger rights_case_grant_insert_guard ENABLE ALWAYS';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_owner', 'consent_migrator', 'membership_owner', 'transition_owner', 'case_state_owner', 'platform_schema_owner'] LOOP
    IF pg_catalog.has_table_privilege(r, rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege(r, rel.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0059: % tiene privilegios sobre platform.rights_case_grant', r;
    END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['membership_owner', 'grant_owner', 'consent_owner', 'transition_owner', 'app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'platform', 'CREATE') THEN RAISE EXCEPTION '0059: % conserva CREATE en el esquema platform', r; END IF;
  END LOOP;
END
$assert$;
