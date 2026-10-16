-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §6 / §10 fila 6d, F-PR6-40, F-PR6-45 (seguridad de PR #101: la lectura cross-tenant de app.rights_case NO puede ser una policy del dueño
-- consent_owner, porque consent_migrator hereda sus privilegios); specs/db-roles.spec.yaml (rights_case_lookup_owner, INV-DBR-03). Depende de 0059 y del rol de cluster de 0064 (los archivos cluster corren antes).
-- 0059 esta mergeada y es inmutable: esta migracion nueva corrige su resultado. El runner aplica cada migracion de database UNA vez (checksum en ops.schema_migration) y nunca re-evalua los $assert$ de 0059.
--
-- Que cambia (como consent_owner, dueño de app.rights_case y de app.rights_case_tenant_of hasta aqui):
--   * app.rights_case_tenant_of(text) pasa a ser del rol dedicado rights_case_lookup_owner (NOLOGIN, NOBYPASSRLS, sin miembros salvo consent_owner con SET sin herencia). El cuerpo no cambia (exactamente una fila,
--     si no 0/ambiguo = deniega). EXECUTE sigue siendo solo de grant_owner.
--   * rights_case_lookup_owner recibe SELECT SOLO de (tenant_id, case_ref, status) de app.rights_case y UNA policy de SELECT `TO rights_case_lookup_owner` (rights_case_lookup_select).
--   * Se elimina la policy rights_case_owner_lookup_select TO consent_owner de 0059 (la heredaba consent_migrator). consent_owner vuelve a no tener ninguna policy sobre app.rights_case.
-- Idempotente: GRANT repetibles, DROP POLICY IF EXISTS y ALTER OWNER al mismo dueño son no-ops.

SET LOCAL ROLE consent_owner;

GRANT USAGE ON SCHEMA app TO rights_case_lookup_owner;
GRANT CREATE ON SCHEMA app TO rights_case_lookup_owner; -- temporal: ALTER ... OWNER TO exige CREATE del nuevo dueño; se revoca abajo
GRANT SELECT (tenant_id, case_ref, status) ON app.rights_case TO rights_case_lookup_owner;
DROP POLICY IF EXISTS rights_case_lookup_select ON app.rights_case;
CREATE POLICY rights_case_lookup_select ON app.rights_case FOR SELECT TO rights_case_lookup_owner USING (true);
ALTER FUNCTION app.rights_case_tenant_of(text) OWNER TO rights_case_lookup_owner;
REVOKE CREATE ON SCHEMA app FROM rights_case_lookup_owner;
DROP POLICY IF EXISTS rights_case_owner_lookup_select ON app.rights_case;

DO $assert65$
DECLARE
  r   text;
  rel record;
  def text;
  fn  record;
BEGIN
  SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'app' AND c.relname = 'rights_case';
  -- grant_owner: sin privilegio ni policy sobre la tabla; USAGE sobre app y EXECUTE de EXACTAMENTE dos funciones de app.
  IF NOT pg_catalog.has_schema_privilege('grant_owner', 'app', 'USAGE') OR pg_catalog.has_schema_privilege('grant_owner', 'app', 'CREATE') THEN RAISE EXCEPTION '0065: grant_owner debe tener USAGE y no CREATE sobre app'; END IF;
  IF pg_catalog.has_table_privilege('grant_owner', rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('grant_owner', rel.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0065: grant_owner tiene privilegios sobre app.rights_case (solo via app.rights_case_tenant_of)';
  END IF;
  SELECT pg_catalog.string_agg(p.proname::pg_catalog.text || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')', ',' ORDER BY p.proname::pg_catalog.text COLLATE "C") INTO def
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'app' AND pg_catalog.has_function_privilege('grant_owner', p.oid, 'EXECUTE');
  IF def IS DISTINCT FROM 'current_tenant_id(),rights_case_tenant_of(p_case_ref text)' THEN
    RAISE EXCEPTION '0065: grant_owner debe ejecutar exactamente app.current_tenant_id() y app.rights_case_tenant_of(text) en app (hay: %)', def;
  END IF;
  -- Policies: ninguna para consent_owner ni grant_owner; exactamente UNA TO rights_case_lookup_owner.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rel.oid AND p.polroles && ARRAY[(SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'grant_owner'), (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner')]::oid[]) THEN
    RAISE EXCEPTION '0065: hay una policy de grant_owner o consent_owner sobre app.rights_case (el dueño y su herencia no leen cross-tenant)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rel.oid AND p.polname = 'rights_case_lookup_select' AND p.polcmd = 'r'
         AND p.polroles = ARRAY[(SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'rights_case_lookup_owner')]::oid[]) <> 1 THEN
    RAISE EXCEPTION '0065: falta la policy de SELECT TO rights_case_lookup_owner en app.rights_case';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rel.oid AND p.polname = 'rights_case_owner_lookup_select') THEN RAISE EXCEPTION '0065: sigue la policy rights_case_owner_lookup_select de 0059'; END IF;
  -- rights_case_lookup_owner: solo SELECT por columnas (tenant_id, case_ref, status), sin CREATE en app, sin membresias salvo consent_owner (SET, sin herencia ni ADMIN) y no miembro de nadie.
  IF pg_catalog.has_table_privilege('rights_case_lookup_owner', rel.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('rights_case_lookup_owner', rel.oid, 'INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0065: rights_case_lookup_owner tiene mas privilegios de los previstos sobre app.rights_case';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped
              AND (a.attname IN ('tenant_id', 'case_ref', 'status')) <> pg_catalog.has_column_privilege('rights_case_lookup_owner', rel.oid, a.attnum, 'SELECT')) THEN
    RAISE EXCEPTION '0065: rights_case_lookup_owner debe leer exactamente (tenant_id, case_ref, status)';
  END IF;
  IF pg_catalog.has_schema_privilege('rights_case_lookup_owner', 'app', 'CREATE') THEN RAISE EXCEPTION '0065: rights_case_lookup_owner conserva CREATE en app'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.roleid WHERE x.rolname = 'rights_case_lookup_owner'
              AND NOT (m.member = (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner') AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
    RAISE EXCEPTION '0065: rights_case_lookup_owner solo puede tener a consent_owner como miembro (SET, sin herencia ni ADMIN)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member WHERE x.rolname = 'rights_case_lookup_owner') THEN
    RAISE EXCEPTION '0065: rights_case_lookup_owner no debe ser miembro de ningun rol';
  END IF;
  -- La funcion: dueño, SECURITY DEFINER, search_path fijo, sin SQL dinamico, ACL exacta (solo grant_owner), sin EXECUTE de ningun otro rol.
  SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc INTO fn FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'app' AND p.proname = 'rights_case_tenant_of';
  IF fn.oid IS NULL OR pg_catalog.pg_get_userbyid(fn.proowner) <> 'rights_case_lookup_owner' OR NOT fn.prosecdef OR fn.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR pg_catalog.has_function_privilege('public', fn.oid, 'EXECUTE') OR fn.prosrc ~* '\mexecute\M' THEN
    RAISE EXCEPTION '0065: app.rights_case_tenant_of: dueño/SECURITY DEFINER/search_path/ACL incorrectos';
  END IF;
  IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                 FROM pg_catalog.aclexplode(COALESCE(fn.proacl, pg_catalog.acldefault('f', fn.proowner))) a WHERE a.grantee <> fn.proowner), '') IS DISTINCT FROM 'grant_owner' THEN
    RAISE EXCEPTION '0065: la ACL de app.rights_case_tenant_of no es exactamente [grant_owner]';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'worker', 'integrity_verifier', 'integrity_reconciler', 'membership_owner', 'transition_owner', 'consent_owner', 'consent_migrator'] LOOP
    IF pg_catalog.has_function_privilege(r, fn.oid, 'EXECUTE') THEN RAISE EXCEPTION '0065: % puede ejecutar app.rights_case_tenant_of', r; END IF;
  END LOOP;
END
$assert65$;
