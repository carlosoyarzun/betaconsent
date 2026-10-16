-- scope: database
-- Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c), F-PR7-01 (P1 hoy; P0 antes de REAL_DATA; funciones compartidas y dueños de esquema), R-21-1/FN-12; decisiones de Carlos del 2026-10-17 (C-2: esquemas app y ops a
-- owners NOLOGIN; C-3: funciones compartidas a un owner NOLOGIN propio); specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-01, INV-DBR-03). Depende de 0080 (roles de cluster) y 0081. Regla de Carlos (2026-10-01): las migraciones
-- mergeadas no se editan.
--
-- El trojan (F-PR7-01): consent_owner (el migrador) era dueño de app.current_tenant_id() (policies del ledger y de todas las tablas, cuerpos SECURITY DEFINER), ops.catalog_environment() (DEFAULT de audit_event.environment) y
-- app.is_reserved_email (CHECK evaluado por transition_owner), y dueño de los esquemas app y ops. Con CREATE OR REPLACE de esas funciones ejecutaria codigo como transition_owner/ledger_writer; y el dueño de un esquema puede
-- DROP de objetos ajenos dentro de el (DROP FUNCTION/TABLE/CASCADE), lo que anula el cierre por privilegio de los otros owners.
--
-- Que cambia:
--   1. app.current_tenant_id(), app.is_reserved_email(text) y ops.catalog_environment() pasan a shared_fn_owner (NOLOGIN, USAGE sin CREATE en app y ops). ACL de EXECUTE conservada (solo cambia el grantor);
--      consent_owner deja de ejecutarlas (no las usa: las policies, DEFAULT y CHECK las evaluan los roles que escriben).
--   2. El esquema app pasa a app_schema_owner y el esquema ops a ops_schema_owner (NOLOGIN). consent_owner conserva USAGE, CREATE (las migraciones siguen creando objetos propios en ellos) pero ya no puede DROP SCHEMA ni
--      DROP de objetos ajenos. Las ACL de esquema de los demas roles se conservan (cambia el grantor).
-- Como 0027: el cambio de dueño de un esquema exige CREATE en la base para el nuevo dueño (consent_owner es datdba); el grant es temporal y se revoca en la misma migracion.
-- Idempotente: cada paso se condiciona al estado del catalogo.

SET LOCAL ROLE consent_owner;

-- 1. Funciones compartidas. ALTER FUNCTION ... OWNER TO exige CREATE del nuevo dueño en el esquema de la funcion (temporal).
DO $shared$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT n.nspname::pg_catalog.text AS sch, p.proname::pg_catalog.text AS fname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE pg_catalog.pg_get_userbyid(p.proowner) = 'consent_owner'
              AND ((n.nspname = 'app' AND p.proname IN ('current_tenant_id', 'is_reserved_email')) OR (n.nspname = 'ops' AND p.proname = 'catalog_environment'))
            ORDER BY 1, 2 LOOP
    EXECUTE pg_catalog.format('GRANT USAGE, CREATE ON SCHEMA %I TO shared_fn_owner', f.sch);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.%I(%s) OWNER TO shared_fn_owner', f.sch, f.fname, f.args);
    EXECUTE pg_catalog.format('REVOKE CREATE ON SCHEMA %I FROM shared_fn_owner', f.sch); -- conserva USAGE (resolver sus funciones por nombre en ceremonias); nunca CREATE
  END LOOP;
END
$shared$;

-- 2. Dueños de esquema. Temporal: CREATE en la base para los dos nuevos dueños (ALTER SCHEMA ... OWNER exige CREATE en la base; patron 0027).
DO $schemas$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'app' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'consent_owner')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'ops' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'consent_owner') THEN
    EXECUTE pg_catalog.format('GRANT CREATE ON DATABASE %I TO app_schema_owner, ops_schema_owner', pg_catalog.current_database());
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'app' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'consent_owner') THEN
      ALTER SCHEMA app OWNER TO app_schema_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'ops' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'consent_owner') THEN
      ALTER SCHEMA ops OWNER TO ops_schema_owner;
    END IF;
    EXECUTE pg_catalog.format('REVOKE CREATE ON DATABASE %I FROM app_schema_owner, ops_schema_owner', pg_catalog.current_database());
  END IF;
END
$schemas$;

-- consent_owner perdio USAGE/CREATE al cambiar el dueño (el ACL implicito del dueño viaja al nuevo): se le devuelven como grant explicito del nuevo dueño.
SET LOCAL ROLE app_schema_owner;
GRANT USAGE, CREATE ON SCHEMA app TO consent_owner;
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE ops_schema_owner;
GRANT USAGE, CREATE ON SCHEMA ops TO consent_owner;
SET LOCAL ROLE consent_owner;

-- 3. Aserciones (fail-closed).
DO $assert82$
DECLARE
  r text;
  spec text[];
  fn record;
  n integer;
BEGIN
  -- Funciones compartidas: dueño, SECURITY DEFINER/volatilidad intactos (solo cambia el dueño) y ACL de EXECUTE sin consent_owner ni PUBLIC.
  FOREACH spec SLICE 1 IN ARRAY ARRAY[ARRAY['app', 'current_tenant_id'], ARRAY['app', 'is_reserved_email'], ARRAY['ops', 'catalog_environment']] LOOP
    SELECT p.oid, p.proowner, p.proacl, p.proconfig INTO fn FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = spec[1] AND p.proname = spec[2];
    IF fn.oid IS NULL OR pg_catalog.pg_get_userbyid(fn.proowner) <> 'shared_fn_owner' THEN RAISE EXCEPTION '0082: %.% no pertenece a shared_fn_owner', spec[1], spec[2]; END IF;
    IF fn.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RAISE EXCEPTION '0082: %.% perdio el search_path fijo', spec[1], spec[2]; END IF;
    IF pg_catalog.has_function_privilege('public', fn.oid, 'EXECUTE') THEN RAISE EXCEPTION '0082: PUBLIC puede ejecutar %.%', spec[1], spec[2]; END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(fn.proacl, pg_catalog.acldefault('f', fn.proowner))) a
                WHERE a.grantor <> fn.proowner OR a.grantee = (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'consent_owner')) THEN
      RAISE EXCEPTION '0082: la ACL de %.% tiene entradas de consent_owner (grantor o grantee)', spec[1], spec[2];
    END IF;
    IF pg_catalog.has_function_privilege('consent_owner', fn.oid, 'EXECUTE') THEN RAISE EXCEPTION '0082: consent_owner puede ejecutar %.%', spec[1], spec[2]; END IF;
    -- Los roles de runtime que las evaluan (policies, DEFAULT, CHECK) siguen pudiendo ejecutarlas.
    FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw'] LOOP
      IF spec[2] <> 'is_reserved_email' AND NOT pg_catalog.has_function_privilege(r, fn.oid, 'EXECUTE') THEN RAISE EXCEPTION '0082: % perdio EXECUTE de %.%', r, spec[1], spec[2]; END IF;
    END LOOP;
  END LOOP;
  -- Ninguna funcion de consent_owner es referida por objetos de otros owners: las unicas funciones de consent_owner que quedan son disparadores de SUS propias tablas.
  FOR fn IN SELECT n2.nspname::pg_catalog.text AS sch, p.proname::pg_catalog.text AS fname, p.oid
              FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n2 ON n2.oid = p.pronamespace WHERE pg_catalog.pg_get_userbyid(p.proowner) = 'consent_owner' LOOP
    -- referidas desde cuerpos de funciones de OTROS dueños (por nombre calificado)
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc g WHERE g.proowner <> (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'consent_owner')
                AND g.pronamespace NOT IN (SELECT s.oid FROM pg_catalog.pg_namespace s WHERE s.nspname IN ('pg_catalog', 'information_schema'))
                AND g.prosrc ~ ('\m' || fn.sch || '\.' || fn.fname || '\M')) THEN
      RAISE EXCEPTION '0082: %.% (de consent_owner) es nombrada por una funcion de otro dueño', fn.sch, fn.fname;
    END IF;
    -- referidas por objetos dependientes (trigger, policy, DEFAULT, CHECK, indice, regla) de relaciones de OTROS dueños
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_depend d
      LEFT JOIN pg_catalog.pg_trigger tg ON d.classid = 'pg_trigger'::pg_catalog.regclass AND tg.oid = d.objid
      LEFT JOIN pg_catalog.pg_policy po ON d.classid = 'pg_policy'::pg_catalog.regclass AND po.oid = d.objid
      LEFT JOIN pg_catalog.pg_attrdef ad ON d.classid = 'pg_attrdef'::pg_catalog.regclass AND ad.oid = d.objid
      LEFT JOIN pg_catalog.pg_constraint co ON d.classid = 'pg_constraint'::pg_catalog.regclass AND co.oid = d.objid
      LEFT JOIN pg_catalog.pg_rewrite rw ON d.classid = 'pg_rewrite'::pg_catalog.regclass AND rw.oid = d.objid
      LEFT JOIN pg_catalog.pg_index ix ON d.classid = 'pg_class'::pg_catalog.regclass AND ix.indexrelid = d.objid
      JOIN pg_catalog.pg_class rel ON rel.oid = COALESCE(tg.tgrelid, po.polrelid, ad.adrelid, co.conrelid, rw.ev_class, ix.indrelid)
     WHERE d.refclassid = 'pg_proc'::pg_catalog.regclass AND d.refobjid = fn.oid AND rel.relowner <> (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'consent_owner');
    IF n > 0 THEN RAISE EXCEPTION '0082: %.% (de consent_owner) es referida por % objeto(s) de relaciones de otros dueños', fn.sch, fn.fname, n; END IF;
  END LOOP;
  -- Esquemas: dueños NOLOGIN dedicados; consent_owner con USAGE y CREATE explicitos y sin ser dueño; sin CREATE temporal en la base.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace s WHERE s.nspname = 'app' AND pg_catalog.pg_get_userbyid(s.nspowner) = 'app_schema_owner') THEN RAISE EXCEPTION '0082: el esquema app no pertenece a app_schema_owner'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace s WHERE s.nspname = 'ops' AND pg_catalog.pg_get_userbyid(s.nspowner) = 'ops_schema_owner') THEN RAISE EXCEPTION '0082: el esquema ops no pertenece a ops_schema_owner'; END IF;
  FOREACH r IN ARRAY ARRAY['app', 'ops'] LOOP
    IF NOT (pg_catalog.has_schema_privilege('consent_owner', r, 'USAGE') AND pg_catalog.has_schema_privilege('consent_owner', r, 'CREATE')) THEN RAISE EXCEPTION '0082: consent_owner perdio USAGE o CREATE en %', r; END IF;
    IF pg_catalog.pg_has_role('consent_owner', (SELECT s.nspowner FROM pg_catalog.pg_namespace s WHERE s.nspname = r), 'USAGE') THEN RAISE EXCEPTION '0082: consent_owner hereda los privilegios del dueño del esquema %', r; END IF;
    IF pg_catalog.has_schema_privilege('shared_fn_owner', r, 'CREATE') OR pg_catalog.has_schema_privilege('case_state_owner', r, 'CREATE') THEN RAISE EXCEPTION '0082: queda un CREATE temporal en %', r; END IF;
  END LOOP;
  -- Los usos de esquema de los roles de runtime y owners se conservan: ninguno pierde USAGE en app/ops por el cambio de dueño.
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'transition_owner', 'grant_owner'] LOOP
    IF NOT pg_catalog.has_schema_privilege(r, 'app', 'USAGE') THEN RAISE EXCEPTION '0082: % perdio USAGE en app', r; END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'security_event_owner', 'transition_owner', 'ledger_writer'] LOOP
    IF NOT pg_catalog.has_schema_privilege(r, 'ops', 'USAGE') THEN RAISE EXCEPTION '0082: % perdio USAGE en ops', r; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_database d, pg_catalog.aclexplode(d.datacl) a WHERE d.datname = pg_catalog.current_database()
              AND a.privilege_type = 'CREATE' AND a.grantee IN (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname IN ('app_schema_owner', 'ops_schema_owner', 'shared_fn_owner'))) THEN
    RAISE EXCEPTION '0082: queda CREATE en la base para un owner nuevo (el grant temporal no quedo revocado)';
  END IF;
  -- Ningun owner nuevo es dueño de objetos fuera de su dominio.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner IN (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname IN ('app_schema_owner', 'ops_schema_owner', 'shared_fn_owner', 'revocation_recovery_reader')) AND c.relnamespace > 0) THEN
    RAISE EXCEPTION '0082: un owner de esquema o de funciones compartidas es dueño de una relacion';
  END IF;
END
$assert82$;
