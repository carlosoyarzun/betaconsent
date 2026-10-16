-- scope: database
-- Gobierna: ADR-010 rev. 6 §10 fila PR-7 ("mover app.revocation/app.rights_case (Q16)", sub-PR 7c), F-PR7-01, FN-6; decision de Carlos del 2026-10-17 (C-2: Q16 literal, mover las tablas al esquema case_state);
-- specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-01, INV-DBR-03); specs/state-machines/revocation.spec.yaml y rights-case.spec.yaml. Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan.
--
-- Que cambia:
--   * app.revocation y app.rights_case pasan a case_state.revocation y case_state.rights_case y a ser del dueño del esquema case_state (case_state_owner). consent_owner (el migrador) deja de ser dueño: ya no puede
--     DROP, DISABLE TRIGGER ni ALTER sobre ellas (FN-6). Indices, constraints, triggers (ENABLE ALWAYS), policies y ACL viajan con la tabla; los GRANT existentes se conservan con case_state_owner como grantor.
--   * Los cuerpos de las funciones que las nombran (plpgsql con search_path = pg_catalog, referencias por nombre) se recrean con el nombre nuevo. Se hace por catalogo (pg_get_functiondef con el nombre reemplazado) y por
--     CADA dueño con SET LOCAL ROLE literal (transition_owner, grant_owner, ledger_writer, rights_case_lookup_owner), para no copiar a mano ~30 cuerpos y no cambiar nada mas: la aserción final compara una huella
--     (dueño, SECURITY DEFINER, search_path, ACL, volatilidad, firma) de TODAS las funciones tocadas antes y despues. CREATE temporal de cada dueño sobre su esquema (patron 0066/0070), revocado al final.
--   * USAGE sobre case_state para los roles que leen las tablas desde fuera del esquema: integrity_reconciler (policy de SELECT por columnas) y rights_case_lookup_owner (app.rights_case_tenant_of).
--     app_rw, worker, platform_rw y transition_owner ya lo tenian.
-- Las migraciones previas (0006-0070) siguen refiriendose a app.revocation/app.rights_case: corren ANTES de esta en una base nueva. A partir de 0081 todo SQL usa case_state.*.
-- Idempotente: si las tablas ya estan en case_state no hace nada (cada paso se condiciona al estado del catalogo).

SET LOCAL ROLE consent_owner;

DO $snapshot$
BEGIN
  -- Huella de las funciones que se van a recrear (se compara al final). Se guarda en un GUC local a la tx.
  PERFORM pg_catalog.set_config('cns.pr7c_fn_digest', COALESCE((
    SELECT pg_catalog.md5(pg_catalog.string_agg(
             n.nspname::pg_catalog.text || '.' || p.proname::pg_catalog.text || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')|' || pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text || '|' || p.prosecdef::pg_catalog.text || '|'
             || COALESCE(p.proconfig::pg_catalog.text, '') || '|' || COALESCE(p.proacl::pg_catalog.text, '') || '|' || p.provolatile::pg_catalog.text || '|' || p.proretset::pg_catalog.text || '|' || p.prorettype::pg_catalog.text || '|'
             || COALESCE(p.proargnames::pg_catalog.text, '') || '|' || p.prolang::pg_catalog.text || '|' || p.proleakproof::pg_catalog.text || '|' || p.proparallel::pg_catalog.text,
             E'\n' ORDER BY n.nspname::pg_catalog.text COLLATE "C", p.proname::pg_catalog.text COLLATE "C", pg_catalog.pg_get_function_identity_arguments(p.oid) COLLATE "C"))
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE p.prosrc ~ '\mapp\.(revocation|rights_case)\M'), ''), true);
END
$snapshot$;

-- 1. Transferir el dominio de las tablas a case_state_owner. ALTER TABLE ... OWNER TO exige que el nuevo dueño tenga CREATE en el esquema actual de la tabla (app, de consent_owner todavia).
-- Idempotencia: solo si la tabla sigue en app.
DO $own$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname IN ('revocation', 'rights_case')) THEN
    GRANT USAGE, CREATE ON SCHEMA app TO case_state_owner; -- temporal: se revoca abajo
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'revocation') THEN
      ALTER TABLE app.revocation OWNER TO case_state_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'rights_case') THEN
      ALTER TABLE app.rights_case OWNER TO case_state_owner;
    END IF;
  END IF;
END
$own$;

-- 2. Mover las tablas como su dueño nuevo: necesita USAGE sobre app (para resolver el nombre) y es dueño de case_state (CREATE implicito).
SET LOCAL ROLE case_state_owner;
DO $move$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'revocation') THEN
    ALTER TABLE app.revocation SET SCHEMA case_state;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'rights_case') THEN
    ALTER TABLE app.rights_case SET SCHEMA case_state;
  END IF;
END
$move$;
-- Lectores de las tablas desde fuera del esquema. CREATE temporal de transition_owner (CREATE OR REPLACE de sus funciones; se revoca antes de cerrar).
GRANT USAGE ON SCHEMA case_state TO integrity_reconciler, rights_case_lookup_owner;
GRANT CREATE ON SCHEMA case_state TO transition_owner;
SET LOCAL ROLE consent_owner;
REVOKE USAGE, CREATE ON SCHEMA app FROM case_state_owner;

-- 3. Recrear las funciones por dueño (SET LOCAL ROLE literal; el cuerpo es el vigente con el nombre nuevo).
-- 3a. transition_owner: funciones de transicion de case_state.
SET LOCAL ROLE transition_owner;
DO $rewrite_transition$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p WHERE p.proowner = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) AND p.prosrc ~ '\mapp\.(revocation|rights_case)\M' ORDER BY p.oid LOOP
    EXECUTE pg_catalog.regexp_replace(pg_catalog.pg_get_functiondef(f.oid), '\mapp\.(revocation|rights_case)\M', 'case_state.\1', 'g');
  END LOOP;
END
$rewrite_transition$;
SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM transition_owner;

-- 3b. grant_owner: platform.open_case_session (CREATE temporal sobre platform, de platform_schema_owner).
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE platform_schema_owner;
GRANT CREATE ON SCHEMA platform TO grant_owner;
SET LOCAL ROLE grant_owner;
DO $rewrite_grant$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p WHERE p.proowner = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) AND p.prosrc ~ '\mapp\.(revocation|rights_case)\M' ORDER BY p.oid LOOP
    EXECUTE pg_catalog.regexp_replace(pg_catalog.pg_get_functiondef(f.oid), '\mapp\.(revocation|rights_case)\M', 'case_state.\1', 'g');
  END LOOP;
END
$rewrite_grant$;
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE platform_schema_owner;
REVOKE CREATE ON SCHEMA platform FROM grant_owner;

-- 3c. ledger_writer: ledger_gen.guard_consent_decision (CREATE temporal sobre ledger_gen, de ledger_gen_owner).
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE ledger_gen_owner;
GRANT CREATE ON SCHEMA ledger_gen TO ledger_writer;
SET LOCAL ROLE ledger_writer;
DO $rewrite_ledger$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p WHERE p.proowner = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) AND p.prosrc ~ '\mapp\.(revocation|rights_case)\M' ORDER BY p.oid LOOP
    EXECUTE pg_catalog.regexp_replace(pg_catalog.pg_get_functiondef(f.oid), '\mapp\.(revocation|rights_case)\M', 'case_state.\1', 'g');
  END LOOP;
END
$rewrite_ledger$;
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE ledger_gen_owner;
REVOKE CREATE ON SCHEMA ledger_gen FROM ledger_writer;

-- 3d. rights_case_lookup_owner: app.rights_case_tenant_of (CREATE temporal sobre app, de consent_owner todavia dueño del esquema; 0082 lo transfiere despues).
SET LOCAL ROLE consent_owner;
GRANT CREATE ON SCHEMA app TO rights_case_lookup_owner;
SET LOCAL ROLE rights_case_lookup_owner;
DO $rewrite_lookup$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p WHERE p.proowner = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) AND p.prosrc ~ '\mapp\.(revocation|rights_case)\M' ORDER BY p.oid LOOP
    EXECUTE pg_catalog.regexp_replace(pg_catalog.pg_get_functiondef(f.oid), '\mapp\.(revocation|rights_case)\M', 'case_state.\1', 'g');
  END LOOP;
END
$rewrite_lookup$;
SET LOCAL ROLE consent_owner;
REVOKE CREATE ON SCHEMA app FROM rights_case_lookup_owner;

-- 4. Aserciones (fail-closed): la migracion aborta si algo no quedo como se declara.
DO $assert81$
DECLARE
  t text;
  rel oid;
  n integer;
  digest_after text;
  r text;
BEGIN
  -- Las tablas viven en case_state, de case_state_owner, y ya no existen en app.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'app' AND c.relname IN ('revocation', 'rights_case')) THEN
    RAISE EXCEPTION '0081: app.revocation o app.rights_case siguen en el esquema app';
  END IF;
  FOREACH t IN ARRAY ARRAY['revocation', 'rights_case'] LOOP
    SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
     WHERE s.nspname = 'case_state' AND c.relname = t AND c.relkind = 'r' AND pg_catalog.pg_get_userbyid(c.relowner) = 'case_state_owner';
    IF rel IS NULL THEN RAISE EXCEPTION '0081: case_state.% no existe o no pertenece a case_state_owner', t; END IF;
    IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = rel) THEN RAISE EXCEPTION '0081: case_state.% perdio ENABLE/FORCE ROW LEVEL SECURITY', t; END IF;
    -- Indices y secuencias que viajan con la tabla: todos del mismo dueño y esquema.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
                WHERE i.indrelid = rel AND (ic.relnamespace <> (SELECT s.oid FROM pg_catalog.pg_namespace s WHERE s.nspname = 'case_state') OR pg_catalog.pg_get_userbyid(ic.relowner) <> 'case_state_owner')) THEN
      RAISE EXCEPTION '0081: hay indices de case_state.% fuera de case_state o de otro dueño', t;
    END IF;
    -- consent_owner (y el migrador por herencia) ya no es dueño ni tiene privilegio alguno.
    IF pg_catalog.has_table_privilege('consent_owner', rel, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('consent_owner', rel, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0081: consent_owner conserva privilegios sobre case_state.%', t;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a WHERE c.oid = rel AND (a.grantor <> (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'case_state_owner')
                                                                                                           OR a.grantee = (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'consent_owner')))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute at, pg_catalog.aclexplode(at.attacl) a WHERE at.attrelid = rel AND (a.grantor <> (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'case_state_owner')
                                                                                                           OR a.grantee = (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'consent_owner'))) THEN
      RAISE EXCEPTION '0081: la ACL de case_state.% tiene entradas de consent_owner (grantor o grantee)', t;
    END IF;
  END LOOP;
  -- Triggers del ledger/guarda (ENABLE ALWAYS) intactos: 3 por tabla.
  FOREACH t IN ARRAY ARRAY['revocation', 'rights_case'] LOOP
    SELECT pg_catalog.count(*) INTO n FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
     WHERE s.nspname = 'case_state' AND c.relname = t AND NOT g.tgisinternal AND g.tgenabled = 'A' AND g.tgname LIKE (t || '\_%');
    IF n <> 3 THEN RAISE EXCEPTION '0081: case_state.% debe conservar exactamente 3 triggers ENABLE ALWAYS (hay %)', t, n; END IF;
  END LOOP;
  -- Ningun cuerpo de funcion nombra ya las tablas viejas (ni en comentarios): el nombre viejo ya no resuelve.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
              WHERE s.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prosrc ~ '\mapp\.(revocation|rights_case)\M') THEN
    RAISE EXCEPTION '0081: queda alguna funcion que nombra app.revocation o app.rights_case';
  END IF;
  -- La huella de las funciones recreadas (dueño, SECURITY DEFINER, search_path, ACL, volatilidad, firma) no cambio: se recalcula con el MISMO criterio sobre las que ahora nombran case_state.*.
  SELECT COALESCE(pg_catalog.md5(pg_catalog.string_agg(
           n2.nspname::pg_catalog.text || '.' || p.proname::pg_catalog.text || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')|' || pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text || '|' || p.prosecdef::pg_catalog.text || '|'
           || COALESCE(p.proconfig::pg_catalog.text, '') || '|' || COALESCE(p.proacl::pg_catalog.text, '') || '|' || p.provolatile::pg_catalog.text || '|' || p.proretset::pg_catalog.text || '|' || p.prorettype::pg_catalog.text || '|'
           || COALESCE(p.proargnames::pg_catalog.text, '') || '|' || p.prolang::pg_catalog.text || '|' || p.proleakproof::pg_catalog.text || '|' || p.proparallel::pg_catalog.text,
           E'\n' ORDER BY n2.nspname::pg_catalog.text COLLATE "C", p.proname::pg_catalog.text COLLATE "C", pg_catalog.pg_get_function_identity_arguments(p.oid) COLLATE "C")), '')
    INTO digest_after
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n2 ON n2.oid = p.pronamespace
   WHERE p.prosrc ~ '\mcase_state\.(revocation|rights_case)\M';
  -- (Funciones que ya nombraban case_state.revocation antes —ninguna en 0037-0070— entrarian en la huella posterior y no en la anterior: la comparacion lo detectaria.)
  IF pg_catalog.current_setting('cns.pr7c_fn_digest', true) <> '' AND digest_after IS DISTINCT FROM pg_catalog.current_setting('cns.pr7c_fn_digest', true) THEN -- (en una reaplicacion no hay funciones con el nombre viejo: huella vacia, nada que comparar)
    RAISE EXCEPTION '0081: la huella de las funciones recreadas cambio (dueño, SECURITY DEFINER, search_path, ACL, volatilidad o firma)';
  END IF;
  -- Los CREATE temporales quedaron revocados.
  FOREACH r IN ARRAY ARRAY['transition_owner', 'consent_owner', 'consent_migrator', 'app_rw', 'platform_rw', 'worker', 'integrity_reconciler', 'rights_case_lookup_owner'] LOOP
    IF pg_catalog.has_schema_privilege(r, 'case_state', 'CREATE') THEN RAISE EXCEPTION '0081: % conserva CREATE en case_state', r; END IF;
  END LOOP;
  IF pg_catalog.has_schema_privilege('grant_owner', 'platform', 'CREATE') THEN RAISE EXCEPTION '0081: grant_owner conserva CREATE en platform'; END IF;
  IF pg_catalog.has_schema_privilege('ledger_writer', 'ledger_gen', 'CREATE') THEN RAISE EXCEPTION '0081: ledger_writer conserva CREATE en ledger_gen'; END IF;
  IF pg_catalog.has_schema_privilege('rights_case_lookup_owner', 'app', 'CREATE') OR pg_catalog.has_schema_privilege('case_state_owner', 'app', 'CREATE') OR pg_catalog.has_schema_privilege('case_state_owner', 'app', 'USAGE') THEN
    RAISE EXCEPTION '0081: rights_case_lookup_owner o case_state_owner conservan privilegios sobre el esquema app';
  END IF;
  -- Lectores de fuera del esquema con USAGE (sin CREATE).
  FOREACH r IN ARRAY ARRAY['integrity_reconciler', 'rights_case_lookup_owner', 'app_rw', 'worker', 'platform_rw', 'transition_owner'] LOOP
    IF NOT pg_catalog.has_schema_privilege(r, 'case_state', 'USAGE') THEN RAISE EXCEPTION '0081: % no tiene USAGE sobre case_state', r; END IF;
  END LOOP;
END
$assert81$;
