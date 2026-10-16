-- scope: database
-- Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c), F-6D3-SEC-08 (decision de Carlos del 2026-10-17: rol NOLOGIN propio dueño de case_state.list_confirmed_unapplied, con la policy TO ese rol en vez de la policy
-- cross-tenant de transition_owner), F-6D3-SEC-01 (descubrimiento de CONFIRMED sin APPLIED para el respaldo R4 del worker), ADR-010 rev. 5 §4.2.a (G-3); specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-01).
-- Depende de 0080 (rol de cluster) y 0081 (case_state.revocation). Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan; 0067 y 0070 siguen siendo las vigentes hasta aqui y esta las corrige.
--
-- Que cambia:
--   * Se elimina la policy revocation_transition_recovery_select TO transition_owner (la unica excepcion cross-tenant de transition_owner, dueño de todas las transiciones; solo se cumplia bajo el GUC
--     case_state.effect = 'list_confirmed_unapplied', que cualquier funcion de transition_owner podia fijar).
--   * Nueva policy revocation_recovery_reader_select de SELECT TO revocation_recovery_reader (status = 'CONFIRMED'): ya no depende de un GUC; el rol solo es alcanzable por la funcion que posee.
--   * revocation_recovery_reader: USAGE de case_state, SELECT SOLO de (tenant_id, revocation_ref, status, created_at) de case_state.revocation (ni una columna mas), sin CREATE.
--   * case_state.list_confirmed_unapplied(integer, text[]) se recrea como dueño revocation_recovery_reader (SECURITY DEFINER, search_path fijo, mismo contrato: solo (tenant_id, revocation_ref) de CONFIRMED, limite 1..100,
--     omision <= 1000, solo session_user = worker); EXECUTE solo worker. Ya no fija el GUC case_state.effect.
-- Idempotente: DROP ... IF EXISTS y recreacion del objeto completo.

SET LOCAL ROLE consent_owner;

-- 1. Como dueño de la tabla (case_state_owner): privilegios y policy del rol nuevo; CREATE temporal para crear la funcion (se revoca abajo).
SET LOCAL ROLE case_state_owner;
GRANT USAGE, CREATE ON SCHEMA case_state TO revocation_recovery_reader;
GRANT SELECT (tenant_id, revocation_ref, status, created_at) ON case_state.revocation TO revocation_recovery_reader;
DROP POLICY IF EXISTS revocation_transition_recovery_select ON case_state.revocation;
DROP POLICY IF EXISTS revocation_recovery_reader_select ON case_state.revocation;
CREATE POLICY revocation_recovery_reader_select ON case_state.revocation FOR SELECT TO revocation_recovery_reader USING (status = 'CONFIRMED');

-- 2. La funcion vieja (de transition_owner) se elimina y se recrea como dueño revocation_recovery_reader.
SET LOCAL ROLE consent_owner;
SET LOCAL ROLE transition_owner;
DROP FUNCTION IF EXISTS case_state.list_confirmed_unapplied(integer, text[]);

SET LOCAL ROLE consent_owner;
SET LOCAL ROLE revocation_recovery_reader;
CREATE FUNCTION case_state.list_confirmed_unapplied(p_limit integer, p_skip_refs text[]) RETURNS TABLE (o_tenant_id uuid, o_revocation_ref text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF session_user <> 'worker' THEN RAISE EXCEPTION 'llamador no autorizado' USING ERRCODE = 'RC004'; END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN RAISE EXCEPTION 'limite invalido' USING ERRCODE = '22023'; END IF;
  IF pg_catalog.cardinality(COALESCE(p_skip_refs, ARRAY[]::text[])) > 1000 THEN RAISE EXCEPTION 'lista de omision demasiado grande' USING ERRCODE = '22023'; END IF;
  RETURN QUERY
    SELECT r.tenant_id, r.revocation_ref FROM case_state.revocation r
     WHERE r.status = 'CONFIRMED' AND r.revocation_ref <> ALL (COALESCE(p_skip_refs, ARRAY[]::text[]))
     ORDER BY r.created_at, r.revocation_ref LIMIT p_limit;
END
$fn$;
REVOKE ALL ON FUNCTION case_state.list_confirmed_unapplied(integer, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION case_state.list_confirmed_unapplied(integer, text[]) TO worker;

SET LOCAL ROLE consent_owner;
SET LOCAL ROLE case_state_owner;
REVOKE CREATE ON SCHEMA case_state FROM revocation_recovery_reader;
SET LOCAL ROLE consent_owner;

-- 3. Aserciones (fail-closed).
DO $assert83$
DECLARE
  rv oid;
  fn record;
  r text;
BEGIN
  SELECT c.oid INTO rv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'case_state' AND c.relname = 'revocation';
  IF rv IS NULL THEN RAISE EXCEPTION '0083: falta case_state.revocation'; END IF;
  -- La policy cross-tenant de transition_owner no existe; existe exactamente UNA lectura cross-tenant (TO revocation_recovery_reader, solo CONFIRMED).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polname = 'revocation_transition_recovery_select') THEN RAISE EXCEPTION '0083: sigue la policy revocation_transition_recovery_select'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polroles @> ARRAY[(SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'transition_owner')]::oid[]
              AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%CONFIRMED%') THEN
    RAISE EXCEPTION '0083: transition_owner conserva una policy que lee CONFIRMED cross-tenant';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polname = 'revocation_recovery_reader_select' AND p.polcmd = 'r'
         AND p.polroles = ARRAY[(SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'revocation_recovery_reader')]::oid[]
         AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%CONFIRMED%' AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) NOT LIKE '%current_setting%') <> 1 THEN
    RAISE EXCEPTION '0083: falta la policy de SELECT TO revocation_recovery_reader (solo CONFIRMED, sin GUC)';
  END IF;
  -- El rol: SELECT por columnas exacto, ningun otro privilegio, sin CREATE en case_state ni en app/ops, miembro de nadie.
  IF pg_catalog.has_table_privilege('revocation_recovery_reader', rv, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('revocation_recovery_reader', rv, 'INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0083: revocation_recovery_reader tiene mas privilegios de los previstos sobre case_state.revocation';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = rv AND a.attnum > 0 AND NOT a.attisdropped
              AND (a.attname IN ('tenant_id', 'revocation_ref', 'status', 'created_at')) <> pg_catalog.has_column_privilege('revocation_recovery_reader', rv, a.attnum, 'SELECT')) THEN
    RAISE EXCEPTION '0083: revocation_recovery_reader debe leer exactamente (tenant_id, revocation_ref, status, created_at)';
  END IF;
  FOREACH r IN ARRAY ARRAY['case_state', 'app', 'ops', 'platform', 'integrity', 'ledger_gen'] LOOP
    IF pg_catalog.has_schema_privilege('revocation_recovery_reader', r, 'CREATE') THEN RAISE EXCEPTION '0083: revocation_recovery_reader tiene CREATE en %', r; END IF;
  END LOOP;
  IF NOT pg_catalog.has_schema_privilege('revocation_recovery_reader', 'case_state', 'USAGE') THEN RAISE EXCEPTION '0083: revocation_recovery_reader no tiene USAGE en case_state'; END IF;
  IF pg_catalog.has_schema_privilege('revocation_recovery_reader', 'integrity', 'USAGE') OR pg_catalog.has_schema_privilege('revocation_recovery_reader', 'platform', 'USAGE') THEN
    RAISE EXCEPTION '0083: revocation_recovery_reader tiene USAGE fuera de case_state';
  END IF;
  -- La funcion: dueño, SECURITY DEFINER, search_path fijo, sin SQL dinamico, ACL exacta (solo worker).
  SELECT p.oid, p.prosecdef, p.proconfig, p.proacl, p.proowner, p.prosrc INTO fn FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
   WHERE s.nspname = 'case_state' AND p.proname = 'list_confirmed_unapplied';
  IF fn.oid IS NULL OR pg_catalog.pg_get_userbyid(fn.proowner) <> 'revocation_recovery_reader' OR NOT fn.prosecdef OR fn.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
     OR pg_catalog.has_function_privilege('public', fn.oid, 'EXECUTE') OR fn.prosrc ~* '\mexecute\M' THEN
    RAISE EXCEPTION '0083: case_state.list_confirmed_unapplied: dueño/SECURITY DEFINER/search_path/ACL incorrectos';
  END IF;
  IF COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C")
                 FROM pg_catalog.aclexplode(COALESCE(fn.proacl, pg_catalog.acldefault('f', fn.proowner))) a WHERE a.grantee <> fn.proowner), '') IS DISTINCT FROM 'worker' THEN
    RAISE EXCEPTION '0083: la ACL de case_state.list_confirmed_unapplied no es exactamente [worker]';
  END IF;
  FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'integrity_verifier', 'integrity_reconciler', 'integrity_chain_verifier', 'transition_owner', 'consent_owner', 'consent_migrator'] LOOP
    IF pg_catalog.has_function_privilege(r, fn.oid, 'EXECUTE') THEN RAISE EXCEPTION '0083: % puede ejecutar case_state.list_confirmed_unapplied', r; END IF;
  END LOOP;
  -- Pertenencia: solo consent_owner con SET (sin herencia ni ADMIN, solo IT0B_SYNTHETIC); no es miembro de nadie.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.roleid WHERE x.rolname = 'revocation_recovery_reader'
              AND NOT (m.member = (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner') AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
    RAISE EXCEPTION '0083: revocation_recovery_reader solo puede tener a consent_owner como miembro (SET, sin herencia ni ADMIN)';
  END IF;
END
$assert83$;
