-- scope: cluster
-- Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c), F-PR7-01 (P1 hoy; P0 antes de REAL_DATA), F-6D3-SEC-08, Q16, R-21-1/FN-12; decisiones de Carlos del 2026-10-17 (C-2: Q16 literal + esquemas app/ops a owners NOLOGIN;
-- C-3: funciones compartidas a un owner NOLOGIN propio; F-6D3-SEC-08: rol propio para list_confirmed_unapplied); specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-01, INV-DBR-03).
-- Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan; esta es nueva.
--
-- Roles de cluster nuevos de PR-7c. Solo roles y membresias de asuncion: ningun privilegio sobre objetos (eso es 0081-0083, de database: los archivos cluster se aplican antes que los de database).
-- Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope) y es idempotente (patron 0034/0064). No fija contrasena (NOLOGIN).
--
--   app_schema_owner         NOLOGIN. Dueño del esquema app (0082). El dueño de un esquema puede DROP de objetos ajenos dentro de el: por eso consent_owner (el migrador) deja de serlo y conserva solo USAGE, CREATE.
--   ops_schema_owner         NOLOGIN. Dueño del esquema ops (0082). Cierra R-21-1 (DROP de tablas de ops por el dueño del esquema).
--   shared_fn_owner          NOLOGIN. Dueño de las funciones compartidas que otros owners referencian desde policies, DEFAULT, CHECK y cuerpos SECURITY DEFINER: app.current_tenant_id(), app.is_reserved_email(text),
--                            ops.catalog_environment() (0082). Sin CREATE en ningun esquema ni privilegio sobre tablas. Con CREATE OR REPLACE sobre ellas, consent_owner ejecutaria codigo como otro owner (F-PR7-01).
--   revocation_recovery_reader NOLOGIN. Dueño solo de case_state.list_confirmed_unapplied (0083) y de la unica policy de lectura cross-tenant de case_state.revocation (F-6D3-SEC-08: sale de transition_owner).
--
-- Modo de roles (ADR-010 §4.1.1): el runner fija el GUC cns.db_role_mode antes de la fase de cluster. Solo en IT0B_SYNTHETIC consent_owner recibe SET (INHERIT FALSE, sin ADMIN) sobre los cuatro roles:
-- PostgreSQL exige poder asumirlos para ALTER ... OWNER TO y para crear objetos como ellos (patron 0034/0046/0064, Q-15 c). Con INHERIT FALSE consent_owner (y consent_migrator, que hereda de consent_owner) NO
-- hereda sus privilegios. En REAL_DATA solo ddl_breakglass tendra SET (PR-7d). Si el GUC falta o esta vacio aplica IT0B_SYNTHETIC.

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_schema_owner', 'ops_schema_owner', 'shared_fn_owner', 'revocation_recovery_reader'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
END
$roles$;

DO $grants$
BEGIN
  IF COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') <> 'REAL_DATA' THEN
    GRANT app_schema_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT ops_schema_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT shared_fn_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT revocation_recovery_reader TO consent_owner WITH INHERIT FALSE, SET TRUE;
  END IF;
END
$grants$;

-- Un GRANT repetido no quita ADMIN OPTION: se revoca de forma condicional (solo si existe, para no emitir WARNING por corrida).
DO $admin$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY ARRAY['app_schema_owner', 'ops_schema_owner', 'shared_fn_owner', 'revocation_recovery_reader'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = g AND x.rolname = 'consent_owner' AND m.admin_option) THEN
      EXECUTE pg_catalog.format('REVOKE ADMIN OPTION FOR %I FROM consent_owner', g);
    END IF;
  END LOOP;
END
$admin$;

-- Los roles nuevos no son miembros de ningun otro rol, y ningun rol de runtime ni el migrador es miembro de ellos (el migrador solo llega de forma transitiva por consent_owner y con un cambio de rol explicito).
DO $revoke$
DECLARE
  g text;
  u text;
  m record;
BEGIN
  FOREACH g IN ARRAY ARRAY['app_schema_owner', 'ops_schema_owner', 'shared_fn_owner', 'revocation_recovery_reader'] LOOP
    FOR m IN SELECT r.rolname AS role_name FROM pg_catalog.pg_auth_members am
               JOIN pg_catalog.pg_roles r ON r.oid = am.roleid JOIN pg_catalog.pg_roles x ON x.oid = am.member
              WHERE x.rolname = g LOOP
      EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.role_name, g);
    END LOOP;
    FOREACH u IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'integrity_reconciler', 'integrity_chain_verifier', 'consent_migrator'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members am
                   JOIN pg_catalog.pg_roles r ON r.oid = am.roleid JOIN pg_catalog.pg_roles x ON x.oid = am.member
                  WHERE r.rolname = g AND x.rolname = u) THEN
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', g, u);
      END IF;
    END LOOP;
  END LOOP;
END
$revoke$;

-- Aserciones del estado resultante (fail-closed).
DO $assert80$
DECLARE
  g text;
  rec record;
BEGIN
  FOREACH g IN ARRAY ARRAY['app_schema_owner', 'ops_schema_owner', 'shared_fn_owner', 'revocation_recovery_reader'] LOOP
    SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = g;
    IF NOT FOUND THEN RAISE EXCEPTION '0080: falta el rol %', g; END IF;
    IF rec.rolcanlogin OR rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls THEN
      RAISE EXCEPTION '0080: % debe ser NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS', g;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = rec.oid
                AND NOT (m.member = (SELECT c.oid FROM pg_catalog.pg_roles c WHERE c.rolname = 'consent_owner') AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
      RAISE EXCEPTION '0080: % solo puede tener a consent_owner como miembro (SET, sin herencia ni ADMIN)', g;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid OR m.grantor = rec.oid) THEN
      RAISE EXCEPTION '0080: % no debe ser miembro de ningun rol ni grantor', g;
    END IF;
  END LOOP;
END
$assert80$;
