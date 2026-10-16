-- scope: cluster
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §6 / §10 fila 6d, F-PR6-40, F-PR6-45 (seguridad de PR #101: la lectura cross-tenant de app.rights_case NO puede ser una policy del dueño
-- consent_owner, porque consent_migrator hereda sus privilegios); specs/db-roles.spec.yaml (rights_case_lookup_owner, INV-DBR-03). Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan.
--
-- Rol de cluster nuevo de PR-6d parte 1. Solo el rol y su membresia de asuncion: ningun privilegio sobre objetos (eso es 0059, que corre despues: los archivos cluster se aplican antes que los de database).
-- Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope) y es idempotente (patron 0046). No fija contrasena (NOLOGIN).
--
--   rights_case_lookup_owner  NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION. Dueño de app.rights_case_tenant_of (SECURITY DEFINER); SELECT solo de (tenant_id, case_ref, status) de
--                            app.rights_case y UNA policy TO este rol (0059). Ningun proceso LOGIN es miembro, ni directo ni transitivo, y el rol no es miembro de nadie.
--
-- Modo de roles (ADR-010 §4.1.1): el runner fija el GUC cns.db_role_mode antes de la fase de cluster. Solo en IT0B_SYNTHETIC consent_owner recibe SET (INHERIT FALSE, sin ADMIN) sobre el rol: PostgreSQL exige
-- poder asumirlo para crear objetos como el (patron 0034/0046, Q-15 c). Con INHERIT FALSE consent_owner (y consent_migrator, que hereda de consent_owner) NO hereda sus privilegios. En REAL_DATA solo
-- ddl_breakglass tendra SET (PR-7). Si el GUC falta o esta vacio aplica IT0B_SYNTHETIC.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rights_case_lookup_owner') THEN
    CREATE ROLE rights_case_lookup_owner NOLOGIN;
  END IF;
  ALTER ROLE rights_case_lookup_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$roles$;

DO $grants$
BEGIN
  IF COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') <> 'REAL_DATA' THEN
    GRANT rights_case_lookup_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
  END IF;
END
$grants$;

-- Un GRANT repetido no quita ADMIN OPTION: se revoca de forma condicional (solo si existe, para no emitir WARNING por corrida).
DO $admin$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
               JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
              WHERE r.rolname = 'rights_case_lookup_owner' AND x.rolname = 'consent_owner' AND m.admin_option) THEN
    REVOKE ADMIN OPTION FOR rights_case_lookup_owner FROM consent_owner;
  END IF;
END
$admin$;

-- El rol no es miembro de ningun otro (ni owner ni runtime): se revoca cualquier membresia preexistente.
DO $revoke$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE x.rolname = 'rights_case_lookup_owner' LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM rights_case_lookup_owner', m.role_name);
  END LOOP;
END
$revoke$;

-- Aserciones del estado resultante (fail-closed).
DO $assert64$
DECLARE
  rec record;
BEGIN
  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'rights_case_lookup_owner';
  IF NOT FOUND THEN RAISE EXCEPTION '0064: falta el rol rights_case_lookup_owner'; END IF;
  IF rec.rolcanlogin OR rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls THEN
    RAISE EXCEPTION '0064: rights_case_lookup_owner debe ser NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS';
  END IF;
  -- Miembros: ninguno, salvo consent_owner con SET sin herencia ni ADMIN (solo IT0B_SYNTHETIC). Ni miembro de nadie, ni grantor.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = rec.oid
              AND NOT (m.member = (SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'consent_owner') AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
    RAISE EXCEPTION '0064: rights_case_lookup_owner solo puede tener a consent_owner como miembro (SET, sin herencia ni ADMIN)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid OR m.grantor = rec.oid) THEN
    RAISE EXCEPTION '0064: rights_case_lookup_owner no debe ser miembro de ningun rol ni grantor';
  END IF;
END
$assert64$;
