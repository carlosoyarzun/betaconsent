-- scope: cluster
-- Gobierna: CA-124 (H09), ADR-002, ADR-006 §1/§4-§6, DEC-BR-014 §4 (solo datos sintéticos),
-- SEC-CNS-012 (P1-1, P1-3 de lampone-security en el diseño de CA-124).
--
-- Roles del cluster. Se ejecuta UNA vez por cluster como superusuario, únicamente para
-- crear roles (ninguna otra migración corre como superusuario). Es idempotente: se puede
-- reaplicar y reasegura los atributos. NO fija contraseñas (cero secretos en el repo): las
-- contraseñas las pone src/infra/adapters/postgres/migrate.ts (setRolePasswords) desde
-- variables de entorno efímeras; un rol LOGIN sin contraseña no puede autenticarse por TCP.
--
--   consent_owner         NOLOGIN. Dueño de esquemas/tablas/funciones (esquemas app, integrity, ops).
--   tenant_resolve_owner  NOLOGIN. Dueño del esquema tenant_resolve y de sus funciones SECURITY DEFINER.
--   consent_migrator      LOGIN, miembro de consent_owner. Su credencial existe solo en el paso de
--                         migración; nunca en el proceso web.
--   app_rw, worker, platform_rw
--                         LOGIN, NOSUPERUSER, NOBYPASSRLS, sin pertenecer a ningún owner y sin
--                         CREATE en ningún esquema (incluido public, ver 0001).

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['consent_owner', 'tenant_resolve_owner'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;

  FOREACH r IN ARRAY ARRAY['consent_migrator', 'app_rw', 'worker', 'platform_rw'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
END
$roles$;

-- El migrador hereda los privilegios del dueño y puede hacer SET ROLE consent_owner (el
-- runner ejecuta cada migración de base de datos como consent_owner).
GRANT consent_owner TO consent_migrator WITH INHERIT TRUE, SET TRUE;
-- consent_owner debe poder crear el esquema tenant_resolve con AUTHORIZATION tenant_resolve_owner.
GRANT tenant_resolve_owner TO consent_owner WITH INHERIT TRUE, SET TRUE;

-- Los roles de runtime NO son miembros de ningún owner (invariante que verifica
-- startup-checks.ts y TEST-CNS-744). Reasegurar por si un despliegue previo los hubiera unido.
REVOKE consent_owner FROM app_rw, worker, platform_rw;
REVOKE tenant_resolve_owner FROM app_rw, worker, platform_rw;

-- P1-1: una tx abandonada no debe retener locks ni la conexión (D9: 10 s, decisión de Carlos 2026-09-29).
ALTER ROLE app_rw SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE worker SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE platform_rw SET idle_in_transaction_session_timeout = '10s';
