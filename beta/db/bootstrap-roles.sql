-- Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-02.
-- Lo ejecuta UN SUPERUSUARIO una sola vez por clúster (idempotente), con psql:
--   psql "$SUPERUSER_URL" -v dbname=consent -v migrator_password=... -v app_password=... -f db/bootstrap-roles.sql
-- Tres roles (reemplaza los ~12 del repo anterior):
--   consent_owner    NOLOGIN. Dueño de la base y de TODOS los objetos y funciones SECURITY DEFINER.
--   consent_migrator LOGIN NOINHERIT. Miembro de consent_owner solo con SET (SET ROLE en cada migración); no hereda privilegios.
--   consent_app      LOGIN, sin BYPASSRLS/CREATEDB/CREATEROLE y SIN membresía en consent_owner (proceso web y CLI).
-- Requiere PostgreSQL >= 16 (GRANT ... WITH INHERIT FALSE, SET TRUE).
-- Las contraseñas llegan por variables de psql; no se guardan en el repo.

\set ON_ERROR_STOP on

SELECT 'CREATE ROLE consent_owner NOLOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consent_owner') \gexec
SELECT 'CREATE ROLE consent_migrator LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consent_migrator') \gexec
SELECT 'CREATE ROLE consent_app LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consent_app') \gexec

ALTER ROLE consent_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
ALTER ROLE consent_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION PASSWORD :'migrator_password';
ALTER ROLE consent_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION PASSWORD :'app_password';

-- El migrador puede SET ROLE consent_owner pero no hereda sus privilegios.
GRANT consent_owner TO consent_migrator WITH INHERIT FALSE, SET TRUE;
-- consent_app NO es miembro de consent_owner (ni de forma indirecta).
REVOKE consent_owner FROM consent_app;

SELECT format('CREATE DATABASE %I OWNER consent_owner ENCODING ''UTF8'' TEMPLATE template0', :'dbname')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'dbname') \gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'dbname') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO consent_migrator, consent_app', :'dbname') \gexec
