-- Gobierna: ADR-010 rev. 6 §4.5.3/§4.5.4, Q13, Q-20 (c); decisiones de Carlos del 2026-10-16 (C-4, C-5). PR-7e. Solo datos sinteticos.
--
-- CIERRA una ceremonia: ddl_breakglass vuelve a NOLOGIN con la credencial vencida y sin contrasena (el verificador de la ceremonia se descarta), se terminan sus sesiones y se registra closed_at (unico UPDATE que admite
-- el trigger de breakglass.ceremony). Superusuario del cluster, conectado a la base de la aplicacion. Idempotente para el rol; falla si la ceremonia no existe o ya estaba cerrada.
--
--   psql "$SUPERUSER_URL" -v ON_ERROR_STOP=1 -v ceremony_ref=CER-20261017-01 -f db/ceremonies/close.sql

\set ON_ERROR_STOP on
SET log_statement = 'none';

BEGIN;
ALTER ROLE ddl_breakglass NOLOGIN PASSWORD NULL VALID UNTIL '1970-01-01 00:00:00+00';
SELECT pg_catalog.pg_terminate_backend(a.pid) FROM pg_catalog.pg_stat_activity a WHERE a.usename = 'ddl_breakglass';
UPDATE breakglass.ceremony SET closed_at = pg_catalog.now() WHERE ceremony_ref = :'ceremony_ref' AND closed_at IS NULL;
SELECT (count(*) = 1) AS closed_ok FROM breakglass.ceremony WHERE ceremony_ref = :'ceremony_ref' AND closed_at IS NOT NULL \gset
\if :closed_ok
\else
  DO $abort$ BEGIN RAISE EXCEPTION 'close.sql: la ceremonia no existe; no se cierra nada.' USING ERRCODE = 'invalid_parameter_value'; END $abort$;
\endif
COMMIT;
\echo 'close.sql: ceremonia cerrada; ddl_breakglass NOLOGIN y sin sesiones.'
