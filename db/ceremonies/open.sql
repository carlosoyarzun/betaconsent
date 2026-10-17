-- Gobierna: ADR-010 rev. 6 §4.5.3/§4.5.4 (ceremonia de break-glass, Q13, Q-20 (c)), F-PR7-07, decisiones de Carlos del 2026-10-16 (C-4: Carlos solo en IT0b sintetico, dos personas antes de datos reales;
-- apertura con verificador SCRAM calculado en el CLIENTE; C-5 LEGAL DECISION: logs de ceremonia minimizados y solo DDL). PR-7e. Solo datos sinteticos.
--
-- ABRE una ceremonia: inserta la fila en breakglass.ceremony y habilita el LOGIN de ddl_breakglass por una ventana <= P-46 (60 min, CHECK de la tabla) con un VERIFICADOR SCRAM-SHA-256 calculado del lado del cliente
-- (tools/ceremony/scram-verifier.ts): la contrasena en texto plano NUNCA llega al servidor ni a sus logs; el verificador es un hash salado. Superusuario del cluster, conectado a la BASE de la aplicacion.
--
--   CNS_CEREMONY_VERIFIER="$VERIFIER" psql "$SUPERUSER_URL" -v ON_ERROR_STOP=1 -v ceremony_ref=CER-20261017-01 -v reason_code=REHEARSAL -v ticket_ref=CA-999 -v valid_minutes=30 -f db/ceremonies/open.sql
--
-- Variables: ceremony_ref (referencia opaca, ^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$), reason_code (DDL_LEDGER | DDL_SCHEMA | PRINCIPAL_BOOTSTRAP | INCIDENT_RECOVERY | REHEARSAL), ticket_ref (Jira CA-n), valid_minutes (1..60).
-- El verificador (SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>) se lee del ENTORNO con \getenv (variable CNS_CEREMONY_VERIFIER; psql 15+), NUNCA por argv (-v verifier=...): un argumento de linea de comandos
-- queda visible en `ps` y en el historial del shell (F-PR7D-07). Sin personas, sin datos del dominio. Solo DDL en la sesion de la ceremonia (la sesion usa log_statement = 'ddl', sin parametros).
-- El ancla firmada antes/despues de la ceremonia (Q13) llega con PR-7f (F-R6-1, C-7 pendiente de Carlos): hasta entonces la evidencia es SECUNDARIA (fila de ceremonia + log de sesion).

\set ON_ERROR_STOP on

-- Este script no deja el verificador ni nada de la ceremonia en el log del servidor de esta sesion de superusuario.
SET log_statement = 'none';
SET log_min_duration_statement = -1;
-- pg_stat_statements registraria el ALTER ROLE ... PASSWORD (utilidad) con el verificador: no se rastrean sentencias de utilidad en esta sesion (F-PR7D-07). Si la extension no esta cargada, es un placeholder inocuo.
SET pg_stat_statements.track_utility = off;
\getenv verifier CNS_CEREMONY_VERIFIER

SELECT (:'verifier' ~ '^SCRAM-SHA-256\$[0-9]{4,7}:[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$') AS verifier_ok,
       (:'valid_minutes' ~ '^[0-9]{1,2}$' AND :'valid_minutes'::int BETWEEN 1 AND 60) AS minutes_ok \gset
\if :verifier_ok
\else
  DO $abort$ BEGIN RAISE EXCEPTION 'open.sql: el verificador no tiene el formato SCRAM-SHA-256 (calculelo con tools/ceremony/scram-verifier.ts); no se abre nada.' USING ERRCODE = 'invalid_parameter_value'; END $abort$;
\endif
\if :minutes_ok
\else
  DO $abort$ BEGIN RAISE EXCEPTION 'open.sql: valid_minutes debe ser un entero entre 1 y 60 (P-46); no se abre nada.' USING ERRCODE = 'invalid_parameter_value'; END $abort$;
\endif

BEGIN;

-- Una sola ceremonia abierta a la vez (ddl_breakglass tiene CONNECTION LIMIT 1 y un solo verificador).
SELECT (count(*) = 0) AS none_open FROM breakglass.ceremony WHERE closed_at IS NULL \gset
\if :none_open
\else
  DO $abort$ BEGIN RAISE EXCEPTION 'open.sql: ya hay una ceremonia abierta; cierrela con close.sql antes de abrir otra.' USING ERRCODE = 'invalid_parameter_value'; END $abort$;
\endif

INSERT INTO breakglass.ceremony (ceremony_ref, valid_until, reason_code, ticket_ref)
VALUES (:'ceremony_ref', pg_catalog.now() + pg_catalog.make_interval(mins => :valid_minutes), :'reason_code', :'ticket_ref');

SELECT pg_catalog.format('ALTER ROLE ddl_breakglass LOGIN PASSWORD %L VALID UNTIL %L', :'verifier', c.valid_until) AS stmt
  FROM breakglass.ceremony c WHERE c.ceremony_ref = :'ceremony_ref' \gexec

COMMIT;
\echo 'open.sql: ceremonia abierta; ddl_breakglass puede iniciar sesion hasta valid_until. Cierre con db/ceremonies/close.sql.'
