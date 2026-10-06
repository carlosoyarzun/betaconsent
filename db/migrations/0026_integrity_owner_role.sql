-- scope: cluster
-- Gobierna: X8 decision 3 (Carlos, 2026-10-06), F-X8-11, DEC-BR-014 §6 (owner NOLOGIN distinto del
-- migrador), ADR-002 §2, INV-CM-01 (append-only). Regla de Carlos (2026-10-01): 0000-0025 no se editan.
--
-- Rol del cluster dueno del ledger (esquema integrity, integrity.audit_event y su funcion de
-- inmutabilidad; la transferencia la hace 0027). Se crea en alcance cluster (ninguna migracion de base
-- tiene CREATEROLE). Idempotente; mismo patron que 0004/0018.
--
--   integrity_owner  NOLOGIN, NOSUPERUSER, NOBYPASSRLS. consent_owner puede SET ROLE (WITH INHERIT FALSE,
--                    SET TRUE: no hereda sus privilegios) y solo lo hace en migraciones que lo declaran
--                    con SET LOCAL ROLE integrity_owner y pasan por CODEOWNERS. Ningun rol de runtime es
--                    miembro (lo verifican catalog.test.ts y startup-checks.ts).
--
-- Residual aceptado para IT0 (F-X8-11): el migrador sigue pudiendo asumirlo con un SET ROLE explicito
-- (migrador -> consent_owner -> integrity_owner); impedirlo requiere un break-glass fuera del runner (ADR-010).

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_owner') THEN
    CREATE ROLE integrity_owner NOLOGIN;
  END IF;
  ALTER ROLE integrity_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$role$;

GRANT integrity_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;

REVOKE integrity_owner FROM app_rw, worker, platform_rw;
