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
-- Residual F-X8-11 (PENDIENTE de aceptacion de Carlos; caduca antes de datos reales/G6: ADR-010 break-glass +
-- ancla externa): el migrador puede asumir integrity_owner con un SET ROLE explicito (migrador ->
-- consent_owner -> integrity_owner) y entonces tiene control total del ledger (DISABLE TRIGGER, CREATE OR
-- REPLACE de la funcion, DROP). La cadena SHA-256 sin ancla externa no lo detecta. Ademas consent_owner es
-- datdba y puede DROP DATABASE. Esta migracion solo logra que el DDL del ledger deba declararse y revisarse.

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_owner') THEN
    CREATE ROLE integrity_owner NOLOGIN;
  END IF;
  ALTER ROLE integrity_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$role$;

GRANT integrity_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;

-- Solo si hay membresia (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles g ON g.oid = m.roleid JOIN pg_catalog.pg_roles u ON u.oid = m.member
                WHERE g.rolname = 'integrity_owner' AND u.rolname = r) THEN
      EXECUTE pg_catalog.format('REVOKE integrity_owner FROM %I', r);
    END IF;
  END LOOP;
END
$revoke$;
