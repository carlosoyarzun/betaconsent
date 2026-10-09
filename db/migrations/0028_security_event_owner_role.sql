-- scope: cluster
-- Gobierna: SEC-CNS-021 PR-1 (aceptada por Carlos 2026-10-08; §3 matriz de roles, §4.1 M+1), P-34, CA-146, ADR-010 rev. 3 §4.1 / §4.1.1,
-- SEC-CNS-006 rev. 5, INV-21-06, INV-CM-01 (append-only). Regla de Carlos (2026-10-01): 0000-0027 no se editan.
--
-- Rol del cluster dueno de ops.security_event y, en PRs posteriores de SEC-CNS-021, de ops.retention_policy / ops.purge_run / ops.otp_budget
-- y de las funciones de purga P-34. La transferencia de ops.security_event la hace 0029. Se crea en alcance cluster (ninguna migracion de
-- base tiene CREATEROLE). Idempotente; mismo patron que 0026 (integrity_owner).
--
--   security_event_owner  NOLOGIN, NOSUPERUSER, NOBYPASSRLS. consent_owner puede SET ROLE (WITH INHERIT FALSE, SET TRUE: no hereda sus
--                         privilegios) y solo lo hace en migraciones que lo declaran con SET LOCAL ROLE security_event_owner y pasan por
--                         CODEOWNERS (allowlist en tools/spec-checks/integrity-owner-checker.ts). Ningun rol de runtime es miembro
--                         (lo verifican catalog.test.ts y startup-checks.ts).
--
-- Residual R-21-1 / F-2 (P2, aceptado solo IT0b sintetico; revisar antes de datos reales, ADR-010 §4.5): la membresia de consent_owner es
-- transitoria (F-7, D7) y consent_owner sigue siendo dueno del esquema ops, por lo que puede DROP de tablas de ops. Misma clase que F-X8-11 / R-22.

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'security_event_owner') THEN
    CREATE ROLE security_event_owner NOLOGIN;
  END IF;
  ALTER ROLE security_event_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$role$;

GRANT security_event_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;

-- Solo si hay membresia (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles g ON g.oid = m.roleid JOIN pg_catalog.pg_roles u ON u.oid = m.member
                WHERE g.rolname = 'security_event_owner' AND u.rolname = r) THEN
      EXECUTE pg_catalog.format('REVOKE security_event_owner FROM %I', r);
    END IF;
  END LOOP;
END
$revoke$;
