-- scope: cluster
-- Gobierna: API-CNS-116 (GET /staff/roster), REQ-CNS-036 AC-04..AC-09, UX-CNS-005, DEC-BR-019 (Notion),
-- diseno api-cns-116-staff-list-design.md rev. 2, SEC-CNS-018 rev. 2 (R1), ADR-002, ADR-006 §1/§4-§6,
-- DEC-BR-014 §4 (solo datos sinteticos). Regla de Carlos (2026-10-01): 0000-0017 no se editan.
--
-- Roles del cluster de la proyeccion del roster del colegio. Se ejecuta como superusuario (consent_owner
-- tiene NOCREATEROLE, ver 0000_roles.sql y migrate.ts); es idempotente y no fija contrasenas.
--
--   staff_roster_owner   NOLOGIN. Dueno de la vista app.staff_roster_invitation_status (0019). Unico rol con
--                        SELECT por columna + policy sobre las tablas base para esa vista. consent_owner
--                        puede SET ROLE (para crear la vista y cederle la propiedad) pero NO hereda sus
--                        privilegios; el rol de runtime NO es miembro (lo verifica startup-checks.ts).
--   staff_roster_reader  NOLOGIN. Solo SELECT sobre la vista. app_rw es miembro WITH INHERIT FALSE, SET TRUE:
--                        no hereda nada y solo puede asumirlo con SET LOCAL ROLE dentro del GET /staff/roster.

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['staff_roster_owner', 'staff_roster_reader'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
END
$roles$;

-- Patron tenant_resolve_owner (0000): SET sin INHERIT.
GRANT staff_roster_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
-- Solo app_rw puede asumir el lector, y sin heredar sus privilegios.
GRANT staff_roster_reader TO app_rw WITH INHERIT FALSE, SET TRUE;

-- Ningun otro rol de runtime es miembro de ninguno de los dos.
REVOKE staff_roster_owner FROM app_rw, worker, platform_rw;
REVOKE staff_roster_reader FROM worker, platform_rw;
