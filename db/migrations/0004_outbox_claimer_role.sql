-- scope: cluster
-- Gobierna: CA-124 (H09), PR-B; postgres-design.md rev. 2 §4 P1-6 (claim del worker devuelve solo
-- (tenant_id, id)), SEC-CNS-012 (P1-2, P1-6), ADR-006 §4-§6.
--
-- Rol del claim del outbox. Se crea en alcance cluster (los roles son del cluster; ninguna migracion
-- de base tiene CREATEROLE). El runner aplica TODO el alcance cluster antes que el de base, de modo
-- que existe cuando 0003_outbox.sql (database) lo usa, aunque su numero sea posterior. Idempotente.
--
--   outbox_claimer  NOLOGIN, NOSUPERUSER, NOBYPASSRLS, no miembro de ningun owner. Dueno de la
--                   funcion SECURITY DEFINER app.outbox_claim; privilegios minimos por columna.
--
-- El migrador (y solo el, no los roles de runtime) puede hacer SET ROLE outbox_claimer para crear
-- la funcion con ese dueno, sin heredar sus privilegios (INHERIT FALSE).

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'outbox_claimer') THEN
    CREATE ROLE outbox_claimer NOLOGIN;
  END IF;
  ALTER ROLE outbox_claimer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$role$;

GRANT outbox_claimer TO consent_migrator WITH INHERIT FALSE, SET TRUE;

-- Invariante: ni los roles de runtime ni los owners son miembros de outbox_claimer, y este no es
-- miembro de nadie (verificado por tests/integration/postgres/catalog.test.ts).
REVOKE outbox_claimer FROM app_rw, worker, platform_rw;
