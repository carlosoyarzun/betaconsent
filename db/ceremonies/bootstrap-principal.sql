-- Gobierna: ADR-010 rev. 6 / rev. 4 §4.4 (Q10: bootstrap de los primeros principals PLATFORM), F-A10-17 (parte bootstrap), C-4 y C-8 (Carlos 2026-10-16: break-glass solo para el bootstrap/re-bootstrap; el alta rutinaria es
-- PR-7g), PR-7e. Solo datos SINTETICOS (platform.principal_identity.data_class = SYNTHETIC por CHECK).
--
-- Alta del vinculo principal_ref <-> sub_hmac ATESTADO FUERA DE BANDA y de la asignacion PLATFORM (doble control de la tabla: solicitante <> aprobador <> principal). Se ejecuta DENTRO de una ceremonia abierta (open.sql)
-- con la sesion de ddl_breakglass (SET ROLE membership_owner; la membresia llega de 0086). Los valores son seudonimos (UUIDv4 y HMAC hex), nunca correo, nombre ni RUT; la sesion usa log_statement = 'ddl', asi que este DML no se
-- escribe en el log. No hay literales de datos en el archivo: todo viene de variables psql.
--
--   psql "postgresql://ddl_breakglass@<host>/<db>" -v ON_ERROR_STOP=1 -v principal_ref=<uuidv4> -v sub_hmac=<64 hex> -v requested_by_ref=<uuidv4> -v approved_by_ref=<uuidv4> -f db/ceremonies/bootstrap-principal.sql
--
-- IT0b sintetico (C-4 (i)): Carlos solo; requested_by_ref y approved_by_ref son referencias UUIDv4 DISTINTAS (la tabla exige approved_by_ref <> requested_by_ref y ambos <> principal_ref), p. ej. la del operador y la de la
-- ceremonia. Antes de datos reales (C-4 (ii)): dos personas distintas (operador del host y aprobador) y >= 3 PLATFORM (Q10).

\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE membership_owner;

INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref)
VALUES (:'principal_ref', 'PLATFORM', 'PENDING', :'requested_by_ref')
ON CONFLICT (principal_ref, platform_role, (COALESCE(approver_class, ''))) DO NOTHING;

UPDATE platform.platform_role_assignment
   SET status = 'ACTIVE', approved_by_ref = :'approved_by_ref', approved_at = pg_catalog.now()
 WHERE principal_ref = :'principal_ref' AND platform_role = 'PLATFORM' AND status = 'PENDING';

INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES (:'principal_ref', :'sub_hmac')
ON CONFLICT DO NOTHING;

COMMIT;
