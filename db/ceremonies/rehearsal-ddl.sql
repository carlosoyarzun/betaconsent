-- Gobierna: ADR-010 rev. 6 fila PR-7 de §10 (ensayo de ceremonia con evidencia), TEST-CNS-1856; PR-7e. Solo datos sinteticos.
-- DDL MINIMO del ensayo: dentro de la sesion de ddl_breakglass (ceremonia abierta) asume integrity_owner, crea una tabla de prueba vacia en integrity y la elimina. No toca el ledger ni sus triggers/policies. Solo DDL.

BEGIN;
SET LOCAL ROLE integrity_owner;
CREATE TABLE integrity.ceremony_rehearsal_probe (probe_id integer PRIMARY KEY);
DROP TABLE integrity.ceremony_rehearsal_probe;
COMMIT;
