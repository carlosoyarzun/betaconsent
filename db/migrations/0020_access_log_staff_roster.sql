-- scope: database
-- Gobierna: API-CNS-116 (GET /staff/roster), diseno api-cns-116-staff-list-design.md rev. 2 §6 (P2-c),
-- DEC-BR-014 rev. 8 §3 X6 (lecturas de staff a ops.access_log, no al ledger), DEC-BR-019 (Notion), SEC-CNS-018
-- rev. 2, ADR-002 §10, INV-CM-01 (append-only), DEC-BR-014 §4 (solo sinteticos). 0000-0017 no se editan.
--
-- Amplia el vocabulario de ops.access_log (0014) con la lectura del roster del colegio:
--   action = STAFF_ROSTER_READ, resource_type = STAFF_ROSTER. UNA fila por request, con resource_ref = tenant_id
--   (el recurso leido es el roster completo del tenant, no una participacion: con una participacion por alumno
--   un registro por participacion degeneraria en uno por alumno, sin valor de auditoria). resource_ref conserva
--   el CHECK UUIDv4: un tenant_id que no sea v4 hace fallar el INSERT y el GET responde 503 (fail-closed).
-- Ademas liga action y resource_type (un par permitido por accion) para que no se mezclen vocabularios.

ALTER TABLE ops.access_log DROP CONSTRAINT access_log_action_enum;
ALTER TABLE ops.access_log DROP CONSTRAINT access_log_resource_type_enum;
ALTER TABLE ops.access_log ADD CONSTRAINT access_log_action_enum
  CHECK (action IN ('RIGHTS_CASE_READ', 'STAFF_ROSTER_READ'));
ALTER TABLE ops.access_log ADD CONSTRAINT access_log_resource_type_enum
  CHECK (resource_type IN ('RIGHTS_CASE', 'STAFF_ROSTER'));
ALTER TABLE ops.access_log ADD CONSTRAINT access_log_action_resource_pair
  CHECK ((action = 'RIGHTS_CASE_READ' AND resource_type = 'RIGHTS_CASE')
      OR (action = 'STAFF_ROSTER_READ' AND resource_type = 'STAFF_ROSTER'));
