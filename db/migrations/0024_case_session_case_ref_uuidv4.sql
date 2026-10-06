-- scope: database
-- Gobierna: CA-141 (P1-1 de la revision de seguridad del diseno, 2026-10-06), specs/session.spec.yaml (INV-SE-06: toda fila de
-- sesion se proyecta a un evento valido), common.schema.json#/$defs/Ref (UUIDv4), residual R-SE-02. 0000-0023 no se editan.
--
-- app.case_session.case_ref pasa de "longitud 1..100" (0022) a Ref UUIDv4: es el mismo CHECK que ops.security_event.case_ref (0025).
-- Sin esto, un login CASE con un caseRef no UUID crearia una sesion cuyo evento CASE_LOGIN/CASE_LOGOUT no se puede escribir.
-- NOT VALID: no relee filas previas (una base local con sesiones sinteticas viejas no debe impedir migrar); el CHECK rige para
-- toda fila nueva o actualizada. Una sesion previa con caseRef no UUID no puede revocarse (falla cerrado: 503) y vence sola (8 h).
ALTER TABLE app.case_session
  ADD CONSTRAINT case_session_case_ref_uuidv4 CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') NOT VALID;
