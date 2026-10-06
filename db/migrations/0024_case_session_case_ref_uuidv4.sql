-- scope: database
-- Gobierna: CA-141 (P1-1 de la revision de seguridad del diseno, 2026-10-06; R1 de la aprobacion condicionada), specs/session.spec.yaml
-- (INV-SE-06: toda fila de sesion se proyecta a un evento valido), common.schema.json#/$defs/Ref (UUIDv4), residual R-SE-02.
-- 0000-0023 no se editan (esta migracion aun no esta en main, por eso pudo ajustarse).
--
-- app.case_session.case_ref pasa de "longitud 1..100" (0022) a Ref UUIDv4: es el mismo CHECK que ops.security_event.case_ref (0025),
-- de modo que ninguna sesion CASE pueda existir sin un evento CASE_LOGIN/CASE_LOGOUT escribible.
-- Filas previas: las sesiones CASE con case_ref que no es UUIDv4 se ELIMINAN antes de crear el CHECK (validado, sin NOT VALID). Son sesiones
-- efimeras (8 h) y solo pueden existir en una base LOCAL anterior a este cambio (datos sinteticos): borrarlas equivale a cerrarlas SIN evento.
-- El migrador es el dueno y la tabla es FORCE RLS sin policy para el dueno, asi que se apaga FORCE solo durante el DELETE (misma tx).
ALTER TABLE app.case_session NO FORCE ROW LEVEL SECURITY;
DELETE FROM app.case_session WHERE case_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
ALTER TABLE app.case_session FORCE ROW LEVEL SECURITY;
ALTER TABLE app.case_session
  ADD CONSTRAINT case_session_case_ref_uuidv4 CHECK (case_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
