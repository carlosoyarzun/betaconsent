-- scope: database
-- Gobierna: X8 decision 3 (Carlos, 2026-10-06), F-X8-11, DEC-BR-014 §6, ADR-002 §2, INV-CM-01.
-- Regla de Carlos (2026-10-01): 0000-0026 no se editan; esta migracion es nueva.
--
-- Transfiere el ledger a integrity_owner (0026): esquema integrity, integrity.audit_event (arrastra
-- indices, triggers y policies) e integrity.audit_event_immutable(). Desde aqui consent_owner (y por tanto
-- el migrador) ya no es dueno ni hereda privilegios sobre el ledger: todo DDL futuro sobre integrity.*
-- debe declarar SET LOCAL ROLE integrity_owner. A integrity_owner NO se le concede USAGE/EXECUTE sobre
-- app/ops (minimo privilegio); una migracion futura que lo necesite lo concede de forma explicita.
-- Corre como consent_owner, que debe ser dueno de la base (si no lo es, el GRANT del paso 1 falla y la
-- migracion aborta: fail-closed).

-- 1. ALTER TABLE/FUNCTION ... OWNER exigen que el nuevo dueno tenga CREATE en el esquema (y USAGE para
-- resolver el nombre); ALTER SCHEMA ... OWNER exige CREATE en la base. Ambos grants son temporales.
-- Los objetos se transfieren ANTES que el esquema: despues, consent_owner ya no resuelve integrity.*.
GRANT USAGE, CREATE ON SCHEMA integrity TO integrity_owner;
DO $grant$
BEGIN
  EXECUTE pg_catalog.format('GRANT CREATE ON DATABASE %I TO integrity_owner', pg_catalog.current_database());
END
$grant$;

-- 2-3. Ledger y funcion de inmutabilidad. El ACL de app_rw (SELECT + INSERT por columnas) se conserva.
ALTER TABLE integrity.audit_event OWNER TO integrity_owner;
ALTER FUNCTION integrity.audit_event_immutable() OWNER TO integrity_owner;

-- 4. Esquema. El grant sobre el esquema pasa a ser del propio dueno (ACL implicito del dueno).
ALTER SCHEMA integrity OWNER TO integrity_owner;

-- 5. Revocar el CREATE temporal en la base.
DO $revoke$
BEGIN
  EXECUTE pg_catalog.format('REVOKE CREATE ON DATABASE %I FROM integrity_owner', pg_catalog.current_database());
END
$revoke$;

-- 6. Lo que integrity_owner cree a futuro no es ejecutable por PUBLIC por defecto.
SET LOCAL ROLE integrity_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SET LOCAL ROLE consent_owner;

-- 7. Aserciones: la migracion aborta si algo no quedo como se declara. Se consulta el catalogo por
-- nombre (sin regclass/regprocedure): consent_owner ya no tiene USAGE en el esquema integrity.
DO $assert$
DECLARE
  ledger oid;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'integrity' AND pg_catalog.pg_get_userbyid(n.nspowner) = 'integrity_owner') THEN
    RAISE EXCEPTION 'el esquema integrity no pertenece a integrity_owner';
  END IF;

  SELECT c.oid INTO ledger FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'integrity' AND c.relname = 'audit_event' AND pg_catalog.pg_get_userbyid(c.relowner) = 'integrity_owner';
  IF ledger IS NULL THEN RAISE EXCEPTION 'integrity.audit_event no pertenece a integrity_owner'; END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'integrity' AND p.proname = 'audit_event_immutable' AND pg_catalog.pg_get_userbyid(p.proowner) = 'integrity_owner') THEN
    RAISE EXCEPTION 'integrity.audit_event_immutable() no pertenece a integrity_owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'integrity' AND pg_catalog.pg_get_userbyid(p.proowner) <> 'integrity_owner') THEN
    RAISE EXCEPTION 'hay funciones en integrity que no pertenecen a integrity_owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'integrity' AND pg_catalog.pg_get_userbyid(c.relowner) <> 'integrity_owner') THEN
    RAISE EXCEPTION 'hay relaciones (tablas, indices, secuencias, vistas) en integrity que no pertenecen a integrity_owner';
  END IF;
  IF pg_catalog.has_database_privilege('integrity_owner', pg_catalog.current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'integrity_owner conserva CREATE en la base (el grant temporal no quedo revocado)';
  END IF;

  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t
       WHERE t.tgrelid = ledger AND t.tgname LIKE 'audit_event\_no\_%' AND t.tgenabled = 'A') <> 2 THEN
    RAISE EXCEPTION 'los triggers append-only de integrity.audit_event deben seguir ENABLE ALWAYS';
  END IF;

  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = ledger) THEN
    RAISE EXCEPTION 'integrity.audit_event perdio ENABLE/FORCE ROW LEVEL SECURITY';
  END IF;

  IF pg_catalog.has_table_privilege('consent_owner', ledger, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'consent_owner conserva privilegios sobre integrity.audit_event';
  END IF;
  IF pg_catalog.has_schema_privilege('consent_owner', 'integrity', 'CREATE') THEN
    RAISE EXCEPTION 'consent_owner conserva CREATE en el esquema integrity';
  END IF;
END
$assert$;
