-- scope: cluster
-- Gobierna: ADR-010 rev. 6 §3 (fila PR-7: ancla Merkle + puerto AnchorStore), §4.5.5 (F-R6-1: firmante separado del chain-verifier, PROPUESTO; C-7 de Carlos PENDIENTE), plan PR-7 v3 (PR-7b, T-17); specs/db-roles.spec.yaml (integrity_anchor_signer,
-- INV-DBR-01, INV-DBR-02, INV-DBR-03). Regla de Carlos (2026-10-01): las migraciones mergeadas (0000-0074) no se editan.
--
-- Rol de cluster nuevo de PR-7b: `integrity_anchor_signer`, firmante del ancla (octavo proceso, PR-7f). Se crea NOLOGIN: no hay credencial activa sin un proceso que la use (T-17); PR-7f lo pasa a LOGIN. Solo el rol: los privilegios
-- sobre objetos son de 0076-0079 (ambito base). Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope) y es idempotente (patron 0072). No fija contrasena (nunca el repo).
--
--   integrity_anchor_signer  NOLOGIN al crearse, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT. Sin membresias (ni miembro de un owner ni de ningun rol) y sin miembros.
--                            Defensa en profundidad (no es el control; el cliente puede anularla): default_transaction_read_only = on y timeouts finitos. El control son los privilegios.
--
-- LOGIN/NOLOGIN: esta migracion corre en CADA deploy, asi que NO fija el atributo en el ALTER ROLE ni lo asierta (si lo fijara, PR-7f no podria darle LOGIN sin editar una migracion mergeada): el rol nace NOLOGIN (CREATE) y
-- PR-7f lo pasa a LOGIN con su propia migracion de cluster. Que siga NOLOGIN hasta PR-7f lo afirma TEST-CNS-1774. La aserción final falla cerrado si el rol gana una membresia o un atributo peligroso.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_anchor_signer') THEN
    CREATE ROLE integrity_anchor_signer NOLOGIN;
  END IF;
  ALTER ROLE integrity_anchor_signer NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
END
$roles$;

-- Ninguna membresia (en ningun sentido). Solo si existe (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name, x.rolname AS member_name
             FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
             JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE x.rolname = 'integrity_anchor_signer' OR r.rolname = 'integrity_anchor_signer' LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.role_name, m.member_name);
  END LOOP;
END
$revoke$;

ALTER ROLE integrity_anchor_signer SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE integrity_anchor_signer SET statement_timeout = '30s';
ALTER ROLE integrity_anchor_signer SET default_transaction_read_only = on;

DO $assert75$
DECLARE
  rec record;
  cfg text[];
BEGIN
  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'integrity_anchor_signer';
  IF NOT FOUND THEN RAISE EXCEPTION '0075: falta el rol integrity_anchor_signer'; END IF;
  IF rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls OR rec.rolinherit THEN
    RAISE EXCEPTION '0075: integrity_anchor_signer debe ser NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS y NOINHERIT';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid OR m.roleid = rec.oid OR m.grantor = rec.oid) THEN
    RAISE EXCEPTION '0075: integrity_anchor_signer no debe tener membresias (ni como miembro, ni como rol concedido, ni como grantor)';
  END IF;
  cfg := COALESCE(rec.rolconfig, ARRAY[]::text[]);
  IF NOT ('default_transaction_read_only=on' = ANY (cfg)) OR NOT ('idle_in_transaction_session_timeout=30s' = ANY (cfg)) OR NOT ('statement_timeout=30s' = ANY (cfg)) OR pg_catalog.cardinality(cfg) <> 3 THEN
    RAISE EXCEPTION '0075: integrity_anchor_signer debe tener exactamente los 3 settings propios (read-only y timeouts finitos)';
  END IF;
END
$assert75$;
