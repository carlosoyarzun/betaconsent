-- scope: database
-- Gobierna: ADR-010 rev. 6 §1 (fila `integrity_chain_verifier`: sin privilegios fuera del ledger y ops.db_catalog), §3 (fila PR-6f), PR-7 sub-PR 7a (plan de PR-7, T-1 y SEC-6F-03); specs/db-roles.spec.yaml (integrity_chain_verifier, INV-DBR-01);
-- registers/findings-register-IT0.md (SEC-6F-03). 0073 esta mergeada y es inmutable (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- 0073 concedio USAGE sobre `app` al chain-verifier solo porque startup-checks.ts resolvia por nombre `app.staff_roster_invitation_status` (regclass exige USAGE del esquema). PR-7a cambia esa resolucion a catalogo
-- (pg_class + pg_namespace, por OID) y el rol ya no necesita ni un solo privilegio sobre `app`. Se revoca. Queda con USAGE en `integrity` (lectura del ledger) y `ops` (SELECT de ops.db_catalog) y nada mas.
-- Idempotente (REVOKE repetible). El esquema `app` es de consent_owner (0001): el REVOKE corre con SET LOCAL ROLE consent_owner, como el GRANT de 0073.

SET LOCAL ROLE consent_owner;

REVOKE ALL ON SCHEMA app FROM integrity_chain_verifier;

-- Aserciones (fail-closed): ACL exacta resultante del chain-verifier sobre esquemas.
DO $assert74$
DECLARE
  rid oid;
  rec record;
BEGIN
  SELECT r.oid INTO rid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_chain_verifier';
  IF rid IS NULL THEN RAISE EXCEPTION '0074: falta el rol integrity_chain_verifier (lo crea 0072)'; END IF;

  -- app: ningun privilegio (ni USAGE ni CREATE) para el rol; ACL del esquema sin ninguna entrada concedida al rol (PUBLIC tampoco le da USAGE en app: se verifica por has_schema_privilege, que incluye PUBLIC).
  IF pg_catalog.has_schema_privilege('integrity_chain_verifier', 'app', 'USAGE,CREATE') THEN
    RAISE EXCEPTION '0074: integrity_chain_verifier conserva USAGE o CREATE sobre el esquema app (SEC-6F-03)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a WHERE n.nspname = 'app' AND a.grantee = rid) THEN
    RAISE EXCEPTION '0074: la ACL del esquema app aun tiene una entrada para integrity_chain_verifier';
  END IF;

  -- Resto de esquemas no de sistema: USAGE solo en integrity, ops (y public por PUBLIC); ningun CREATE.
  FOR rec IN SELECT n.nspname AS name FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' LOOP
    IF pg_catalog.has_schema_privilege('integrity_chain_verifier', rec.name, 'CREATE') THEN RAISE EXCEPTION '0074: integrity_chain_verifier tiene CREATE en %', rec.name; END IF;
    IF pg_catalog.has_schema_privilege('integrity_chain_verifier', rec.name, 'USAGE') AND rec.name NOT IN ('integrity', 'ops', 'public') THEN
      RAISE EXCEPTION '0074: integrity_chain_verifier tiene USAGE sobre el esquema % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_schema_privilege('integrity_chain_verifier', 'integrity', 'USAGE') OR NOT pg_catalog.has_schema_privilege('integrity_chain_verifier', 'ops', 'USAGE') THEN
    RAISE EXCEPTION '0074: integrity_chain_verifier debe conservar USAGE sobre integrity y ops';
  END IF;
  -- Lo concedido por 0073 sobre el ledger y el catalogo no cambia. Se resuelve por OID de catalogo: el migrador (consent_owner) no tiene USAGE de integrity y un nombre de relacion (regclass) lo exigiria.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'ops' AND c.relname = 'db_catalog' AND pg_catalog.has_table_privilege('integrity_chain_verifier', c.oid, 'SELECT'))
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'integrity' AND c.relname = 'audit_event' AND pg_catalog.has_column_privilege('integrity_chain_verifier', c.oid, 'event_hash', 'SELECT')) THEN
    RAISE EXCEPTION '0074: integrity_chain_verifier perdio SELECT sobre ops.db_catalog o integrity.audit_event';
  END IF;
END
$assert74$;
