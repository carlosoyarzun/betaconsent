-- scope: cluster
-- Gobierna: ADR-010 rev. 5 §2 (fila `reconciler` -> `integrity_reconciler`), §4.2.c (conciliacion), §10 fila 6e, G-9 (aprobado), F-PR6-29, P2(e) (aceptada por Carlos el 2026-10-15 para IT0b);
-- specs/db-roles.spec.yaml (integrity_reconciler, INV-DBR-01, INV-DBR-02, INV-DBR-03, INV-DBR-08). Regla de Carlos (2026-10-01): las migraciones mergeadas (0000-0051) no se editan.
--
-- Rol de cluster nuevo de PR-6e: `integrity_reconciler`, rol de runtime (LOGIN) del proceso `reconciler` (sexto proceso y credencial). Solo el rol: ningun privilegio sobre objetos
-- (eso es 0057-0059). Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope) y es idempotente (patron 0034/0046). No fija contrasena: la pone setRolePasswords
-- desde el entorno (nunca el repo).
--
--   integrity_reconciler  LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS. Sin membresias (ni miembro de un owner ni de ningun rol) y sin miembros: la lectura
--                         cross-tenant del ledger y de los estados es por policies de SELECT explicitas `TO integrity_reconciler` (0057/0058), no por BYPASSRLS ni por herencia.
--                         Defensa en profundidad (no es el control): default_transaction_read_only = on; el control son los privilegios (solo SELECT por columnas).
--
-- No es miembro de ningun owner de §4.1.1: se revoca cualquier membresia preexistente (como 0034 para integrity_verifier) y la aserción final falla cerrado si queda alguna.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_reconciler') THEN
    CREATE ROLE integrity_reconciler LOGIN;
  END IF;
  ALTER ROLE integrity_reconciler LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$roles$;

-- Ninguna membresia: ni del reconciler en otros roles (owners, runtime, alcance) ni de otros en el reconciler. Solo si existe (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name, x.rolname AS member_name
             FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
             JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE x.rolname = 'integrity_reconciler' OR r.rolname = 'integrity_reconciler' LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.role_name, m.member_name);
  END LOOP;
END
$revoke$;

-- Timeout PROPIO y holgado (seguridad PR #99 P2-3): el reconciler lee un snapshot REPEATABLE READ tenant por tenant y procesa en CPU entre lecturas; los 10s de 0000/0034 lo matarian a mitad de corrida.
-- Sigue siendo finito (D9). Mas solo lectura por defecto.
ALTER ROLE integrity_reconciler SET idle_in_transaction_session_timeout = '120s';
ALTER ROLE integrity_reconciler SET default_transaction_read_only = on;

-- Aserciones del estado resultante (fail-closed).
DO $assert56$
DECLARE
  rec record;
BEGIN
  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'integrity_reconciler';
  IF NOT FOUND THEN RAISE EXCEPTION '0056: falta el rol integrity_reconciler'; END IF;
  IF NOT rec.rolcanlogin OR rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls THEN
    RAISE EXCEPTION '0056: integrity_reconciler debe ser LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid OR m.roleid = rec.oid OR m.grantor = rec.oid) THEN
    RAISE EXCEPTION '0056: integrity_reconciler no debe tener membresias (ni como miembro, ni como rol concedido, ni como grantor)';
  END IF;
END
$assert56$;
