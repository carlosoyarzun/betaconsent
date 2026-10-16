-- scope: cluster
-- Gobierna: ADR-010 rev. 6 §1 (fila `chain-verifier` -> `integrity_chain_verifier`; D-1 (b), aceptada por Carlos el 2026-10-16), §3 (fila PR-6f), F-PR6E-06, SEC-06-1, SEC-06-6, C11/C12/C13 de la revision de seguridad;
-- specs/db-roles.spec.yaml (integrity_chain_verifier, INV-DBR-01, INV-DBR-02, INV-DBR-03). Regla de Carlos (2026-10-01): las migraciones mergeadas (0000-0071) no se editan.
--
-- Rol de cluster nuevo de PR-6f: `integrity_chain_verifier`, rol de runtime (LOGIN) del proceso `chain-verifier` (septimo proceso y credencial). Solo el rol: ningun privilegio sobre objetos
-- (eso es 0073, de ambito base). Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope), tambien sobre una base vacia, y es idempotente (patron 0034/0056).
-- Por eso la aserción final es solo de ATRIBUTOS, MEMBRESIAS y SETTINGS del rol: no referencia ningun objeto de base. No fija contrasena: la pone setRolePasswords desde el entorno (nunca el repo).
--
--   integrity_chain_verifier  LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT. Sin membresias (ni miembro de un owner ni de ningun rol) y sin miembros: la lectura
--                             cross-tenant del ledger es por una policy de SELECT explicita `TO integrity_chain_verifier` (0073), no por BYPASSRLS ni por herencia.
--                             NOINHERIT es defensa ante una membresia futura accidental (no impide SET ROLE; el control real es la aserción de cero membresias en ambos sentidos, en cada deploy).
--                             Defensa en profundidad (no es el control; el cliente puede anularla): default_transaction_read_only = on, mas timeouts propios y finitos (el control son los privilegios: solo SELECT).
--
-- No es miembro de ningun owner de §4.1.1: se revoca cualquier membresia preexistente (patron 0034:99-105 / 0056) y la aserción final falla cerrado si queda alguna.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_chain_verifier') THEN
    CREATE ROLE integrity_chain_verifier LOGIN;
  END IF;
  ALTER ROLE integrity_chain_verifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
END
$roles$;

-- Ninguna membresia: ni del chain-verifier en otros roles (owners, runtime, alcance) ni de otros en el chain-verifier. Solo si existe (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name, x.rolname AS member_name
             FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
             JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE x.rolname = 'integrity_chain_verifier' OR r.rolname = 'integrity_chain_verifier' LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.role_name, m.member_name);
  END LOOP;
END
$revoke$;

-- Timeouts PROPIOS y finitos (D9). El recomputo lee un snapshot REPEATABLE READ tenant por tenant, por lotes, y procesa en CPU (SHA-256) entre lecturas: los 10s de 0000/0034 lo matarian a mitad de corrida
-- (patron 0056:41, valor PROPOSED 120s). statement_timeout acota cada lote de lectura (una consulta por lote, keyset por (tenant_id, chain_seq)).
ALTER ROLE integrity_chain_verifier SET idle_in_transaction_session_timeout = '120s';
ALTER ROLE integrity_chain_verifier SET statement_timeout = '120s';
ALTER ROLE integrity_chain_verifier SET default_transaction_read_only = on;

-- Aserciones del estado resultante (fail-closed). SOLO atributos, membresias (en ambos sentidos) y settings del rol: nada de objetos de base (esta migracion corre antes que 0073 y en cada deploy).
DO $assert72$
DECLARE
  rec record;
  cfg text[];
BEGIN
  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'integrity_chain_verifier';
  IF NOT FOUND THEN RAISE EXCEPTION '0072: falta el rol integrity_chain_verifier'; END IF;
  IF NOT rec.rolcanlogin OR rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls OR rec.rolinherit THEN
    RAISE EXCEPTION '0072: integrity_chain_verifier debe ser LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS y NOINHERIT';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid OR m.roleid = rec.oid OR m.grantor = rec.oid) THEN
    RAISE EXCEPTION '0072: integrity_chain_verifier no debe tener membresias (ni como miembro, ni como rol concedido, ni como grantor)';
  END IF;
  cfg := COALESCE(rec.rolconfig, ARRAY[]::text[]);
  IF NOT ('default_transaction_read_only=on' = ANY (cfg)) THEN RAISE EXCEPTION '0072: integrity_chain_verifier debe fijar default_transaction_read_only = on'; END IF;
  IF NOT ('idle_in_transaction_session_timeout=120s' = ANY (cfg)) THEN RAISE EXCEPTION '0072: integrity_chain_verifier debe fijar un idle_in_transaction_session_timeout finito (120s)'; END IF;
  IF NOT ('statement_timeout=120s' = ANY (cfg)) THEN RAISE EXCEPTION '0072: integrity_chain_verifier debe fijar un statement_timeout finito (120s)'; END IF;
  IF pg_catalog.cardinality(cfg) <> 3 THEN RAISE EXCEPTION '0072: integrity_chain_verifier debe tener exactamente 3 settings (sin settings extra)'; END IF;
END
$assert72$;
