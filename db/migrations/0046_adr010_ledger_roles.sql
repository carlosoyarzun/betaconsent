-- scope: cluster
-- Gobierna: ADR-010 rev. 5 §4.1/§4.1.1/§4.2.b (aceptada por Carlos el 2026-10-15 para IT0b; LG-1..LG-10, F-PR6-11, F-A10-30), PR-b (ledger generado por la base);
-- specs/db-roles.spec.yaml (ledger_writer, ledger_gen_owner, INV-DBR-03, INV-DBR-07). Regla de Carlos (2026-10-01): las migraciones mergeadas (0000-0045) no se editan.
--
-- Roles de cluster nuevos de PR-b. Solo roles y membresias: ningun esquema, tabla, funcion ni privilegio (eso es 0047 en adelante). Se ejecuta como superusuario en
-- CADA deploy (migrate.ts applyClusterScope) y es idempotente (patron 0034). No fija contrasenas (son NOLOGIN).
--
--   ledger_gen_owner  NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION. Dueno del esquema ledger_gen (mismo patron que case_state_owner).
--   ledger_writer     igual. Dueno de las funciones ledger_gen.emit_* / guard_* / ledger_append / seed_local_catalog_event; unico rol con INSERT del ledger derivado de las filas
--                     de estado (los 19 pares de la policy audit_event_ledger_insert). Sin miembros de runtime (§4.1.1): ningun proceso LOGIN es miembro, ni directo ni transitivo.
--
-- Modo de roles (ADR-010 §4.1.1): el runner fija el GUC de sesion cns.db_role_mode (IT0B_SYNTHETIC o REAL_DATA) antes de la fase de cluster. Solo en IT0B_SYNTHETIC consent_owner
-- recibe SET (INHERIT FALSE, sin ADMIN) sobre los dos roles nuevos: PostgreSQL exige poder asumir el rol destino para ALTER ... OWNER TO y para crear objetos como ese rol
-- (patron 0034, Q-15 c). En REAL_DATA solo ddl_breakglass tendra SET (PR-7). Si el GUC falta o esta vacio aplica IT0B_SYNTHETIC.

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['ledger_gen_owner', 'ledger_writer'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
END
$roles$;

DO $grants$
BEGIN
  IF COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') <> 'REAL_DATA' THEN
    GRANT ledger_gen_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT ledger_writer TO consent_owner WITH INHERIT FALSE, SET TRUE;
  END IF;
END
$grants$;

-- Un GRANT repetido no quita ADMIN OPTION: se revoca de forma condicional (solo si existe, para no emitir WARNING por corrida).
DO $admin$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY ARRAY['ledger_gen_owner', 'ledger_writer'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = g AND x.rolname = 'consent_owner' AND m.admin_option) THEN
      EXECUTE pg_catalog.format('REVOKE ADMIN OPTION FOR %I FROM consent_owner', g);
    END IF;
  END LOOP;
END
$admin$;

-- Ningun rol de runtime ni el migrador es miembro de los roles nuevos (el migrador solo llega a ellos de forma transitiva por consent_owner, y solo con un cambio de rol
-- explicito). Solo si hay membresia (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  g text;
  u text;
BEGIN
  FOREACH g IN ARRAY ARRAY['ledger_gen_owner', 'ledger_writer'] LOOP
    FOREACH u IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'consent_migrator'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                   JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                  WHERE r.rolname = g AND x.rolname = u) THEN
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', g, u);
      END IF;
    END LOOP;
  END LOOP;
END
$revoke$;

-- Aserciones del estado resultante (fail-closed): atributos exactos y sin membresias de runtime.
DO $assert46$
DECLARE
  r text;
  rec record;
BEGIN
  FOREACH r IN ARRAY ARRAY['ledger_gen_owner', 'ledger_writer'] LOOP
    SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = r;
    IF NOT FOUND THEN RAISE EXCEPTION '0046: falta el rol %', r; END IF;
    IF rec.rolcanlogin OR rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls THEN
      RAISE EXCEPTION '0046: % debe ser NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS', r;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE m.roleid = rec.oid AND x.rolname <> 'consent_owner') THEN
      RAISE EXCEPTION '0046: % solo puede tener como miembro a consent_owner (sin miembros de runtime)', r;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid) THEN
      RAISE EXCEPTION '0046: % no debe ser miembro de ningun rol', r;
    END IF;
  END LOOP;
END
$assert46$;
