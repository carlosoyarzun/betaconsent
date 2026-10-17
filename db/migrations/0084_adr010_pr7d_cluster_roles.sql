-- scope: cluster
-- Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7d/7e: db_owner_nologin y CREATE explicito; ddl_breakglass NOLOGIN + auditoria de sesiones, Q-20 (c); breakglass.ceremony, Q13), §4.5.2/§4.5.3/§4.5.4, INV-DBR-03/09,
-- F-PR7-04, F-PR7-06, F-PR7-12, F-PRB-06, F-PR7C-06, F-A10-10, F-A10-11; decisiones de Carlos del 2026-10-16 (C-1: revoke de integrity_owner en AMBOS modos; C-4: break-glass; C-5 (LEGAL DECISION): logs de ceremonia
-- minimizados y solo DDL; C-9: textos); specs/db-roles.spec.yaml rev. 0.8. Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan; esta es nueva.
--
-- Roles de cluster nuevos de PR-7d y sus membresias. (Revision de seguridad del PR #109, F-PR7D-02: sin concesion transitoria a consent_owner; el esquema breakglass lo crea 0085 en cluster-post.) Se aplica ANTES de las migraciones de base (migrate.ts applyClusterScope, fase "cluster"); el REVOKE de integrity_owner, el cambio de dueño de la base y el modo REAL_DATA
-- son de la fase POSTERIOR (0086, `-- scope: cluster-post`), que corre despues de las migraciones de base: una base nueva necesita que consent_owner conserve SET sobre integrity_owner mientras se aplican 0027, 0030, 0037...
-- Se ejecuta como superusuario en CADA deploy y es idempotente (patron 0034/0075/0080). No fija contrasena (el repo no tiene credenciales; la de la ceremonia se entrega como verificador SCRAM, db/ceremonies/).
--
--   db_owner_nologin       NOLOGIN. Dueño de la BASE (ALTER DATABASE ... OWNER en 0086): quita a consent_owner el poder de DROP DATABASE y de conceder CREATE en la base. Sin miembros ni membresias.
--   breakglass_log_owner   NOLOGIN. Dueño del esquema breakglass y de breakglass.ceremony (0085). SIN miembros ni membresias, nunca (ni siquiera transitorias: F-PR7D-02): 0085 (cluster-post) lo asume con SET LOCAL ROLE desde el
--                          superusuario del deploy, sin membresia; nadie mas puede asumirlo (solo el superusuario del cluster escribe la tabla, en las ceremonias).
--   ddl_breakglass         NOLOGIN al crearse, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT, CONNECTION LIMIT 1. Miembro (INHERIT FALSE, SET TRUE, sin ADMIN) de los 17 owners gobernados
--                          (OWNER_ROLES de role-membership.ts menos consent_owner; la lista esta en 0086 y un test la compara). Es el UNICO rol que asume owners fuera de las migraciones aplicadas por consent_owner.
--                          Sus membresias las concede 0086 (fase posterior): varias migraciones de base ya mergeadas (0029, ...) asertan que consent_owner es el UNICO miembro de su owner, asi que durante las migraciones de base
--                          ddl_breakglass no es miembro de ninguno (esta migracion revoca las que hubiera de un deploy anterior y 0086 las restablece).
--                          Auditoria de sesion (Q-20 (c)): log_statement = 'ddl' (NO 'all': las ceremonias son solo DDL y el log no debe escribir datos, F-PR7-07, C-5), log_parameter_max_length = 0 (y _on_error);
--                          log_connections/log_disconnections son del postgresql.conf del host (infra/postgres/), no de un ALTER ROLE (son parametros de arranque de sesion).
--
-- LOGIN/NOLOGIN de ddl_breakglass: esta migracion corre en CADA deploy, asi que NO fija el atributo (si lo fijara cerraria una ceremonia abierta; la abre db/ceremonies/open.sql y la cierra close.sql). Que siga NOLOGIN fuera de
-- ceremonia lo afirman migrate.ts (aserción posterior al deploy: un deploy con una ceremonia abierta falla cerrado) y el modo breakglass-watch del chain-verifier (1 min).

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
  ALTER ROLE db_owner_nologin NOLOGIN;
  ALTER ROLE breakglass_log_owner NOLOGIN;
  ALTER ROLE ddl_breakglass NOINHERIT CONNECTION LIMIT 1;
END
$roles$;

-- Reafirma los settings de ddl_breakglass en cada deploy (F-A10-11).
ALTER ROLE ddl_breakglass SET log_statement = 'ddl';
ALTER ROLE ddl_breakglass SET log_parameter_max_length = 0;
ALTER ROLE ddl_breakglass SET log_parameter_max_length_on_error = 0;
ALTER ROLE ddl_breakglass SET idle_in_transaction_session_timeout = '10min';

-- Ninguna membresia de los tres roles (las de ddl_breakglass las concede 0086). Se revoca de forma condicional (REVOKE sobre un no miembro emite un WARNING por corrida); incluye la transitoria consent_owner -> breakglass_log_owner de versiones previas de esta migracion.
DO $revoke$
DECLARE
  m record;
BEGIN
  FOR m IN SELECT r.rolname AS role_name, x.rolname AS member_name
             FROM pg_catalog.pg_auth_members am
             JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
             JOIN pg_catalog.pg_roles x ON x.oid = am.member
            WHERE (x.rolname IN ('db_owner_nologin', 'breakglass_log_owner'))
               OR (r.rolname IN ('db_owner_nologin', 'ddl_breakglass'))
               OR (x.rolname = 'ddl_breakglass')
               OR (r.rolname = 'breakglass_log_owner') LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.role_name, m.member_name);
  END LOOP;
END
$revoke$;

-- Ningun rol de runtime ni el migrador es miembro de los tres roles.
DO $runtime$
DECLARE
  g text;
  u text;
BEGIN
  FOREACH g IN ARRAY ARRAY['db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass'] LOOP
    FOREACH u IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'integrity_reconciler', 'integrity_chain_verifier', 'consent_migrator'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members am
                   JOIN pg_catalog.pg_roles r ON r.oid = am.roleid JOIN pg_catalog.pg_roles x ON x.oid = am.member
                  WHERE r.rolname = g AND x.rolname = u) THEN
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', g, u);
      END IF;
    END LOOP;
  END LOOP;
END
$runtime$;

-- Aserciones del estado resultante (fail-closed).
DO $assert84$
DECLARE
  g text;
  rec record;
  cfg text[];
BEGIN
  FOREACH g IN ARRAY ARRAY['db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass'] LOOP
    SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = g;
    IF NOT FOUND THEN RAISE EXCEPTION '0084: falta el rol %', g; END IF;
    IF rec.rolsuper OR rec.rolcreatedb OR rec.rolcreaterole OR rec.rolreplication OR rec.rolbypassrls THEN
      RAISE EXCEPTION '0084: % debe ser NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS', g;
    END IF;
    IF g <> 'ddl_breakglass' AND rec.rolcanlogin THEN RAISE EXCEPTION '0084: % debe ser NOLOGIN', g; END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.grantor = rec.oid) THEN RAISE EXCEPTION '0084: % no debe ser grantor de ninguna membresia', g; END IF;
  END LOOP;

  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'ddl_breakglass';
  IF rec.rolinherit OR rec.rolconnlimit <> 1 THEN RAISE EXCEPTION '0084: ddl_breakglass debe ser NOINHERIT y CONNECTION LIMIT 1'; END IF;
  cfg := COALESCE(rec.rolconfig, ARRAY[]::text[]);
  IF NOT ('log_statement=ddl' = ANY (cfg)) OR NOT ('log_parameter_max_length=0' = ANY (cfg)) OR NOT ('log_parameter_max_length_on_error=0' = ANY (cfg))
     OR NOT ('idle_in_transaction_session_timeout=10min' = ANY (cfg)) OR pg_catalog.cardinality(cfg) <> 4 THEN
    RAISE EXCEPTION '0084: ddl_breakglass debe tener exactamente los 4 settings propios (log_statement=ddl, log_parameter_max_length=0 y _on_error=0, timeout de transaccion ociosa)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid) THEN
    RAISE EXCEPTION '0084: durante las migraciones de base ddl_breakglass no es miembro de ningun rol (0086 le concede los 17 owners)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = rec.oid) THEN RAISE EXCEPTION '0084: nadie puede ser miembro de ddl_breakglass'; END IF;

  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'db_owner_nologin';
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = rec.oid OR m.member = rec.oid) THEN RAISE EXCEPTION '0084: db_owner_nologin no tiene miembros ni membresias'; END IF;

  SELECT * INTO rec FROM pg_catalog.pg_roles x WHERE x.rolname = 'breakglass_log_owner';
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = rec.oid) THEN RAISE EXCEPTION '0084: breakglass_log_owner no es miembro de ningun rol'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = rec.oid) THEN RAISE EXCEPTION '0084: breakglass_log_owner no puede tener miembros (INV-DBR-09, F-PR7D-02)'; END IF;
END
$assert84$;
