-- scope: cluster-post
-- Gobierna: ADR-010 rev. 6 §4.5.1 (revoke de integrity_owner a consent_owner; R-22/F-X8-11/CA-144), §4.5.2 (db_owner_nologin y CREATE explicito; F-PR7-04), §4.1.1 / INV-DBR-03 (modo REAL_DATA: REVOKE explicito, F-PRB-06, F-PR7C-06),
-- F-A10-10 (CONNECT/TEMP de PUBLIC), F-PR7-12; decisiones de Carlos del 2026-10-16 (C-1: el revoke de integrity_owner aplica en AMBOS modos; texto aceptado); specs/db-roles.spec.yaml rev. 0.8 (INV-DBR-03, INV-DBR-09).
-- Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan; esta es nueva.
--
-- FASE POSTERIOR del alcance de superusuario (migrate.ts applyClusterPostScope): corre DESPUES de las migraciones de base, en CADA deploy, y es idempotente. Por que no esta en la fase cluster: 0026 re-otorga
-- `consent_owner -> integrity_owner` (y 0028/0034/0046/0064/0080 los demas SET) en cada corrida; una base NUEVA aplica 0027, 0030, 0037, ... con SET LOCAL ROLE de esos owners, asi que el revoke solo puede ir al final del deploy.
-- Para que el catalogo no muestre nunca el estado intermedio, applyClusterScope ejecuta la fase cluster y esta en UNA transaccion cuando no hay migraciones de base pendientes (el caso normal); con migraciones pendientes se difiere
-- (deferPost) y se ejecuta justo despues. Si el deploy se interrumpe entre ambas, startup-checks y la aserción de membresia lo detectan (INV-DBR-03; F-PR7-05).
--
-- Que hace (todo sobre la base de conexion del superusuario del deploy, que es la base de la aplicacion):
--  1. REVOKE integrity_owner FROM consent_owner (ambos modos). Desde aqui TODA DDL sobre integrity.* va por ceremonia (db/ceremonies/): ddl_breakglass es el unico rol que lo asume (0084).
--  2. REVOKE de la membresia transitoria consent_owner -> breakglass_log_owner (0084) y GRANT de los 17 owners a ddl_breakglass (INHERIT FALSE, SET TRUE, sin ADMIN; 0084 las revoca al inicio del deploy porque
--     0029 y otras migraciones de base asertan que consent_owner es el unico miembro de su owner).
--  3. REAL_DATA (GUC cns.db_role_mode fijado por el runner): REVOKE explicito de TODA membresia SET de consent_owner sobre los 17 owners y de consent_migrator -> outbox_claimer. Omitir el GRANT no basta: 0000/0018/0026/0028/0034/0046/0064/0080
--     las re-otorgan o las dejan de corridas previas en IT0B (F-PRB-06, F-PR7C-06).
--  4. Base: ALTER DATABASE OWNER TO db_owner_nologin; CREATE explicito: GRANT CREATE ON DATABASE a consent_owner solo en IT0B_SYNTHETIC (tras perder datdba nadie podria concederlo desde el alcance de base; en REAL_DATA se revoca y los
--     esquemas nuevos van por ceremonia, F-PR7-04); REVOKE CONNECT/TEMP de PUBLIC y GRANT CONNECT explicito por rol (F-A10-10).
--  5. Aserciones (fail-closed).
-- El modo REAL_DATA de la aserción es VERIFICABLE, no una autorizacion de datos reales (F-PR7-12): sigue bloqueado por F-PR7-01 (REAL_DATA_BLOCKERS) y el catalogo exige data_class = SYNTHETIC.

DO $revoke$
DECLARE
  g text;
  real_data boolean := COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') = 'REAL_DATA';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
              WHERE r.rolname = 'integrity_owner' AND x.rolname = 'consent_owner') THEN
    REVOKE integrity_owner FROM consent_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
              WHERE r.rolname = 'breakglass_log_owner' AND x.rolname = 'consent_owner') THEN
    REVOKE breakglass_log_owner FROM consent_owner;
  END IF;
  FOREACH g IN ARRAY ARRAY[
    'tenant_resolve_owner', 'staff_roster_owner', 'integrity_owner', 'security_event_owner', 'outbox_claimer', 'platform_schema_owner', 'grant_owner', 'membership_owner',
    'case_state_owner', 'transition_owner', 'ledger_gen_owner', 'ledger_writer', 'rights_case_lookup_owner', 'app_schema_owner', 'ops_schema_owner', 'shared_fn_owner',
    'revocation_recovery_reader'] LOOP
    EXECUTE pg_catalog.format('GRANT %I TO ddl_breakglass WITH INHERIT FALSE, SET TRUE', g);
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = g AND x.rolname = 'ddl_breakglass' AND m.admin_option) THEN
      EXECUTE pg_catalog.format('REVOKE ADMIN OPTION FOR %I FROM ddl_breakglass', g);
    END IF;
  END LOOP;
  IF real_data THEN
    FOREACH g IN ARRAY ARRAY[
      'tenant_resolve_owner', 'staff_roster_owner', 'integrity_owner', 'security_event_owner', 'outbox_claimer', 'platform_schema_owner', 'grant_owner', 'membership_owner',
      'case_state_owner', 'transition_owner', 'ledger_gen_owner', 'ledger_writer', 'rights_case_lookup_owner', 'app_schema_owner', 'ops_schema_owner', 'shared_fn_owner',
      'revocation_recovery_reader'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                  WHERE r.rolname = g AND x.rolname = 'consent_owner') THEN
        EXECUTE pg_catalog.format('REVOKE %I FROM consent_owner', g);
      END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = 'outbox_claimer' AND x.rolname = 'consent_migrator') THEN
      REVOKE outbox_claimer FROM consent_migrator;
    END IF;
  END IF;
END
$revoke$;

DO $database$
DECLARE
  db text := pg_catalog.current_database();
  real_data boolean := COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') = 'REAL_DATA';
  r text;
BEGIN
  EXECUTE pg_catalog.format('ALTER DATABASE %I OWNER TO db_owner_nologin', db);
  EXECUTE pg_catalog.format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', db);
  FOREACH r IN ARRAY ARRAY['consent_migrator', 'app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'integrity_reconciler', 'integrity_chain_verifier', 'ddl_breakglass'] LOOP
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO %I', db, r);
  END LOOP;
  IF real_data THEN
    EXECUTE pg_catalog.format('REVOKE CREATE ON DATABASE %I FROM consent_owner', db);
  ELSE
    EXECUTE pg_catalog.format('GRANT CREATE ON DATABASE %I TO consent_owner', db);
  END IF;
END
$database$;

DO $assert86$
DECLARE
  db text := pg_catalog.current_database();
  real_data boolean := COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') = 'REAL_DATA';
  g text;
  owner_name text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
              WHERE r.rolname = 'integrity_owner' AND x.rolname <> 'ddl_breakglass') THEN
    RAISE EXCEPTION '0086: integrity_owner solo puede tener a ddl_breakglass como miembro (INV-DBR-03, R-22)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid WHERE r.rolname = 'breakglass_log_owner') THEN
    RAISE EXCEPTION '0086: nadie puede asumir breakglass_log_owner (INV-DBR-09)';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member WHERE x.rolname = 'ddl_breakglass') <> 17
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member WHERE x.rolname = 'ddl_breakglass' AND (m.inherit_option OR NOT m.set_option OR m.admin_option)) THEN
    RAISE EXCEPTION '0086: ddl_breakglass debe ser miembro de exactamente 17 owners, todos con INHERIT FALSE, SET TRUE y sin ADMIN (INV-DBR-03)';
  END IF;
  IF real_data AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles x ON x.oid = m.member
                            WHERE x.rolname = 'consent_owner' AND m.set_option) THEN
    RAISE EXCEPTION '0086: en REAL_DATA consent_owner no puede tener ninguna membresia SET (INV-DBR-03)';
  END IF;
  IF real_data AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                            WHERE x.rolname = 'consent_migrator' AND r.rolname <> 'consent_owner') THEN
    RAISE EXCEPTION '0086: en REAL_DATA consent_migrator solo es miembro de consent_owner (INV-DBR-03)';
  END IF;
  SELECT pg_catalog.pg_get_userbyid(d.datdba) INTO owner_name FROM pg_catalog.pg_database d WHERE d.datname = db;
  IF owner_name IS DISTINCT FROM 'db_owner_nologin' THEN RAISE EXCEPTION '0086: el dueño de la base debe ser db_owner_nologin (INV-DBR-09)'; END IF;
  IF pg_catalog.has_database_privilege('consent_owner', db, 'CREATE') = real_data THEN
    RAISE EXCEPTION '0086: CREATE en la base: consent_owner lo tiene solo en IT0B_SYNTHETIC';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_database d, pg_catalog.aclexplode(COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))) a
              WHERE d.datname = db AND a.grantee = 0 AND a.privilege_type IN ('CONNECT', 'TEMPORARY', 'CREATE')) THEN
    RAISE EXCEPTION '0086: PUBLIC no puede tener CONNECT, TEMPORARY ni CREATE en la base (F-A10-10)';
  END IF;
  FOREACH g IN ARRAY ARRAY['consent_migrator', 'app_rw', 'worker', 'platform_rw', 'integrity_verifier', 'integrity_reconciler', 'integrity_chain_verifier', 'ddl_breakglass'] LOOP
    IF NOT pg_catalog.has_database_privilege(g, db, 'CONNECT') THEN RAISE EXCEPTION '0086: % necesita CONNECT explicito en la base', g; END IF;
  END LOOP;
END
$assert86$;
