-- scope: cluster
-- Gobierna: ADR-010 rev. 4 §4.1, §4.1.1, §7 fila PR-2; specs/db-roles.spec.yaml rev. 0.2 (INV-DBR-01, INV-DBR-03);
-- decisiones de Carlos del 2026-10-11: Q-15 (c), Q-18 (transition_owner NOLOGIN), Q-19. Regla de Carlos (2026-10-01):
-- las migraciones mergeadas (0000-0033) no se editan.
--
-- Roles de cluster nuevos de ADR-010 PR-2. Solo roles y membresias: ningun esquema, tabla, funcion ni privilegio
-- (eso es PR-3 a PR-7). Se ejecuta como superusuario en CADA deploy (migrate.ts applyClusterScope) y es idempotente
-- (patron 0000, 0026 y 0028). No fija contrasenas: las pone setRolePasswords desde el entorno.
--
--   Owners (NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION):
--     platform_schema_owner  dueno futuro del esquema platform (PR-3).
--     membership_owner       dueno futuro de tenant_membership / platform_role_assignment (PR-3).
--     grant_owner            dueno futuro de nonces, grants, aserciones y sesiones CASE/PLATFORM (PR-3..PR-5).
--     case_state_owner       dueno futuro del esquema case_state (PR-5) y, tras PR-7, de las tablas de transicion.
--     transition_owner       dueno de las funciones SECURITY DEFINER de transicion de revocation y rights_case (Q-18, PR-5).
--     consent_owner es miembro de cada uno WITH INHERIT FALSE, SET TRUE (Q-15 c): solo puede asumirlos con un cambio de
--     rol explicito en migraciones revisadas por CODEOWNERS; no hereda sus privilegios. Residual aceptado solo para
--     IT0B_SYNTHETIC; en REAL_DATA (PR-7) la membresia se revoca y la DDL va por la ceremonia ddl_breakglass.
--
--   rights_operator (NOLOGIN, mismas restricciones): rol de alcance del operador de derechos. Sin miembros en PR-2;
--     platform_rw sera miembro INHERIT FALSE, SET TRUE en PR-5.
--
--   integrity_verifier (LOGIN, NOSUPERUSER, NOBYPASSRLS, ...): rol de runtime del proceso verifier. Sin membresias y
--     sin privilegios sobre ningun objeto en PR-2 (los de canje, conciliacion y checkpoints llegan en PR-4, PR-5 y PR-7).
--     Su contrasena la fija setRolePasswords.
--
-- Modo de roles (ADR-010 §4.1.1): el runner (migrate.ts applyClusterScope) fija el GUC de sesion cns.db_role_mode (IT0B_SYNTHETIC o
-- REAL_DATA) antes de la fase de cluster. El GRANT de SET de consent_owner sobre los 5 owners nuevos se omite si el modo es REAL_DATA
-- (nadie tiene SET sobre los owners de §4.1.1 en operacion normal). Si el GUC falta o esta vacio, aplica el comportamiento IT0B_SYNTHETIC.
-- Tampoco se otorga ADMIN OPTION a nadie: si consent_owner lo tuviera sobre un owner nuevo, se revoca (la aserción compara admin_option).
-- platform_rw -> rights_operator NO se revoca aqui: la aserción de membresia detecta una concesion prematura y PR-5 la agrega a la lista.
--
-- Fuera de PR-2: ddl_breakglass, breakglass_log_owner, db_owner_nologin y el retiro de las membresias de consent_owner
-- (PR-7); la membresia platform_rw -> rights_operator (PR-5).

DO $roles$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['platform_schema_owner', 'membership_owner', 'grant_owner', 'case_state_owner', 'transition_owner', 'rights_operator'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'integrity_verifier') THEN
    CREATE ROLE integrity_verifier LOGIN;
  END IF;
  ALTER ROLE integrity_verifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END
$roles$;

-- Q-15 (c): consent_owner solo puede SET (sin INHERIT, sin ADMIN) sobre los owners nuevos, salvo en REAL_DATA (ver cabecera).
DO $grants$
BEGIN
  IF COALESCE(NULLIF(pg_catalog.current_setting('cns.db_role_mode', true), ''), 'IT0B_SYNTHETIC') <> 'REAL_DATA' THEN
    GRANT platform_schema_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT membership_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT grant_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT case_state_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
    GRANT transition_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;
  END IF;
END
$grants$;

-- Un GRANT repetido no quita ADMIN OPTION: se revoca de forma condicional (solo si existe, para no emitir WARNING por corrida).
DO $admin$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY ARRAY['platform_schema_owner', 'membership_owner', 'grant_owner', 'case_state_owner', 'transition_owner'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = g AND x.rolname = 'consent_owner' AND m.admin_option) THEN
      EXECUTE pg_catalog.format('REVOKE ADMIN OPTION FOR %I FROM consent_owner', g);
    END IF;
  END LOOP;
END
$admin$;

-- Ningun rol de runtime ni el migrador es miembro de los owners nuevos (el migrador solo llega a ellos de forma transitiva por consent_owner,
-- y solo con un cambio de rol explicito). Solo si hay membresia (REVOKE sobre un no miembro emite un WARNING por corrida).
DO $revoke$
DECLARE
  g text;
  u text;
BEGIN
  FOREACH g IN ARRAY ARRAY['platform_schema_owner', 'membership_owner', 'grant_owner', 'case_state_owner', 'transition_owner'] LOOP
    FOREACH u IN ARRAY ARRAY['app_rw', 'worker', 'integrity_verifier', 'consent_migrator'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                   JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                  WHERE r.rolname = g AND x.rolname = u) THEN
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', g, u);
      END IF;
    END LOOP;
  END LOOP;

  -- integrity_verifier no pertenece a ningun owner preexistente ni a staff_roster_reader. (platform_rw tampoco, pero ver cabecera.)
  FOREACH g IN ARRAY ARRAY['consent_owner', 'tenant_resolve_owner', 'staff_roster_owner', 'staff_roster_reader', 'integrity_owner', 'security_event_owner', 'outbox_claimer', 'rights_operator'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                 JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
                WHERE r.rolname = g AND x.rolname = 'integrity_verifier') THEN
      EXECUTE pg_catalog.format('REVOKE %I FROM integrity_verifier', g);
    END IF;
  END LOOP;
END
$revoke$;

-- Misma disciplina de timeout que 0000 para los roles de runtime (D9).
ALTER ROLE integrity_verifier SET idle_in_transaction_session_timeout = '10s';
