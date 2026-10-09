-- scope: database
-- Gobierna: SEC-CNS-021 PR-1 (aceptada por Carlos 2026-10-08; §3, §4.1 M+2; D1 a, D2 a), CA-146, P-34, INV-21-04/05/06, SEC-CNS-006 rev. 5,
-- contracts/schemas/security-event-payloads.schema.json (API-CNS-184), ADR-010 rev. 3 §4.1, INV-CM-01, INV-CM-02.
-- Regla de Carlos (2026-10-01): 0000-0028 no se editan; esta migracion es nueva.
--
-- 1. Extiende ops.security_event con la familia OTP / RECOVERY / MANAGEMENT (columnas opacas: refs UUIDv4 y enums; sin PII, sin correo,
--    sin texto libre) y la forma por familia (security_event_otp_shape), espejo del JSON schema. En este PR la tabla solo admite los
--    tipos; los emisores siguen escribiendo en el ledger hasta SEC-CNS-021 PR-2 (F-1, D1 a).
-- 2. Policy de INSERT para app_rw por familia: OTP_* / RECOVERY / MGMT y, de forma transitoria, STAFF_* / CASE_* hasta ADR-010 PR-5
--    (que los pasa a platform_rw).
-- 3. Transfiere ops.security_event y ops.security_event_immutable() a security_event_owner (0028), patron 0027. Desde aqui consent_owner
--    ya no es dueno ni hereda privilegios sobre la tabla: todo DDL futuro debe declarar SET LOCAL ROLE security_event_owner.
--    El esquema ops sigue siendo de consent_owner (R-21-1, F-2: aceptado IT0b).
-- Sin purga en este PR: sigue vigente el append-only incondicional de 0025 (la purga P-34 llega en SEC-CNS-021 PR-3).

-- 1. Columnas (consent_owner aun es el dueno de la tabla). Todas NULL a nivel de tabla; la forma la fija security_event_otp_shape.
ALTER TABLE ops.security_event
  ADD COLUMN verification_ref uuid,
  ADD COLUMN otp_scope        text,
  ADD COLUMN scope_class      text,
  ADD COLUMN channel_ref      uuid,
  ADD COLUMN key_kind         text,
  ADD COLUMN window_kind      text,
  ADD COLUMN chain_ref        uuid,
  ADD COLUMN recovery_ref     uuid,
  ADD COLUMN trigger_kind     text;

ALTER TABLE ops.security_event
  ADD CONSTRAINT security_event_verification_ref_uuidv4 CHECK (verification_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT security_event_channel_ref_uuidv4 CHECK (channel_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT security_event_chain_ref_uuidv4 CHECK (chain_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT security_event_recovery_ref_uuidv4 CHECK (recovery_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT security_event_otp_scope_enum CHECK (otp_scope IN ('DECISION', 'REVOCATION', 'MANAGE')),
  ADD CONSTRAINT security_event_scope_class_enum CHECK (scope_class IN ('DECISION', 'RIGHTS')),
  ADD CONSTRAINT security_event_key_kind_enum CHECK (key_kind IN ('CHANNEL', 'INVITATION', 'CHAIN')),
  ADD CONSTRAINT security_event_window_kind_enum CHECK (window_kind IN ('DAY_1', 'DAYS_30')),
  ADD CONSTRAINT security_event_trigger_kind_enum CHECK (trigger_kind IN ('REQUESTER_ASKED', 'LIMIT_REACHED', 'CASE_CONTACT', 'SCHOOL_REPORTED', 'RECEIPT_REISSUED', 'FAILURE_CAP'));

ALTER TABLE ops.security_event DROP CONSTRAINT security_event_type_enum;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_type_enum CHECK (event_type IN (
  'STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION',
  'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
  'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED'));

-- Forma por familia (exacta: cada columna es obligatoria o NULL segun el tipo). Espejo de security-event-payloads.schema.json:
--   sesion (5 tipos)            : columnas OTP/recovery/management NULL (las de sesion las exige security_event_session_shape, 0025)
--   OTP_ISSUED                  : verification_ref, otp_scope, channel_ref
--   OTP_FAILED/LOCKED/EXPIRED   : verification_ref, otp_scope
--   OTP_BUDGET_EXHAUSTED        : verification_ref, scope_class, key_kind, window_kind (INVITATION solo DECISION, CHAIN solo RIGHTS,
--                                 DAYS_30 solo (RIGHTS, CHAIN))
--   RECOVERY_TOKEN_ISSUED       : recovery_ref + trigger_kind en {REQUESTER_ASKED, LIMIT_REACHED, CASE_CONTACT, SCHOOL_REPORTED}
--   MANAGEMENT_TOKEN_ROTATED    : chain_ref + trigger_kind en {RECEIPT_REISSUED, FAILURE_CAP}
-- Los tipos no de sesion llevan NULL en las columnas de sesion. Cada rama usa IS [NOT] NULL (nunca NULL) para que el CHECK no pase por NULL.
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_otp_shape CHECK (
  CASE
    WHEN event_type IN ('STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION') THEN
      verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
      AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
    ELSE
      actor_ref IS NULL AND actor_role IS NULL AND session_kind IS NULL AND session_ref IS NULL AND case_ref IS NULL
      AND CASE event_type
        WHEN 'OTP_ISSUED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NOT NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_FAILED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_LOCKED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_EXPIRED' THEN
          verification_ref IS NOT NULL AND otp_scope IS NOT NULL AND channel_ref IS NULL AND scope_class IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        WHEN 'OTP_BUDGET_EXHAUSTED' THEN
          verification_ref IS NOT NULL AND scope_class IS NOT NULL AND key_kind IS NOT NULL AND window_kind IS NOT NULL
          AND otp_scope IS NULL AND channel_ref IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
          AND (key_kind <> 'INVITATION' OR scope_class = 'DECISION')
          AND (key_kind <> 'CHAIN' OR scope_class = 'RIGHTS')
          AND (window_kind <> 'DAYS_30' OR (scope_class = 'RIGHTS' AND key_kind = 'CHAIN'))
        WHEN 'RECOVERY_TOKEN_ISSUED' THEN
          recovery_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('REQUESTER_ASKED', 'LIMIT_REACHED', 'CASE_CONTACT', 'SCHOOL_REPORTED')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL
        WHEN 'MANAGEMENT_TOKEN_ROTATED' THEN
          chain_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('RECEIPT_REISSUED', 'FAILURE_CAP')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND recovery_ref IS NULL
        ELSE false
      END
  END
);

-- 2. Policy de INSERT por familia (reemplaza security_event_tenant_insert de 0025). Los tipos de sesion son transitorios: ADR-010 PR-5 los
-- pasa a platform_rw. Siguen sin policy SELECT/UPDATE/DELETE para app_rw (D-5).
DROP POLICY security_event_tenant_insert ON ops.security_event;
CREATE POLICY security_event_app_rw_insert ON ops.security_event FOR INSERT TO app_rw
  WITH CHECK (
    tenant_id = app.current_tenant_id()
    AND event_type IN (
      'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
      'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED',
      'STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION')
  );

GRANT INSERT (verification_ref, otp_scope, scope_class, channel_ref, key_kind, window_kind, chain_ref, recovery_ref, trigger_kind)
  ON ops.security_event TO app_rw;

-- 3. Transferencia (patron 0027). ALTER ... OWNER exige que el nuevo dueno tenga CREATE (y USAGE) en el esquema; el CREATE es temporal.
-- Los triggers, indices, policies y la secuencia de identidad acompanan a la tabla. El esquema ops NO se transfiere (R-21-1).
GRANT USAGE, CREATE ON SCHEMA ops TO security_event_owner;
ALTER TABLE ops.security_event OWNER TO security_event_owner;
ALTER FUNCTION ops.security_event_immutable() OWNER TO security_event_owner;
REVOKE CREATE ON SCHEMA ops FROM security_event_owner;

-- Lo que security_event_owner cree a futuro no es ejecutable por PUBLIC por defecto.
SET LOCAL ROLE security_event_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SET LOCAL ROLE consent_owner;

-- 4. Aserciones: la migracion aborta si algo no quedo como se declara (INV-21-06). Se consulta el catalogo por nombre.
DO $assert$
DECLARE
  tbl oid;
BEGIN
  SELECT c.oid INTO tbl FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'ops' AND c.relname = 'security_event' AND pg_catalog.pg_get_userbyid(c.relowner) = 'security_event_owner';
  IF tbl IS NULL THEN RAISE EXCEPTION 'ops.security_event no pertenece a security_event_owner'; END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'ops' AND p.proname = 'security_event_immutable' AND pg_catalog.pg_get_userbyid(p.proowner) = 'security_event_owner') THEN
    RAISE EXCEPTION 'ops.security_event_immutable() no pertenece a security_event_owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'ops' AND c.relname LIKE 'security\_event%' AND pg_catalog.pg_get_userbyid(c.relowner) <> 'security_event_owner') THEN
    RAISE EXCEPTION 'hay relaciones security_event* (indices, secuencias) que no pertenecen a security_event_owner';
  END IF;
  IF pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE') THEN
    RAISE EXCEPTION 'security_event_owner conserva CREATE en el esquema ops (el grant temporal no quedo revocado)';
  END IF;

  -- Triggers append-only: ENABLE ALWAYS, ejecutan ops.security_event_immutable() y cubren UPDATE, DELETE (fila) y TRUNCATE (sentencia).
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t
       WHERE t.tgrelid = tbl AND t.tgname LIKE 'security\_event\_no\_%' AND t.tgenabled = 'A'
         AND t.tgfoid = (SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                          WHERE n.nspname = 'ops' AND p.proname = 'security_event_immutable')) <> 2 THEN
    RAISE EXCEPTION 'los triggers append-only de ops.security_event deben ser ENABLE ALWAYS y ejecutar ops.security_event_immutable()';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = tbl AND t.tgname = 'security_event_no_update_delete'
                    AND (t.tgtype & 1) = 1 AND (t.tgtype & 2) = 2 AND (t.tgtype & 8) = 8 AND (t.tgtype & 16) = 16 AND (t.tgtype & 32) = 0)
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = tbl AND t.tgname = 'security_event_no_truncate'
                    AND (t.tgtype & 1) = 0 AND (t.tgtype & 2) = 2 AND (t.tgtype & 32) = 32) THEN
    RAISE EXCEPTION 'los triggers de ops.security_event deben ser BEFORE ROW UPDATE/DELETE y BEFORE STATEMENT TRUNCATE';
  END IF;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = tbl) THEN
    RAISE EXCEPTION 'ops.security_event perdio ENABLE/FORCE ROW LEVEL SECURITY';
  END IF;
  IF pg_catalog.has_table_privilege('consent_owner', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'consent_owner conserva privilegios sobre ops.security_event';
  END IF;
  -- Runtime: app_rw solo INSERT; worker y platform_rw, nada (INV-21-05).
  IF pg_catalog.has_any_column_privilege('app_rw', tbl, 'SELECT,UPDATE')
     OR pg_catalog.has_table_privilege('app_rw', tbl, 'DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'app_rw tiene privilegios de mas sobre ops.security_event (solo INSERT por columnas)';
  END IF;
  IF pg_catalog.has_any_column_privilege('worker', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('worker', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR pg_catalog.has_any_column_privilege('platform_rw', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('platform_rw', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'worker o platform_rw tienen privilegios sobre ops.security_event';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl) <> 1 THEN
    RAISE EXCEPTION 'ops.security_event debe tener exactamente una policy (INSERT de app_rw)';
  END IF;
END
$assert$;
