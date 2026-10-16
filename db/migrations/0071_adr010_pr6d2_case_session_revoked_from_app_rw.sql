-- scope: database
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §2 (web/app_rw "No puede": DML y policies sobre app.case_session, CASE_* en ops.security_event, `/platform/*`), §6 (la sesion CASE vive en
-- `platform`; en LOCAL se elimina el dev-login CASE, P6-4), §10 filas 6c/6d, opcion A de Carlos (2026-10-15: 6c -> 6d); specs/db-roles.spec.yaml (app_rw: app.case_session "PR-5 REVOKE ALL (pasa a platform)"); D3 / F-A10-31, F-PR6-39.
-- Que hace: (1) REVOKE ALL (tabla y columnas) de app.case_session a app_rw y DROP de sus cuatro policies: la sesion CASE de `web` (dev-login) deja de existir; la unica sesion CASE es platform.platform_session (0052/0053).
--           (2) La policy security_event_app_rw_insert pierde CASE_LOGIN y CASE_LOGOUT y la rotacion CASE (SESSION_REVOKED_BY_ROTATION con session_kind CASE): app_rw conserva solo los eventos STAFF y de OTP/recuperacion/entrega.
-- No toca los SELECT de integrity_reconciler sobre app.case_session (6e). Idempotente: REVOKE y DROP POLICY IF EXISTS / ALTER POLICY repetibles.

REVOKE ALL ON app.case_session FROM app_rw;
DROP POLICY IF EXISTS case_session_tenant_select ON app.case_session;
DROP POLICY IF EXISTS case_session_tenant_insert ON app.case_session;
DROP POLICY IF EXISTS case_session_tenant_update ON app.case_session;
DROP POLICY IF EXISTS case_session_tenant_delete_expired ON app.case_session;

SELECT pg_catalog.set_config('m0071.had_app_usage', pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE')::pg_catalog.text, true);
GRANT USAGE ON SCHEMA app TO security_event_owner;
SET LOCAL ROLE security_event_owner;
ALTER POLICY security_event_app_rw_insert ON ops.security_event
  WITH CHECK (
    tenant_id = app.current_tenant_id()
    AND event_type IN (
      'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
      'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED', 'GUEST_MESSAGE_DELIVERY_FAILED',
      'STAFF_LOGIN', 'STAFF_LOGOUT', 'SESSION_REVOKED_BY_ROTATION')
    AND session_kind IS DISTINCT FROM 'CASE'
  );
SET LOCAL ROLE consent_owner;
DO $revoke$
BEGIN
  IF pg_catalog.current_setting('m0071.had_app_usage') <> 'true' THEN REVOKE USAGE ON SCHEMA app FROM security_event_owner; END IF;
END
$revoke$;

DO $assert71$
DECLARE
  cs oid;
  se oid := 'ops.security_event'::pg_catalog.regclass;
  v_expr text;
BEGIN
  SELECT c.oid INTO cs FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'case_session';
  IF pg_catalog.has_table_privilege('app_rw', cs, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('app_rw', cs, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION '0071: app_rw conserva privilegios sobre app.case_session';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = cs AND (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'app_rw') = ANY (p.polroles)) THEN
    RAISE EXCEPTION '0071: app_rw conserva policies sobre app.case_session';
  END IF;
  SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) INTO v_expr FROM pg_catalog.pg_policy p WHERE p.polrelid = se AND p.polname = 'security_event_app_rw_insert';
  IF v_expr IS NULL OR v_expr LIKE '%CASE_LOGIN%' OR v_expr LIKE '%CASE_LOGOUT%' OR v_expr NOT LIKE '%STAFF_LOGIN%' OR v_expr NOT LIKE '%tenant_id = app.current_tenant_id()%' OR v_expr NOT LIKE '%CASE%' THEN
    RAISE EXCEPTION '0071: security_event_app_rw_insert no excluye CASE_* (o perdio los tipos STAFF/OTP o el aislamiento por tenant)';
  END IF;
  IF pg_catalog.current_setting('m0071.had_app_usage') <> 'true' AND pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE') THEN RAISE EXCEPTION '0071: el USAGE temporal sobre app no quedo revocado'; END IF;
END
$assert71$;
