-- scope: database
-- Gobierna: SEC-CNS-PR94 P2-A (revision de seguridad del PR #94, flujo del invitado v2; pedido de Carlos 2026-10-14), UX-CNS-006 / UX-CNS-006b (mensajes RECEIPT y
-- MANAGEMENT_LINK al canal ligado), consent-decision.spec.yaml C3/C5, SEC-CNS-006 rev. 5, INV-21-04 (solo refs opacas y enums; cero PII), INV-CM-02.
-- Regla de Carlos (2026-10-01): 0000-0044 no se editan; esta migracion es nueva.
--
-- Un fallo de entrega POST-COMMIT del RECEIPT o del MANAGEMENT_LINK dejaba rastro solo en stderr y en el sink dev. Ahora queda un evento persistente en
-- ops.security_event (fuera del ledger de consentimiento; la decision ya confirmo y NO se revierte):
--   GUEST_MESSAGE_DELIVERY_FAILED: delivery_kind IN ('RECEIPT', 'MANAGEMENT_LINK') + receipt_ref (UUIDv4 opaco de la decision). Sin token, sin canal, sin correo.
-- 1. Dos columnas nuevas (NULL salvo en el tipo nuevo; CHECK security_event_delivery_cols_only_for_type).
-- 2. security_event_type_enum y security_event_otp_shape admiten el tipo nuevo (misma redaccion que 0033 mas la rama nueva).
-- 3. Policy security_event_app_rw_insert admite el tipo nuevo (ALTER POLICY) y app_rw recibe INSERT solo de las dos columnas nuevas. Sin SELECT/UPDATE/DELETE.
-- Tabla de security_event_owner (0029): el DDL va con SET LOCAL ROLE security_event_owner. ALTER POLICY resuelve app.current_tenant_id(): security_event_owner ya
-- tiene USAGE sobre app desde 0031 (nunca revocado; se asegura abajo con un grant temporal que se revoca solo si no lo tenia). Idempotente: ADD COLUMN IF NOT EXISTS,
-- DROP CONSTRAINT IF EXISTS + ADD, ALTER POLICY y GRANT repetibles.

-- A. Como consent_owner: USAGE sobre app para el dueno (temporal si no lo tenia). Se recuerda en un GUC local a la tx.
SELECT pg_catalog.set_config('m0045.had_app_usage', pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE')::pg_catalog.text, true);
GRANT USAGE ON SCHEMA app TO security_event_owner;

-- B. Como security_event_owner.
SET LOCAL ROLE security_event_owner;

ALTER TABLE ops.security_event
  ADD COLUMN IF NOT EXISTS delivery_kind text,
  ADD COLUMN IF NOT EXISTS receipt_ref  uuid;

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_delivery_kind_enum;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_delivery_kind_enum CHECK (delivery_kind IN ('RECEIPT', 'MANAGEMENT_LINK'));
ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_receipt_ref_uuidv4;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_receipt_ref_uuidv4
  CHECK (receipt_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
-- Las columnas nuevas solo existen en el tipo nuevo; el resto de los tipos las lleva NULL (asi las ramas previas de la forma no cambian).
ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_delivery_cols_only_for_type;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_delivery_cols_only_for_type
  CHECK (event_type = 'GUEST_MESSAGE_DELIVERY_FAILED' OR (delivery_kind IS NULL AND receipt_ref IS NULL));

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_type_enum;
ALTER TABLE ops.security_event ADD CONSTRAINT security_event_type_enum CHECK (event_type IN (
  'STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION',
  'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
  'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED', 'GUEST_MESSAGE_DELIVERY_FAILED'));

ALTER TABLE ops.security_event DROP CONSTRAINT IF EXISTS security_event_otp_shape;
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
          AND (window_kind <> 'LIFETIME' OR (scope_class = 'DECISION' AND key_kind = 'INVITATION'))
        WHEN 'RECOVERY_TOKEN_ISSUED' THEN
          recovery_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('REQUESTER_ASKED', 'LIMIT_REACHED', 'CASE_CONTACT', 'SCHOOL_REPORTED')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL
        WHEN 'MANAGEMENT_TOKEN_ROTATED' THEN
          chain_ref IS NOT NULL AND trigger_kind IS NOT NULL AND trigger_kind IN ('RECEIPT_REISSUED', 'FAILURE_CAP')
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND recovery_ref IS NULL
        WHEN 'GUEST_MESSAGE_DELIVERY_FAILED' THEN
          delivery_kind IS NOT NULL AND receipt_ref IS NOT NULL
          AND verification_ref IS NULL AND otp_scope IS NULL AND scope_class IS NULL AND channel_ref IS NULL AND key_kind IS NULL
          AND window_kind IS NULL AND chain_ref IS NULL AND recovery_ref IS NULL AND trigger_kind IS NULL
        ELSE false
      END
  END
);

ALTER POLICY security_event_app_rw_insert ON ops.security_event
  WITH CHECK (
    tenant_id = app.current_tenant_id()
    AND event_type IN (
      'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
      'RECOVERY_TOKEN_ISSUED', 'MANAGEMENT_TOKEN_ROTATED', 'GUEST_MESSAGE_DELIVERY_FAILED',
      'STAFF_LOGIN', 'STAFF_LOGOUT', 'CASE_LOGIN', 'CASE_LOGOUT', 'SESSION_REVOKED_BY_ROTATION')
  );

GRANT INSERT (delivery_kind, receipt_ref) ON ops.security_event TO app_rw;

-- C. De vuelta a consent_owner: se retira el USAGE temporal solo si no lo tenia antes.
SET LOCAL ROLE consent_owner;
DO $revoke$
BEGIN
  IF pg_catalog.current_setting('m0045.had_app_usage') <> 'true' THEN
    REVOKE USAGE ON SCHEMA app FROM security_event_owner;
  END IF;
END
$revoke$;

-- D. Aserciones (fail-closed): estado exacto resultante.
DO $assert$
DECLARE
  tbl oid := 'ops.security_event'::pg_catalog.regclass;
  v_def text;
BEGIN
  IF pg_catalog.pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = tbl)) <> 'security_event_owner' THEN
    RAISE EXCEPTION '0045: ops.security_event debe seguir siendo de security_event_owner';
  END IF;
  IF pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE') THEN
    RAISE EXCEPTION '0045: security_event_owner conserva CREATE en ops';
  END IF;
  IF pg_catalog.current_setting('m0045.had_app_usage') <> 'true' AND pg_catalog.has_schema_privilege('security_event_owner', 'app', 'USAGE') THEN
    RAISE EXCEPTION '0045: el USAGE temporal sobre app no quedo revocado';
  END IF;
  -- Tipo: el CHECK enumera exactamente 13 tipos, con el nuevo.
  SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO v_def FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.conname = 'security_event_type_enum' AND c.convalidated;
  IF v_def IS NULL OR v_def NOT LIKE '%GUEST_MESSAGE_DELIVERY_FAILED%'
     OR (pg_catalog.length(v_def) - pg_catalog.length(pg_catalog.replace(v_def, '''::text', ''))) / 7 <> 13 THEN
    RAISE EXCEPTION '0045: security_event_type_enum no enumera exactamente los 13 tipos esperados';
  END IF;
  SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO v_def FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.conname = 'security_event_otp_shape' AND c.convalidated;
  IF v_def IS NULL OR v_def NOT LIKE '%GUEST_MESSAGE_DELIVERY_FAILED%' OR v_def NOT LIKE '%LIFETIME%' THEN
    RAISE EXCEPTION '0045: security_event_otp_shape no tiene la rama del tipo nuevo (o perdio LIFETIME)';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid = tbl AND c.convalidated
        AND c.conname IN ('security_event_delivery_kind_enum', 'security_event_receipt_ref_uuidv4', 'security_event_delivery_cols_only_for_type')) <> 3 THEN
    RAISE EXCEPTION '0045: faltan CHECK de las columnas nuevas o no estan validados';
  END IF;
  -- Policies: exactamente las declaradas (0031/0033); la de app_rw nombra el tipo nuevo.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl)
     IS DISTINCT FROM 'security_event_app_rw_insert:a:app_rw security_event_owner_update:w:security_event_owner security_event_purge_delete:d:security_event_owner security_event_purge_select:r:security_event_owner' THEN
    RAISE EXCEPTION '0045: las policies de ops.security_event no son exactamente las declaradas';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl AND p.polname = 'security_event_app_rw_insert'
                   AND pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%GUEST_MESSAGE_DELIVERY_FAILED%') THEN
    RAISE EXCEPTION '0045: la policy de INSERT de app_rw no admite el tipo nuevo';
  END IF;
  -- Privilegios: app_rw solo INSERT en las columnas nuevas; ningun otro rol de runtime recibe nada.
  IF NOT pg_catalog.has_column_privilege('app_rw', tbl, 'delivery_kind', 'INSERT') OR NOT pg_catalog.has_column_privilege('app_rw', tbl, 'receipt_ref', 'INSERT')
     OR pg_catalog.has_column_privilege('app_rw', tbl, 'delivery_kind', 'SELECT') OR pg_catalog.has_column_privilege('app_rw', tbl, 'receipt_ref', 'SELECT')
     OR pg_catalog.has_column_privilege('app_rw', tbl, 'delivery_kind', 'UPDATE') OR pg_catalog.has_column_privilege('app_rw', tbl, 'receipt_ref', 'UPDATE')
     OR pg_catalog.has_any_column_privilege('worker', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_any_column_privilege('platform_rw', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('consent_owner', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION '0045: privilegios de ops.security_event distintos de los declarados';
  END IF;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = tbl) THEN
    RAISE EXCEPTION '0045: ops.security_event perdio ENABLE/FORCE ROW LEVEL SECURITY';
  END IF;
END
$assert$;
