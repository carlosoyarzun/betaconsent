-- scope: database
-- Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`: SELECT cross-tenant sin PII de integrity.audit_event), §4.2.c, §4.5.1 (DDL de integrity.* como integrity_owner, antes de PR-7), §10 fila 6e,
-- condicion de §15.3 / seguridad rev. c punto 7 (integrity_reconciler es NOBYPASSRLS: la lectura cross-tenant exige una policy de SELECT explicita `TO integrity_reconciler`, con assert);
-- specs/db-roles.spec.yaml (integrity_reconciler, INV-DBR-08). 0042/0047 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- integrity.audit_event es del ledger (dueno integrity_owner; RLS ENABLE + FORCE). Se concede al reconciler:
--   * USAGE sobre el esquema integrity;
--   * SELECT POR COLUMNAS de SOLO 7 columnas sin contenido: tenant_id, aggregate_type, aggregate_id, sequence, event_type, chain_seq, occurred_at. SIN payload (lleva seudonimos del titular,
--     LG-9), sin recorded_by_ref / cosigned_by_ref, sin idempotency_key_hash ni hashes de la cadena (seguridad PR #99, P1-1: ADR-010 rev. 5 §2 "columnas sin PII" y §4.2.c "el verifier conserva el
--     recomputo de la cadena"). Por eso el reconciler NO recomputa la cadena SHA-256: eso es del verifier (OI-DBR-10 / F-PR6E-06).
--   * una policy de SELECT explicita `TO integrity_reconciler USING (true)` (cross-tenant a proposito: la conciliacion recorre todos los tenants). Es la UNICA policy del rol sobre la tabla.
-- Ningun INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER. No se crea ninguna funcion (TEST-CNS-1470).
-- No se conceden permisos a otros roles ni se modifican las policies existentes (todas son `TO <rol>` y no alcanzan al reconciler).
-- DDL como integrity_owner (allowlist de integrity-owner-checker.ts) y sin grants temporales: la policy no usa funciones de app.
-- Idempotente: GRANT/REVOKE repetibles y DROP POLICY IF EXISTS + CREATE POLICY.

SET LOCAL ROLE integrity_owner;

GRANT USAGE ON SCHEMA integrity TO integrity_reconciler;

GRANT SELECT (tenant_id, aggregate_type, aggregate_id, sequence, event_type, chain_seq, occurred_at) ON integrity.audit_event TO integrity_reconciler;

DROP POLICY IF EXISTS audit_event_reconciler_select ON integrity.audit_event;
CREATE POLICY audit_event_reconciler_select ON integrity.audit_event FOR SELECT TO integrity_reconciler USING (true);

SET LOCAL ROLE consent_owner;

-- Aserciones (fail-closed): estado exacto resultante.
DO $assert57$
DECLARE
  led oid;
  col text;
  cnt int;
BEGIN
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  IF led IS NULL THEN RAISE EXCEPTION '0057: falta integrity.audit_event'; END IF;
  IF NOT pg_catalog.has_schema_privilege('integrity_reconciler', 'integrity', 'USAGE') OR pg_catalog.has_schema_privilege('integrity_reconciler', 'integrity', 'CREATE') THEN
    RAISE EXCEPTION '0057: integrity_reconciler debe tener solo USAGE sobre integrity';
  END IF;
  -- Columnas legibles: EXACTAMENTE las 7 aprobadas (sin payload, hashes ni refs de actor), y ninguna con escritura/REFERENCES.
  FOR col IN SELECT a.attname FROM pg_catalog.pg_attribute a WHERE a.attrelid = led AND a.attnum > 0 AND NOT a.attisdropped LOOP
    IF pg_catalog.has_column_privilege('integrity_reconciler', led, col, 'SELECT') <> (col = ANY (ARRAY['tenant_id', 'aggregate_type', 'aggregate_id', 'sequence', 'event_type', 'chain_seq', 'occurred_at'])) THEN
      RAISE EXCEPTION '0057: SELECT de integrity_reconciler sobre la columna % no coincide con las 7 aprobadas', col;
    END IF;
    IF pg_catalog.has_column_privilege('integrity_reconciler', led, col, 'INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION '0057: integrity_reconciler tiene escritura/REFERENCES en la columna %', col; END IF;
  END LOOP;
  IF pg_catalog.has_table_privilege('integrity_reconciler', led, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION '0057: integrity_reconciler tiene privilegios de escritura sobre integrity.audit_event';
  END IF;
  -- Policies que alcanzan al reconciler (nombradas o PUBLIC): exactamente la de SELECT.
  SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p
   WHERE p.polrelid = led AND (0::oid = ANY (p.polroles) OR (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_reconciler') = ANY (p.polroles));
  IF cnt <> 1 THEN RAISE EXCEPTION '0057: integrity.audit_event debe tener exactamente 1 policy que alcance a integrity_reconciler (hay %)', cnt; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_reconciler_select' AND p.polcmd = 'r'
        AND pg_catalog.array_length(p.polroles, 1) = 1 AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'integrity_reconciler'
        AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true') <> 1 THEN
    RAISE EXCEPTION '0057: falta la policy audit_event_reconciler_select (SELECT, TO integrity_reconciler, USING (true))';
  END IF;
  -- RLS sigue ENABLE + FORCE (sin ella la policy seria irrelevante y el resto de roles verian todo).
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = led) THEN RAISE EXCEPTION '0057: integrity.audit_event perdio RLS ENABLE/FORCE'; END IF;
  -- Ningun otro rol de runtime gano lectura cross-tenant: integrity_verifier y platform_rw siguen sin SELECT.
  IF pg_catalog.has_any_column_privilege('integrity_verifier', led, 'SELECT') OR pg_catalog.has_any_column_privilege('platform_rw', led, 'SELECT') THEN
    RAISE EXCEPTION '0057: integrity_verifier o platform_rw tienen SELECT sobre integrity.audit_event';
  END IF;
END
$assert57$;
