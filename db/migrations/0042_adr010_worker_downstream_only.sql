-- scope: database
-- Gobierna: ADR-010 rev. 4 §7 fila PR-6 ("Entrypoints web/platform/worker/verifier; unidades en infra/ (ADR-003); pools por rol"), §4.2 (funciones SYSTEM: EXECUTE solo `worker`,
-- GRD-CM-15), INV-DBR-06; specs/state-machines/revocation.spec.yaml R5/R6/R7 (FN-RV-13..15, executedBy worker); plan PR-6 sub-PR 6a (rev. 2 §5.1); registers/findings-register-IT0.md
-- F-A10-26 (parcial), F-PR6-20. 0037 y 0039 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- 1) R5-R7 solo worker: REVOKE EXECUTE de case_state.mark_downstream_emitted / record_downstream_ack / record_erasure_attestation a app_rw. R4 (apply_revocation) NO se toca
--    (queda EXECUTE app_rw + worker hasta la enmienda P6-2 de ADR-010, decision de Carlos pendiente).
-- 2) Lectura minima del worker para ejecutar R5-R7 (el dominio lee la Revocation y el ledger del agregado ANTES de llamar a la funcion SYSTEM: expectedSequence, subscriptionRefs congeladas):
--    SELECT (sin DML) sobre app.revocation y integrity.audit_event, siempre bajo RLS por tenant (policy TO worker con app.current_tenant_id()). El worker sigue sin DML directo en ledger ni
--    app.revocation (spec db-roles `mustNot`); escribe solo por las funciones SYSTEM. Es una ampliacion de superficie de lectura del worker: F-PR6-20 (P2) para revision de lampone-security.
--    DDL sobre integrity.* como integrity_owner (allowlist de integrity-owner-checker.ts; antes de PR-7), con USAGE/EXECUTE temporales sobre app igual que 0037.
-- 3) integrity_verifier: USAGE sobre app y ops + SELECT de ops.db_catalog (una fila, sin PII), lo que 0001 da a app_rw/worker/platform_rw y catalog.test.ts ya anticipaba ("el verifier
--    recibe en PR-4", nunca entregado). Sin eso el verifier NO puede ejecutar los chequeos de arranque de INV-DBR-02 (leer ops.db_catalog para contrastar CNS_ENVIRONMENT con la base,
--    F-PR6-08) y el proceso verifier no arranca. Sin privilegios de tabla en app.* ni EXECUTE de funciones de app/ops (aserciones). F-PR6-21 (P2) para revision de lampone-security.
-- 4) $assert$ final con el estado exacto resultante.
-- Idempotente: REVOKE/GRANT repetibles y DROP POLICY IF EXISTS + CREATE POLICY.

-- 1. R5-R7 solo worker (dueno de las funciones: transition_owner) ----------------------------------------------------------------------------
SET LOCAL ROLE transition_owner;
REVOKE EXECUTE ON FUNCTION case_state.mark_downstream_emitted(text, text[], integer) FROM app_rw;
REVOKE EXECUTE ON FUNCTION case_state.record_downstream_ack(text, text, integer) FROM app_rw;
REVOKE EXECUTE ON FUNCTION case_state.record_erasure_attestation(text, text, integer) FROM app_rw;
SET LOCAL ROLE consent_owner;

-- 2a. app.revocation: SELECT del worker bajo RLS por tenant (dueno: consent_owner) ----------------------------------------------------------
GRANT SELECT ON app.revocation TO worker;
DROP POLICY IF EXISTS revocation_worker_select ON app.revocation;
CREATE POLICY revocation_worker_select ON app.revocation FOR SELECT TO worker
  USING (tenant_id = app.current_tenant_id());

-- 2b. integrity.audit_event: SELECT del worker bajo RLS por tenant (dueno: integrity_owner) -------------------------------------------------
GRANT USAGE ON SCHEMA app TO integrity_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO integrity_owner;
SET LOCAL ROLE integrity_owner;
GRANT SELECT ON integrity.audit_event TO worker;
DROP POLICY IF EXISTS audit_event_worker_select ON integrity.audit_event;
CREATE POLICY audit_event_worker_select ON integrity.audit_event FOR SELECT TO worker
  USING (tenant_id = app.current_tenant_id());
SET LOCAL ROLE consent_owner;
REVOKE EXECUTE ON FUNCTION app.current_tenant_id() FROM integrity_owner;
REVOKE USAGE ON SCHEMA app FROM integrity_owner;

-- 3. integrity_verifier: lo minimo para los chequeos de arranque (dueno de app/ops/db_catalog: consent_owner) ---------------------------------------------
GRANT USAGE ON SCHEMA app, ops TO integrity_verifier;
GRANT SELECT ON ops.db_catalog TO integrity_verifier;

-- 4. Aserciones ----------------------------------------------------------------------------------------------------------------------------
DO $assert$
DECLARE
  fn text;
  r text;
  rv oid;
  led oid;
  oid_fn oid;
BEGIN
  -- R5-R7: EXECUTE solo worker (ademas del dueno).
  FOREACH fn IN ARRAY ARRAY['mark_downstream_emitted', 'record_downstream_ack', 'record_erasure_attestation'] LOOP
    FOR oid_fn IN SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = fn LOOP
      IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::text COLLATE "C")
            FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
           WHERE p.oid = oid_fn AND a.grantee <> p.proowner) IS DISTINCT FROM 'worker' THEN
        RAISE EXCEPTION 'la ACL de case_state.%() no es exactamente EXECUTE para worker', fn;
      END IF;
      IF pg_catalog.has_function_privilege('public', oid_fn, 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC puede ejecutar case_state.%()', fn; END IF;
      FOREACH r IN ARRAY ARRAY['app_rw', 'platform_rw', 'integrity_verifier', 'consent_owner', 'consent_migrator'] LOOP
        IF pg_catalog.has_function_privilege(r, oid_fn, 'EXECUTE') THEN RAISE EXCEPTION '% puede ejecutar case_state.%() (R5-R7 son solo del worker)', r, fn; END IF;
      END LOOP;
    END LOOP;
  END LOOP;
  -- R4 intacta (enmienda P6-2 pendiente): app_rw y worker. consent_owner no tiene USAGE en case_state: se resuelve por oid de catalogo, nunca por nombre regprocedure.
  SELECT p.oid INTO oid_fn FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'apply_revocation';
  IF oid_fn IS NULL OR NOT pg_catalog.has_function_privilege('app_rw', oid_fn, 'EXECUTE') OR NOT pg_catalog.has_function_privilege('worker', oid_fn, 'EXECUTE') THEN
    RAISE EXCEPTION 'apply_revocation (R4) debe conservar EXECUTE para app_rw y worker hasta la enmienda P6-2';
  END IF;

  -- worker: solo SELECT sobre app.revocation e integrity.audit_event, bajo RLS exacta.
  SELECT c.oid INTO rv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'revocation';
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  IF NOT pg_catalog.has_table_privilege('worker', rv, 'SELECT') OR NOT pg_catalog.has_table_privilege('worker', led, 'SELECT') THEN RAISE EXCEPTION 'worker no tiene SELECT'; END IF;
  IF pg_catalog.has_any_column_privilege('worker', rv, 'INSERT,UPDATE,REFERENCES') OR pg_catalog.has_table_privilege('worker', rv, 'DELETE,TRUNCATE,TRIGGER')
     OR pg_catalog.has_any_column_privilege('worker', led, 'INSERT,UPDATE,REFERENCES') OR pg_catalog.has_table_privilege('worker', led, 'DELETE,TRUNCATE,TRIGGER') THEN
    RAISE EXCEPTION 'worker tiene privilegios de escritura sobre app.revocation o integrity.audit_event';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rv AND p.polname = 'revocation_worker_select' AND p.polcmd = 'r'
        AND pg_catalog.array_length(p.polroles, 1) = 1 AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'worker'
        AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%tenant_id = app.current_tenant_id()%') <> 1 THEN
    RAISE EXCEPTION 'falta la policy revocation_worker_select (SELECT, TO worker, tenant_id = app.current_tenant_id())';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_worker_select' AND p.polcmd = 'r'
        AND pg_catalog.array_length(p.polroles, 1) = 1 AND pg_catalog.pg_get_userbyid(p.polroles[1]) = 'worker'
        AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) LIKE '%tenant_id = app.current_tenant_id()%') <> 1 THEN
    RAISE EXCEPTION 'falta la policy audit_event_worker_select (SELECT, TO worker, tenant_id = app.current_tenant_id())';
  END IF;
  -- Ningun otro rol de runtime gano lectura (platform_rw, integrity_verifier siguen sin SELECT sobre ambas tablas).
  FOREACH r IN ARRAY ARRAY['platform_rw', 'integrity_verifier'] LOOP
    IF pg_catalog.has_any_column_privilege(r, rv, 'SELECT') OR pg_catalog.has_any_column_privilege(r, led, 'SELECT') THEN RAISE EXCEPTION '% tiene SELECT sobre app.revocation o integrity.audit_event', r; END IF;
  END LOOP;
  -- integrity_verifier: USAGE en app y ops, SELECT solo de ops.db_catalog, ningun otro privilegio de tabla ni EXECUTE de funciones en app/ops, sin CREATE.
  IF NOT pg_catalog.has_schema_privilege('integrity_verifier', 'app', 'USAGE') OR NOT pg_catalog.has_schema_privilege('integrity_verifier', 'ops', 'USAGE') THEN
    RAISE EXCEPTION 'integrity_verifier sin USAGE sobre app/ops (chequeos de arranque)';
  END IF;
  IF pg_catalog.has_schema_privilege('integrity_verifier', 'app', 'CREATE') OR pg_catalog.has_schema_privilege('integrity_verifier', 'ops', 'CREATE') THEN
    RAISE EXCEPTION 'integrity_verifier tiene CREATE en app/ops';
  END IF;
  FOR fn IN SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname IN ('app', 'ops') AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname || '.' || c.relname <> 'ops.db_catalog'
               AND (pg_catalog.has_table_privilege('integrity_verifier', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    OR pg_catalog.has_any_column_privilege('integrity_verifier', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')) LOOP
    RAISE EXCEPTION 'integrity_verifier tiene privilegios sobre %', fn;
  END LOOP;
  FOR fn IN SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname IN ('app', 'ops') AND CASE WHEN c.relkind = 'S' THEN pg_catalog.has_sequence_privilege('integrity_verifier', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END LOOP
    RAISE EXCEPTION 'integrity_verifier tiene privilegios sobre la secuencia %', fn;
  END LOOP;
  IF NOT pg_catalog.has_table_privilege('integrity_verifier', 'ops.db_catalog', 'SELECT')
     OR pg_catalog.has_table_privilege('integrity_verifier', 'ops.db_catalog', 'INSERT,UPDATE,DELETE,TRUNCATE') THEN
    RAISE EXCEPTION 'integrity_verifier debe tener solo SELECT sobre ops.db_catalog';
  END IF;
  FOR fn IN SELECT n.nspname || '.' || p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname IN ('app', 'ops') AND pg_catalog.has_function_privilege('integrity_verifier', p.oid, 'EXECUTE') LOOP
    RAISE EXCEPTION 'integrity_verifier puede ejecutar %()', fn;
  END LOOP;
  -- Sin grants temporales.
  IF pg_catalog.has_schema_privilege('integrity_owner', 'app', 'USAGE') THEN RAISE EXCEPTION 'integrity_owner conserva USAGE sobre app (grant temporal)'; END IF;
  IF pg_catalog.has_function_privilege('integrity_owner', 'app.current_tenant_id()', 'EXECUTE') THEN RAISE EXCEPTION 'integrity_owner conserva EXECUTE de app.current_tenant_id()'; END IF;
END
$assert$;
