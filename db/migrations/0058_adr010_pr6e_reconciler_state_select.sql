-- scope: database
-- Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`: SELECT cross-tenant de columnas sin PII de las tablas de estado), §4.2.c (conciliacion estado <-> ledger; CANCELLED <-> INVITATION_CANCELLED,
-- REVOKED <-> CONSENT_REVOKED), §10 fila 6e, condicion de §15.3 (policies de SELECT explicitas TO integrity_reconciler, con assert), F-PR6-29; specs/db-roles.spec.yaml (integrity_reconciler, INV-DBR-08).
--
-- Lo ESTRICTAMENTE necesario para conciliar lo que hoy emite el ledger desde estados (las tablas son de consent_owner; el runner ya corre como consent_owner):
--   * app.invitation:        SELECT (tenant_id, invitation_ref, state)         -> I1..I7 e I9 (CANCELLED <-> INVITATION_CANCELLED).
--   * app.consent_decision:  SELECT (tenant_id, consent_id, state)             -> C3/C5/C6 (GRANTED/DECLINED/REVOKED <-> CONSENT_GRANTED/CONSENT_DECLINED/CONSENT_REVOKED).
--   Solo identificadores opacos y el estado: SIN recipient_channel_ref, token_hash, subject_ref, decision_maker_ref, bound_decision_maker_ref ni ninguna otra columna. Sin DML.
--   REVOKED <-> CONSENT_REVOKED se concilia con el payload del evento (revokedDecisionRef): no hace falta leer app.revocation.
--   Cada una con UNA policy de SELECT `TO integrity_reconciler USING (true)` (cross-tenant a proposito, rol NOBYPASSRLS).
--   + USAGE sobre app y ops y SELECT de ops.db_catalog (una fila, sin PII): chequeos de arranque (INV-DBR-02, F-PR6-08), igual que 0042 paso 3 para integrity_verifier.
-- FUERA de 6e (FINDING F-PR6E-01): app.rights_case, app.case_session y platform.session_event. Las sesiones y CASE_* llegan en 6c (en paralelo) y rights_case no tiene siembra con eventos en LOCAL;
-- sumarlas sin productor de eventos coherente daria falsos positivos. Se agregan en una migracion nueva cuando 6c las defina.
-- Sin EXECUTE de ninguna funcion de app/ops/platform/case_state y sin acceso a platform.principal_identity ni oidc_exchange (P2(e)).
-- Idempotente: GRANT repetibles y DROP POLICY IF EXISTS + CREATE POLICY.

GRANT USAGE ON SCHEMA app, ops TO integrity_reconciler;
GRANT SELECT ON ops.db_catalog TO integrity_reconciler;

GRANT SELECT (tenant_id, invitation_ref, state) ON app.invitation TO integrity_reconciler;
DROP POLICY IF EXISTS invitation_reconciler_select ON app.invitation;
CREATE POLICY invitation_reconciler_select ON app.invitation FOR SELECT TO integrity_reconciler USING (true);

GRANT SELECT (tenant_id, consent_id, state) ON app.consent_decision TO integrity_reconciler;
DROP POLICY IF EXISTS consent_decision_reconciler_select ON app.consent_decision;
CREATE POLICY consent_decision_reconciler_select ON app.consent_decision FOR SELECT TO integrity_reconciler USING (true);

-- Aserciones (fail-closed): estado exacto resultante.
DO $assert58$
DECLARE
  rel text;
  pol text;
  rid oid;
  cnt int;
  rec record;
BEGIN
  IF NOT pg_catalog.has_schema_privilege('integrity_reconciler', 'app', 'USAGE') OR NOT pg_catalog.has_schema_privilege('integrity_reconciler', 'ops', 'USAGE') THEN
    RAISE EXCEPTION '0058: integrity_reconciler sin USAGE sobre app/ops (chequeos de arranque)';
  END IF;
  IF pg_catalog.has_schema_privilege('integrity_reconciler', 'app', 'CREATE') OR pg_catalog.has_schema_privilege('integrity_reconciler', 'ops', 'CREATE') THEN
    RAISE EXCEPTION '0058: integrity_reconciler tiene CREATE en app/ops';
  END IF;
  IF NOT pg_catalog.has_table_privilege('integrity_reconciler', 'ops.db_catalog', 'SELECT')
     OR pg_catalog.has_table_privilege('integrity_reconciler', 'ops.db_catalog', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION '0058: integrity_reconciler debe tener solo SELECT sobre ops.db_catalog';
  END IF;

  -- Tablas de app/ops con privilegios del reconciler: SOLO invitation y consent_decision (columnas exactas) y ops.db_catalog.
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name, c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname IN ('app', 'ops') AND c.relkind IN ('r', 'p', 'v', 'm', 'f') LOOP
    IF rec.name IN ('app.invitation', 'app.consent_decision', 'ops.db_catalog') THEN
      IF pg_catalog.has_table_privilege('integrity_reconciler', rec.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'INSERT,UPDATE,REFERENCES') THEN
        RAISE EXCEPTION '0058: integrity_reconciler tiene privilegios de escritura sobre %', rec.name;
      END IF;
    ELSIF pg_catalog.has_table_privilege('integrity_reconciler', rec.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0058: integrity_reconciler tiene privilegios sobre % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname IN ('app', 'ops') AND CASE WHEN c.relkind = 'S' THEN pg_catalog.has_sequence_privilege('integrity_reconciler', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END LOOP
    RAISE EXCEPTION '0058: integrity_reconciler tiene privilegios sobre la secuencia %', rec.name;
  END LOOP;

  -- Columnas exactas legibles (sin PII).
  FOR rec IN SELECT * FROM (VALUES ('app.invitation', 'tenant_id,invitation_ref,state'), ('app.consent_decision', 'tenant_id,consent_id,state')) AS v(rel, cols) LOOP
    SELECT pg_catalog.string_agg(a.attname::text, ',' ORDER BY a.attname::text COLLATE "C") INTO pol
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = rec.rel::pg_catalog.regclass AND a.attnum > 0 AND NOT a.attisdropped
       AND pg_catalog.has_column_privilege('integrity_reconciler', a.attrelid, a.attname, 'SELECT');
    IF pol IS DISTINCT FROM (SELECT pg_catalog.string_agg(x, ',' ORDER BY x COLLATE "C") FROM pg_catalog.unnest(pg_catalog.string_to_array(rec.cols, ',')) AS x) THEN
      RAISE EXCEPTION '0058: columnas legibles de % distintas de las aprobadas (%)', rec.rel, rec.cols;
    END IF;
  END LOOP;

  -- Policies que alcanzan al reconciler (nombradas o PUBLIC): exactamente una por tabla, de SELECT, USING (true).
  SELECT r.oid INTO rid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_reconciler';
  FOR rec IN SELECT * FROM (VALUES ('app.invitation', 'invitation_reconciler_select'), ('app.consent_decision', 'consent_decision_reconciler_select')) AS v(rel, polname) LOOP
    SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE p.polrelid = rec.rel::pg_catalog.regclass AND (0::oid = ANY (p.polroles) OR rid = ANY (p.polroles));
    IF cnt <> 1 THEN RAISE EXCEPTION '0058: % debe tener exactamente 1 policy que alcance a integrity_reconciler (hay %)', rec.rel, cnt; END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rec.rel::pg_catalog.regclass AND p.polname = rec.polname AND p.polcmd = 'r'
          AND pg_catalog.array_length(p.polroles, 1) = 1 AND p.polroles[1] = rid AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true') <> 1 THEN
      RAISE EXCEPTION '0058: falta la policy % (SELECT, TO integrity_reconciler, USING (true))', rec.polname;
    END IF;
    IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = rec.rel::pg_catalog.regclass) THEN
      RAISE EXCEPTION '0058: % perdio RLS ENABLE/FORCE', rec.rel;
    END IF;
  END LOOP;
  -- En todo el catalogo, el reconciler solo aparece en TRES policies (audit_event, invitation, consent_decision).
  SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE rid = ANY (p.polroles);
  IF cnt <> 3 THEN RAISE EXCEPTION '0058: integrity_reconciler debe aparecer en exactamente 3 policies (hay %)', cnt; END IF;

  -- Sin EXECUTE de funciones de dominio (el reconciler solo lee; no hay aserciones, sesiones ni transiciones).
  FOR rec IN SELECT n.nspname || '.' || p.proname AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname IN ('app', 'ops', 'platform', 'case_state', 'ledger_gen', 'integrity', 'tenant_resolve')
                AND pg_catalog.has_function_privilege('integrity_reconciler', p.oid, 'EXECUTE') LOOP
    RAISE EXCEPTION '0058: integrity_reconciler puede ejecutar %()', rec.name;
  END LOOP;
  -- P2(e): ni el reconciler ni el verifier leen la identidad del principal.
  -- (por catalogo, por oid: consent_owner no tiene USAGE en platform y to_regclass('platform.*') fallaria).
  FOR rec IN SELECT c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relname = 'principal_identity' LOOP
    IF pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_any_column_privilege('integrity_verifier', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0058: integrity_reconciler o integrity_verifier tienen privilegios sobre platform.principal_identity (P2(e))';
    END IF;
  END LOOP;
END
$assert58$;
