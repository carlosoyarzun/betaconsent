-- scope: database
-- Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`: SELECT cross-tenant de columnas sin PII de las tablas de estado), §4.2.c (conciliacion estado <-> ledger; CANCELLED <-> INVITATION_CANCELLED,
-- REVOKED <-> CONSENT_REVOKED), §10 fila 6e, condicion de §15.3 (policies de SELECT explicitas TO integrity_reconciler, con assert), F-PR6-29; specs/db-roles.spec.yaml (integrity_reconciler, INV-DBR-08).
-- Seguridad PR #99: P1-1 (REVOKED sale de app.revocation, no del payload del ledger) y P2-4 (el assert recorre TODOS los esquemas no de sistema).
--
-- Lo ESTRICTAMENTE necesario para conciliar lo que hoy emite el ledger desde estados (las tablas son de consent_owner; el runner ya corre como consent_owner):
--   * app.invitation:        SELECT (tenant_id, invitation_ref, state)                           -> I1..I7 e I9 (CANCELLED <-> INVITATION_CANCELLED).
--   * app.consent_decision:  SELECT (tenant_id, consent_id, state)                               -> C3/C5/C6 (GRANTED/DECLINED/REVOKED <-> CONSENT_GRANTED/CONSENT_DECLINED/CONSENT_REVOKED).
--   * app.revocation:        SELECT (tenant_id, revocation_ref, revoked_decision_ref)            -> vincula el evento Revocation:CONSENT_REVOKED (aggregate_id = revocation_ref) con la decision REVOKED.
--                            (se agrega revocation_ref a lo pedido: sin el no hay vinculo evento->decision sin leer payload.)
--   Solo identificadores opacos y el estado: SIN recipient_channel_ref, token_hash, subject_ref, decision_maker_ref, bound_decision_maker_ref ni ninguna otra columna. Sin DML.
--   Cada una con UNA policy de SELECT `TO integrity_reconciler USING (true)` (cross-tenant a proposito, rol NOBYPASSRLS).
--   + USAGE sobre app y ops y SELECT de ops.db_catalog (una fila, sin PII): chequeos de arranque (INV-DBR-02, F-PR6-08), igual que 0042 paso 3 para integrity_verifier.
-- FUERA de 6e (FINDING F-PR6E-01): app.rights_case, app.case_session y platform.session_event (6c los define; sin productor de eventos coherente daria falsos positivos).
-- Sin EXECUTE de ninguna funcion y sin acceso a platform.principal_identity ni oidc_exchange (P2(e)).
-- Idempotente: GRANT repetibles y DROP POLICY IF EXISTS + CREATE POLICY.

GRANT USAGE ON SCHEMA app, ops TO integrity_reconciler;
GRANT SELECT ON ops.db_catalog TO integrity_reconciler;

GRANT SELECT (tenant_id, invitation_ref, state) ON app.invitation TO integrity_reconciler;
DROP POLICY IF EXISTS invitation_reconciler_select ON app.invitation;
CREATE POLICY invitation_reconciler_select ON app.invitation FOR SELECT TO integrity_reconciler USING (true);

GRANT SELECT (tenant_id, consent_id, state) ON app.consent_decision TO integrity_reconciler;
DROP POLICY IF EXISTS consent_decision_reconciler_select ON app.consent_decision;
CREATE POLICY consent_decision_reconciler_select ON app.consent_decision FOR SELECT TO integrity_reconciler USING (true);

GRANT SELECT (tenant_id, revocation_ref, revoked_decision_ref) ON app.revocation TO integrity_reconciler;
DROP POLICY IF EXISTS revocation_reconciler_select ON app.revocation;
CREATE POLICY revocation_reconciler_select ON app.revocation FOR SELECT TO integrity_reconciler USING (true);

-- Aserciones (fail-closed): estado exacto resultante. Recorre TODOS los esquemas no de sistema (pii, platform, tenant_resolve, case_state, ledger_gen, integrity, ...), no una lista fija.
DO $assert58$
DECLARE
  pol text;
  rid oid;
  cnt int;
  rec record;
  col text;
  allowed_cols text[];
  relid oid;
BEGIN
  IF NOT pg_catalog.has_schema_privilege('integrity_reconciler', 'app', 'USAGE') OR NOT pg_catalog.has_schema_privilege('integrity_reconciler', 'ops', 'USAGE') THEN
    RAISE EXCEPTION '0058: integrity_reconciler sin USAGE sobre app/ops (chequeos de arranque)';
  END IF;
  -- Ningun CREATE en ningun esquema; USAGE solo en integrity, app y ops (el resto de esquemas no de sistema, p. ej. platform, pii, case_state, ledger_gen, tenant_resolve: sin USAGE).
  FOR rec IN SELECT n.nspname AS name FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' LOOP
    IF pg_catalog.has_schema_privilege('integrity_reconciler', rec.name, 'CREATE') THEN RAISE EXCEPTION '0058: integrity_reconciler tiene CREATE en %', rec.name; END IF;
    IF pg_catalog.has_schema_privilege('integrity_reconciler', rec.name, 'USAGE') AND rec.name NOT IN ('integrity', 'app', 'ops', 'public') THEN
      RAISE EXCEPTION '0058: integrity_reconciler tiene USAGE sobre el esquema % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_table_privilege('integrity_reconciler', 'ops.db_catalog', 'SELECT')
     OR pg_catalog.has_table_privilege('integrity_reconciler', 'ops.db_catalog', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION '0058: integrity_reconciler debe tener solo SELECT sobre ops.db_catalog';
  END IF;

  -- Relaciones de TODO esquema no de sistema (tablas, vistas, matviews, foraneas): solo las cuatro de lectura aprobadas y ops.db_catalog; ninguna con escritura.
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name, c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') LOOP
    IF pg_catalog.has_table_privilege('integrity_reconciler', rec.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0058: integrity_reconciler tiene privilegios de escritura sobre %', rec.name;
    END IF;
    IF rec.name NOT IN ('app.invitation', 'app.consent_decision', 'app.revocation', 'integrity.audit_event', 'ops.db_catalog')
       AND (pg_catalog.has_table_privilege('integrity_reconciler', rec.oid, 'SELECT') OR pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'SELECT')) THEN
      RAISE EXCEPTION '0058: integrity_reconciler tiene SELECT sobre % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  -- Secuencias de todo esquema.
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                AND CASE WHEN c.relkind = 'S' THEN pg_catalog.has_sequence_privilege('integrity_reconciler', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END LOOP
    RAISE EXCEPTION '0058: integrity_reconciler tiene privilegios sobre la secuencia %', rec.name;
  END LOOP;

  -- Columnas exactas legibles (sin PII ni payload) de las cuatro tablas.
  FOR rec IN SELECT * FROM (VALUES
      ('app.invitation', ARRAY['tenant_id', 'invitation_ref', 'state']),
      ('app.consent_decision', ARRAY['tenant_id', 'consent_id', 'state']),
      ('app.revocation', ARRAY['tenant_id', 'revocation_ref', 'revoked_decision_ref']),
      ('integrity.audit_event', ARRAY['tenant_id', 'aggregate_type', 'aggregate_id', 'sequence', 'event_type', 'chain_seq', 'occurred_at'])) AS v(rel, cols) LOOP
    allowed_cols := rec.cols;
    relid := (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname || '.' || c.relname = rec.rel);
    FOR col IN SELECT a.attname FROM pg_catalog.pg_attribute a WHERE a.attrelid = relid AND a.attnum > 0 AND NOT a.attisdropped LOOP
      IF pg_catalog.has_column_privilege('integrity_reconciler', relid, col, 'SELECT') <> (col = ANY (allowed_cols)) THEN
        RAISE EXCEPTION '0058: la lectura de % por integrity_reconciler en la columna % no coincide con las aprobadas', rec.rel, col;
      END IF;
    END LOOP;
  END LOOP;

  -- Policies que alcanzan al reconciler (nombradas o PUBLIC): exactamente una por tabla, de SELECT, USING (true), en las cuatro.
  SELECT r.oid INTO rid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_reconciler';
  FOR rec IN SELECT * FROM (VALUES
      ('app.invitation', 'invitation_reconciler_select'), ('app.consent_decision', 'consent_decision_reconciler_select'),
      ('app.revocation', 'revocation_reconciler_select'), ('integrity.audit_event', 'audit_event_reconciler_select')) AS v(rel, polname) LOOP
    relid := (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname || '.' || c.relname = rec.rel);
    SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE p.polrelid = relid AND (0::oid = ANY (p.polroles) OR rid = ANY (p.polroles));
    IF cnt <> 1 THEN RAISE EXCEPTION '0058: % debe tener exactamente 1 policy que alcance a integrity_reconciler (hay %)', rec.rel, cnt; END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = relid AND p.polname = rec.polname AND p.polcmd = 'r'
          AND pg_catalog.array_length(p.polroles, 1) = 1 AND p.polroles[1] = rid AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true') <> 1 THEN
      RAISE EXCEPTION '0058: falta la policy % (SELECT, TO integrity_reconciler, USING (true))', rec.polname;
    END IF;
    IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = relid) THEN
      RAISE EXCEPTION '0058: % perdio RLS ENABLE/FORCE', rec.rel;
    END IF;
  END LOOP;
  -- En todo el catalogo, el reconciler solo aparece en CUATRO policies.
  SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE rid = ANY (p.polroles);
  IF cnt <> 4 THEN RAISE EXCEPTION '0058: integrity_reconciler debe aparecer en exactamente 4 policies (hay %)', cnt; END IF;

  -- Sin EXECUTE de funciones de ningun esquema no de sistema (el reconciler solo lee; no hay aserciones, sesiones ni transiciones).
  FOR rec IN SELECT n.nspname || '.' || p.proname AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND pg_catalog.has_function_privilege('integrity_reconciler', p.oid, 'EXECUTE') LOOP
    RAISE EXCEPTION '0058: integrity_reconciler puede ejecutar %()', rec.name;
  END LOOP;
  -- P2(e): ni el reconciler ni el verifier leen la identidad del principal (por catalogo, por oid: consent_owner no tiene USAGE en platform).
  FOR rec IN SELECT c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relname = 'principal_identity' LOOP
    IF pg_catalog.has_any_column_privilege('integrity_reconciler', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
       OR pg_catalog.has_any_column_privilege('integrity_verifier', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0058: integrity_reconciler o integrity_verifier tienen privilegios sobre platform.principal_identity (P2(e))';
    END IF;
  END LOOP;
END
$assert58$;
