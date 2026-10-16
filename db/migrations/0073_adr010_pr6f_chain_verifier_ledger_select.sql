-- scope: database
-- Gobierna: ADR-010 rev. 6 §1 (fila `integrity_chain_verifier`: SELECT por columnas de las 17 de la cadena, policy unica cross-tenant, FORCE RLS), §2 (recomputo y arranque con asserts C5/C6), §3 (fila PR-6f), §4.5.1 (DDL de
-- integrity.* como integrity_owner antes del revoke de PR-7), D-1 (b) (Carlos, 2026-10-16), F-PR6E-06, OI-DBR-10, SEC-06-1, SEC-R6-1; C1 y C5 de la revision de seguridad; specs/db-roles.spec.yaml (integrity_chain_verifier).
-- 0042/0057 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva. El rol lo crea 0072 (cluster).
--
-- integrity.audit_event es del ledger (dueno integrity_owner; RLS ENABLE + FORCE). Se concede al chain-verifier:
--   * USAGE sobre integrity;
--   * SELECT POR COLUMNAS de las 17 que entran al recomputo (ledger-chain.ts: ChainLinkFields + payload + event_hash): tenant_id, chain_seq, aggregate_type, aggregate_id, sequence, event_type, actor_type,
--     actor_role, recorded_by_ref, cosigned_by_ref, idempotency_key_hash, occurred_at, environment, payload, payload_hash, previous_event_hash, event_hash. SIN event_id, evidentiary ni data_class (no entran al hash).
--     NO son columnas sin PII: `payload` lleva seudonimos del titular (LG-9, LEGAL DECISION abierta; F-06-B) y las refs de actor son refs de staff. Contenido en IT0 por el CHECK audit_event_data_class_synthetic
--     (0002:40) y porque el rol no tiene egress ni secretos; la lectura de payload y de refs de actor exige LG-9 resuelta antes de REAL_DATA.
--   * una policy de SELECT explicita `TO integrity_chain_verifier USING (true)` (cross-tenant a proposito: el recomputo recorre todos los tenants; rol NOBYPASSRLS). Es la UNICA policy del rol sobre la tabla.
--   * USAGE sobre app y ops y SELECT de ops.db_catalog (una fila, sin PII): chequeos de arranque (startup-checks.ts resuelve app.staff_roster_invitation_status por nombre -> exige USAGE de app, y lee ops.db_catalog),
--     igual que 0058 para el reconciler (SEC-R6-1). Ningun otro privilegio sobre app ni ops.
-- Ningun INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER, ningun CREATE y ningun EXECUTE. No se crea ninguna funcion. No se modifican las policies existentes (todas son `TO <rol>` y no alcanzan al rol nuevo).
-- Idempotente: REVOKE ALL previo (revoca tambien los privilegios de columna), GRANT repetibles y DROP POLICY IF EXISTS + CREATE POLICY.

SET LOCAL ROLE integrity_owner;

REVOKE ALL ON integrity.audit_event FROM integrity_chain_verifier;
REVOKE ALL ON SCHEMA integrity FROM integrity_chain_verifier;
GRANT USAGE ON SCHEMA integrity TO integrity_chain_verifier;

GRANT SELECT (tenant_id, chain_seq, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, recorded_by_ref, cosigned_by_ref, idempotency_key_hash,
              occurred_at, environment, payload, payload_hash, previous_event_hash, event_hash)
  ON integrity.audit_event TO integrity_chain_verifier;

DROP POLICY IF EXISTS audit_event_chain_verifier_select ON integrity.audit_event;
CREATE POLICY audit_event_chain_verifier_select ON integrity.audit_event FOR SELECT TO integrity_chain_verifier USING (true);

SET LOCAL ROLE consent_owner;

REVOKE ALL ON SCHEMA app, ops FROM integrity_chain_verifier;
REVOKE ALL ON ops.db_catalog FROM integrity_chain_verifier;
GRANT USAGE ON SCHEMA app, ops TO integrity_chain_verifier;
GRANT SELECT ON ops.db_catalog TO integrity_chain_verifier;

-- Aserciones (fail-closed): estado exacto resultante (C1, C5).
DO $assert73$
DECLARE
  led oid;
  rid oid;
  col text;
  cnt int;
  rec record;
  chain_cols text[] := ARRAY['tenant_id', 'chain_seq', 'aggregate_type', 'aggregate_id', 'sequence', 'event_type', 'actor_type', 'actor_role', 'recorded_by_ref', 'cosigned_by_ref', 'idempotency_key_hash',
                             'occurred_at', 'environment', 'payload', 'payload_hash', 'previous_event_hash', 'event_hash'];
BEGIN
  SELECT r.oid INTO rid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_chain_verifier';
  IF rid IS NULL THEN RAISE EXCEPTION '0073: falta el rol integrity_chain_verifier (lo crea 0072)'; END IF;
  SELECT c.oid INTO led FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'audit_event';
  IF led IS NULL THEN RAISE EXCEPTION '0073: falta integrity.audit_event'; END IF;

  -- Esquemas: USAGE solo en integrity, app y ops (y public, que PostgreSQL concede a PUBLIC); ningun CREATE en ninguno.
  FOR rec IN SELECT n.nspname AS name FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' LOOP
    IF pg_catalog.has_schema_privilege('integrity_chain_verifier', rec.name, 'CREATE') THEN RAISE EXCEPTION '0073: integrity_chain_verifier tiene CREATE en %', rec.name; END IF;
    IF pg_catalog.has_schema_privilege('integrity_chain_verifier', rec.name, 'USAGE') AND rec.name NOT IN ('integrity', 'app', 'ops', 'public') THEN
      RAISE EXCEPTION '0073: integrity_chain_verifier tiene USAGE sobre el esquema % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_schema_privilege('integrity_chain_verifier', 'integrity', 'USAGE') OR NOT pg_catalog.has_schema_privilege('integrity_chain_verifier', 'app', 'USAGE')
     OR NOT pg_catalog.has_schema_privilege('integrity_chain_verifier', 'ops', 'USAGE') THEN
    RAISE EXCEPTION '0073: integrity_chain_verifier debe tener USAGE sobre integrity, app y ops';
  END IF;

  -- Columnas legibles de integrity.audit_event: EXACTAMENTE las 17 (sin event_id, evidentiary ni data_class), y ninguna con escritura/REFERENCES.
  FOR col IN SELECT a.attname FROM pg_catalog.pg_attribute a WHERE a.attrelid = led AND a.attnum > 0 AND NOT a.attisdropped LOOP
    IF pg_catalog.has_column_privilege('integrity_chain_verifier', led, col, 'SELECT') <> (col = ANY (chain_cols)) THEN
      RAISE EXCEPTION '0073: SELECT de integrity_chain_verifier sobre la columna % no coincide con las 17 de la cadena', col;
    END IF;
    IF pg_catalog.has_column_privilege('integrity_chain_verifier', led, col, 'INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION '0073: integrity_chain_verifier tiene escritura/REFERENCES en la columna %', col; END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid = led AND a.attnum > 0 AND NOT a.attisdropped AND a.attname = ANY (chain_cols)) <> 17 THEN
    RAISE EXCEPTION '0073: integrity.audit_event no tiene las 17 columnas de la cadena';
  END IF;
  IF pg_catalog.has_table_privilege('integrity_chain_verifier', led, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION '0073: integrity_chain_verifier tiene privilegios de escritura sobre integrity.audit_event';
  END IF;

  -- Policies que alcanzan al rol (nombradas, PUBLIC o RESTRICTIVE): exactamente 1, permisiva, SELECT, USING (true), sin WITH CHECK (C5). Una RESTRICTIVE filtraria tenants en silencio.
  SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND (0::oid = ANY (p.polroles) OR rid = ANY (p.polroles));
  IF cnt <> 1 THEN RAISE EXCEPTION '0073: integrity.audit_event debe tener exactamente 1 policy que alcance a integrity_chain_verifier (hay %)', cnt; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = led AND p.polname = 'audit_event_chain_verifier_select' AND p.polcmd = 'r' AND p.polpermissive
        AND pg_catalog.array_length(p.polroles, 1) = 1 AND p.polroles[1] = rid AND p.polwithcheck IS NULL AND pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true') <> 1 THEN
    RAISE EXCEPTION '0073: falta la policy audit_event_chain_verifier_select (permisiva, SELECT, TO integrity_chain_verifier, USING (true), sin WITH CHECK)';
  END IF;
  -- En todo el catalogo el rol aparece en UNA sola policy.
  SELECT pg_catalog.count(*) INTO cnt FROM pg_catalog.pg_policy p WHERE rid = ANY (p.polroles);
  IF cnt <> 1 THEN RAISE EXCEPTION '0073: integrity_chain_verifier debe aparecer en exactamente 1 policy (hay %)', cnt; END IF;
  -- RLS sigue ENABLE + FORCE y los triggers append-only siguen ENABLE ALWAYS (0027).
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = led) THEN RAISE EXCEPTION '0073: integrity.audit_event perdio RLS ENABLE/FORCE'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = led AND t.tgname LIKE 'audit_event\_no\_%' AND t.tgenabled = 'A') <> 2 THEN
    RAISE EXCEPTION '0073: los triggers append-only de integrity.audit_event deben seguir ENABLE ALWAYS';
  END IF;

  -- Relaciones de TODO esquema no de sistema: sin escritura en ninguna; SELECT solo en integrity.audit_event (las 17) y ops.db_catalog.
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name, c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') LOOP
    IF pg_catalog.has_table_privilege('integrity_chain_verifier', rec.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege('integrity_chain_verifier', rec.oid, 'INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0073: integrity_chain_verifier tiene privilegios de escritura sobre %', rec.name;
    END IF;
    IF rec.name NOT IN ('integrity.audit_event', 'ops.db_catalog')
       AND (pg_catalog.has_table_privilege('integrity_chain_verifier', rec.oid, 'SELECT') OR pg_catalog.has_any_column_privilege('integrity_chain_verifier', rec.oid, 'SELECT')) THEN
      RAISE EXCEPTION '0073: integrity_chain_verifier tiene SELECT sobre % (fuera de su alcance)', rec.name;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_table_privilege('integrity_chain_verifier', 'ops.db_catalog', 'SELECT') THEN RAISE EXCEPTION '0073: integrity_chain_verifier debe tener SELECT sobre ops.db_catalog'; END IF;
  -- Secuencias de todo esquema.
  FOR rec IN SELECT n.nspname || '.' || c.relname AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                AND CASE WHEN c.relkind = 'S' THEN pg_catalog.has_sequence_privilege('integrity_chain_verifier', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END LOOP
    RAISE EXCEPTION '0073: integrity_chain_verifier tiene privilegios sobre la secuencia %', rec.name;
  END LOOP;
  -- Sin EXECUTE de ninguna funcion fuera de pg_catalog (el chain-verifier solo lee; no hay aserciones, sesiones ni transiciones).
  FOR rec IN SELECT n.nspname || '.' || p.proname AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND pg_catalog.has_function_privilege('integrity_chain_verifier', p.oid, 'EXECUTE') LOOP
    RAISE EXCEPTION '0073: integrity_chain_verifier puede ejecutar %()', rec.name;
  END LOOP;
  -- P2(e)/G-9: ni el chain-verifier lee la identidad del principal.
  FOR rec IN SELECT c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relname = 'principal_identity' LOOP
    IF pg_catalog.has_any_column_privilege('integrity_chain_verifier', rec.oid, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION '0073: integrity_chain_verifier tiene privilegios sobre platform.principal_identity (P2(e))';
    END IF;
  END LOOP;

  -- Regresion de PR-6e: el reconciler sigue con EXACTAMENTE las 7 columnas de 0057 (sin payload, hashes ni refs de actor).
  FOR col IN SELECT a.attname FROM pg_catalog.pg_attribute a WHERE a.attrelid = led AND a.attnum > 0 AND NOT a.attisdropped LOOP
    IF pg_catalog.has_column_privilege('integrity_reconciler', led, col, 'SELECT') <> (col = ANY (ARRAY['tenant_id', 'aggregate_type', 'aggregate_id', 'sequence', 'event_type', 'chain_seq', 'occurred_at'])) THEN
      RAISE EXCEPTION '0073: el reconciler dejo de tener exactamente las 7 columnas aprobadas (columna %)', col;
    END IF;
  END LOOP;
  -- Ningun otro rol de runtime gano lectura del ledger: integrity_verifier (OIDC; SEC-06-1) y platform_rw siguen sin SELECT.
  IF pg_catalog.has_any_column_privilege('integrity_verifier', led, 'SELECT') OR pg_catalog.has_any_column_privilege('platform_rw', led, 'SELECT') THEN
    RAISE EXCEPTION '0073: integrity_verifier o platform_rw tienen SELECT sobre integrity.audit_event';
  END IF;
END
$assert73$;
