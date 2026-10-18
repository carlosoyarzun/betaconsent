-- scope: database
-- Gobierna: ADR-010 rev. 6 §1 (integrity_chain_verifier: antes "DML de ningun tipo"; desde PR-7b solo INSERT en chain_run/chain_checkpoint), rev. 5 §2 (integrity_reconciler), §4.5.5 (integrity_anchor_signer), plan PR-7 v3 (PR-7b: "ACL exacta
-- por rol"; "ningun otro rol gana INSERT"); specs/db-roles.spec.yaml (INV-DBR-01, INV-DBR-02). Sin DDL: SOLO aserciones transversales de los tres roles de integridad sobre TODO el catalogo (fail-closed), despues de 0076-0078.
-- 0073 asierta "SELECT/escritura solo donde corresponde" una vez, en el momento de migrar (no vuelve a correr): esta migracion la reemplaza como aserción vigente para el chain-verifier tras abrir las dos excepciones.

DO $assert79$
DECLARE
  rec record;
  r text;
  got text;
  want text;
BEGIN
  -- Matriz esperada por rol: relaciones con INSERT (cualquier columna) y con SELECT (cualquier columna). Todo lo demas, en CUALQUIER esquema no de sistema, debe estar denegado.
  FOREACH r IN ARRAY ARRAY['integrity_chain_verifier', 'integrity_reconciler', 'integrity_anchor_signer'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles x WHERE x.rolname = r) THEN RAISE EXCEPTION '0079: falta el rol %', r; END IF;
    FOR rec IN SELECT n.nspname || '.' || c.relname AS name, c.oid AS oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') LOOP
      IF pg_catalog.has_table_privilege(r, rec.oid, 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege(r, rec.oid, 'UPDATE,REFERENCES') THEN
        RAISE EXCEPTION '0079: % tiene UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER sobre %', r, rec.name;
      END IF;
      want := CASE
        WHEN r = 'integrity_chain_verifier' AND rec.name IN ('integrity.chain_run', 'integrity.chain_checkpoint') THEN 'INSERT'
        WHEN r = 'integrity_reconciler' AND rec.name = 'integrity.reconcile_run' THEN 'INSERT'
        WHEN r = 'integrity_anchor_signer' AND rec.name = 'integrity.anchor' THEN 'INSERT'
        ELSE '-' END;
      got := CASE WHEN pg_catalog.has_any_column_privilege(r, rec.oid, 'INSERT') THEN 'INSERT' ELSE '-' END;
      IF got <> want THEN RAISE EXCEPTION '0079: INSERT de % sobre % no coincide con lo esperado (esperado %, hay %)', r, rec.name, want, got; END IF;
      -- SELECT: matriz exacta para el chain-verifier y el firmante. El reconciler lee las tablas de estado concedidas en 0057/0058 (lista exacta asertada alli): aqui solo se exige que NO lea las tablas nuevas.
      IF r = 'integrity_reconciler' THEN
        IF rec.name IN ('integrity.chain_run', 'integrity.chain_checkpoint', 'integrity.reconcile_run', 'integrity.anchor') AND pg_catalog.has_any_column_privilege(r, rec.oid, 'SELECT') THEN
          RAISE EXCEPTION '0079: integrity_reconciler tiene SELECT sobre %', rec.name;
        END IF;
      ELSE
        want := CASE
          WHEN r = 'integrity_chain_verifier' AND rec.name IN ('integrity.audit_event', 'ops.db_catalog', 'integrity.chain_checkpoint') THEN 'SELECT'
          WHEN r = 'integrity_anchor_signer' AND rec.name IN ('integrity.chain_run', 'integrity.chain_checkpoint', 'integrity.anchor') THEN 'SELECT'
          ELSE '-' END;
        got := CASE WHEN pg_catalog.has_any_column_privilege(r, rec.oid, 'SELECT') THEN 'SELECT' ELSE '-' END;
        IF got <> want THEN RAISE EXCEPTION '0079: SELECT de % sobre % no coincide con lo esperado (esperado %, hay %)', r, rec.name, want, got; END IF;
      END IF;
    END LOOP;
    -- Sin secuencias ni EXECUTE fuera de pg_catalog; sin CREATE en ningun esquema.
    FOR rec IN SELECT n.nspname || '.' || c.relname AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND CASE WHEN c.relkind = 'S' THEN pg_catalog.has_sequence_privilege(r, c.oid, 'USAGE,SELECT,UPDATE') ELSE false END LOOP
      RAISE EXCEPTION '0079: % tiene privilegios sobre la secuencia %', r, rec.name;
    END LOOP;
    FOR rec IN SELECT n.nspname || '.' || p.proname AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND pg_catalog.has_function_privilege(r, p.oid, 'EXECUTE') LOOP
      RAISE EXCEPTION '0079: % puede ejecutar %()', r, rec.name;
    END LOOP;
    FOR rec IN SELECT n.nspname AS name FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND pg_catalog.has_schema_privilege(r, n.oid, 'CREATE') LOOP
      RAISE EXCEPTION '0079: % tiene CREATE en el esquema %', r, rec.name;
    END LOOP;
  END LOOP;
  -- El firmante no toca el ledger (la raiz la calcula el chain-verifier) ni el estado de dominio.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'integrity' AND c.relname = 'audit_event' AND pg_catalog.has_any_column_privilege('integrity_anchor_signer', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')) THEN
    RAISE EXCEPTION '0079: integrity_anchor_signer tiene privilegios sobre integrity.audit_event';
  END IF;
  IF pg_catalog.has_schema_privilege('integrity_anchor_signer', 'app', 'USAGE') OR pg_catalog.has_schema_privilege('integrity_anchor_signer', 'ops', 'USAGE') THEN
    RAISE EXCEPTION '0079: integrity_anchor_signer tiene USAGE sobre app u ops';
  END IF;
  -- Ningun otro rol de runtime gano escritura en integrity.* nuevo (la ACL exacta de cada tabla la asierta su migracion; aqui el cruce por rol de runtime).
  FOREACH r IN ARRAY ARRAY['app_rw', 'worker', 'platform_rw', 'integrity_verifier'] LOOP
    FOR rec IN SELECT c.relname AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'integrity' AND c.relname IN ('chain_run', 'chain_checkpoint', 'reconcile_run', 'anchor')
                  AND (pg_catalog.has_table_privilege(r, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege(r, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')) LOOP
      RAISE EXCEPTION '0079: % tiene privilegios sobre integrity.%', r, rec.name;
    END LOOP;
  END LOOP;
END
$assert79$;
