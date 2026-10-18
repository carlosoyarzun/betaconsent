-- scope: database
-- Gobierna: ADR-010 rev. 6 §3 (fila PR-7: persistencia de checkpoints y cabeza por tenant por el chain-verifier; el calculo de la raiz pasa al chain-verifier), §4.5.1 (DDL de integrity.* como integrity_owner antes del revoke),
-- F-PR6E-05 (deteccion de truncamiento de cola), D-1 (b), D-3; plan PR-7 v3 (PR-7b, T-2, T-3, T-4, T-6); C-10 (Carlos, 2026-10-16); specs/db-roles.spec.yaml (integrity_chain_verifier, integrity_anchor_signer).
-- 0072/0073 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva. 0075 (cluster) crea integrity_anchor_signer.
--
-- Tablas del chain-verifier (dueno integrity_owner; sin tenant_id en chain_run; sin PII: tenant = colegio, hashes y conteos):
--   integrity.chain_run         una fila por corrida (exit 0 o 2). merkle_root y merkle_format SOLO si exit_code = 0 (CHECK). El run_id lo genera el cliente: el verifier solo INSERTA (sin RETURNING, sin SELECT).
--   integrity.chain_checkpoint  una fila por tenant verificado OK y por corrida: cabeza (chain_seq, event_hash). Un trigger BEFORE INSERT valida contra el ledger (la cabeza existe con ese hash) y contra el checkpoint
--                               anterior del tenant (nunca regresa; igual seq => igual hash): un chain-verifier comprometido no puede plantar cabezas falsas ni retroceder.
--   SEC-7D-09: un CONSTRAINT TRIGGER DEFERRABLE INITIALLY DEFERRED sobre chain_run (se evalua al COMMIT, con los checkpoints de la misma tx) exige, para exit_code = 0, un checkpoint del run por CADA tenant del ledger
--                               cuya genesis (chain_seq = 1) tenga occurred_at <= started_at, y leaf_count = count(checkpoints del run): un run que omite un tenant (viejo o nuevo) no queda como verde.
--   SEC-7D-09 (endurecido): BEFORE INSERT `chain_run_started_guard` (SECURITY DEFINER de integrity_owner, que lee chain_run por una policy propia; el verifier sigue sin SELECT): started_at dentro de
--                               [clock_timestamp() - 15 min, clock_timestamp()] (reloj real, no el de la tx: una tx abierta antes de una genesis no puede confirmar mucho despues) y estrictamente mayor que el de todo run previo (serializa los inserts con LOCK SHARE ROW EXCLUSIVE). El guard diferido
--                               ademas exige checkpoint para todo tenant que ya tuvo alguno en un run anterior (sin depender de started_at) y leaf_count >= 1 si el ledger tiene alguna genesis.
-- Ambas: append-only (triggers ENABLE ALWAYS: tambien para el superusuario y con session_replication_role = replica), RLS ENABLE + FORCE, sin purga (T-4).
--   * integrity_chain_verifier: INSERT por columnas en chain_run (sin finished_at: lo fija la base) y en chain_checkpoint (sin recorded_at); SELECT de chain_checkpoint (policy unica cross-tenant); NADA sobre chain_run salvo INSERT.
--   * integrity_anchor_signer (NOLOGIN hasta PR-7f): SELECT por columnas de chain_run (raiz) y de chain_checkpoint (cabezas que se publican). Sin ningun privilegio sobre integrity.audit_event (rev. 6: la raiz la calcula el chain-verifier).
-- Las funciones de trigger son SECURITY INVOKER (corren con los privilegios de quien inserta: el verifier ya lee el ledger por su policy): no requieren EXECUTE ni se concede EXECUTE a nadie (PUBLIC revocado).
-- Se aplica una vez (registro del runner); las aserciones fallan cerrado.

SET LOCAL ROLE integrity_owner;

CREATE FUNCTION integrity.append_only_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'integrity.% es append-only (ADR-010 rev. 6, PR-7b)', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
REVOKE ALL ON FUNCTION integrity.append_only_guard() FROM PUBLIC;

CREATE TABLE integrity.chain_run (
  run_id        uuid        NOT NULL CONSTRAINT chain_run_pkey PRIMARY KEY,
  started_at    timestamptz NOT NULL,
  finished_at   timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  environment   text        NOT NULL CONSTRAINT chain_run_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  tenants       integer     NOT NULL CONSTRAINT chain_run_tenants_nonneg CHECK (tenants >= 0),
  events        bigint      NOT NULL CONSTRAINT chain_run_events_nonneg CHECK (events >= 0),
  exit_code     smallint    NOT NULL CONSTRAINT chain_run_exit_code_enum CHECK (exit_code IN (0, 2)),
  leaf_count    integer     NOT NULL CONSTRAINT chain_run_leaf_count_nonneg CHECK (leaf_count >= 0),
  merkle_root   text        CONSTRAINT chain_run_merkle_root_shape CHECK (merkle_root ~ '^[0-9a-f]{64}$'),
  merkle_format text        CONSTRAINT chain_run_merkle_format_shape CHECK (merkle_format ~ '^[A-Za-z0-9._-]{1,40}$'),
  CONSTRAINT chain_run_root_only_if_ok CHECK ((exit_code = 0) = (merkle_root IS NOT NULL) AND (merkle_root IS NULL) = (merkle_format IS NULL)),
  CONSTRAINT chain_run_leaf_count_bounds CHECK (leaf_count <= tenants AND (exit_code = 0 OR leaf_count = 0))
);

CREATE TABLE integrity.chain_checkpoint (
  run_id          uuid        NOT NULL CONSTRAINT chain_checkpoint_run_fk REFERENCES integrity.chain_run (run_id),
  tenant_id       uuid        NOT NULL,
  head_chain_seq  bigint      NOT NULL CONSTRAINT chain_checkpoint_head_positive CHECK (head_chain_seq >= 1),
  head_event_hash text        NOT NULL CONSTRAINT chain_checkpoint_head_hash_shape CHECK (head_event_hash ~ '^[0-9a-f]{64}$'),
  verified_events bigint      NOT NULL CONSTRAINT chain_checkpoint_verified_bounds CHECK (verified_events >= 1 AND verified_events <= head_chain_seq),
  recorded_at     timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  CONSTRAINT chain_checkpoint_pkey PRIMARY KEY (run_id, tenant_id)
);
CREATE INDEX chain_checkpoint_tenant_head_idx ON integrity.chain_checkpoint (tenant_id, head_chain_seq DESC);

-- Valida la cabeza contra el ledger y contra el checkpoint anterior (T-2). SECURITY INVOKER: lee con los privilegios del verifier (17 columnas + policy cross-tenant; SELECT de chain_checkpoint).
CREATE FUNCTION integrity.chain_checkpoint_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM integrity.audit_event e WHERE e.tenant_id = NEW.tenant_id AND e.chain_seq = NEW.head_chain_seq AND e.event_hash = NEW.head_event_hash) THEN
    RAISE EXCEPTION 'integrity.chain_checkpoint: la cabeza no existe en el ledger con ese hash' USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM integrity.chain_checkpoint c
              WHERE c.tenant_id = NEW.tenant_id AND (c.head_chain_seq > NEW.head_chain_seq OR (c.head_chain_seq = NEW.head_chain_seq AND c.head_event_hash <> NEW.head_event_hash))) THEN
    RAISE EXCEPTION 'integrity.chain_checkpoint: la cabeza no puede retroceder ni cambiar de hash con la misma secuencia' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION integrity.chain_checkpoint_guard() FROM PUBLIC;

CREATE TRIGGER chain_checkpoint_guard BEFORE INSERT ON integrity.chain_checkpoint FOR EACH ROW EXECUTE FUNCTION integrity.chain_checkpoint_guard();
CREATE TRIGGER chain_run_no_update_delete BEFORE UPDATE OR DELETE ON integrity.chain_run FOR EACH ROW EXECUTE FUNCTION integrity.append_only_guard();
CREATE TRIGGER chain_run_no_truncate BEFORE TRUNCATE ON integrity.chain_run FOR EACH STATEMENT EXECUTE FUNCTION integrity.append_only_guard();
CREATE TRIGGER chain_checkpoint_no_update_delete BEFORE UPDATE OR DELETE ON integrity.chain_checkpoint FOR EACH ROW EXECUTE FUNCTION integrity.append_only_guard();
CREATE TRIGGER chain_checkpoint_no_truncate BEFORE TRUNCATE ON integrity.chain_checkpoint FOR EACH STATEMENT EXECUTE FUNCTION integrity.append_only_guard();
-- SEC-7D-09: cota y monotonia de started_at. SECURITY DEFINER (dueno integrity_owner, search_path fijo) porque el verifier no puede leer chain_run; la policy chain_run_owner_select permite al dueno (FORCE RLS) verlo.
-- Se usa clock_timestamp() (no transaction_timestamp()): un verifier no puede abrir la tx antes de una genesis y confirmar mucho despues con un started_at viejo. El started_at lo declara el cliente y la persistencia corre en otra tx despues de la instantanea: por eso es una cota (no un DEFAULT).
CREATE FUNCTION integrity.chain_run_started_guard() RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  LOCK TABLE integrity.chain_run IN SHARE ROW EXCLUSIVE MODE;
  IF NEW.started_at > pg_catalog.clock_timestamp() OR NEW.started_at < pg_catalog.clock_timestamp() - INTERVAL '15 minutes' THEN
    RAISE EXCEPTION 'integrity.chain_run: started_at fuera de la cota (clock_timestamp() - 15 min, clock_timestamp())' USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM integrity.chain_run r WHERE r.started_at >= NEW.started_at) THEN
    RAISE EXCEPTION 'integrity.chain_run: started_at debe ser mayor que el de todo run previo' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION integrity.chain_run_started_guard() FROM PUBLIC;
CREATE TRIGGER chain_run_started_guard BEFORE INSERT ON integrity.chain_run FOR EACH ROW EXECUTE FUNCTION integrity.chain_run_started_guard();
ALTER TABLE integrity.chain_run ENABLE ALWAYS TRIGGER chain_run_started_guard;
CREATE POLICY chain_run_owner_select ON integrity.chain_run FOR SELECT TO integrity_owner USING (true);

-- SEC-7D-09: completitud del run exit 0 (se evalua al COMMIT: el run se inserta antes que sus checkpoints en la misma tx). SECURITY INVOKER: el verifier lee el ledger (policy cross-tenant) y chain_checkpoint.
CREATE FUNCTION integrity.chain_run_complete_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF NEW.exit_code = 0 THEN
    IF EXISTS (SELECT 1 FROM integrity.audit_event e
                WHERE e.chain_seq = 1 AND e.occurred_at <= NEW.started_at
                  AND NOT EXISTS (SELECT 1 FROM integrity.chain_checkpoint c WHERE c.run_id = NEW.run_id AND c.tenant_id = e.tenant_id)) THEN
      RAISE EXCEPTION 'integrity.chain_run: un run exit 0 debe llevar un checkpoint por cada tenant del ledger con genesis <= started_at' USING ERRCODE = 'check_violation';
    END IF;
    -- Sin depender de started_at: todo tenant que ya tuvo un checkpoint en un run anterior debe tenerlo tambien aqui.
    IF EXISTS (SELECT 1 FROM integrity.chain_checkpoint p
                WHERE p.run_id <> NEW.run_id
                  AND NOT EXISTS (SELECT 1 FROM integrity.chain_checkpoint c WHERE c.run_id = NEW.run_id AND c.tenant_id = p.tenant_id)) THEN
      RAISE EXCEPTION 'integrity.chain_run: un run exit 0 debe llevar checkpoint de todo tenant que ya tuvo alguno' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.leaf_count <> (SELECT pg_catalog.count(*) FROM integrity.chain_checkpoint c WHERE c.run_id = NEW.run_id) THEN
      RAISE EXCEPTION 'integrity.chain_run: leaf_count debe ser igual a los checkpoints del run' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.leaf_count < 1 AND EXISTS (SELECT 1 FROM integrity.audit_event e WHERE e.chain_seq = 1) THEN
      RAISE EXCEPTION 'integrity.chain_run: el ledger tiene genesis: un run exit 0 exige leaf_count >= 1' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION integrity.chain_run_complete_guard() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER chain_run_complete_guard AFTER INSERT ON integrity.chain_run DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION integrity.chain_run_complete_guard();
ALTER TABLE integrity.chain_run ENABLE ALWAYS TRIGGER chain_run_complete_guard;
ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_guard;
ALTER TABLE integrity.chain_run ENABLE ALWAYS TRIGGER chain_run_no_update_delete;
ALTER TABLE integrity.chain_run ENABLE ALWAYS TRIGGER chain_run_no_truncate;
ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_no_update_delete;
ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_no_truncate;

ALTER TABLE integrity.chain_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.chain_run FORCE ROW LEVEL SECURITY;
ALTER TABLE integrity.chain_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.chain_checkpoint FORCE ROW LEVEL SECURITY;

-- Policies cross-tenant a proposito (los roles son NOBYPASSRLS; las tablas no llevan datos del titular). Una por rol y comando.
CREATE POLICY chain_run_verifier_insert ON integrity.chain_run FOR INSERT TO integrity_chain_verifier WITH CHECK (true);
CREATE POLICY chain_run_signer_select ON integrity.chain_run FOR SELECT TO integrity_anchor_signer USING (true);
CREATE POLICY chain_checkpoint_verifier_insert ON integrity.chain_checkpoint FOR INSERT TO integrity_chain_verifier WITH CHECK (true);
CREATE POLICY chain_checkpoint_verifier_select ON integrity.chain_checkpoint FOR SELECT TO integrity_chain_verifier USING (true);
CREATE POLICY chain_checkpoint_signer_select ON integrity.chain_checkpoint FOR SELECT TO integrity_anchor_signer USING (true);

REVOKE ALL ON integrity.chain_run, integrity.chain_checkpoint FROM PUBLIC;
GRANT INSERT (run_id, started_at, environment, tenants, events, exit_code, leaf_count, merkle_root, merkle_format) ON integrity.chain_run TO integrity_chain_verifier;
GRANT INSERT (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) ON integrity.chain_checkpoint TO integrity_chain_verifier;
GRANT SELECT ON integrity.chain_checkpoint TO integrity_chain_verifier;
GRANT USAGE ON SCHEMA integrity TO integrity_anchor_signer;
GRANT SELECT (run_id, finished_at, environment, exit_code, leaf_count, merkle_root, merkle_format) ON integrity.chain_run TO integrity_anchor_signer;
GRANT SELECT (run_id, tenant_id, head_chain_seq, head_event_hash) ON integrity.chain_checkpoint TO integrity_anchor_signer;

-- Aserciones (fail-closed): ACL EXACTA por columna (incluye PUBLIC), dueno, RLS, policies y triggers ENABLE ALWAYS. La aserción cruzada con el resto de roles es 0079.
DO $assert76$
DECLARE
  expect_run text[] := ARRAY[
    'integrity_chain_verifier:INSERT:run_id', 'integrity_chain_verifier:INSERT:started_at', 'integrity_chain_verifier:INSERT:environment', 'integrity_chain_verifier:INSERT:tenants', 'integrity_chain_verifier:INSERT:events',
    'integrity_chain_verifier:INSERT:exit_code', 'integrity_chain_verifier:INSERT:leaf_count', 'integrity_chain_verifier:INSERT:merkle_root', 'integrity_chain_verifier:INSERT:merkle_format',
    'integrity_anchor_signer:SELECT:run_id', 'integrity_anchor_signer:SELECT:finished_at', 'integrity_anchor_signer:SELECT:environment', 'integrity_anchor_signer:SELECT:exit_code', 'integrity_anchor_signer:SELECT:leaf_count',
    'integrity_anchor_signer:SELECT:merkle_root', 'integrity_anchor_signer:SELECT:merkle_format'];
  expect_ckp text[] := ARRAY[
    'integrity_chain_verifier:INSERT:run_id', 'integrity_chain_verifier:INSERT:tenant_id', 'integrity_chain_verifier:INSERT:head_chain_seq', 'integrity_chain_verifier:INSERT:head_event_hash', 'integrity_chain_verifier:INSERT:verified_events',
    'integrity_chain_verifier:SELECT:*',
    'integrity_anchor_signer:SELECT:run_id', 'integrity_anchor_signer:SELECT:tenant_id', 'integrity_anchor_signer:SELECT:head_chain_seq', 'integrity_anchor_signer:SELECT:head_event_hash'];
  t text;
  expected text[];
  actual text[];
  rel oid;
BEGIN
  FOREACH t IN ARRAY ARRAY['chain_run', 'chain_checkpoint'] LOOP
    SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = t;
    IF rel IS NULL THEN RAISE EXCEPTION '0076: falta integrity.%', t; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = rel AND pg_catalog.pg_get_userbyid(c.relowner) = 'integrity_owner' AND c.relrowsecurity AND c.relforcerowsecurity) THEN
      RAISE EXCEPTION '0076: integrity.% debe ser de integrity_owner con RLS ENABLE + FORCE', t;
    END IF;
    expected := CASE t WHEN 'chain_run' THEN expect_run ELSE expect_ckp END;
    SELECT COALESCE(pg_catalog.array_agg(x.item ORDER BY x.item COLLATE "C"), ARRAY[]::text[]) INTO actual FROM (
      SELECT pg_catalog.format('%s:%s:*', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type) AS item
        FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE c.oid = rel AND a.grantee <> c.relowner
      UNION ALL
      SELECT pg_catalog.format('%s:%s:%s', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, at.attname)
        FROM pg_catalog.pg_attribute at, LATERAL pg_catalog.aclexplode(at.attacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE at.attrelid = rel AND at.attnum > 0 AND NOT at.attisdropped) x;
    IF actual IS DISTINCT FROM (SELECT pg_catalog.array_agg(e ORDER BY e COLLATE "C") FROM pg_catalog.unnest(expected) e) THEN
      RAISE EXCEPTION '0076: ACL de integrity.% distinta de la esperada (hay %)', t, actual;
    END IF;
  END LOOP;
  -- Policies: exactamente las 3 de chain_run y las 3 de chain_checkpoint, permisivas, de un solo rol.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'chain_run') <> 3
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'chain_checkpoint') <> 3
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'integrity' AND c.relname IN ('chain_run', 'chain_checkpoint') AND (NOT p.polpermissive OR pg_catalog.array_length(p.polroles, 1) <> 1 OR 0::oid = ANY (p.polroles))) THEN
    RAISE EXCEPTION '0076: policies de chain_run/chain_checkpoint distintas de las esperadas';
  END IF;
  -- Triggers append-only y de validacion: ENABLE ALWAYS.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class c ON c.oid = tg.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE NOT tg.tgisinternal AND tg.tgenabled = 'A' AND n.nspname = 'integrity' AND c.relname IN ('chain_run', 'chain_checkpoint')) <> 7
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger tg WHERE tg.tgrelid = 'integrity.chain_run'::regclass AND tg.tgname = 'chain_run_complete_guard' AND tg.tgdeferrable AND tg.tginitdeferred) THEN
    RAISE EXCEPTION '0076: los 7 triggers (chain_run_complete_guard DEFERRABLE INITIALLY DEFERRED) de chain_run/chain_checkpoint deben ser ENABLE ALWAYS';
  END IF;
  -- Funciones: de integrity_owner, SECURITY INVOKER (salvo chain_run_started_guard: DEFINER, search_path fijo), sin EXECUTE para nadie mas.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'integrity' AND p.proname IN ('append_only_guard', 'chain_checkpoint_guard', 'chain_run_complete_guard', 'chain_run_started_guard') AND ((p.prosecdef <> (p.proname = 'chain_run_started_guard')) OR pg_catalog.pg_get_userbyid(p.proowner) <> 'integrity_owner'
                OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a WHERE a.grantee <> p.proowner))) THEN
    RAISE EXCEPTION '0076: las funciones de trigger deben ser SECURITY INVOKER, de integrity_owner y sin EXECUTE para otros roles';
  END IF;
END
$assert76$;

SET LOCAL ROLE consent_owner;
