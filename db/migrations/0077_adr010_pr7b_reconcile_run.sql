-- scope: database
-- Gobierna: ADR-010 rev. 5 §4.2.c y §7 ("persistencia de la conciliacion", hasta PR-7 solo exit code y log), rev. 6 §3 (fila PR-7), plan PR-7 v3 (PR-7b, T-4); specs/db-roles.spec.yaml (integrity_reconciler, INV-DBR-08).
-- 0056-0058 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- integrity.reconcile_run (dueno integrity_owner): una fila por corrida del reconciler (exit 0 o 2) con CONTEOS por codigo de divergencia. SIN ids de agregado, SIN tenant, SIN detail, SIN PII: solo el enum de divergencia
-- (DivergenceKind: [A-Z_]{1,40}) y cuantas hubo. Append-only (triggers ENABLE ALWAYS), RLS ENABLE + FORCE, sin purga (T-4).
--   * integrity_reconciler: INSERT por columnas (sin finished_at) y NADA mas sobre la tabla (sin SELECT: no hay RETURNING; el run_id lo genera el cliente). Policy INSERT TO integrity_reconciler WITH CHECK (true).
--     Ningun otro rol tiene privilegio alguno sobre la tabla. El reconciler sigue SIN privilegios de escritura sobre cualquier otra relacion y con las 7 columnas del ledger de 0057.
-- El trigger de validacion es SECURITY INVOKER (sin EXECUTE para nadie): claves = enum [A-Z_]{1,40}, valores = enteros >= 1, suma = divergences.

SET LOCAL ROLE integrity_owner;

CREATE TABLE integrity.reconcile_run (
  run_id              uuid        NOT NULL CONSTRAINT reconcile_run_pkey PRIMARY KEY,
  started_at          timestamptz NOT NULL,
  finished_at         timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  environment         text        NOT NULL CONSTRAINT reconcile_run_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  tenants             integer     NOT NULL CONSTRAINT reconcile_run_tenants_nonneg CHECK (tenants >= 0),
  events              bigint      NOT NULL CONSTRAINT reconcile_run_events_nonneg CHECK (events >= 0),
  divergences         integer     NOT NULL CONSTRAINT reconcile_run_divergences_nonneg CHECK (divergences >= 0),
  divergences_by_code jsonb       NOT NULL CONSTRAINT reconcile_run_by_code_object CHECK (pg_catalog.jsonb_typeof(divergences_by_code) = 'object'),
  exit_code           smallint    NOT NULL CONSTRAINT reconcile_run_exit_code_enum CHECK (exit_code IN (0, 2)),
  CONSTRAINT reconcile_run_exit_matches_divergences CHECK ((exit_code = 0) = (divergences = 0))
);

CREATE FUNCTION integrity.reconcile_run_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  total bigint := 0;
  item record;
BEGIN
  FOR item IN SELECT j.key AS k, j.value AS v FROM pg_catalog.jsonb_each(NEW.divergences_by_code) AS j LOOP
    IF item.k !~ '^[A-Z_]{1,40}$' OR pg_catalog.jsonb_typeof(item.v) <> 'number' OR item.v::text !~ '^[1-9][0-9]{0,8}$' THEN
      RAISE EXCEPTION 'integrity.reconcile_run: divergences_by_code solo admite codigos [A-Z_]{1,40} con conteos enteros >= 1' USING ERRCODE = 'check_violation';
    END IF;
    total := total + (item.v::text)::bigint;
  END LOOP;
  IF total <> NEW.divergences THEN
    RAISE EXCEPTION 'integrity.reconcile_run: la suma de divergences_by_code no coincide con divergences' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION integrity.reconcile_run_guard() FROM PUBLIC;

CREATE TRIGGER reconcile_run_guard BEFORE INSERT ON integrity.reconcile_run FOR EACH ROW EXECUTE FUNCTION integrity.reconcile_run_guard();
CREATE TRIGGER reconcile_run_no_update_delete BEFORE UPDATE OR DELETE ON integrity.reconcile_run FOR EACH ROW EXECUTE FUNCTION integrity.append_only_guard();
CREATE TRIGGER reconcile_run_no_truncate BEFORE TRUNCATE ON integrity.reconcile_run FOR EACH STATEMENT EXECUTE FUNCTION integrity.append_only_guard();
ALTER TABLE integrity.reconcile_run ENABLE ALWAYS TRIGGER reconcile_run_guard;
ALTER TABLE integrity.reconcile_run ENABLE ALWAYS TRIGGER reconcile_run_no_update_delete;
ALTER TABLE integrity.reconcile_run ENABLE ALWAYS TRIGGER reconcile_run_no_truncate;

ALTER TABLE integrity.reconcile_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.reconcile_run FORCE ROW LEVEL SECURITY;
CREATE POLICY reconcile_run_reconciler_insert ON integrity.reconcile_run FOR INSERT TO integrity_reconciler WITH CHECK (true);

REVOKE ALL ON integrity.reconcile_run FROM PUBLIC;
GRANT INSERT (run_id, started_at, environment, tenants, events, divergences, divergences_by_code, exit_code) ON integrity.reconcile_run TO integrity_reconciler;

DO $assert77$
DECLARE
  rel oid;
  expected text[] := ARRAY['integrity_reconciler:INSERT:run_id', 'integrity_reconciler:INSERT:started_at', 'integrity_reconciler:INSERT:environment', 'integrity_reconciler:INSERT:tenants', 'integrity_reconciler:INSERT:events',
                           'integrity_reconciler:INSERT:divergences', 'integrity_reconciler:INSERT:divergences_by_code', 'integrity_reconciler:INSERT:exit_code'];
  actual text[];
BEGIN
  SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'reconcile_run';
  IF rel IS NULL THEN RAISE EXCEPTION '0077: falta integrity.reconcile_run'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = rel AND pg_catalog.pg_get_userbyid(c.relowner) = 'integrity_owner' AND c.relrowsecurity AND c.relforcerowsecurity) THEN
    RAISE EXCEPTION '0077: integrity.reconcile_run debe ser de integrity_owner con RLS ENABLE + FORCE';
  END IF;
  SELECT COALESCE(pg_catalog.array_agg(x.item ORDER BY x.item COLLATE "C"), ARRAY[]::text[]) INTO actual FROM (
    SELECT pg_catalog.format('%s:%s:*', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type) AS item
      FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE c.oid = rel AND a.grantee <> c.relowner
    UNION ALL
    SELECT pg_catalog.format('%s:%s:%s', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, at.attname)
      FROM pg_catalog.pg_attribute at, LATERAL pg_catalog.aclexplode(at.attacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE at.attrelid = rel AND at.attnum > 0 AND NOT at.attisdropped) x;
  IF actual IS DISTINCT FROM (SELECT pg_catalog.array_agg(e ORDER BY e COLLATE "C") FROM pg_catalog.unnest(expected) e) THEN
    RAISE EXCEPTION '0077: ACL de integrity.reconcile_run distinta de la esperada (hay %)', actual;
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rel) <> 1
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rel AND p.polname = 'reconcile_run_reconciler_insert' AND p.polcmd = 'a' AND p.polpermissive
                      AND pg_catalog.array_length(p.polroles, 1) = 1 AND p.polroles[1] = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_reconciler')) THEN
    RAISE EXCEPTION '0077: integrity.reconcile_run debe tener exactamente la policy de INSERT del reconciler';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger tg WHERE NOT tg.tgisinternal AND tg.tgenabled = 'A' AND tg.tgrelid = rel) <> 3 THEN
    RAISE EXCEPTION '0077: los 3 triggers de integrity.reconcile_run deben ser ENABLE ALWAYS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'integrity' AND p.proname = 'reconcile_run_guard' AND (p.prosecdef OR pg_catalog.pg_get_userbyid(p.proowner) <> 'integrity_owner'
                OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a WHERE a.grantee <> p.proowner))) THEN
    RAISE EXCEPTION '0077: reconcile_run_guard debe ser SECURITY INVOKER, de integrity_owner y sin EXECUTE para otros roles';
  END IF;
END
$assert77$;

SET LOCAL ROLE consent_owner;
