-- scope: database
-- Gobierna: ADR-010 rev. 6 §4.5.5 y fila PR-7 de §3 (ancla Merkle + puerto AnchorStore; la firma Ed25519 y la publicacion NO son del chain-verifier: F-R6-1, PROPUESTO), plan PR-7 v3 (PR-7b: "toda la DDL de integrity.*
-- que queda antes del revoke va aqui"; formato agnostico para no depender de F-R6-1; T-4, T-6, T-17, F-PR7-14); C-7 de Carlos PENDIENTE: ESTA migracion NO implementa firma ni publicacion, solo la bitacora local encadenada.
--
-- integrity.anchor (dueno integrity_owner): bitacora LOCAL de anclas, append-only (triggers ENABLE ALWAYS), RLS ENABLE + FORCE, sin purga. NO tiene valor de evidencia por si sola (F-PR7-14): el superusuario puede reescribirla; el valor
-- esta en la publicacion externa (PR-7f), y toda verificacion contra el ancla debe leer el AnchorStore externo, nunca esta tabla. Columnas genericas (el formato de firma y el algoritmo los fija PR-7f/ADR-011):
--   anchor_seq (1, 2, ...), created_at (de la base), environment, run_id (chain_run exit 0 cuya raiz se ancla), leaf_count, merkle_root, prev_anchor_hash (NULL solo en la primera), anchor_hash (hash del registro, lo calcula el
--   firmante), key_id, signature (texto: base64/base64url), format_version.
-- Trigger BEFORE INSERT (SECURITY INVOKER; corre con los privilegios del firmante): (1) merkle_root, leaf_count y environment deben ser EXACTAMENTE los de la chain_run exit 0 referida (un firmante comprometido no puede
-- firmar una raiz que el chain-verifier no calculo); (2) encadenamiento: anchor_seq = ultima + 1 y prev_anchor_hash = anchor_hash de la ultima (la primera: seq 1 y prev NULL). El PK impide bifurcaciones.
--   * integrity_anchor_signer (NOLOGIN hasta PR-7f): SELECT de la tabla y INSERT por columnas (sin created_at). Ningun otro rol tiene privilegio alguno sobre ella. Sin ningun privilegio sobre integrity.audit_event.

SET LOCAL ROLE integrity_owner;

CREATE TABLE integrity.anchor (
  anchor_seq       bigint      NOT NULL CONSTRAINT anchor_pkey PRIMARY KEY CONSTRAINT anchor_seq_positive CHECK (anchor_seq >= 1),
  created_at       timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  environment      text        NOT NULL CONSTRAINT anchor_environment_enum CHECK (environment IN ('LOCAL', 'DEV', 'STAGING', 'PRODUCTION')),
  run_id           uuid        NOT NULL CONSTRAINT anchor_run_fk REFERENCES integrity.chain_run (run_id),
  leaf_count       integer     NOT NULL CONSTRAINT anchor_leaf_count_nonneg CHECK (leaf_count >= 0),
  merkle_root      text        NOT NULL CONSTRAINT anchor_merkle_root_shape CHECK (merkle_root ~ '^[0-9a-f]{64}$'),
  prev_anchor_hash text        CONSTRAINT anchor_prev_hash_shape CHECK (prev_anchor_hash ~ '^[0-9a-f]{64}$'),
  anchor_hash      text        NOT NULL CONSTRAINT anchor_hash_shape CHECK (anchor_hash ~ '^[0-9a-f]{64}$') CONSTRAINT anchor_hash_unique UNIQUE,
  key_id           text        NOT NULL CONSTRAINT anchor_key_id_shape CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
  signature        text        NOT NULL CONSTRAINT anchor_signature_shape CHECK (signature ~ '^[A-Za-z0-9+/=_-]{16,512}$'),
  format_version   smallint    NOT NULL CONSTRAINT anchor_format_version_positive CHECK (format_version >= 1),
  CONSTRAINT anchor_prev_only_first CHECK ((anchor_seq = 1) = (prev_anchor_hash IS NULL))
);

CREATE FUNCTION integrity.anchor_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  last_seq bigint;
  last_hash text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM integrity.chain_run r
                  WHERE r.run_id = NEW.run_id AND r.exit_code = 0 AND r.merkle_root = NEW.merkle_root AND r.leaf_count = NEW.leaf_count AND r.environment = NEW.environment) THEN
    RAISE EXCEPTION 'integrity.anchor: la raiz, el numero de hojas y el entorno deben ser los de una corrida chain_run exit 0' USING ERRCODE = 'check_violation';
  END IF;
  SELECT a.anchor_seq, a.anchor_hash INTO last_seq, last_hash FROM integrity.anchor a ORDER BY a.anchor_seq DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW.anchor_seq <> 1 THEN RAISE EXCEPTION 'integrity.anchor: la primera ancla debe tener anchor_seq = 1' USING ERRCODE = 'check_violation'; END IF;
  ELSE
    IF NEW.anchor_seq <> last_seq + 1 OR NEW.prev_anchor_hash IS DISTINCT FROM last_hash THEN
      RAISE EXCEPTION 'integrity.anchor: la cadena de anclas exige anchor_seq = ultima + 1 y prev_anchor_hash = hash de la ultima' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION integrity.anchor_guard() FROM PUBLIC;

CREATE TRIGGER anchor_guard BEFORE INSERT ON integrity.anchor FOR EACH ROW EXECUTE FUNCTION integrity.anchor_guard();
CREATE TRIGGER anchor_no_update_delete BEFORE UPDATE OR DELETE ON integrity.anchor FOR EACH ROW EXECUTE FUNCTION integrity.append_only_guard();
CREATE TRIGGER anchor_no_truncate BEFORE TRUNCATE ON integrity.anchor FOR EACH STATEMENT EXECUTE FUNCTION integrity.append_only_guard();
ALTER TABLE integrity.anchor ENABLE ALWAYS TRIGGER anchor_guard;
ALTER TABLE integrity.anchor ENABLE ALWAYS TRIGGER anchor_no_update_delete;
ALTER TABLE integrity.anchor ENABLE ALWAYS TRIGGER anchor_no_truncate;

ALTER TABLE integrity.anchor ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrity.anchor FORCE ROW LEVEL SECURITY;
CREATE POLICY anchor_signer_select ON integrity.anchor FOR SELECT TO integrity_anchor_signer USING (true);
CREATE POLICY anchor_signer_insert ON integrity.anchor FOR INSERT TO integrity_anchor_signer WITH CHECK (true);

REVOKE ALL ON integrity.anchor FROM PUBLIC;
GRANT SELECT ON integrity.anchor TO integrity_anchor_signer;
GRANT INSERT (anchor_seq, environment, run_id, leaf_count, merkle_root, prev_anchor_hash, anchor_hash, key_id, signature, format_version) ON integrity.anchor TO integrity_anchor_signer;

DO $assert78$
DECLARE
  rel oid;
  expected text[] := ARRAY['integrity_anchor_signer:SELECT:*', 'integrity_anchor_signer:INSERT:anchor_seq', 'integrity_anchor_signer:INSERT:environment', 'integrity_anchor_signer:INSERT:run_id', 'integrity_anchor_signer:INSERT:leaf_count',
                           'integrity_anchor_signer:INSERT:merkle_root', 'integrity_anchor_signer:INSERT:prev_anchor_hash', 'integrity_anchor_signer:INSERT:anchor_hash', 'integrity_anchor_signer:INSERT:key_id',
                           'integrity_anchor_signer:INSERT:signature', 'integrity_anchor_signer:INSERT:format_version'];
  actual text[];
BEGIN
  SELECT c.oid INTO rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'anchor';
  IF rel IS NULL THEN RAISE EXCEPTION '0078: falta integrity.anchor'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = rel AND pg_catalog.pg_get_userbyid(c.relowner) = 'integrity_owner' AND c.relrowsecurity AND c.relforcerowsecurity) THEN
    RAISE EXCEPTION '0078: integrity.anchor debe ser de integrity_owner con RLS ENABLE + FORCE';
  END IF;
  SELECT COALESCE(pg_catalog.array_agg(x.item ORDER BY x.item COLLATE "C"), ARRAY[]::text[]) INTO actual FROM (
    SELECT pg_catalog.format('%s:%s:*', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type) AS item
      FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE c.oid = rel AND a.grantee <> c.relowner
    UNION ALL
    SELECT pg_catalog.format('%s:%s:%s', COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, at.attname)
      FROM pg_catalog.pg_attribute at, LATERAL pg_catalog.aclexplode(at.attacl) a LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE at.attrelid = rel AND at.attnum > 0 AND NOT at.attisdropped) x;
  IF actual IS DISTINCT FROM (SELECT pg_catalog.array_agg(e ORDER BY e COLLATE "C") FROM pg_catalog.unnest(expected) e) THEN
    RAISE EXCEPTION '0078: ACL de integrity.anchor distinta de la esperada (hay %)', actual;
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = rel) <> 2
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = rel AND (NOT p.polpermissive OR pg_catalog.array_length(p.polroles, 1) <> 1
                  OR p.polroles[1] <> (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'integrity_anchor_signer'))) THEN
    RAISE EXCEPTION '0078: integrity.anchor debe tener exactamente las 2 policies del firmante';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger tg WHERE NOT tg.tgisinternal AND tg.tgenabled = 'A' AND tg.tgrelid = rel) <> 3 THEN
    RAISE EXCEPTION '0078: los 3 triggers de integrity.anchor deben ser ENABLE ALWAYS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'integrity' AND p.proname = 'anchor_guard' AND (p.prosecdef OR pg_catalog.pg_get_userbyid(p.proowner) <> 'integrity_owner'
                OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a WHERE a.grantee <> p.proowner))) THEN
    RAISE EXCEPTION '0078: anchor_guard debe ser SECURITY INVOKER, de integrity_owner y sin EXECUTE para otros roles';
  END IF;
END
$assert78$;

SET LOCAL ROLE consent_owner;
