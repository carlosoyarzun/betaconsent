-- scope: local-fixture
-- Gobierna: CA-124 (H09), SEC-CNS-017 finding (c), DEC-BR-014 §4 (solo datos sinteticos), 0005_tenant_catalog.sql
-- (app.subject y app.school_participation son SELECT-only para app_rw: el dominio nunca los crea).
--
-- LOCAL-ONLY / SYNTHETIC DATA ONLY. NO es una migracion versionada: no vive en db/migrations, no se registra en
-- ops.schema_migration y solo lo corre applyLocalFixtures (src/infra/adapters/postgres/local-fixtures.ts) como
-- consent_migrator (rol no superusuario; nunca desde el proceso web). Idempotente (ON CONFLICT DO NOTHING).
-- Los valores deben coincidir con src/server/entrypoints/dev-local-config.ts (lo verifica un test).

-- Igual que startup-checks: exactamente UNA fila (count(*) = 1) LOCAL/SYNTHETIC; con EXISTS bastaba una fila LOCAL
-- entre varias (SEC-CNS-017 P2).
DO $$
BEGIN
  IF (SELECT count(*) FROM ops.db_catalog) <> 1 THEN
    RAISE EXCEPTION 'fixtures locales: ops.db_catalog debe tener exactamente una fila; se aborta' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF (SELECT count(*) FROM ops.db_catalog WHERE environment = 'LOCAL' AND data_class = 'SYNTHETIC') <> 1 THEN
    RAISE EXCEPTION 'fixtures locales: ops.db_catalog no es LOCAL/SYNTHETIC; se aborta' USING ERRCODE = 'invalid_parameter_value';
  END IF;
END
$$;

-- El dueno (consent_owner) esta sujeto a FORCE RLS y no hay politica de INSERT para nadie: se desactiva FORCE solo
-- dentro de esta tx (se restaura antes del COMMIT; el fallo de cualquier paso revierte todo).
ALTER TABLE app.subject NO FORCE ROW LEVEL SECURITY;
ALTER TABLE app.school_participation NO FORCE ROW LEVEL SECURITY;

-- Tenant de dev (LOCAL_ONLY_DEV_TENANT_ID) y otro colegio (LOCAL_ONLY_DEV_OTHER_TENANT_ID).
INSERT INTO app.subject (tenant_id, subject_ref) VALUES
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'e8d2b4a6-3c19-4f75-b6e0-1a9c7d5f3b82'),  -- LOCAL_ONLY_DEV_SUBJECT_REF
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'b7c3d1e5-2a48-4f96-8d10-6e9f0a2c4b73'),  -- LOCAL_ONLY_DEV_STAFF_SUBJECT_REF
  ('5d2e8a1c-6b3f-4d97-9c04-7e1a3b5d9f20', 'b7c3d1e5-2a48-4f96-8d10-6e9f0a2c4b73'),
  -- alumnos sinteticos 2..6 de la consola dev (LOCAL_ONLY_DEV_STAFF_STUDENTS), solo colegio de dev
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'e74bb5c4-bc34-4f14-b773-ed7be16c7eab'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'cbd3aca8-1fd0-4ce5-aeaf-6ccf4c8d9bd4'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '7ac9347f-c8ce-4de6-94ac-30ad4bb19c99'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'b07be7e0-88b9-4233-807c-ae6263b45aa7'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '9467c808-e8d3-486d-a73a-87a6cfdc02ef')
ON CONFLICT DO NOTHING;

INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'd4f8a2c6-7b13-4e59-a8c2-0f3d5b7e9a14', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),  -- LOCAL_ONLY_DEV_PARTICIPATION_REF
  ('5d2e8a1c-6b3f-4d97-9c04-7e1a3b5d9f20', 'd4f8a2c6-7b13-4e59-a8c2-0f3d5b7e9a14', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '9bd69327-dcfb-476e-b638-439f138dafe9', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '3f529dbe-d674-4e2e-bda8-b8548ab5a0ed', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', 'a5197e72-eee4-4784-8e2e-aa225e037977', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '4a54ce87-8bff-4487-8f5b-2f620867768e', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE'),
  ('c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48', '74a01146-1bf6-4d67-bffe-bd72c89332dc', 'BETA_2026_01', 'LECTORPRO', 'ACTIVE')
ON CONFLICT DO NOTHING;

ALTER TABLE app.subject FORCE ROW LEVEL SECURITY;
ALTER TABLE app.school_participation FORCE ROW LEVEL SECURITY;
