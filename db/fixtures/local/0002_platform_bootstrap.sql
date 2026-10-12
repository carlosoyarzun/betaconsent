-- scope: local-fixture
-- Gobierna: ADR-010 rev. 4 §4.4 (Q10: bootstrap de los primeros principals PLATFORM), §7 fila PR-4; decision de Carlos del 2026-10-11 (3): el bootstrap del primer PLATFORM
-- en LOCAL es un fixture sintetico dentro de los fixtures locales (patron TEST-CNS-879); STAGING y datos reales van por la ceremonia de break-glass de PR-7
-- (NO implementada aqui). DEC-BR-014 §4 (solo datos sinteticos).
--
-- LOCAL-ONLY / SYNTHETIC DATA ONLY. NO es una migracion versionada: solo lo corre applyLocalFixtures (src/infra/adapters/postgres/local-fixtures.ts) como
-- consent_migrator -> consent_owner; el propio archivo hace SET LOCAL ROLE membership_owner (consent_owner tiene SET sobre ese owner solo en el modo IT0B_SYNTHETIC; en
-- REAL_DATA esta membresia no existe y este fixture falla, como debe).
-- Idempotente. Siembra DOS principals PLATFORM (A y B): el doble control exige solicitante <> aprobador y approved_by_ref <> principal_ref, asi que con uno solo
-- nunca se podria aprobar un tercero. Cada fila nace PENDING (guard) y pasa a ACTIVE con approved_by_ref distinto de principal_ref y de requested_by_ref
-- (los dos "sembradores" son UUIDv4 sinteticos sin rol). principal_identity vincula cada principal con un sub_hmac SINTETICO (sha256 de una etiqueta, NO el HMAC de
-- un sub real ni del dominio consent-app/sub-hmac/v1); un IdP sintetico LOCAL que quiera ingresar como A o B debe emitir un sub cuyo HMAC con la clave K_sub de ese LOCAL sea este valor, o el test
-- inserta su propio vinculo. Ningun dato personal; ninguna credencial.

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

SET LOCAL ROLE membership_owner;

INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES
  ('580ddfe4-9026-486f-becc-19f561a20106', 'PLATFORM', 'PENDING', 'ff121af5-3e96-4618-a630-e319c5fef4bf'),  -- LOCAL_ONLY_PLATFORM_A
  ('44bb73f9-d898-479f-bfcd-d70c3f8ca624', 'PLATFORM', 'PENDING', 'ff121af5-3e96-4618-a630-e319c5fef4bf')   -- LOCAL_ONLY_PLATFORM_B
ON CONFLICT (principal_ref, platform_role, (COALESCE(approver_class, ''))) DO NOTHING;

UPDATE platform.platform_role_assignment
   SET status = 'ACTIVE', approved_by_ref = 'b6df8070-1104-41b8-ab88-3f82ddb76ff1', approved_at = now()
 WHERE principal_ref IN ('580ddfe4-9026-486f-becc-19f561a20106', '44bb73f9-d898-479f-bfcd-d70c3f8ca624')
   AND platform_role = 'PLATFORM' AND status = 'PENDING';

INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES
  ('580ddfe4-9026-486f-becc-19f561a20106', 'cbb968503306bf736c0ab475f04ce1984504e051e34401a28c55393d44e4384f'),
  ('44bb73f9-d898-479f-bfcd-d70c3f8ca624', '2108f83549810505c9ff784208423d2c3d21bd639475b7bc4a39b9da2510eba0')
ON CONFLICT DO NOTHING;
