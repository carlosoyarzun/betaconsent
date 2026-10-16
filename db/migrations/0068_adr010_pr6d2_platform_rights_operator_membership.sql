-- scope: cluster
-- Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §2 (fila `rights_operator`: "platform_rw es miembro INHERIT FALSE, SET TRUE"; entrega 6c -> 6d por la opcion A de Carlos, 2026-10-15), §10 filas
-- 6c/6d; specs/db-roles.spec.yaml (membershipAssertion IT0B_SYNTHETIC y REAL_DATA; rights_operator.setRoleBy; INV-DBR-03); F-PR6-04, F-PR6-39. Aplica en ambos modos (no es una membresia de owner).
-- Que hace: platform_rw puede hacer SET LOCAL ROLE rights_operator (nunca hereda sus privilegios) para ejecutar las funciones de operador de case_state. Ningun otro runtime es miembro (app_rw, worker, verifiers).
-- Idempotente: el GRANT repetido no cambia el estado; se revoca ADMIN OPTION solo si existiera.

GRANT rights_operator TO platform_rw WITH INHERIT FALSE, SET TRUE;

DO $admin$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
               JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
              WHERE r.rolname = 'rights_operator' AND x.rolname = 'platform_rw' AND m.admin_option) THEN
    REVOKE ADMIN OPTION FOR rights_operator FROM platform_rw;
  END IF;
END
$admin$;

DO $assert68$
BEGIN
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles r ON r.oid = m.roleid JOIN pg_catalog.pg_roles x ON x.oid = m.member
       WHERE r.rolname = 'rights_operator' AND x.rolname = 'platform_rw' AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option) <> 1 THEN
    RAISE EXCEPTION '0068: platform_rw debe ser miembro de rights_operator exactamente INHERIT FALSE, SET TRUE, sin ADMIN';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
              WHERE r.rolname = 'rights_operator' AND m.member <> (SELECT x.oid FROM pg_catalog.pg_roles x WHERE x.rolname = 'platform_rw')) THEN
    RAISE EXCEPTION '0068: rights_operator solo puede tener a platform_rw como miembro';
  END IF;
END
$assert68$;
