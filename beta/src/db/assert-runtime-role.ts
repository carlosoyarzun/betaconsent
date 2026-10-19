// Gobierna: SEC-CNS-024 F-SB-02 (SEC-CNS-023 §B). Gate de arranque del ROL de runtime: el proceso web debe conectarse como consent_app, sin superusuario, sin BYPASSRLS,
// sin SET ROLE activo y sin membresía en ningún rol (ni consent_owner/consent_migrator ni predefinidos como pg_write_all_data). Si CNS_DATABASE_URL apuntara al
// superusuario o al migrador, el proceso NO arranca. Complementa a assertEnvironment (entorno vs catálogo); ambos se llaman antes de aceptar tráfico.

import type { Queryable } from "./assert-environment.ts";

export class RuntimeRoleError extends Error {
  readonly violations: readonly string[];
  constructor(violations: readonly string[]) {
    super(`El rol de conexión no es apto para runtime: ${violations.join("; ")}. Abortando (fail-closed).`);
    this.name = "RuntimeRoleError";
    this.violations = violations;
  }
}

interface RoleRow {
  session_user: string;
  current_user: string;
  rolsuper: boolean;
  rolbypassrls: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolreplication: boolean;
  member_of_any: boolean;
  member_of_privileged: boolean;
}

export const RUNTIME_ROLE = "consent_app";

export async function assertRuntimeRole(db: Queryable): Promise<void> {
  const { rows } = await db.query<RoleRow>(
    `SELECT session_user::text AS session_user, current_user::text AS current_user,
            r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
            EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS member_of_any,
            COALESCE((SELECT bool_or(pg_has_role(current_user, x.oid, 'MEMBER')) FROM pg_roles x WHERE x.rolname IN ('consent_owner', 'consent_migrator')), false) AS member_of_privileged
       FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const r = rows[0];
  if (r === undefined) throw new RuntimeRoleError(["no se pudo leer el rol actual"]);
  const v: string[] = [];
  if (r.rolsuper) v.push("es superusuario");
  if (r.rolbypassrls) v.push("tiene BYPASSRLS");
  if (r.rolcreaterole || r.rolcreatedb || r.rolreplication) v.push("tiene CREATEROLE/CREATEDB/REPLICATION");
  if (r.session_user !== r.current_user) v.push("session_user distinto de current_user (SET ROLE activo)");
  if (r.member_of_privileged) v.push("es miembro de consent_owner o consent_migrator");
  else if (r.member_of_any) v.push("es miembro de otro rol (p. ej. pg_write_all_data)");
  if (r.current_user !== RUNTIME_ROLE) v.push(`no es ${RUNTIME_ROLE}`);
  if (v.length > 0) throw new RuntimeRoleError(v);
}
