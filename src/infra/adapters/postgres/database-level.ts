// Gobierna: ADR-010 rev. 6 §4.5.2 (db_owner_nologin y CREATE explicito), §4.5.3 (ddl_breakglass NOLOGIN, Q-20 (c)), §4.5.4 (breakglass_log_owner), INV-DBR-03/09, F-PR7-04, F-PR7-12, F-A10-10, F-A10-11;
// specs/db-roles.spec.yaml rev. 0.8; migraciones 0084 (roles) y 0086 (fase cluster-post). PR-7d.
//
// Aserción del estado a nivel de BASE y de los tres roles de PR-7d. La usan el runner (migrate.ts, tras la fase cluster y tras la fase database; superusuario) y startup-checks.ts (modo estricto: roleMode REAL_DATA).
// Solo lee catalogos publicos (pg_database, pg_roles, pg_auth_members): sirve con cualquier rol. Igualdad EXACTA y fail-closed; solo nombres de rol y de configuracion, nunca valores de datos.
//
// REAL_DATA es un modo VERIFICABLE, no una autorizacion de datos reales (F-PR7-12): REAL_DATA_BLOCKERS (F-PR7-01) lo mantiene bloqueado al resolverlo desde el entorno y el catalogo sigue exigiendo data_class = SYNTHETIC.

import type { Queryable } from "./pool.ts";
import type { DbRoleMode } from "./role-membership.ts";

/** Roles que se conectan a la base de la aplicacion (CONNECT explicito; PUBLIC no tiene CONNECT, F-A10-10). consent_owner y los demas owners son NOLOGIN y no se conectan. */
export const CONNECT_ROLES: readonly string[] = [
  "consent_migrator",
  "app_rw",
  "worker",
  "platform_rw",
  "integrity_verifier",
  "integrity_reconciler",
  "integrity_chain_verifier",
  "ddl_breakglass",
];

/**
 * Settings propios de ddl_breakglass (Q-20 (c), C-5, F-PR7-07): log_statement='ddl' (NO 'all': el log no escribe datos; las ceremonias son DDL) y sin parametros en el log. log_connections/log_disconnections
 * son del postgresql.conf del host (infra/postgres/postgresql.breakglass.conf.example), no de un ALTER ROLE.
 */
export const DDL_BREAKGLASS_SETTINGS: readonly string[] = [
  "idle_in_transaction_session_timeout=10min",
  "log_parameter_max_length=0",
  "log_parameter_max_length_on_error=0",
  "log_statement=ddl",
];

export interface DatabaseLevelOptions {
  /** true = ddl_breakglass debe ser NOLOGIN (aserción del deploy: una ceremonia abierta bloquea un deploy). El arranque de un proceso de runtime no lo exige; lo vigila el modo breakglass-watch. */
  readonly breakglassMustBeClosed?: boolean;
}

interface RoleRow {
  rolname: string;
  rolcanlogin: boolean;
  rolsuper: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
  rolinherit: boolean;
  rolconnlimit: number;
  rolconfig: string[] | null;
  members: number | string;
}

interface DatabaseRow {
  datdba_name: string;
  public_privileges: string[] | null;
  owner_create: boolean;
  missing_connect: string[] | null;
}

/** Devuelve las diferencias (vacio = coincide). Fail-closed: si no se puede leer, lo informa como diferencia. */
export async function checkDatabaseLevel(db: Queryable, mode: DbRoleMode, options: DatabaseLevelOptions = {}): Promise<string[]> {
  const problems: string[] = [];
  try {
    const database = await db.query<DatabaseRow>(
      `SELECT pg_catalog.pg_get_userbyid(d.datdba)::pg_catalog.text AS datdba_name,
              (SELECT pg_catalog.array_agg(a.privilege_type::pg_catalog.text ORDER BY a.privilege_type)
                 FROM pg_catalog.aclexplode(COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))) a WHERE a.grantee = 0) AS public_privileges,
              pg_catalog.has_database_privilege('consent_owner', d.oid, 'CREATE') AS owner_create,
              (SELECT pg_catalog.array_agg(c.rolname::pg_catalog.text ORDER BY c.rolname) FROM pg_catalog.unnest($1::pg_catalog.text[]) AS c(rolname)
                WHERE NOT COALESCE(pg_catalog.has_database_privilege(c.rolname, d.oid, 'CONNECT'), false)) AS missing_connect
         FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()`,
      [[...CONNECT_ROLES]],
    );
    const row = database.rows[0];
    if (row === undefined) return ["no se pudo leer la base actual (INV-DBR-09)"];
    if (row.datdba_name !== "db_owner_nologin") problems.push(`el dueño de la base es ${row.datdba_name} y debe ser db_owner_nologin (INV-DBR-09)`);
    const publicPrivileges = (row.public_privileges ?? []).filter((p) => p === "CONNECT" || p === "TEMPORARY" || p === "CREATE");
    if (publicPrivileges.length > 0) problems.push(`PUBLIC tiene ${publicPrivileges.join(", ")} en la base (F-A10-10)`);
    // CREATE explicito: consent_owner lo tiene solo en IT0B_SYNTHETIC; en REAL_DATA los esquemas nuevos van por ceremonia (F-PR7-04).
    if (mode === "IT0B_SYNTHETIC" && row.owner_create !== true) problems.push("consent_owner debe tener CREATE explicito en la base en IT0B_SYNTHETIC (F-PR7-04)");
    if (mode === "REAL_DATA" && row.owner_create === true) problems.push("consent_owner no puede tener CREATE en la base en REAL_DATA (F-PR7-04)");
    if ((row.missing_connect ?? []).length > 0) problems.push(`falta CONNECT explicito en la base para: ${(row.missing_connect ?? []).join(", ")} (F-A10-10)`);

    const roles = await db.query<RoleRow>(
      `SELECT r.rolname::pg_catalog.text AS rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls, r.rolinherit, r.rolconnlimit, r.rolconfig,
              (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members m WHERE m.roleid = r.oid) AS members
         FROM pg_catalog.pg_roles r WHERE r.rolname IN ('db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass')`,
    );
    const byName = new Map(roles.rows.map((r) => [r.rolname, r]));
    for (const name of ["db_owner_nologin", "breakglass_log_owner", "ddl_breakglass"]) {
      const r = byName.get(name);
      if (r === undefined) {
        problems.push(`falta el rol ${name} (INV-DBR-09)`);
        continue;
      }
      if (r.rolsuper || r.rolcreatedb || r.rolcreaterole || r.rolreplication || r.rolbypassrls) problems.push(`${name} debe ser NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION y NOBYPASSRLS (INV-DBR-09)`);
      if (name !== "ddl_breakglass" && r.rolcanlogin) problems.push(`${name} debe ser NOLOGIN (INV-DBR-09)`);
      if (name !== "ddl_breakglass" && Number(r.members) > 0) problems.push(`${name} no puede tener miembros (INV-DBR-09)`);
    }
    const bg = byName.get("ddl_breakglass");
    if (bg !== undefined) {
      if (options.breakglassMustBeClosed === true && bg.rolcanlogin) problems.push("ddl_breakglass tiene LOGIN fuera de una ceremonia (INV-DBR-09, Q-20 (c)): cierre la ceremonia (db/ceremonies/close.sql) antes de desplegar");
      if (bg.rolinherit || Number(bg.rolconnlimit) !== 1) problems.push("ddl_breakglass debe ser NOINHERIT y CONNECTION LIMIT 1 (INV-DBR-09)");
      if (Number(bg.members) > 0) problems.push("ddl_breakglass no puede tener miembros (INV-DBR-09)");
      const config = [...(bg.rolconfig ?? [])].sort();
      if (config.join("|") !== [...DDL_BREAKGLASS_SETTINGS].sort().join("|")) problems.push("ddl_breakglass debe tener exactamente los settings de auditoria de sesion (log_statement=ddl, sin parametros en el log; Q-20 (c))");
    }
  } catch {
    problems.push("no se pudo verificar el estado a nivel de base (INV-DBR-09)");
  }
  return problems;
}
