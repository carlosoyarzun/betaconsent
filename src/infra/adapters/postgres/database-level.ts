// Gobierna: ADR-010 rev. 6 §4.5.2 (db_owner_nologin y CREATE explicito), §4.5.3 (ddl_breakglass NOLOGIN, Q-20 (c)), §4.5.4 (breakglass_log_owner), INV-DBR-03/09, F-PR7-04, F-PR7-12, F-A10-10, F-A10-11;
// specs/db-roles.spec.yaml rev. 0.8; migraciones 0084 (roles) y 0086 (fase cluster-post). PR-7d.
//
// Aserción del estado a nivel de BASE y de los tres roles de PR-7d. La usan el runner (migrate.ts, tras la fase cluster y tras la fase database; superusuario) y startup-checks.ts (modo estricto: roleMode REAL_DATA).
// Solo lee catalogos publicos (pg_database, pg_roles, pg_auth_members): sirve con cualquier rol. Igualdad EXACTA y fail-closed; solo nombres de rol y de configuracion, nunca valores de datos.
//
// REAL_DATA es un modo VERIFICABLE, no una autorizacion de datos reales (F-PR7-12): REAL_DATA_BLOCKERS (F-PR7-01) lo mantiene bloqueado al resolverlo desde el entorno y el catalogo sigue exigiendo data_class = SYNTHETIC.

import type { Queryable } from "./pool.ts";
import { GOVERNED_ROLES } from "./role-membership.ts";
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

/**
 * ADR-010 rev. 6 PR-7d (F-PR7D-02, P1-2): estado EXACTO del esquema `breakglass` (creado por 0085 en cluster-post como superusuario con SET LOCAL ROLE breakglass_log_owner). Cada elemento es un "hecho" del catalogo; la igualdad con
 * esta lista es exacta (fail-closed): dueños del esquema, de la tabla y de la funcion; ACL del esquema, de la tabla y por columna; RLS habilitada y forzada; los 2 triggers con tgenabled = 'A' (ENABLE ALWAYS), su tipo y su funcion;
 * UNA sola policy; constraints (nombre y tipo); y ningun otro objeto en el esquema. Lo usan el deploy (assertDeployState), startup-checks (estricto) y la vigilancia (breakglass-watch).
 */
export const BREAKGLASS_EXPECTED_FACTS: readonly string[] = [
  "col_acl|closed_at|integrity_chain_verifier:breakglass_log_owner:SELECT:false",
  "col_acl|ceremony_ref|integrity_chain_verifier:breakglass_log_owner:SELECT:false",
  "col_acl|opened_at|integrity_chain_verifier:breakglass_log_owner:SELECT:false",
  "col_acl|valid_until|integrity_chain_verifier:breakglass_log_owner:SELECT:false",
  "constraint|ceremony_closed_after_open|c",
  "constraint|ceremony_pkey|p",
  "constraint|ceremony_reason_code|c",
  "constraint|ceremony_ref_shape|c",
  "constraint|ceremony_ticket_shape|c",
  "constraint|ceremony_window|c",
  'fn|breakglass.ceremony_guard()|breakglass_log_owner|false|{"search_path=pg_catalog, pg_temp"}|{breakglass_log_owner=X/breakglass_log_owner}',
  "policy|ceremony_watch_select|r|true|integrity_chain_verifier|true|",
  "rel|ceremony|r|breakglass_log_owner|rls=true|force=true|breakglass_log_owner:breakglass_log_owner:DELETE:false,breakglass_log_owner:breakglass_log_owner:INSERT:false,breakglass_log_owner:breakglass_log_owner:REFERENCES:false,breakglass_log_owner:breakglass_log_owner:SELECT:false,breakglass_log_owner:breakglass_log_owner:TRIGGER:false,breakglass_log_owner:breakglass_log_owner:TRUNCATE:false,breakglass_log_owner:breakglass_log_owner:UPDATE:false",
  "rel|ceremony_pkey|i|breakglass_log_owner|rls=false|force=false|",
  "schema|owner=breakglass_log_owner|acl=breakglass_log_owner:breakglass_log_owner:CREATE:false,breakglass_log_owner:breakglass_log_owner:USAGE:false,integrity_chain_verifier:breakglass_log_owner:USAGE:false",
  "trigger|ceremony_guard|A|breakglass.ceremony_guard|27|notqual",
  "trigger|ceremony_no_truncate|A|breakglass.ceremony_guard|34|notqual",
];

/** Consulta de los hechos del esquema breakglass (solo catalogos publicos; nombres de objeto y de rol, nunca datos). Se omite el MAINTAIN autoconcedido por el dueño (PostgreSQL 17+) para no depender de la version. */
const BREAKGLASS_FACTS_SQL = `
WITH ns AS (SELECT n.oid, n.nspowner, n.nspacl FROM pg_catalog.pg_namespace n WHERE n.nspname = 'breakglass')
SELECT 'schema|owner=' || pg_catalog.pg_get_userbyid(ns.nspowner)::pg_catalog.text || '|acl=' || COALESCE((
         SELECT pg_catalog.string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text END || ':' || pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text || ':' || a.privilege_type || ':' || a.is_grantable::pg_catalog.text, ',' ORDER BY (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text END) COLLATE "C", a.privilege_type COLLATE "C")
           FROM pg_catalog.aclexplode(COALESCE(ns.nspacl, pg_catalog.acldefault('n', ns.nspowner))) a), '') AS fact
  FROM ns
UNION ALL
SELECT 'rel|' || c.relname::pg_catalog.text || '|' || c.relkind::pg_catalog.text || '|' || pg_catalog.pg_get_userbyid(c.relowner)::pg_catalog.text || '|rls=' || c.relrowsecurity::pg_catalog.text || '|force=' || c.relforcerowsecurity::pg_catalog.text || '|'
       || CASE WHEN c.relkind = 'r' THEN COALESCE((SELECT pg_catalog.string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text END || ':' || pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text || ':' || a.privilege_type || ':' || a.is_grantable::pg_catalog.text, ',' ORDER BY (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text END) COLLATE "C", a.privilege_type COLLATE "C")
                                                    FROM pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a WHERE NOT (a.privilege_type = 'MAINTAIN' AND a.grantee = c.relowner AND a.grantor = c.relowner)), '') ELSE '' END
  FROM pg_catalog.pg_class c JOIN ns ON ns.oid = c.relnamespace
UNION ALL
SELECT 'col_acl|' || at.attname::pg_catalog.text || '|' || pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text || ':' || a.privilege_type || ':' || a.is_grantable::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C", a.privilege_type COLLATE "C")
  FROM pg_catalog.pg_attribute at JOIN pg_catalog.pg_class c ON c.oid = at.attrelid JOIN ns ON ns.oid = c.relnamespace, pg_catalog.aclexplode(at.attacl) a
 WHERE at.attacl IS NOT NULL AND NOT at.attisdropped GROUP BY at.attname
UNION ALL
SELECT 'trigger|' || t.tgname::pg_catalog.text || '|' || t.tgenabled::pg_catalog.text || '|' || pf.pronamespace::pg_catalog.regnamespace::pg_catalog.text || '.' || pf.proname::pg_catalog.text || '|' || t.tgtype::pg_catalog.text || '|' || CASE WHEN t.tgqual IS NULL THEN 'notqual' ELSE 'qual' END
  FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN ns ON ns.oid = c.relnamespace JOIN pg_catalog.pg_proc pf ON pf.oid = t.tgfoid WHERE NOT t.tgisinternal
UNION ALL
SELECT 'policy|' || p.polname::pg_catalog.text || '|' || p.polcmd::pg_catalog.text || '|' || p.polpermissive::pg_catalog.text || '|'
       || COALESCE((SELECT pg_catalog.string_agg(CASE WHEN x = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x)::pg_catalog.text END, ',' ORDER BY x) FROM pg_catalog.unnest(p.polroles) AS x), '') || '|'
       || COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') || '|' || COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
  FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN ns ON ns.oid = c.relnamespace
UNION ALL
SELECT 'fn|' || n.nspname::pg_catalog.text || '.' || p.proname::pg_catalog.text || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')|' || pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text || '|' || p.prosecdef::pg_catalog.text || '|' || COALESCE(p.proconfig::pg_catalog.text, '') || '|' || COALESCE(p.proacl::pg_catalog.text, '')
  FROM pg_catalog.pg_proc p JOIN ns ON ns.oid = p.pronamespace JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
UNION ALL
SELECT 'constraint|' || k.conname::pg_catalog.text || '|' || k.contype::pg_catalog.text
  FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid JOIN ns ON ns.oid = c.relnamespace WHERE k.contype <> 'n'
`;

/** Diferencias entre el esquema breakglass real y BREAKGLASS_EXPECTED_FACTS (vacio = exacto). Fail-closed: si el esquema no existe lo informa. Solo nombres de objeto y de rol. */
export async function checkBreakglassState(db: Queryable): Promise<string[]> {
  try {
    const r = await db.query<{ fact: string }>(BREAKGLASS_FACTS_SQL);
    const actual = r.rows.map((x) => x.fact);
    if (actual.length === 0) return ["falta el esquema breakglass (0085, fase cluster-post; INV-DBR-09, F-PR7D-02)"];
    const problems: string[] = [];
    const count = (xs: readonly string[]): Map<string, number> => {
      const m = new Map<string, number>();
      for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
      return m;
    };
    const want = count(BREAKGLASS_EXPECTED_FACTS);
    const have = count(actual);
    for (const [fact, n] of have) if (n > (want.get(fact) ?? 0)) problems.push(`breakglass: sobra ${fact} (INV-DBR-09)`);
    for (const [fact, n] of want) if (n > (have.get(fact) ?? 0)) problems.push(`breakglass: falta ${fact} (INV-DBR-09)`);
    return problems;
  } catch {
    return ["no se pudo verificar el estado exacto del esquema breakglass (INV-DBR-09)"];
  }
}

/** GUC que, fijadas a nivel de base (ALTER DATABASE ... SET), cambiarian el rol efectivo o la auditoria de la sesion de ceremonia. */
const SENSITIVE_DATABASE_GUCS: readonly string[] = ["role", "session_authorization", "log_statement", "log_parameter_max_length", "log_parameter_max_length_on_error", "session_replication_role", "search_path"];

/**
 * ADR-010 rev. 6 PR-7d (F-PR7D-05, TEST-CNS-1863; "DBR-12" del plan: settings de ddl_breakglass): `ALTER ROLE ... IN DATABASE ... SET` (pg_db_role_setting) PISA el ALTER ROLE global de rolconfig. Ningun rol gobernado
 * (los tres de nivel de base, los owners, el migrador y los de runtime) puede tener un setting propio en ESTA base, y a nivel de base (setrole = 0) no se fijan las GUC sensibles de auditoria o de rol.
 */
export async function checkDbRoleSettings(db: Queryable): Promise<string[]> {
  try {
    const r = await db.query<{ scope: string; setting: string; for_role: boolean }>(
      `SELECT COALESCE(r.rolname::pg_catalog.text, '(todos los roles)') AS scope, pg_catalog.split_part(c, '=', 1) AS setting, s.setrole <> 0 AS for_role
         FROM pg_catalog.pg_db_role_setting s
         LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
         CROSS JOIN LATERAL pg_catalog.unnest(s.setconfig) AS c
        WHERE s.setdatabase = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database())
          AND ((s.setrole <> 0 AND r.rolname = ANY($1::pg_catalog.text[])) OR (s.setrole = 0 AND pg_catalog.lower(pg_catalog.split_part(c, '=', 1)) = ANY($2::pg_catalog.text[])))`,
      [[...GOVERNED_ROLES, ...CONNECT_ROLES], [...SENSITIVE_DATABASE_GUCS]],
    );
    return r.rows.map((x) => `pg_db_role_setting fija ${x.setting} ${x.for_role ? `para ${x.scope} en esta base (ALTER ROLE ... IN DATABASE ... SET pisa los settings del rol)` : "a nivel de base (ALTER DATABASE ... SET)"} (INV-DBR-09, F-PR7D-05)`);
  } catch {
    return ["no se pudo verificar pg_db_role_setting (INV-DBR-09)"];
  }
}

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
    problems.push(...(await checkDbRoleSettings(db)));
    problems.push(...(await checkBreakglassState(db)));
  } catch {
    problems.push("no se pudo verificar el estado a nivel de base (INV-DBR-09)");
  }
  return problems;
}
