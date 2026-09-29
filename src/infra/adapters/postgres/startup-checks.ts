// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (synthetic_only_environment, ERR-CM-11),
// ADR-002 §2/§8, SEC-CNS-012 N2-06; TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño).
//
// Chequeo de arranque del rol de runtime (P2 de CI del diseño de CA-124): el servicio NO
// arranca si el rol de la conexión es superusuario, BYPASSRLS, miembro de un owner, puede
// CREAR en algún esquema o cambiar session_replication_role, o si el catálogo de la base no
// es SYNTHETIC/LOCAL|DEV|STAGING (o difiere del environment configurado).

import type { Queryable } from "./pool.ts";

export interface StartupCheckOptions {
  /** Environment declarado por la configuración; si difiere del catálogo, no arranca (SEC N2-06). */
  expectedEnvironment?: "LOCAL" | "DEV" | "STAGING";
}

export interface StartupCheckResult {
  ok: boolean;
  failures: string[];
}

export class StartupCheckError extends Error {
  readonly failures: string[];
  constructor(failures: string[]) {
    super(`ERR-CM-11: chequeo de arranque de la base falló: ${failures.join("; ")}`);
    this.name = "StartupCheckError";
    this.failures = failures;
  }
}

const ALLOWED_ENVIRONMENTS = new Set(["LOCAL", "DEV", "STAGING"]);

export async function runStartupChecks(db: Queryable, options: StartupCheckOptions = {}): Promise<StartupCheckResult> {
  const failures: string[] = [];

  const role = await db.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean }>(
    "SELECT rolname, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
  );
  const me = role.rows[0];
  if (me === undefined) {
    failures.push("no se pudo leer el rol de la conexión");
  } else {
    if (me.rolsuper) failures.push("el rol de la conexión es superusuario");
    if (me.rolbypassrls) failures.push("el rol de la conexión tiene BYPASSRLS");
  }

  const membership = await db.query<{ owner: string; member: boolean }>(
    `SELECT o.rolname AS owner, pg_catalog.pg_has_role(current_user, o.oid, 'MEMBER') AS member
       FROM pg_catalog.pg_roles o WHERE o.rolname IN ('consent_owner', 'tenant_resolve_owner')`,
  );
  if (membership.rows.length < 2) failures.push("faltan los roles owner (base sin migrar)");
  for (const row of membership.rows) {
    if (row.member) failures.push(`el rol de la conexión es miembro de ${row.owner}`);
  }

  const create = await db.query<{ nspname: string }>(
    `SELECT nspname FROM pg_catalog.pg_namespace
      WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
        AND pg_catalog.has_schema_privilege(current_user, oid, 'CREATE')`,
  );
  for (const row of create.rows) failures.push(`el rol de la conexión tiene CREATE en el esquema ${row.nspname}`);

  const replication = await db.query<{ can_set: boolean }>(
    "SELECT pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET') AS can_set",
  );
  if (replication.rows[0]?.can_set === true) failures.push("el rol de la conexión puede fijar session_replication_role");

  try {
    const catalog = await db.query<{ data_class: string; environment: string }>("SELECT data_class, environment FROM ops.db_catalog");
    const row = catalog.rows[0];
    if (catalog.rows.length !== 1 || row === undefined) {
      failures.push("ops.db_catalog debe tener exactamente una fila");
    } else {
      if (row.data_class !== "SYNTHETIC") failures.push("el catálogo de la base no es SYNTHETIC");
      if (!ALLOWED_ENVIRONMENTS.has(row.environment)) failures.push("el environment del catálogo no es LOCAL, DEV ni STAGING");
      if (options.expectedEnvironment !== undefined && options.expectedEnvironment !== row.environment) {
        failures.push("el environment configurado difiere del catálogo de la base");
      }
    }
  } catch {
    failures.push("no se pudo leer ops.db_catalog");
  }

  return { ok: failures.length === 0, failures };
}

export async function assertStartupChecks(db: Queryable, options: StartupCheckOptions = {}): Promise<void> {
  const result = await runStartupChecks(db, options);
  if (!result.ok) throw new StartupCheckError(result.failures);
}
