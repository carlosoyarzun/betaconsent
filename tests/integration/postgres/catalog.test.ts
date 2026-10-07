// Gobierna: CA-124 (H09), ADR-002 §2/§8, ADR-006 §4, common.spec.yaml (GRD-CM-11), diseño de
// CA-124 P1-2/P1-3/P1-5/P1-6. Tests de catálogo sobre la base migrada.
// TEST-CNS-743 (propuesto 713, parte PR-A), TEST-CNS-744 (propuesto 716, roles),
// TEST-CNS-745 (propuesto 720), TEST-CNS-746 (propuesto 723), TEST-CNS-747 (propuesto 724, base real).
// Requiere Postgres real (harness.ts): skip fuera de CI sin entorno.

import assert from "node:assert/strict";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { pgTest } from "./harness.ts";
import type { PgRole } from "./harness.ts";

const RUNTIME_ROLES: PgRole[] = ["app_rw", "worker", "platform_rw"];
const OWNERS = ["consent_owner", "tenant_resolve_owner", "integrity_owner"];
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

pgTest("TEST-CNS-744 pg: roles de runtime NOSUPERUSER, NOBYPASSRLS, sin CREATE, fuera de los owners y sin session_replication_role", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const roles = (await admin.query<{
    rolname: string; rolsuper: boolean; rolbypassrls: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean; rolcanlogin: boolean;
  }>(
    `SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin
       FROM pg_roles WHERE rolname = ANY($1)`,
    [[...RUNTIME_ROLES, "consent_migrator", ...OWNERS]],
  )).rows;
  assert.equal(roles.length, 7);
  for (const r of roles) {
    assert.equal(r.rolsuper, false, `${r.rolname} superusuario`);
    assert.equal(r.rolbypassrls, false, `${r.rolname} BYPASSRLS`);
    assert.equal(r.rolcreaterole || r.rolcreatedb || r.rolreplication, false, `${r.rolname} privilegios de cluster`);
    assert.equal(r.rolcanlogin, !OWNERS.includes(r.rolname), `${r.rolname} rolcanlogin (los owners son NOLOGIN)`);
  }

  const schemas = (await admin.query<{ nspname: string }>(
    "SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'",
  )).rows.map((r) => r.nspname);
  assert.ok(["app", "integrity", "ops", "tenant_resolve", "public"].every((s) => schemas.includes(s)));

  for (const role of RUNTIME_ROLES) {
    for (const owner of OWNERS) {
      const m = (await admin.query<{ m: boolean }>("SELECT pg_has_role($1, $2, 'MEMBER') AS m", [role, owner])).rows[0];
      assert.equal(m?.m, false, `${role} es miembro de ${owner}`);
    }
    for (const schema of schemas) {
      const c = (await admin.query<{ c: boolean }>("SELECT has_schema_privilege($1, $2, 'CREATE') AS c", [role, schema])).rows[0];
      assert.equal(c?.c, false, `${role} tiene CREATE en ${schema}`);
    }
    const p = (await admin.query<{ p: boolean }>("SELECT has_parameter_privilege($1, 'session_replication_role', 'SET') AS p", [role])).rows[0];
    assert.equal(p?.p, false, `${role} puede fijar session_replication_role`);
    const db = (await admin.query<{ d: boolean }>("SELECT has_database_privilege($1, current_database(), 'CREATE') AS d", [role])).rows[0];
    assert.equal(db?.d, false, `${role} tiene CREATE en la base`);
  }

  // El migrador sí es miembro de consent_owner (y solo existe en el paso de migración).
  const mig = (await admin.query<{ m: boolean }>("SELECT pg_has_role('consent_migrator', 'consent_owner', 'MEMBER') AS m")).rows[0];
  assert.equal(mig?.m, true);
});

pgTest("TEST-CNS-744 pg: las conexiones de runtime no pueden crear objetos ni cambiar de rol a un owner", async (ctx) => {
  for (const role of RUNTIME_ROLES) {
    const client = await ctx.connectAs(role);
    for (const ddl of ["CREATE TABLE public.x (i int)", "CREATE TABLE app.x (i int)", "CREATE SCHEMA nuevo", "SET ROLE consent_owner", "SET session_replication_role = replica"]) {
      await assert.rejects(() => client.query(ddl), (e: unknown) => codeOf(e) === "42501", `${role}: ${ddl}`);
    }
  }
});

pgTest("TEST-CNS-743 pg: EXECUTE por defecto no llega a PUBLIC (consent_owner, tenant_resolve_owner y outbox_claimer) y tenant_resolve queda cerrado (P1-2, P2-7)", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("CREATE FUNCTION app.probe_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'");
    await migrator.query("SET LOCAL ROLE tenant_resolve_owner");
    await migrator.query("CREATE FUNCTION tenant_resolve.probe_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'");
    // P2-7 (0008): outbox_claimer (dueno de app.outbox_claim) tambien revoca EXECUTE de PUBLIC por defecto.
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("GRANT CREATE ON SCHEMA app TO outbox_claimer");
    await migrator.query("SET LOCAL ROLE outbox_claimer");
    await migrator.query("CREATE FUNCTION app.probe_claimer_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'");
    // Sin USAGE sobre tenant_resolve el migrador ya no puede castear a regprocedure (P2-5): se busca por oid.
    await migrator.query("RESET ROLE");
    for (const fn of ["app.probe_fn()", "tenant_resolve.probe_fn()", "app.probe_claimer_fn()"]) {
      for (const role of [...RUNTIME_ROLES, "public"]) {
        const row = (await migrator.query<{ p: boolean }>(
          role === "public"
            ? "SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE p.oid = (SELECT x.oid FROM pg_proc x JOIN pg_namespace n ON n.oid = x.pronamespace WHERE n.nspname || '.' || x.proname || '()' = $1) AND a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS p"
            : "SELECT has_function_privilege($2, (SELECT x.oid FROM pg_proc x JOIN pg_namespace n ON n.oid = x.pronamespace WHERE n.nspname || '.' || x.proname || '()' = $1), 'EXECUTE') AS p",
          role === "public" ? [fn] : [fn, role],
        )).rows[0];
        assert.equal(row?.p, false, `${role} puede ejecutar ${fn} por defecto`);
      }
    }
  } finally {
    await migrator.query("ROLLBACK");
  }

  const admin = await ctx.connectAsSuperuser();
  const grants = (await admin.query<{ role: string; usage: boolean; create: boolean }>(
    `SELECT r AS role, has_schema_privilege(r, 'tenant_resolve', 'USAGE') AS usage, has_schema_privilege(r, 'tenant_resolve', 'CREATE') AS "create"
       FROM unnest($1::text[]) r`,
    [RUNTIME_ROLES],
  )).rows;
  assert.deepEqual(grants.map((g) => [g.role, g.usage, g.create]), [["app_rw", true, false], ["worker", false, false], ["platform_rw", false, false]]);
  const owner = (await admin.query<{ o: string }>("SELECT nspowner::regrole::text AS o FROM pg_namespace WHERE nspname = 'tenant_resolve'")).rows[0];
  assert.equal(owner?.o, "tenant_resolve_owner");
});

pgTest("TEST-CNS-745 pg: ops.db_catalog es de fila única, SYNTHETIC/LOCAL, inmutable y sin escritura para runtime", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rows = (await admin.query<{ id: boolean; data_class: string; environment: string }>("SELECT id, data_class, environment FROM ops.db_catalog")).rows;
  assert.deepEqual(rows, [{ id: true, data_class: "SYNTHETIC", environment: "LOCAL" }]);

  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>(
    "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'ops.db_catalog'::regclass AND NOT tgisinternal ORDER BY tgname",
  )).rows;
  assert.deepEqual(triggers, [
    { tgname: "db_catalog_no_truncate", tgenabled: "A" },
    { tgname: "db_catalog_no_update_delete", tgenabled: "A" },
  ]);
  const dataClassCheck = (await admin.query<{ def: string }>(
    "SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid = 'ops.db_catalog'::regclass AND conname = 'db_catalog_data_class_synthetic'",
  )).rows[0];
  assert.match(dataClassCheck?.def ?? "", /SYNTHETIC/);

  for (const role of RUNTIME_ROLES) {
    const c = await ctx.connectAs(role);
    assert.equal((await c.query("SELECT 1 FROM ops.db_catalog")).rows.length, 1, `${role} debe poder leer el catálogo`);
    for (const dml of ["UPDATE ops.db_catalog SET environment = 'DEV'", "DELETE FROM ops.db_catalog", "TRUNCATE ops.db_catalog", "INSERT INTO ops.db_catalog (id, environment) VALUES (false, 'DEV')"]) {
      await assert.rejects(() => c.query(dml), (e: unknown) => codeOf(e) === "42501", `${role}: ${dml}`);
    }
  }

  // El migrador (miembro del dueño) tiene el privilegio, pero el trigger lo bloquea.
  const migrator = await ctx.connectAs("consent_migrator");
  for (const dml of ["UPDATE ops.db_catalog SET environment = 'DEV'", "DELETE FROM ops.db_catalog", "TRUNCATE ops.db_catalog"]) {
    await assert.rejects(() => migrator.query(dml), (e: unknown) => codeOf(e) === "23000", `migrador: ${dml}`);
  }
  await assert.rejects(() => migrator.query("SET session_replication_role = replica"), (e: unknown) => codeOf(e) === "42501");
  await assert.rejects(() => migrator.query("INSERT INTO ops.db_catalog (environment) VALUES ('DEV')"), (e: unknown) => codeOf(e) === "23505");
  await assert.rejects(() => migrator.query("INSERT INTO ops.db_catalog (id, environment) VALUES (false, 'DEV')"), (e: unknown) => codeOf(e) === "23514");

  // Ni siquiera un superusuario con session_replication_role = replica (ENABLE ALWAYS).
  await admin.query("SET session_replication_role = replica");
  for (const dml of ["UPDATE ops.db_catalog SET environment = 'DEV'", "DELETE FROM ops.db_catalog", "TRUNCATE ops.db_catalog"]) {
    await assert.rejects(() => admin.query(dml), (e: unknown) => codeOf(e) === "23000", `superusuario replica: ${dml}`);
  }
  await admin.query("SET session_replication_role = origin");

  // Otros valores de data_class/environment no se pueden insertar aunque se saltara la unicidad.
  await admin.query("BEGIN");
  await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER USER");
  await admin.query("DELETE FROM ops.db_catalog");
  for (const [dc, env] of [["REAL", "LOCAL"], ["SYNTHETIC", "PRODUCTION"]]) {
    await admin.query("SAVEPOINT s");
    await assert.rejects(() => admin.query("INSERT INTO ops.db_catalog (data_class, environment) VALUES ($1, $2)", [dc, env]), (e: unknown) => codeOf(e) === "23514", `${dc}/${env}`);
    await admin.query("ROLLBACK TO s");
  }
  await admin.query("ROLLBACK");
});

pgTest("TEST-CNS-746 pg: ningún rol de runtime con BYPASSRLS, sin policies con current_user/session_user y RLS forzada en app e integrity (tablas reales) y sin vistas sin security_invoker sobre tablas RLS", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const bypass = (await admin.query<{ rolname: string }>(
    "SELECT rolname FROM pg_roles WHERE rolbypassrls AND rolname = ANY($1)",
    [[...RUNTIME_ROLES, "consent_migrator", ...OWNERS]],
  )).rows;
  assert.deepEqual(bypass, []);

  const policies = (await admin.query<{ tablename: string; policyname: string }>(
    `SELECT tablename, policyname FROM pg_policies
      WHERE coalesce(qual, '') ~* '\\m(current_user|session_user|current_role|user)\\M'
         OR coalesce(with_check, '') ~* '\\m(current_user|session_user|current_role|user)\\M'`,
  )).rows;
  assert.deepEqual(policies, []);

  // Toda tabla de los esquemas app e integrity exige ENABLE + FORCE ROW LEVEL SECURITY. Desde PR-B
  // existen tablas reales (integrity.audit_event, app.outbox): el chequeo ya no es vacuo.
  const tables = (await admin.query<{ qname: string; forced: boolean }>(
    `SELECT n.nspname || '.' || c.relname AS qname, (c.relrowsecurity AND c.relforcerowsecurity) AS forced
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('app', 'integrity') AND c.relkind IN ('r', 'p')`,
  )).rows;
  assert.ok(tables.some((t) => t.qname === "integrity.audit_event") && tables.some((t) => t.qname === "app.outbox"));
  assert.deepEqual(tables.filter((t) => !t.forced), []);

  // Las policies existen (no vacuo) y ninguna usa current_user/session_user (ya verificado arriba).
  const policyCount = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM pg_policies WHERE schemaname IN ('app', 'integrity')")).rows[0]?.n ?? 0;
  assert.ok(policyCount >= 4, "hay policies reales por revisar");

  // P2-1: ninguna vista (ni materializada) sobre tablas con RLS sin security_invoker; si no, la vista
  // correria con los privilegios de su dueno y esquivaria la policy por tenant.
  // Unica excepcion (API-CNS-116, SEC-CNS-018 rev. 2 R1): app.staff_roster_invitation_status es security_invoker=false
  // A PROPOSITO (proyeccion colapsada del roster del colegio) y solo con: security_barrier=true, dueno
  // staff_roster_owner (nunca consent_owner ni un rol de runtime) y WHERE por tenant explicito. Cualquier otra
  // vista sigue prohibida.
  const views = (await admin.query<{ v: string; barrier: boolean; owner: string }>(
    `SELECT DISTINCT v.oid::regclass::text AS v,
            COALESCE(v.reloptions @> ARRAY['security_barrier=true'], false) AS barrier,
            pg_get_userbyid(v.relowner) AS owner
       FROM pg_class v
       JOIN pg_rewrite r ON r.ev_class = v.oid
       JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
       JOIN pg_class t ON t.oid = d.refobjid AND t.oid <> v.oid
      WHERE v.relkind IN ('v', 'm') AND t.relrowsecurity
        AND (v.relkind = 'm' OR NOT COALESCE(v.reloptions @> ARRAY['security_invoker=true'], false))`,
  )).rows;
  const rosterView = "app.staff_roster_invitation_status";
  assert.deepEqual(views.filter((v) => v.v !== rosterView), [], "vistas sobre tablas con RLS sin security_invoker");
  for (const v of views.filter((x) => x.v === rosterView)) {
    assert.equal(v.barrier, true, "la vista del roster debe ser security_barrier");
    assert.equal(v.owner, "staff_roster_owner", "la vista del roster debe pertenecer a staff_roster_owner");
  }
});

pgTest("TEST-CNS-747 pg: los chequeos de arranque aceptan app_rw/worker/platform_rw y rechazan migrador y superusuario", async (ctx) => {
  for (const role of RUNTIME_ROLES) {
    const result = await runStartupChecks(await ctx.connectAs(role), { expectedEnvironment: "LOCAL" });
    assert.deepEqual(result, { ok: true, failures: [] }, role);
  }

  const migrator = await runStartupChecks(await ctx.connectAs("consent_migrator"));
  assert.equal(migrator.ok, false);
  assert.ok(migrator.failures.some((f) => /miembro de consent_owner/.test(f)));

  const superuser = await runStartupChecks(await ctx.connectAsSuperuser());
  assert.equal(superuser.ok, false);
  assert.ok(superuser.failures.some((f) => /superusuario/.test(f)));

  const mismatch = await runStartupChecks(await ctx.connectAs("app_rw"), { expectedEnvironment: "DEV" });
  assert.equal(mismatch.ok, false);
  assert.ok(mismatch.failures.some((f) => /difiere del catálogo/.test(f)));
});

pgTest("TEST-CNS-884 pg: el arranque web exige current_user = app_rw (worker/platform_rw no pasan con expectedRole)", async (ctx) => {
  const app = await ctx.connectAs("app_rw");
  assert.equal((await runStartupChecks(app, { expectedEnvironment: "LOCAL", expectedRole: "app_rw" })).ok, true);
  for (const role of ["worker", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    const r = await runStartupChecks(c, { expectedEnvironment: "LOCAL", expectedRole: "app_rw" });
    assert.ok(r.failures.some((f) => f.includes("no es app_rw")), role);
  }
});
