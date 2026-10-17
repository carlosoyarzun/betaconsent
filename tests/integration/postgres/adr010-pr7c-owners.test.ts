// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c), F-PR7-01 (trojan del migrador), F-6D3-SEC-08, Q16, R-21-1/FN-12; decisiones de Carlos del 2026-10-16 (C-2, C-3, F-6D3-SEC-08, C-6);
// specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-01, INV-DBR-03). SYNTHETIC ONLY. Requiere Postgres real (harness.ts).
// TEST-CNS-1800 roles de PR-7c; 1801 Q16 (tablas en case_state, consent_owner sin DROP/DISABLE TRIGGER/ALTER); 1802 funciones compartidas (shared_fn_owner, sin CREATE OR REPLACE del migrador);
// 1803 esquemas app/ops de owners NOLOGIN (sin DROP SCHEMA ni DROP de objetos ajenos; consent_owner sigue creando los propios); 1804 recovery reader (F-6D3-SEC-08); 1805 inventario por catalogo igual a la
// allowlist y detecta el trojan; 1806 startup-checks (REAL_DATA bloqueado por F-PR7-01); 1807 0081 y 0083 reaplicables (idempotentes).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkConsentOwnerInventory } from "../../../src/infra/adapters/postgres/consent-owner-inventory.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { recordRh3, seedCaseWorld, seedConfirmedWithoutApplied, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import { CLUSTER_PREFLIGHT_SQL } from "../../../src/infra/adapters/postgres/migrate.ts";
import { MIGRATIONS_DIR, pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const NEW_ROLES = ["app_schema_owner", "ops_schema_owner", "shared_fn_owner", "revocation_recovery_reader"] as const;

/** Ejecuta `sql` como consent_owner (el migrador) dentro de un SAVEPOINT y exige el SQLSTATE dado. */
async function denied(migrator: import("pg").Client, sql: string, code = "42501"): Promise<void> {
  await migrator.query("SAVEPOINT x");
  await assert.rejects(() => migrator.query(sql), (e: unknown) => codeOf(e) === code, sql);
  await migrator.query("ROLLBACK TO x");
}

pgTest("TEST-CNS-1800 pg: los 4 roles de PR-7c son NOLOGIN/NOSUPERUSER/NOBYPASSRLS, sin miembros salvo consent_owner (SET, sin herencia ni ADMIN) y no son miembros de nadie", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const attrs = (await admin.query("SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin FROM pg_roles WHERE rolname = ANY($1) ORDER BY 1", [[...NEW_ROLES]])).rows;
  assert.deepEqual(attrs, [...NEW_ROLES].sort().map((rolname) => ({ rolname, rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false, rolreplication: false, rolcanlogin: false })));
  const edges = (await admin.query<{ member: string; role: string; inherit_option: boolean; set_option: boolean; admin_option: boolean }>(
    `SELECT u.rolname AS member, r.rolname AS role, m.inherit_option, m.set_option, m.admin_option FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
      WHERE r.rolname = ANY($1) OR u.rolname = ANY($1) ORDER BY 2, 1`, [[...NEW_ROLES]],
  )).rows;
  // PR-7d (0086): ddl_breakglass tambien es miembro (SET, sin herencia ni ADMIN) de los 4 roles; nadie mas.
  assert.deepEqual(edges, [...NEW_ROLES].sort().flatMap((role) => ["consent_owner", "ddl_breakglass"].map((member) => ({ member, role, inherit_option: false, set_option: true, admin_option: false }))));
});

pgTest("TEST-CNS-1801 pg (Q16, FN-6): revocation y rights_case estan en case_state, de case_state_owner; consent_owner (y el migrador) no puede DROP, DISABLE TRIGGER, ALTER ni leerlas; app.revocation ya no existe", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rels = (await admin.query<{ q: string; owner: string; force: boolean }>(
    "SELECT n.nspname || '.' || c.relname AS q, pg_get_userbyid(c.relowner) AS owner, c.relforcerowsecurity AS force FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname IN ('revocation', 'rights_case') AND c.relkind = 'r' ORDER BY 1",
  )).rows;
  assert.deepEqual(rels, [{ q: "case_state.revocation", owner: "case_state_owner", force: true }, { q: "case_state.rights_case", owner: "case_state_owner", force: true }]);
  const trg = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'case_state' AND c.relname IN ('revocation', 'rights_case') AND NOT t.tgisinternal AND t.tgenabled = 'A'")).rows[0];
  assert.equal(trg?.n, 6, "6 triggers ENABLE ALWAYS intactos");
  // Ningun cuerpo de funcion nombra ya las tablas viejas.
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p WHERE p.prosrc ~ '\\mapp\\.(revocation|rights_case)\\M'")).rowCount, 0);
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await denied(migrator, "SELECT 1 FROM case_state.revocation"); // sin USAGE sobre case_state
    // Con USAGE concedido (dentro del ROLLBACK) el rechazo ya es por DUEÑO/privilegio de tabla, no por el esquema.
    await migrator.query("SET LOCAL ROLE case_state_owner");
    await migrator.query("GRANT USAGE ON SCHEMA case_state TO consent_owner");
    await migrator.query("SET LOCAL ROLE consent_owner");
    for (const t of ["case_state.revocation", "case_state.rights_case"]) {
      await denied(migrator, `DROP TABLE ${t}`);
      await denied(migrator, `ALTER TABLE ${t} DISABLE TRIGGER ALL`);
      await denied(migrator, `ALTER TABLE ${t} NO FORCE ROW LEVEL SECURITY`);
      await denied(migrator, `ALTER TABLE ${t} ADD COLUMN x_1801 int`);
      await denied(migrator, `CREATE TRIGGER x_1801 BEFORE INSERT ON ${t} FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger()`);
      await denied(migrator, `SELECT 1 FROM ${t}`);
    }
    await denied(migrator, "DROP SCHEMA case_state CASCADE");
  } finally {
    await migrator.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1802 pg (F-PR7-01, C-3): app.current_tenant_id, app.is_reserved_email y ops.catalog_environment son de shared_fn_owner con ACL de EXECUTE conservada; consent_owner no puede CREATE OR REPLACE, ALTER ni DROP, y no las ejecuta", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const fns = (await admin.query<{ q: string; owner: string; acl: string }>(
    `SELECT n.nspname || '.' || p.proname AS q, pg_get_userbyid(p.proowner) AS owner,
            (SELECT string_agg(pg_get_userbyid(a.grantee) || ':' || pg_get_userbyid(a.grantor), ',' ORDER BY pg_get_userbyid(a.grantee)) FROM aclexplode(p.proacl) a) AS acl
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.proname IN ('current_tenant_id', 'is_reserved_email', 'catalog_environment') ORDER BY 1`,
  )).rows;
  assert.deepEqual(fns.map((f) => [f.q, f.owner]), [["app.current_tenant_id", "shared_fn_owner"], ["app.is_reserved_email", "shared_fn_owner"], ["ops.catalog_environment", "shared_fn_owner"]]);
  for (const f of fns) {
    assert.ok(!f.acl.includes("consent_owner"), `${f.q}: sin entradas de consent_owner`);
    for (const e of f.acl.split(",")) assert.equal(e.split(":")[1], "shared_fn_owner", `${f.q}: grantor ${e}`);
  }
  for (const role of ["app_rw", "worker", "platform_rw"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_function_privilege($1, 'app.current_tenant_id()', 'EXECUTE') AS p", [role])).rows[0]?.p, true, role);
  }
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await denied(migrator, "CREATE OR REPLACE FUNCTION app.current_tenant_id() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$");
    await denied(migrator, "CREATE OR REPLACE FUNCTION ops.catalog_environment() RETURNS text LANGUAGE sql AS $$ SELECT 'LOCAL'::text $$");
    await denied(migrator, "ALTER FUNCTION app.is_reserved_email(text) SET search_path = public");
    await denied(migrator, "DROP FUNCTION app.current_tenant_id()");
    await denied(migrator, "SELECT app.current_tenant_id()");
  } finally {
    await migrator.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1803 pg (F-PR7-01, R-21-1/FN-12): app y ops son de owners NOLOGIN; consent_owner conserva USAGE, CREATE y crea objetos propios, pero no hace DROP SCHEMA ni DROP de objetos ajenos (security_event, funciones de otros owners)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const owners = (await admin.query<{ s: string; o: string }>("SELECT nspname AS s, pg_get_userbyid(nspowner) AS o FROM pg_namespace WHERE nspname IN ('app', 'ops') ORDER BY 1")).rows;
  assert.deepEqual(owners, [{ s: "app", o: "app_schema_owner" }, { s: "ops", o: "ops_schema_owner" }]);
  for (const s of ["app", "ops"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_schema_privilege('consent_owner', $1, 'USAGE') AND has_schema_privilege('consent_owner', $1, 'CREATE') AS p", [s])).rows[0]?.p, true);
    assert.equal((await admin.query<{ p: boolean }>("SELECT pg_has_role('consent_owner', nspowner, 'USAGE') AS p FROM pg_namespace WHERE nspname = $1", [s])).rows[0]?.p, false, `consent_owner no hereda al dueño de ${s}`);
  }
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await denied(migrator, "DROP SCHEMA app CASCADE");
    await denied(migrator, "DROP SCHEMA ops CASCADE");
    await denied(migrator, "DROP TABLE ops.security_event");
    await denied(migrator, "DROP FUNCTION case_state.apply_revocation(text, integer)");
    await denied(migrator, "DROP FUNCTION app.rights_case_tenant_of(text)");
    await denied(migrator, "ALTER SCHEMA app OWNER TO consent_owner");
    // Sigue pudiendo crear y borrar objetos PROPIOS (las migraciones siguen creando tablas en app/ops).
    await migrator.query("CREATE TABLE app.probe_1803 (a int)");
    await migrator.query("DROP TABLE app.probe_1803");
  } finally {
    await migrator.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1804 pg (F-6D3-SEC-08): list_confirmed_unapplied es de revocation_recovery_reader; la unica lectura cross-tenant de revocation es su policy; transition_owner no tiene policy cross-tenant; el worker descubre CONFIRMED solo por la funcion", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1804");
  const http = await startPlatformHttp(ctx);
  try {
    await recordRh3(admin, http, w);
  } finally {
    await http.close();
  }
  await seedConfirmedWithoutApplied(admin, w);
  const fn = (await admin.query<{ owner: string; secdef: boolean; cfg: string[] }>(
    "SELECT pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS cfg FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'list_confirmed_unapplied'",
  )).rows[0];
  assert.deepEqual(fn, { owner: "revocation_recovery_reader", secdef: true, cfg: ["search_path=pg_catalog, pg_temp"] });
  const policies = (await admin.query<{ polname: string; roles: string[]; qual: string }>(
    "SELECT policyname AS polname, roles::text[] AS roles, qual FROM pg_policies WHERE schemaname = 'case_state' AND tablename = 'revocation' AND qual NOT LIKE '%current_tenant_id%' ORDER BY 1",
  )).rows.filter((p) => !p.roles.includes("integrity_reconciler"));
  assert.deepEqual(policies, [{ polname: "revocation_recovery_reader_select", roles: ["revocation_recovery_reader"], qual: "(status = 'CONFIRMED'::text)" }]);
  assert.equal((await admin.query("SELECT 1 FROM pg_policies WHERE schemaname = 'case_state' AND tablename = 'revocation' AND 'transition_owner' = ANY(roles) AND qual LIKE '%CONFIRMED%'")).rowCount, 0);
  // Como transition_owner sin tenant: 0 filas (no hay lectura cross-tenant).
  await admin.query("BEGIN");
  try {
    await admin.query("SET LOCAL ROLE transition_owner");
    assert.equal((await admin.query("SELECT 1 FROM case_state.revocation")).rowCount, 0, "transition_owner sin tenant no ve filas");
  } finally {
    await admin.query("ROLLBACK");
  }
  // El rol: columnas exactas.
  const cols = (await admin.query<{ attname: string }>(
    "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'case_state.revocation'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('revocation_recovery_reader', a.attrelid, a.attnum, 'SELECT') ORDER BY 1",
  )).rows.map((r) => r.attname);
  assert.deepEqual(cols, ["created_at", "revocation_ref", "status", "tenant_id"]);
  const worker = await ctx.connectAs("worker");
  const appRw = await ctx.connectAs("app_rw");
  assert.deepEqual((await worker.query("SELECT * FROM case_state.list_confirmed_unapplied(100, ARRAY[]::text[]) WHERE o_revocation_ref = $1", [w.revocationRef])).rows, [{ o_tenant_id: w.tenantId, o_revocation_ref: w.revocationRef }]);
  assert.equal((await worker.query("SELECT 1 FROM case_state.revocation")).rowCount, 0, "lectura directa del worker sin tenant: 0 filas");
  await assert.rejects(appRw.query("SELECT * FROM case_state.list_confirmed_unapplied(10, ARRAY[]::text[])"), (e: unknown) => codeOf(e) === "42501");
});

pgTest("TEST-CNS-1805 pg (F-PR7-01, C-3): el inventario por catalogo de consent_owner coincide con la allowlist; sin V1 ni V4; detecta un trigger, una policy con funcion de consent_owner y una funcion nueva", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  assert.deepEqual(await checkConsentOwnerInventory(admin), []);
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("CREATE FUNCTION app.trojan_1805() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$");
    await migrator.query("CREATE TRIGGER trojan_1805 BEFORE INSERT ON app.outbox FOR EACH ROW EXECUTE FUNCTION app.trojan_1805()");
    const found = await checkConsentOwnerInventory(migrator);
    assert.ok(found.some((p) => p.includes("V2|fn|consent_owner|app.trojan_1805()")), found.join(" | "));
    assert.ok(found.some((p) => p.includes("V2|trigger|app.outbox|trojan_1805")), found.join(" | "));
  } finally {
    await migrator.query("ROLLBACK");
  }
  // V1: una funcion de consent_owner usada por una policy de una tabla de OTRO dueño (case_state_owner) se detecta (superusuario: la creacion directa del atacante esta cubierta por 1801).
  await admin.query("BEGIN");
  try {
    await admin.query("CREATE FUNCTION app.v1_probe_1805() RETURNS boolean LANGUAGE sql AS 'SELECT true'");
    await admin.query("ALTER FUNCTION app.v1_probe_1805() OWNER TO consent_owner");
    await admin.query("CREATE POLICY v1_probe_1805 ON case_state.rights_case FOR SELECT TO app_rw USING (app.v1_probe_1805())");
    const found = await checkConsentOwnerInventory(admin);
    assert.ok(found.some((p) => p.includes("V1|policy|case_state.rights_case|v1_probe_1805|app.v1_probe_1805")), found.join(" | "));
  } finally {
    await admin.query("ROLLBACK");
  }
  assert.deepEqual(await checkConsentOwnerInventory(admin), [], "los ROLLBACK dejaron el catalogo intacto");
  // Revision de seguridad 7c (P1-1, P1-2): cada cambio de superficie del migrador se detecta (cada uno en su transaccion, con ROLLBACK).
  const mutations: Array<{ name: string; sql: string[]; expect: RegExp }> = [
    { name: "CREATE OR REPLACE de una funcion de disparador (el dueño sigue siendo shared_fn_owner; se llega por app_schema_owner + SET, R-22)", sql: ["CREATE OR REPLACE FUNCTION app.invitation_otp_exhausted_monotonic() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NEW; END $$"], expect: /V2\|fn\|shared_fn_owner\|app\.invitation_otp_exhausted_monotonic\(\)/ },
    { name: "DISABLE ROW LEVEL SECURITY", sql: ["ALTER TABLE app.outbox DISABLE ROW LEVEL SECURITY"], expect: /V2\|acl\|app\.outbox\|false\|/ },
    { name: "NO FORCE ROW LEVEL SECURITY", sql: ["ALTER TABLE app.outbox NO FORCE ROW LEVEL SECURITY"], expect: /V2\|acl\|app\.outbox\|true\|false\|/ },
    { name: "ALTER POLICY USING", sql: ["ALTER POLICY outbox_tenant_select ON app.outbox USING (true)"], expect: /V2\|policy\|app\.outbox\|outbox_tenant_select\|/ },
    { name: "DROP de un CHECK sin funciones", sql: ["ALTER TABLE app.outbox DROP CONSTRAINT outbox_status_enum"], expect: /falta respecto de la allowlist.*V2\|constraint\|app\.outbox\|outbox_status_enum\|/ },
    { name: "DROP DEFAULT sin funciones", sql: ["ALTER TABLE app.outbox ALTER COLUMN status DROP DEFAULT"], expect: /falta respecto de la allowlist.*V2\|default\|app\.outbox\|status\|/ },
    { name: "ALTER TRIGGER ... DISABLE (tgenabled)", sql: ["ALTER TABLE app.outbox DISABLE TRIGGER outbox_envelope_immutable"], expect: /V2\|trigger\|app\.outbox\|outbox_envelope_immutable\|D\|/ },
  ];
  for (const m of mutations) {
    await admin.query("BEGIN");
    try {
      for (const stmt of m.sql) await admin.query(stmt);
      const found = await checkConsentOwnerInventory(admin);
      assert.ok(found.some((p) => m.expect.test(p)), `${m.name}: no detectado -> ${found.join(" | ")}`);
    } finally {
      await admin.query("ROLLBACK");
    }
  }
  assert.deepEqual(await checkConsentOwnerInventory(admin), [], "los ROLLBACK de las mutaciones dejaron el catalogo intacto");
  // P2-6 (residual R-22 explicito, no "imposible"): consent_owner SI puede hacer SET ROLE a shared_fn_owner y app_schema_owner (membresia SET sin INHERIT, 0080); lo cubre el inventario (V2|fn con md5(prosrc)), no la prevencion.
  for (const role of ["shared_fn_owner", "app_schema_owner"]) {
    assert.equal((await admin.query<{ r: boolean }>("SELECT pg_has_role('consent_owner', $1, 'SET') AS r", [role])).rows[0]?.r, true, `consent_owner puede SET ROLE ${role} (R-22)`);
  }
});

pgTest("TEST-CNS-1806 pg (C-3): el arranque incluye el inventario y REAL_DATA queda bloqueado mientras F-PR7-01 siga abierto", async (ctx) => {
  const appRw = await ctx.connectAs("app_rw");
  const ok = await runStartupChecks(appRw, { expectedRole: "app_rw", expectedEnvironment: "LOCAL" });
  assert.deepEqual(ok.failures, []);
  const real = await runStartupChecks(appRw, { expectedRole: "app_rw", expectedEnvironment: "LOCAL", roleMode: "REAL_DATA" });
  assert.equal(real.ok, false);
  assert.ok(real.failures.some((f) => f.includes("REAL_DATA") && f.includes("F-PR7-01")), real.failures.join(" | "));
  // Un trojan visible para el rol de runtime hace fallar el arranque (superusuario crea una funcion de consent_owner referida por un default de otro dueño).
  const admin = await ctx.connectAsSuperuser();
  await admin.query("BEGIN");
  try {
    await admin.query("CREATE VIEW app.rule_probe_1806 AS SELECT 1 AS a");
    await admin.query("ALTER TABLE app.rule_probe_1806 OWNER TO consent_owner");
    await admin.query("COMMIT");
  } catch (error) {
    await admin.query("ROLLBACK");
    throw error;
  }
  try {
    const bad = await runStartupChecks(appRw, { expectedRole: "app_rw", expectedEnvironment: "LOCAL" });
    assert.equal(bad.ok, false, "una relacion nueva de consent_owner con ACL fuera de la allowlist falla el arranque");
    assert.ok(bad.failures.some((f) => f.includes("F-PR7-01") && f.includes("rule_probe_1806")), bad.failures.join(" | "));
  } finally {
    await admin.query("DROP VIEW app.rule_probe_1806");
  }
});

pgTest("TEST-CNS-1807 pg: 0081 y 0083 son reaplicables (idempotentes) y dejan el mismo estado", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const snapshot = async (): Promise<string> => (await admin.query<{ s: string }>(
    `SELECT md5(string_agg(x, E'\\n' ORDER BY x)) AS s FROM (
       SELECT 'rel|' || n.nspname || '.' || c.relname || '|' || pg_get_userbyid(c.relowner) || '|' || coalesce(c.relacl::text, '') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('app', 'case_state', 'ops') AND c.relkind = 'r'
       UNION ALL SELECT 'fn|' || n.nspname || '.' || p.proname || '|' || pg_get_userbyid(p.proowner) || '|' || coalesce(p.proacl::text, '') || '|' || md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('app', 'case_state', 'ops', 'platform', 'ledger_gen')
       UNION ALL SELECT 'pol|' || polrelid::regclass || '|' || polname || '|' || polroles::text FROM pg_policy
       UNION ALL SELECT 'nsp|' || nspname || '|' || pg_get_userbyid(nspowner) || '|' || coalesce(nspacl::text, '') FROM pg_namespace WHERE nspname IN ('app', 'ops', 'case_state')) t(x)`,
  )).rows[0]!.s;
  const before = await snapshot();
  // PR-7d: 0083 asevera que consent_owner es el unico miembro de revocation_recovery_reader y ddl_breakglass (0086) tambien lo es. El replay corre como superusuario con SET LOCAL ROLE consent_owner, tras el preflight del
  // runner (sin membresias de ddl_breakglass) y con ROLLBACK, dentro del lock de roles: la membresia no se modifica fuera de la transaccion. El migrador ya no es quien las ejecuta aqui (su camino real es el runner).
  await ctx.withRoleCatalogLock(async () => {
    await admin.query("BEGIN");
    try {
      await admin.query(CLUSTER_PREFLIGHT_SQL);
      for (const file of ["0081_adr010_pr7c_q16_move_revocation_rights_case.sql", "0083_adr010_pr7c_recovery_reader_owner.sql"]) {
        await admin.query("SET LOCAL ROLE consent_owner");
        await admin.query(readFileSync(join(MIGRATIONS_DIR, file), "utf8"));
        await admin.query("RESET ROLE");
      }
      assert.equal(await snapshot(), before);
    } finally {
      await admin.query("ROLLBACK");
    }
  });
});
