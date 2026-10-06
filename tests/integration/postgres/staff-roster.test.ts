// Gobierna: API-CNS-116 (GET /staff/roster), db/migrations/0018..0020, diseno api-cns-116-staff-list-design.md rev. 2 §5/§6/§10,
// SEC-CNS-018 rev. 2 (R1, R2, R3, R6, F-7), DEC-BR-019 (Notion). TEST-CNS-1070..1074 (contrato compartido, via el
// adaptador Postgres), 1075 (roles/grants/RLS de la vista), 1076 (CHECK de state vs ramas del CASE), 1077 (dependencias
// de la vista), 1078 (fallos -> 503 sin datos), 1079 (el adaptador solo consulta la vista), 1092 (access_log 0020).
// Requiere Postgres real (harness.ts); skip sin entorno. Solo datos sinteticos.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Client } from "pg";

import { createPgStaffRosterReader } from "../../../src/infra/adapters/postgres/staff-roster.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { StaffRosterUnavailableError } from "../../../src/server/ports/staff-roster.port.ts";
import { runStaffRosterContract, type RosterHarness, type RosterScene } from "../../contract/ports/staff-roster.contract.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest, type PgTestContext } from "./harness.ts";

const VIEW = "app.staff_roster_invitation_status";
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

async function seedScene(admin: Client, scene: RosterScene): Promise<void> {
  for (const subjectRef of scene.subjects) {
    await admin.query("INSERT INTO app.subject (tenant_id, subject_ref) VALUES ($1, $2)", [scene.tenantId, subjectRef]);
  }
  for (const p of scene.participations) {
    await admin.query(
      "INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, $2, $3, 'LECTORPRO', 'ACTIVE')",
      [scene.tenantId, p.participationRef, p.contextRef],
    );
  }
  let n = 0;
  for (const e of scene.enrollments ?? []) {
    n += 1;
    await admin.query(
      "INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state) VALUES ($1, $2, $3, $4, $5)",
      [scene.tenantId, fixtureUuid(`enr-${scene.tenantId}-${n}`), e.subjectRef, e.participationRef, e.state],
    );
  }
  for (const i of scene.invitations ?? []) {
    n += 1;
    // created_at creciente en orden de la escena (la ultima es la mas reciente); expires_at relativo al reloj de la BD.
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, expires_at, created_at)
       VALUES ($1, $2, $3, 'LECTORPRO', $4, $5,
               CASE WHEN $6::double precision IS NULL THEN NULL ELSE now() + make_interval(secs => $6::double precision / 1000.0) END,
               now() - interval '1 day' + make_interval(secs => $7::double precision))`,
      [scene.tenantId, fixtureUuid(`inv-${scene.tenantId}-${n}`), i.contextRef, i.subjectRef, i.state, i.expiresInMs, n],
    );
  }
}

async function withPool<T>(ctx: PgTestContext, work: (uow: PgUnitOfWork) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    return await work(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

async function accessLogRows(admin: Client, tenantId: string): Promise<{ actorRef: string; resourceRef: string }[]> {
  const r = await admin.query<{ actor_ref: string; resource_ref: string }>(
    "SELECT actor_ref, resource_ref FROM ops.access_log WHERE tenant_id = $1 AND action = 'STAFF_ROSTER_READ' AND resource_type = 'STAFF_ROSTER' ORDER BY access_seq",
    [tenantId],
  );
  return r.rows.map((row) => ({ actorRef: row.actor_ref, resourceRef: row.resource_ref }));
}

// --- Contrato compartido (1070..1074) contra la vista real, via el adaptador Postgres ---------------------------
runStaffRosterContract("postgres", (name, body) => {
  pgTest(name, async (ctx) => {
    const admin = await ctx.connectAsSuperuser();
    await withPool(ctx, async (uow) => {
      const reader = createPgStaffRosterReader(uow);
      const harness: RosterHarness = {
        seed: (scene) => seedScene(admin, scene),
        read: (request) =>
          reader.readPage({
            tenantId: request.tenantId,
            principalRef: request.principalRef ?? fixtureUuid("staff-default"),
            actorRole: "TENANT_ADMIN",
            after: request.after ?? null,
            rowLimit: request.rowLimit,
          }),
        accessLogRows: (tenantId) => accessLogRows(admin, tenantId),
      };
      await body(harness);
    });
  });
});

// --- 1075: roles, grants, RLS, opciones de la vista (R1, R2, T-16) ------------------------------------------------
pgTest("TEST-CNS-1075 pg: la vista es de staff_roster_owner (security_invoker=false, barrier), columnas minimas, grants por columna, policies por tabla base, app_rw sin SELECT sin SET ROLE y el lector sin acceso a tablas base", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const tenant = fixtureUuid("t1075");
  const other = fixtureUuid("t1075-other");
  await seedScene(admin, {
    tenantId: tenant,
    subjects: [fixtureUuid("s1075")],
    participations: [{ participationRef: fixtureUuid("p1075"), contextRef: "CTX_A" }],
    invitations: [{ subjectRef: fixtureUuid("s1075"), contextRef: "CTX_A", state: "SENT", expiresInMs: 3_600_000 }],
  });

  const rel = (await admin.query<{ owner: string; opts: string[] | null; kind: string }>(
    `SELECT pg_get_userbyid(relowner) AS owner, reloptions AS opts, relkind AS kind FROM pg_class WHERE oid = '${VIEW}'::regclass`,
  )).rows[0];
  assert.equal(rel?.kind, "v");
  assert.equal(rel?.owner, "staff_roster_owner");
  assert.ok(rel?.opts?.includes("security_barrier=true"));
  assert.ok(!rel?.opts?.includes("security_invoker=true"), "security_invoker=false (la vista corre con los privilegios de su dueno, que solo ve su tenant por RLS)");

  const columns = (await admin.query<{ attname: string }>(
    `SELECT attname FROM pg_attribute WHERE attrelid = '${VIEW}'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`,
  )).rows.map((r) => r.attname);
  assert.deepEqual(columns, ["subject_ref", "context_ref", "active_enrollment_participation_ref", "staff_status"]);

  // Membresias (R1/R2): consent_owner SET sin INHERIT; app_rw solo del lector (INHERIT FALSE, SET TRUE); nadie mas.
  const hasRole = async (member: string, role: string, mode: string): Promise<boolean> =>
    (await admin.query<{ r: boolean }>("SELECT pg_has_role($1, $2, $3) AS r", [member, role, mode])).rows[0]?.r === true;
  assert.equal(await hasRole("consent_owner", "staff_roster_owner", "MEMBER"), true);
  assert.equal(await hasRole("consent_owner", "staff_roster_owner", "USAGE"), false, "consent_owner no hereda los privilegios del dueno de la vista");
  for (const role of ["app_rw", "worker", "platform_rw"]) assert.equal(await hasRole(role, "staff_roster_owner", "MEMBER"), false, `${role} no es miembro del dueno`);
  assert.equal(await hasRole("app_rw", "staff_roster_reader", "MEMBER"), true);
  assert.equal(await hasRole("app_rw", "staff_roster_reader", "USAGE"), false, "app_rw no hereda del lector");
  for (const role of ["worker", "platform_rw"]) assert.equal(await hasRole(role, "staff_roster_reader", "MEMBER"), false);
  const mem = (await admin.query<{ inherit_option: boolean; set_option: boolean }>(
    `SELECT m.inherit_option, m.set_option FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
      WHERE r.rolname = 'staff_roster_reader' AND u.rolname = 'app_rw'`,
  )).rows;
  assert.deepEqual(mem, [{ inherit_option: false, set_option: true }]);
  const attrs = (await admin.query<{ rolsuper: boolean; rolbypassrls: boolean; rolcanlogin: boolean; rolcreaterole: boolean }>(
    "SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreaterole FROM pg_roles WHERE rolname IN ('staff_roster_owner', 'staff_roster_reader')",
  )).rows;
  assert.equal(attrs.length, 2);
  for (const a of attrs) assert.deepEqual(a, { rolsuper: false, rolbypassrls: false, rolcanlogin: false, rolcreaterole: false });

  // Ni el dueno ni el lector conservan CREATE en ningun esquema.
  const create = (await admin.query<{ nspname: string }>(
    `SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
        AND (has_schema_privilege('staff_roster_owner', oid, 'CREATE') OR has_schema_privilege('staff_roster_reader', oid, 'CREATE'))`,
  )).rows;
  assert.deepEqual(create, []);

  // Grants: lector = solo SELECT de la vista; runtime = nada sobre la vista; dueno = SELECT por columna exacto.
  const priv = async (role: string, relName: string, p: string): Promise<boolean> =>
    (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, $2, $3) AS p", [role, relName, p])).rows[0]?.p === true;
  assert.equal(await priv("staff_roster_reader", VIEW, "SELECT"), true);
  for (const p of ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) assert.equal(await priv("staff_roster_reader", VIEW, p), false, `reader ${p}`);
  for (const role of ["app_rw", "worker", "platform_rw"]) {
    for (const p of ["SELECT", "INSERT", "UPDATE", "DELETE"]) assert.equal(await priv(role, VIEW, p), false, `${role} ${p} ${VIEW}`);
  }
  const cols = async (table: string, role: string): Promise<string[]> =>
    (await admin.query<{ attname: string }>(
      `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege($2, a.attrelid, a.attnum, 'SELECT') ORDER BY a.attname`,
      [table, role],
    )).rows.map((r) => r.attname);
  assert.deepEqual(await cols("app.invitation", "staff_roster_owner"), ["context_ref", "created_at", "expires_at", "invitation_ref", "state", "subject_ref", "tenant_id"]);
  assert.deepEqual(await cols("app.subject", "staff_roster_owner"), ["subject_ref", "tenant_id"]);
  assert.deepEqual(await cols("app.enrollment", "staff_roster_owner"), ["participation_ref", "state", "subject_ref", "tenant_id"]);
  assert.deepEqual(await cols("app.school_participation", "staff_roster_owner"), ["context_ref", "participation_ref", "tenant_id"]);
  for (const t of ["app.invitation", "app.subject", "app.enrollment", "app.school_participation"]) {
    assert.deepEqual(await cols(t, "staff_roster_reader"), [], `el lector no lee ${t}`);
    for (const p of ["INSERT", "UPDATE", "DELETE", "TRUNCATE"]) assert.equal(await priv("staff_roster_owner", t, p), false, `el dueno no escribe ${t}`);
  }

  // Policies: una por tabla base, TO staff_roster_owner, por app.current_tenant_id(), FORCE RLS intacto.
  const pol = (await admin.query<{ tablename: string; roles: string[]; cmd: string; qual: string }>(
    "SELECT tablename, roles::text[] AS roles, cmd, qual FROM pg_policies WHERE schemaname = 'app' AND policyname ~ '_roster_owner_select$' ORDER BY tablename",
  )).rows;
  assert.deepEqual(pol.map((p) => p.tablename), ["enrollment", "invitation", "school_participation", "subject"]);
  for (const p of pol) {
    assert.deepEqual(p.roles, ["staff_roster_owner"]);
    assert.equal(p.cmd, "SELECT");
    assert.match(p.qual, /app\.current_tenant_id\(\)/);
  }
  const forced = (await admin.query<{ relname: string; f: boolean }>(
    "SELECT relname, (relrowsecurity AND relforcerowsecurity) AS f FROM pg_class WHERE oid IN ('app.invitation'::regclass, 'app.subject'::regclass, 'app.enrollment'::regclass, 'app.school_participation'::regclass)",
  )).rows;
  assert.ok(forced.every((r) => r.f));

  // app_rw SIN SET ROLE: permiso denegado sobre la vista; tampoco con el tenant fijado.
  const app = await ctx.connectAs("app_rw");
  await assert.rejects(() => app.query(`SELECT * FROM ${VIEW}`), (e: unknown) => codeOf(e) === "42501");
  await app.query("BEGIN");
  try {
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
    await assert.rejects(() => app.query(`SELECT subject_ref FROM ${VIEW}`), (e: unknown) => codeOf(e) === "42501");
    await app.query("ROLLBACK");
  } finally {
    await app.query("ROLLBACK").catch(() => {});
  }
  // Con SET LOCAL ROLE staff_roster_reader: ve la vista de SU tenant; no ve las tablas base ni columnas sensibles.
  await app.query("BEGIN");
  try {
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
    await app.query("SET LOCAL ROLE staff_roster_reader");
    assert.equal((await app.query<{ me: string }>("SELECT current_user::text AS me")).rows[0]?.me, "staff_roster_reader");
    const rows = (await app.query<{ staff_status: string }>(`SELECT staff_status FROM ${VIEW}`)).rows;
    assert.deepEqual(rows.map((r) => r.staff_status), ["SENT"]);
    await app.query("SAVEPOINT s1");
    for (const sql of ["SELECT state FROM app.invitation", "SELECT * FROM app.invitation", "SELECT subject_ref FROM app.subject", "SELECT 1 FROM app.enrollment", "SELECT 1 FROM app.school_participation", "SELECT 1 FROM ops.access_log"]) {
      await assert.rejects(() => app.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
      await app.query("ROLLBACK TO SAVEPOINT s1");
    }
    for (const sql of [`UPDATE ${VIEW} SET staff_status = 'SENT'`, `DELETE FROM ${VIEW}`]) {
      // La vista no es actualizable (55000) y, aunque lo fuera, el lector no tiene INSERT/UPDATE/DELETE (42501).
      await assert.rejects(() => app.query(sql), (e: unknown) => codeOf(e) === "42501" || codeOf(e) === "55000", sql);
      await app.query("ROLLBACK TO SAVEPOINT s1");
    }
    await app.query("ROLLBACK");
  } finally {
    await app.query("ROLLBACK").catch(() => {});
  }
  // Otro tenant fijado: 0 filas del tenant 1075 (RLS por tenant bajo el dueno de la vista).
  await app.query("BEGIN");
  try {
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [other]);
    await app.query("SET LOCAL ROLE staff_roster_reader");
    assert.deepEqual((await app.query(`SELECT 1 FROM ${VIEW}`)).rows, []);
    await app.query("ROLLBACK");
  } finally {
    await app.query("ROLLBACK").catch(() => {});
  }
  // Sin tenant fijado (NULL): 0 filas.
  await app.query("BEGIN");
  try {
    await app.query("SET LOCAL ROLE staff_roster_reader");
    assert.deepEqual((await app.query(`SELECT 1 FROM ${VIEW}`)).rows, []);
    await app.query("ROLLBACK");
  } finally {
    await app.query("ROLLBACK").catch(() => {});
  }
  // worker y platform_rw no pueden asumir el lector.
  for (const role of ["worker", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(() => c.query("SET ROLE staff_roster_reader"), (e: unknown) => codeOf(e) === "42501");
  }
  // El dueno de la vista (como superusuario con SET ROLE) solo ve su tenant en las tablas base y nunca las columnas sensibles.
  await admin.query("BEGIN");
  try {
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [other]);
    await admin.query("SET LOCAL ROLE staff_roster_owner");
    assert.deepEqual((await admin.query("SELECT 1 FROM app.invitation")).rows, [], "dueno con otro tenant: 0 filas");
    await admin.query("SAVEPOINT s2");
    for (const col of ["recipient_channel_ref", "token_hash", "bound_decision_maker_ref", "consent_version"]) {
      await assert.rejects(() => admin.query(`SELECT ${col} FROM app.invitation`), (e: unknown) => codeOf(e) === "42501", col);
      await admin.query("ROLLBACK TO SAVEPOINT s2");
    }
    await admin.query("ROLLBACK");
  } finally {
    await admin.query("ROLLBACK").catch(() => {});
  }

  // Chequeos de arranque de R2 sobre la base real.
  const checks = await runStartupChecks(app, { expectedEnvironment: "LOCAL", expectedRole: "app_rw" });
  assert.deepEqual(checks, { ok: true, failures: [] });
  for (const role of ["worker", "platform_rw"] as const) {
    assert.deepEqual(await runStartupChecks(await ctx.connectAs(role), { expectedEnvironment: "LOCAL" }), { ok: true, failures: [] }, role);
  }
});

// --- 1076: CHECK invitation_state_enum == ramas del CASE de la vista (T-11) -----------------------------------------
/** Estados `state` que nombra el CASE externo de staff_status en pg_get_viewdef: solo los comparados contra `inv.state`
 * (los nombres de las etiquetas de salida, p. ej. 'SENT', no cuentan aunque coincidan con un estado). */
export function caseStates(viewDef: string): string[] {
  const end = viewDef.indexOf("END AS staff_status");
  assert.ok(end > 0, "pg_get_viewdef no contiene END AS staff_status");
  const segment = viewDef.slice(viewDef.lastIndexOf("CASE", end), end);
  const states = new Set<string>();
  for (const m of segment.matchAll(/inv\.state\s*=\s*(?:'([A-Z_]+)'::text|ANY\s*\(ARRAY\[([^\]]*)\]\))/g)) {
    if (m[1] !== undefined) states.add(m[1]);
    for (const lit of (m[2] ?? "").matchAll(/'([A-Z_]+)'::text/g)) states.add(lit[1] as string);
  }
  return [...states].sort();
}

export function checkStates(constraintDef: string): string[] {
  return [...new Set([...constraintDef.matchAll(/'([A-Z_]+)'::text/g)].map((m) => m[1] as string))].sort();
}

async function catalogSets(admin: Client): Promise<{ check: string[]; branches: string[] }> {
  const check = (await admin.query<{ def: string }>(
    "SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'invitation_state_enum' AND conrelid = 'app.invitation'::regclass",
  )).rows[0]?.def;
  const viewDef = (await admin.query<{ def: string }>(`SELECT pg_get_viewdef('${VIEW}'::regclass, true) AS def`)).rows[0]?.def;
  assert.ok(check && viewDef);
  return { check: checkStates(check), branches: caseStates(viewDef) };
}

pgTest("TEST-CNS-1076 pg: los valores del CHECK invitation_state_enum son exactamente la union de las ramas del CASE de la vista; un estado nuevo hace fallar la comparacion", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const { check, branches } = await catalogSets(admin);
  assert.deepEqual(check, ["COMPLETED", "DECLINED", "DRAFT", "OPENED", "READY", "SENT", "VERIFIED"], "el CHECK vigente");
  assert.deepEqual(branches, check, "ramas del CASE == valores del CHECK");

  // Demostracion de que el test detecta un estado nuevo: se amplia el CHECK dentro de una tx que se revierte.
  await admin.query("BEGIN");
  try {
    await admin.query("ALTER TABLE app.invitation DROP CONSTRAINT invitation_state_enum");
    await admin.query(
      "ALTER TABLE app.invitation ADD CONSTRAINT invitation_state_enum CHECK (state IN ('DRAFT','READY','SENT','OPENED','VERIFIED','COMPLETED','DECLINED','EXPIRED','CANCELLED'))",
    );
    const widened = await catalogSets(admin);
    assert.deepEqual(widened.check.filter((s) => !widened.branches.includes(s)), ["CANCELLED", "EXPIRED"]);
    assert.notDeepEqual(widened.branches, widened.check, "con un estado nuevo la comparacion debe fallar");
  } finally {
    await admin.query("ROLLBACK");
  }
});

// --- 1077: sin dependencia de decision/revocacion/ledger/otp/outbox (T-17) -----------------------------------------
pgTest("TEST-CNS-1077 pg: la vista solo depende de subject, school_participation, invitation y enrollment (nada de decision, revocacion, ledger, otp ni outbox)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const deps = (await admin.query<{ rel: string }>(
    `SELECT DISTINCT d.refobjid::regclass::text AS rel
       FROM pg_depend d JOIN pg_rewrite r ON d.objid = r.oid AND d.classid = 'pg_rewrite'::regclass
      WHERE r.ev_class = '${VIEW}'::regclass AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> '${VIEW}'::regclass
      ORDER BY 1`,
  )).rows.map((r) => r.rel);
  assert.deepEqual(deps, ["app.enrollment", "app.invitation", "app.school_participation", "app.subject"]);
  const viewDef = (await admin.query<{ def: string }>(`SELECT pg_get_viewdef('${VIEW}'::regclass, true) AS def`)).rows[0]?.def ?? "";
  for (const forbidden of ["consent_decision", "receipt", "revocation", "rights_case", "otp", "audit_event", "outbox", "ledger", "token_hash", "recipient_channel_ref", "bound_decision_maker_ref", "consent_version"]) {
    assert.ok(!viewDef.includes(forbidden), `la vista no debe referenciar ${forbidden}`);
  }
  assert.match(viewDef, /current_tenant_id\(\)/);
  // Un CASE sin ELSE se deparsa como `ELSE NULL::text`: cualquier otro valor en ELSE seria una rama por defecto.
  const outer = viewDef.slice(viewDef.lastIndexOf("CASE", viewDef.indexOf("END AS staff_status")), viewDef.indexOf("END AS staff_status"));
  assert.deepEqual([...outer.matchAll(/ELSE\s+([^\n]+)/g)].map((m) => (m[1] ?? "").trim()), ["NULL::text"], "el CASE externo no tiene rama ELSE (desconocido -> NULL)");
});

// --- 1078: fallos -> StaffRosterUnavailableError sin datos (R3, T-18, F-7) -----------------------------------------
pgTest("TEST-CNS-1078 pg: staff_status NULL, rol no aplicado, reloj desfasado y access_log caido responden StaffRosterUnavailableError sin datos ni fila de log (ROLLBACK)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  await withPool(ctx, async (uow) => {
    const isUnavailable = (reason: string) => (e: unknown): boolean => e instanceof StaffRosterUnavailableError && e.reason === reason;
    const request = (tenantId: string) => ({ tenantId, principalRef: fixtureUuid("staff-1078"), actorRole: "TENANT_ADMIN" as const, after: null, rowLimit: 10 });

    // staff_status NULL: SENT sin vencimiento no tiene rama en el CASE -> 503 y ROLLBACK (sin fila de access_log).
    const t = fixtureUuid("t1078");
    await seedScene(admin, {
      tenantId: t,
      subjects: [fixtureUuid("s1078")],
      participations: [{ participationRef: fixtureUuid("p1078"), contextRef: "CTX_A" }],
      invitations: [{ subjectRef: fixtureUuid("s1078"), contextRef: "CTX_A", state: "SENT", expiresInMs: null }],
    });
    await assert.rejects(() => createPgStaffRosterReader(uow).readPage(request(t)), isUnavailable("unknown_status"));
    assert.deepEqual(await accessLogRows(admin, t), [], "ROLLBACK: sin fila de access_log");

    // current_user != staff_roster_reader (el SET ROLE no se aplico): 503 antes de consultar la vista.
    const t2 = fixtureUuid("t1078-b");
    await seedScene(admin, { tenantId: t2, subjects: [fixtureUuid("s1078-b")], participations: [{ participationRef: fixtureUuid("p1078-b"), contextRef: "CTX_A" }] });
    const noRole = {
      withTenantTx: <R>(tenantId: string, work: (tx: { query: (text: string, values?: readonly unknown[]) => Promise<unknown> }) => Promise<R>) =>
        uow.withTenantTx(tenantId, (tx) =>
          work({ query: (text, values) => (text.startsWith("SET LOCAL ROLE") ? tx.query("SELECT 1") : tx.query(text, values)) }),
        ),
    };
    await assert.rejects(
      () => createPgStaffRosterReader(noRole as unknown as PgUnitOfWork).readPage(request(t2)),
      isUnavailable("role_not_applied"),
    );
    assert.deepEqual(await accessLogRows(admin, t2), []);

    // Reloj: proceso adelantado 5 s respecto de la BD -> 503; sin fila de log.
    await assert.rejects(() => createPgStaffRosterReader(uow, { nowMs: () => Date.now() + 5000 }).readPage(request(t2)), isUnavailable("clock_skew"));
    assert.deepEqual(await accessLogRows(admin, t2), []);
    // Con relojes alineados la misma lectura funciona y deja UNA fila.
    assert.equal((await createPgStaffRosterReader(uow).readPage(request(t2))).length, 1);
    assert.equal((await accessLogRows(admin, t2)).length, 1);

    // access_log caido: un tenant_id que no es UUIDv4 hace fallar el CHECK de resource_ref -> 503 sin datos.
    const v1Tenant = "11111111-1111-1111-8111-111111111111"; // version 1, no v4
    await seedScene(admin, { tenantId: v1Tenant, subjects: [fixtureUuid("s1078-c")], participations: [{ participationRef: fixtureUuid("p1078-c"), contextRef: "CTX_A" }] });
    await assert.rejects(() => createPgStaffRosterReader(uow).readPage(request(v1Tenant)), isUnavailable("database"));
    assert.deepEqual(await accessLogRows(admin, v1Tenant), []);
  });
});

// --- 1079: estatico: el adaptador solo consulta la vista y no cambia a otro rol (R3) -------------------------------
pgTest("TEST-CNS-1079 estatico: staff-roster.adapter.ts solo consulta la vista, usa SET LOCAL ROLE staff_roster_reader y no contiene RESET ROLE ni otro SET ROLE", async () => {
  const source = readFileSync(join(MIGRATIONS_DIR, "..", "..", "src", "infra", "adapters", "postgres", "staff-roster.adapter.ts"), "utf8");
  // Se ignoran los comentarios de linea para no contar texto explicativo.
  const code = source.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  assert.ok(!/RESET\s+ROLE/i.test(code), "sin RESET ROLE");
  assert.ok(!/SET\s+SESSION\s+AUTHORIZATION|RESET\s+SESSION/i.test(code), "sin SET SESSION AUTHORIZATION");
  const setRoles = [...code.matchAll(/SET\s+(?:LOCAL\s+)?ROLE\s+([A-Za-z_]+)/gi)].map((m) => m[1]);
  assert.deepEqual(setRoles, ["staff_roster_reader"], "un unico SET ROLE, al lector");
  const fromTargets = [...code.matchAll(/\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_.]*)/g)].map((m) => m[1]);
  assert.deepEqual(fromTargets, ["app.staff_roster_invitation_status"], "el SELECT solo consulta la vista");
  assert.ok(!/\b(?:INSERT|UPDATE|DELETE)\s/i.test(code.replace(/createPgAccessLogAdapter[\s\S]*?\}\);/, "")), "el adaptador no escribe nada salvo via el puerto de access log");
  assert.ok(!/\bstate\b/.test(code.replace(/staff_status/g, "")) || !/SELECT[^;]*\bstate\b/i.test(code), "no se consulta la columna state");
});

// --- 1092: access_log 0020 ----------------------------------------------------------------------------------------
pgTest("TEST-CNS-1092 pg: ops.access_log admite STAFF_ROSTER_READ/STAFF_ROSTER solo emparejados, resource_ref UUIDv4, como app_rw bajo su tenant", async (ctx) => {
  const tenant = fixtureUuid("t1092");
  const actor = fixtureUuid("staff-1092");
  const app = await ctx.connectAs("app_rw");
  const insert = (action: string, type: string, ref: string, tenantId = tenant): Promise<unknown> =>
    app.query(
      "INSERT INTO ops.access_log (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref) VALUES ($1, $2, 'TENANT_ADMIN', $3, $4, $5)",
      [tenantId, actor, action, type, ref],
    );
  await app.query("BEGIN");
  try {
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
    await insert("STAFF_ROSTER_READ", "STAFF_ROSTER", tenant);
    await app.query("SAVEPOINT s");
    for (const [action, type, ref] of [
      ["STAFF_ROSTER_READ", "RIGHTS_CASE", tenant],
      ["RIGHTS_CASE_READ", "STAFF_ROSTER", tenant],
      ["STAFF_ROSTER_READ", "STAFF_ROSTER", "no-es-un-uuid"],
      ["OTRA_ACCION", "STAFF_ROSTER", tenant],
    ] as const) {
      await assert.rejects(() => insert(action, type, ref), (e: unknown) => codeOf(e) === "23514", `${action}/${type}/${ref}`);
      await app.query("ROLLBACK TO SAVEPOINT s");
    }
    // RLS: otro tenant fijado en la tx no puede escribir con el tenant 1092.
    await assert.rejects(() => insert("STAFF_ROSTER_READ", "STAFF_ROSTER", fixtureUuid("t1092-x"), fixtureUuid("t1092-x")), (e: unknown) => codeOf(e) === "42501");
    await app.query("ROLLBACK TO SAVEPOINT s");
    await app.query("COMMIT");
  } finally {
    await app.query("ROLLBACK").catch(() => {});
  }
  const admin = await ctx.connectAsSuperuser();
  assert.deepEqual(await accessLogRows(admin, tenant), [{ actorRef: actor, resourceRef: tenant }]);
  // Sigue siendo append-only.
  await assert.rejects(() => admin.query("UPDATE ops.access_log SET actor_ref = actor_ref WHERE tenant_id = $1", [tenant]), (e: unknown) => codeOf(e) === "23000");
});

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-1071, TEST-CNS-1072, TEST-CNS-1073, TEST-CNS-1074 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
