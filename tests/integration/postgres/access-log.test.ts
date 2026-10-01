// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 ("Las lecturas del operador van a un log de acceso en
// `ops`, no al ledger"), rights-case.spec INV-RC-04, db/migrations/0014_ops_access_log.sql,
// ADR-006 §4-§6, INV-CM-01/02. TEST-CNS-917 (esquema: FORCE RLS, grants minimos, CHECK SYNTHETIC y
// sin PII, inmutabilidad incluido migrator/superusuario/replica) y 918 (contrato del puerto contra
// Postgres). Requiere Postgres real (harness.ts); skip sin entorno. Solo datos sinteticos.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { runAccessLogContract } from "../../contract/ports/access-log.contract.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

runAccessLogContract("postgres", (name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
    try {
      const uow = new PgUnitOfWork(pool);
      await body({ inTenant: (tenantId, work) => uow.inTenant(tenantId, (tx) => work({ accessLog: tx.accessLog })) });
    } finally {
      await pool.end();
    }
  });
});

pgTest("TEST-CNS-917 pg: ops.access_log con FORCE RLS por app.current_tenant_id(), grants minimos, CHECK SYNTHETIC y sin PII, append-only para runtime, migrator y superusuario (incluso replica)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const tenant = fixtureUuid("t917");
  const other = fixtureUuid("t917-other");

  const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
    `SELECT c.relrowsecurity AS rls, c.relforcerowsecurity AS force, pg_get_userbyid(c.relowner) AS owner
       FROM pg_class c WHERE c.oid = 'ops.access_log'::regclass`,
  )).rows[0];
  assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" });

  const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
    "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'ops' AND tablename = 'access_log'",
  )).rows;
  assert.deepEqual(policies.map((p) => p.cmd).sort(), ["INSERT", "SELECT"]);
  for (const p of policies) {
    assert.deepEqual(p.roles, ["app_rw"]);
    assert.match(`${p.qual ?? ""}${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/);
  }

  for (const role of ["app_rw", "worker", "platform_rw"]) {
    for (const privilege of ["UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'ops.access_log', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege}`);
    }
  }
  for (const role of ["worker", "platform_rw"]) {
    for (const privilege of ["SELECT", "INSERT"]) {
      assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'ops.access_log', $2) AS p", [role, privilege])).rows[0]?.p, false, `${role} ${privilege}`);
    }
  }
  assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege('app_rw', 'ops.access_log', 'SELECT') AS p")).rows[0]?.p, true);
  for (const [column, expected] of [
    ["tenant_id", true], ["actor_ref", true], ["actor_role", true], ["action", true], ["resource_type", true], ["resource_ref", true],
    ["access_id", false], ["access_seq", false], ["accessed_at", false], ["environment", false], ["data_class", false],
  ] as const) {
    const r = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', 'ops.access_log', $1, 'INSERT') AS p", [column])).rows[0];
    assert.equal(r?.p, expected, `INSERT(${column})`);
  }

  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>(
    "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'ops.access_log'::regclass AND NOT tgisinternal",
  )).rows;
  assert.deepEqual(triggers.map((t) => t.tgname).sort(), ["access_log_no_truncate", "access_log_no_update_delete"]);
  assert.ok(triggers.every((t) => t.tgenabled === "A"), "ENABLE ALWAYS");

  // CHECK de forma (sin PII), enums y SYNTHETIC, como superusuario (la RLS no aplica; los CHECK si).
  const insert = (over: Record<string, string>): Promise<unknown> => {
    const cols: Record<string, string> = {
      tenant_id: `'${tenant}'`, actor_ref: "'staff-synthetic-01'", actor_role: "'RIGHTS_OPERATOR'", action: "'RIGHTS_CASE_READ'",
      resource_type: "'RIGHTS_CASE'", resource_ref: `'${fixtureUuid("case-917")}'`, ...over,
    };
    return admin.query(`INSERT INTO ops.access_log (${Object.keys(cols).join(",")}) VALUES (${Object.values(cols).join(",")})`);
  };
  const badRows: Array<Record<string, string>> = [
    { actor_ref: "'op@example.invalid'" }, { actor_ref: "'Nombre Apellido'" }, { resource_ref: "'caso de Pedro'" }, { resource_ref: `'${"x".repeat(101)}'` },
    { actor_role: "'ADMIN'" }, { action: "'RIGHTS_CASE_EXPORT'" }, { resource_type: "'PERSON'" }, { data_class: "'REAL'" }, { environment: "'MARS'" },
  ];
  for (const over of badRows) {
    await assert.rejects(() => insert(over), (e: unknown) => codeOf(e) === "23514", JSON.stringify(over));
  }
  await insert({});
  const row = (await admin.query<{ environment: string; data_class: string }>("SELECT environment, data_class FROM ops.access_log WHERE tenant_id = $1", [tenant])).rows[0];
  assert.deepEqual(row, { environment: "LOCAL", data_class: "SYNTHETIC" });

  // Runtime: sin tenant 0 filas y sin escritura; con tenant solo lo propio; no puede mutar ni fijar columnas de la base.
  const app = await ctx.connectAs("app_rw");
  await app.query("BEGIN");
  assert.equal((await app.query<{ n: number }>("SELECT count(*)::int AS n FROM ops.access_log")).rows[0]?.n, 0, "sin tenant");
  await assert.rejects(() => app.query("INSERT INTO ops.access_log (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref) VALUES ($1, 'a', 'RIGHTS_OPERATOR', 'RIGHTS_CASE_READ', 'RIGHTS_CASE', 'r')", [tenant]), (e: unknown) => codeOf(e) === "42501");
  await app.query("ROLLBACK");
  await app.query("BEGIN");
  await app.query("SELECT set_config('app.tenant_id', $1, true)", [other]);
  assert.equal((await app.query<{ n: number }>("SELECT count(*)::int AS n FROM ops.access_log")).rows[0]?.n, 0, "otro tenant no ve lo de A");
  await assert.rejects(() => app.query("INSERT INTO ops.access_log (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref) VALUES ($1, 'a', 'RIGHTS_OPERATOR', 'RIGHTS_CASE_READ', 'RIGHTS_CASE', 'r')", [tenant]), (e: unknown) => codeOf(e) === "42501", "tenant ajeno");
  await app.query("ROLLBACK");
  await app.query("BEGIN");
  await app.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
  await assert.rejects(() => app.query("INSERT INTO ops.access_log (tenant_id, actor_ref, actor_role, action, resource_type, resource_ref, environment) VALUES ($1, 'a', 'RIGHTS_OPERATOR', 'RIGHTS_CASE_READ', 'RIGHTS_CASE', 'r', 'DEV')", [tenant]), (e: unknown) => codeOf(e) === "42501", "environment lo fija la base");
  await app.query("ROLLBACK");
  for (const sql of ["UPDATE ops.access_log SET actor_ref = 'x'", "DELETE FROM ops.access_log", "TRUNCATE ops.access_log"]) {
    await assert.rejects(() => app.query(sql), (e: unknown) => codeOf(e) === "42501", `app_rw: ${sql}`);
  }

  // Migrator (miembro del dueno; con FORCE RLS quitado la fila es visible) y superusuario (+ replica): el trigger bloquea.
  const mutations = ["UPDATE ops.access_log SET actor_ref = 'x'", "DELETE FROM ops.access_log"];
  for (const viaSetRole of [false, true]) {
    const mig = await ctx.connectAs("consent_migrator");
    if (viaSetRole) await mig.query("SET ROLE consent_owner");
    for (const sql of mutations) {
      await mig.query("BEGIN");
      await mig.query("ALTER TABLE ops.access_log NO FORCE ROW LEVEL SECURITY");
      await assert.rejects(() => mig.query(sql), (e: unknown) => codeOf(e) === "23000", `migrador (setRole=${viaSetRole}): ${sql}`);
      await mig.query("ROLLBACK");
    }
    await assert.rejects(() => mig.query("TRUNCATE ops.access_log"), (e: unknown) => codeOf(e) === "23000", `migrador (setRole=${viaSetRole}): TRUNCATE`);
  }
  for (const replica of [false, true]) {
    if (replica) await admin.query("SET session_replication_role = replica");
    for (const sql of [...mutations, "TRUNCATE ops.access_log"]) {
      await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario (replica=${replica}): ${sql}`);
    }
    if (replica) await admin.query("SET session_replication_role = origin");
  }
  assert.equal((await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM ops.access_log WHERE tenant_id = $1", [tenant])).rows[0]?.n, 1, "la fila sigue intacta");
});
