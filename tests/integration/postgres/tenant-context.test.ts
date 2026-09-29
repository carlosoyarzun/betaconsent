// Gobierna: CA-124 (H09), ADR-006 §1/§4-§6, common.spec.yaml (INV-CM-02, INV-3: 0 accesos
// cross-tenant incluida la conexión reusada A->B), diseño de CA-124 P1-1.
// TEST-CNS-740 (propuesto 710), TEST-CNS-742 (propuesto 712), TEST-CNS-750 (app.current_tenant_id).
// Requiere Postgres real (harness.ts): skip fuera de CI sin entorno.

import assert from "node:assert/strict";
import { createPool, acquireCleanClient, TenantContextLeakError } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { pgTest } from "./harness.ts";

const TENANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

pgTest("TEST-CNS-740 pg: una conexión con app.tenant_id de sesión se destruye al adquirirla (fuga A->B)", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    // Simula código defectuoso: fija el tenant a nivel de sesión y devuelve la conexión al pool.
    const dirty = await pool.connect();
    const dirtyPid = (await dirty.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]?.pid;
    await dirty.query("SELECT set_config('app.tenant_id', $1, false)", [TENANT_A]);
    dirty.release();

    await assert.rejects(() => acquireCleanClient(pool), TenantContextLeakError);

    // La conexión contaminada fue destruida: la siguiente es otra sesión y está limpia.
    const clean = await acquireCleanClient(pool);
    try {
      const row = (await clean.query<{ pid: number; tenant: string | null }>(
        "SELECT pg_backend_pid() AS pid, current_setting('app.tenant_id', true) AS tenant",
      )).rows[0];
      assert.notEqual(row?.pid, dirtyPid);
      assert.ok(row?.tenant === null || row?.tenant === "");
    } finally {
      clean.release();
    }
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-740 pg: inTenant A y luego B con la misma conexión (max=1) no arrastra el tenant", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool);
    const read = (tx: { query: (t: string) => Promise<{ rows: Array<Record<string, unknown>> }> }) =>
      tx.query("SELECT app.current_tenant_id()::text AS t, pg_backend_pid() AS pid");
    const a = (await uow.inTenant(TENANT_A, read)).rows[0];
    const b = (await uow.inTenant(TENANT_B, read)).rows[0];
    assert.equal(a?.t, TENANT_A);
    assert.equal(b?.t, TENANT_B);
    assert.equal(a?.pid, b?.pid, "el test exige la misma conexión física");

    const after = await acquireCleanClient(pool);
    try {
      const row = (await after.query<{ t: string | null }>("SELECT app.current_tenant_id()::text AS t")).rows[0];
      assert.equal(row?.t, null);
    } finally {
      after.release();
    }
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-742 pg: un error del trabajo hace ROLLBACK y la conexión vuelve limpia al pool", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool);
    await assert.rejects(
      () =>
        uow.inTenant(TENANT_A, async (tx) => {
          await tx.query("SELECT 1");
          await tx.query("SELECT 1/0");
        }),
      (error: unknown) => (error as { code?: string }).code === "22012",
    );
    const next = (await uow.inTenant(TENANT_B, (tx) => tx.query("SELECT app.current_tenant_id()::text AS t"))).rows[0];
    assert.equal(next?.t, TENANT_B);
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-742 pg: idle_in_transaction_session_timeout = 10s para app_rw, worker y platform_rw (D9)", async (ctx) => {
  for (const role of ["app_rw", "worker", "platform_rw"] as const) {
    const client = await ctx.connectAs(role);
    const row = (await client.query<{ v: string }>("SELECT current_setting('idle_in_transaction_session_timeout') AS v")).rows[0];
    assert.equal(row?.v, "10s", role);
  }
});

pgTest("TEST-CNS-750 pg: app.current_tenant_id() es NULL sin tenant, con '' y devuelve el uuid con tenant", async (ctx) => {
  const client = await ctx.connectAs("app_rw");
  const q = async (sql: string): Promise<string | null> => (await client.query<{ t: string | null }>(sql)).rows[0]?.t ?? null;

  assert.equal(await q("SELECT app.current_tenant_id()::text AS t"), null);
  await client.query("BEGIN");
  assert.equal(await q("SELECT set_config('app.tenant_id', '', true), app.current_tenant_id()::text AS t"), null);
  assert.equal(await q(`SELECT set_config('app.tenant_id', '${TENANT_A}', true), app.current_tenant_id()::text AS t`), TENANT_A);
  await client.query("ROLLBACK");
  assert.equal(await q("SELECT app.current_tenant_id()::text AS t"), null);

  await client.query("BEGIN");
  await client.query("SELECT set_config('app.tenant_id', 'no-es-uuid', true)");
  await assert.rejects(() => client.query("SELECT app.current_tenant_id()"), (e: unknown) => (e as { code?: string }).code === "22P02");
  await client.query("ROLLBACK");
});
