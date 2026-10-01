// Gobierna: CA-124 (PR-B), db/migrations/0002_ledger.sql y 0003_outbox.sql, ADR-002 §2/§8,
// ADR-006 §4-§6, common.spec.yaml ledgerEnvelope, INV-CM-01 (append-only), INV-CM-02/INV-3.
// TEST-CNS-787 (RLS/grants), 788 (append-only), 789 (CHECK/UNIQUE), 790 (sin tenant y A->B sobre
// tablas reales), 791 (claim del worker). Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgLedgerAdapter } from "../../../src/infra/adapters/postgres/ledger.adapter.ts";
import { claimOutbox, createPgOutboxAdapter } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const TABLES = [
  ["integrity", "audit_event"],
  ["app", "outbox"],
] as const;

async function seedAudit(ctx: { connectAsSuperuser(): Promise<import("pg").Client> }, tenant: string, aggregate: string): Promise<void> {
  const admin = await ctx.connectAsSuperuser();
  await admin.query(
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload)
     VALUES ($1, 'Revocation', $2, 1, 'REVOCATION_REQUESTED', 'HUMAN', '{}'::jsonb)`,
    [tenant, aggregate],
  );
}

pgTest("TEST-CNS-787 pg: ledger y outbox con FORCE RLS, policies por app.current_tenant_id() y grants minimos", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const [schema, table] of TABLES) {
    const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
      `SELECT c.relrowsecurity AS rls, c.relforcerowsecurity AS force, pg_get_userbyid(c.relowner) AS owner
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`,
      [schema, table],
    )).rows[0];
    assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" }, `${schema}.${table}`);

    const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
      "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = $1 AND tablename = $2",
      [schema, table],
    )).rows;
    assert.ok(policies.length >= 2, `${schema}.${table} sin policies`);
    const runtime = policies.filter((p) => p.roles.includes("app_rw"));
    assert.deepEqual(runtime.map((p) => p.cmd).sort(), ["INSERT", "SELECT"], "app_rw solo SELECT/INSERT por policy");
    for (const p of runtime) {
      assert.match(`${p.qual ?? ""}${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/);
    }

    for (const privilege of ["UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
      for (const role of ["app_rw", "worker", "platform_rw"]) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, $2, $3) AS p", [role, `${schema}.${table}`, privilege])).rows[0];
        assert.equal(r?.p, false, `${role} ${privilege} ${schema}.${table}`);
      }
    }
    for (const role of ["worker", "platform_rw"]) {
      for (const privilege of ["SELECT", "INSERT"]) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, $2, $3) AS p", [role, `${schema}.${table}`, privilege])).rows[0];
        assert.equal(r?.p, false, `${role} ${privilege} ${schema}.${table}`);
      }
    }
    const sel = (await admin.query<{ p: boolean }>("SELECT has_table_privilege('app_rw', $1, 'SELECT') AS p", [`${schema}.${table}`])).rows[0];
    assert.equal(sel?.p, true);
    for (const column of ["event_id", "environment", "data_class", "status", "attempts", "occurred_at"]) {
      const has = (await admin.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3",
        [schema, table, column],
      )).rows[0]?.n;
      if (!has || column === "occurred_at") continue; // occurred_at del outbox si es insertable (lo aporta el productor)
      const p = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', $1, $2, 'INSERT') AS p", [`${schema}.${table}`, column])).rows[0];
      assert.equal(p?.p, false, `app_rw no debe poder insertar ${schema}.${table}.${column}`);
    }
  }

  // Funcion de entorno por defecto: ejecutable por runtime, no por PUBLIC.
  const fn = (await admin.query<{ p: boolean; c: string[] | null }>(
    `SELECT has_function_privilege('app_rw', 'ops.catalog_environment()', 'EXECUTE') AS p, proconfig AS c
       FROM pg_proc WHERE oid = 'ops.catalog_environment()'::regprocedure`,
  )).rows[0];
  assert.equal(fn?.p, true);
  assert.ok(fn?.c?.some((s) => s.startsWith("search_path=pg_catalog")));

  // Un runtime no puede fijar columnas que decide la base (SEC N2-06) ni escribir sin tenant.
  const app = await ctx.connectAs("app_rw");
  await app.query("BEGIN");
  await app.query("SELECT set_config('app.tenant_id', $1, true)", [fixtureUuid("t787")]);
  await assert.rejects(
    () => app.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, environment)
       VALUES ($1, 'A', 'b', 1, 'E', 'HUMAN', '{}'::jsonb, 'DEV')`,
      [fixtureUuid("t787")],
    ),
    (e: unknown) => codeOf(e) === "42501",
  );
  await app.query("ROLLBACK");
});

pgTest("TEST-CNS-788 pg: el ledger es append-only: UPDATE/DELETE/TRUNCATE fallan para runtime, dueno y superusuario (incluso con session_replication_role=replica)", async (ctx) => {
  const tenant = fixtureUuid("t788");
  const agg = fixtureUuid("agg788");
  await seedAudit(ctx, tenant, agg);
  const admin = await ctx.connectAsSuperuser();

  const app = await ctx.connectAs("app_rw");
  for (const sql of ["UPDATE integrity.audit_event SET event_type = 'X'", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event"]) {
    await assert.rejects(() => app.query(sql), (e: unknown) => codeOf(e) === "42501", `app_rw: ${sql}`);
  }

  for (const replica of [false, true]) {
    if (replica) await admin.query("SET session_replication_role = replica");
    for (const sql of ["UPDATE integrity.audit_event SET event_type = 'X'", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event"]) {
      await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario (replica=${replica}): ${sql}`);
    }
    if (replica) await admin.query("SET session_replication_role = origin");
  }
  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>(
    "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'integrity.audit_event'::regclass AND NOT tgisinternal",
  )).rows;
  assert.deepEqual(triggers.map((t) => t.tgname).sort(), ["audit_event_no_truncate", "audit_event_no_update_delete"]);
  assert.ok(triggers.every((t) => t.tgenabled === "A"), "ENABLE ALWAYS");
  const n = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [tenant])).rows[0]?.n;
  assert.equal(n, 1, "la fila sigue intacta");
});

pgTest("TEST-CNS-789 pg: CHECK y UNIQUE: data_class SYNTHETIC, FIXTURE solo LOCAL, evidentiary solo PRODUCTION, UNIQUE(tenant, aggregate, sequence), dedupe del outbox", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t789");
  const base = (over: Record<string, string>): Promise<unknown> => {
    const cols = { tenant_id: `'${t}'`, aggregate_type: "'A'", aggregate_id: "'agg789'", sequence: "1", event_type: "'E'", actor_type: "'HUMAN'", payload: "'{}'::jsonb", ...over };
    return admin.query(`INSERT INTO integrity.audit_event (${Object.keys(cols).join(",")}) VALUES (${Object.values(cols).join(",")})`);
  };
  await assert.rejects(() => base({ data_class: "'REAL'" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => base({ environment: "'DEV'", actor_type: "'FIXTURE'" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => base({ evidentiary: "true" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => base({ sequence: "0" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => base({ payload: "'[]'::jsonb" }), (e: unknown) => codeOf(e) === "23514");
  await base({});
  await assert.rejects(() => base({}), (e: unknown) => codeOf(e) === "23505");
  const env = (await admin.query<{ environment: string; data_class: string; evidentiary: boolean }>(
    "SELECT environment, data_class, evidentiary FROM integrity.audit_event WHERE tenant_id = $1", [t])).rows[0];
  assert.deepEqual(env, { environment: "LOCAL", data_class: "SYNTHETIC", evidentiary: false });

  const ob = (over: Record<string, string>): Promise<unknown> => {
    const cols = {
      tenant_id: `'${t}'`, dedupe_key: "'k789'", event_type: "'consent.revoked'", schema_version: "'1.0.0'",
      context_ref: "'c'", subject_ref: "'s'", occurred_at: "now()", payload: "'{}'::jsonb", ...over,
    };
    return admin.query(`INSERT INTO app.outbox (${Object.keys(cols).join(",")}) VALUES (${Object.values(cols).join(",")})`);
  };
  await assert.rejects(() => ob({ data_class: "'REAL'" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => ob({ event_type: "'otro'" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => ob({ environment: "'PRODUCTION'" }), (e: unknown) => codeOf(e) === "23514");
  await ob({});
  await assert.rejects(() => ob({}), (e: unknown) => codeOf(e) === "23505");
  await ob({ tenant_id: `'${fixtureUuid("t789-b")}'` });
});

pgTest("TEST-CNS-790 pg: sin tenant no hay filas ni escritura, y la conexion reusada A->B no arrastra el tenant sobre las tablas reales", async (ctx) => {
  const ta = fixtureUuid("t790-a");
  const tb = fixtureUuid("t790-b");
  const agg = fixtureUuid("agg790");
  await seedAudit(ctx, ta, agg);

  // Sin tenant (NULL) y con '' : 0 filas, INSERT rechazado por WITH CHECK (RLS 42501).
  const app = await ctx.connectAs("app_rw");
  for (const setting of [null, ""]) {
    await app.query("BEGIN");
    if (setting !== null) await app.query("SELECT set_config('app.tenant_id', $1, true)", [setting]);
    const seen = (await app.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event")).rows[0]?.n;
    assert.equal(seen, 0, `tenant ${JSON.stringify(setting)}`);
    await assert.rejects(
      () => app.query(
        "INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES ($1, 'A', 'x', 1, 'E', 'HUMAN', '{}'::jsonb)",
        [ta],
      ),
      (e: unknown) => codeOf(e) === "42501",
    );
    await app.query("ROLLBACK");
  }

  // Misma conexion fisica (max=1): A ve lo suyo, B despues ve 0 y no puede leer lo de A.
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool);
    const inA = await uow.inTenant(ta, (tx) => createPgLedgerAdapter(tx).listByAggregate(ta, "Revocation", agg));
    assert.equal(inA.length, 1);
    const inB = await uow.inTenant(tb, async (tx) => {
      const raw = (await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event")).rows[0]?.n;
      const asked = await createPgLedgerAdapter(tx).listByAggregate(ta, "Revocation", agg);
      const o = await createPgOutboxAdapter(tx).enqueue({
        tenantId: tb, eventType: "consent.revoked", contextRef: "BETA_2026_01", subjectRef: fixtureUuid("s790"),
        occurredAt: "2026-09-30T12:00:00.000Z", payload: { revocationRef: fixtureUuid("r790"), scope: "ALL", effectiveAt: "2026-09-30T12:00:00.000Z" },
        dedupeKey: "k790",
      });
      const outboxVisible = (await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox")).rows[0]?.n;
      return { raw, asked: asked.length, outbox: o.tenantId, outboxVisible };
    });
    assert.deepEqual(inB, { raw: 0, asked: 0, outbox: tb, outboxVisible: 1 });
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-791 pg: claim del worker via SECURITY DEFINER cruza tenants, marca CLAIMED, respeta el lease y no hay acceso directo ni BYPASSRLS", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const ta = fixtureUuid("t791-a");
  const tb = fixtureUuid("t791-b");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const [t, key] of [[ta, "k1"], [tb, "k2"]] as const) {
      await uow.inTenant(t, (tx) => createPgOutboxAdapter(tx).enqueue({
        tenantId: t, eventType: "consent.revoked", contextRef: "BETA_2026_01", subjectRef: fixtureUuid(`s791-${key}`),
        occurredAt: "2026-09-30T12:00:00.000Z", payload: { revocationRef: fixtureUuid(`r791-${key}`), scope: "ALL", effectiveAt: "2026-09-30T12:00:00.000Z" },
        dedupeKey: key,
      }));
    }
  } finally {
    await pool.end();
  }

  // Definicion de la funcion: SECURITY DEFINER, search_path fijo, dueno sin BYPASSRLS, sin EXECUTE de PUBLIC.
  const def = (await admin.query<{ secdef: boolean; cfg: string[] | null; owner: string; bypass: boolean; pub: boolean }>(
    `SELECT p.prosecdef AS secdef, p.proconfig AS cfg, pg_get_userbyid(p.proowner) AS owner,
            (SELECT rolbypassrls FROM pg_roles WHERE oid = p.proowner) AS bypass,
            COALESCE((SELECT bool_or(a.grantee = 0) FROM aclexplode(p.proacl) a), false) AS pub
       FROM pg_proc p WHERE p.oid = 'app.outbox_claim(integer, integer)'::regprocedure`,
  )).rows[0];
  assert.equal(def?.secdef, true);
  assert.deepEqual(def?.cfg, ["search_path=pg_catalog, pg_temp"]);
  assert.equal(def?.owner, "consent_owner");
  assert.equal(def?.bypass, false);
  assert.equal(def?.pub, false);

  // Solo el worker ejecuta; app_rw y platform_rw no. El worker no toca la tabla.
  for (const role of ["app_rw", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(() => claimOutbox(c, 10, 60), (e: unknown) => codeOf(e) === "42501", role);
  }
  const worker = await ctx.connectAs("worker");
  await assert.rejects(() => worker.query("SELECT * FROM app.outbox"), (e: unknown) => codeOf(e) === "42501");
  await assert.rejects(() => worker.query("UPDATE app.outbox SET status = 'DELIVERED'"), (e: unknown) => codeOf(e) === "42501");

  const first = await claimOutbox(worker, 100, 60);
  // La base del archivo es compartida con otros tests (789/790 dejan filas PENDING): se filtra por los tenants propios.
  const mine = (events: Awaited<ReturnType<typeof claimOutbox>>) => events.filter((e) => e.envelope.tenantRef === ta || e.envelope.tenantRef === tb);
  assert.deepEqual(mine(first).map((e) => e.envelope.tenantRef).sort(), [ta, tb].sort(), "cruza tenants");
  assert.ok(first.every((e) => e.attempts === 1 && e.envelope.dataClass === "SYNTHETIC"));
  assert.equal((await claimOutbox(worker, 100, 60)).length, 0, "dentro del lease no se reclama");

  const states = (await admin.query<{ status: string }>("SELECT DISTINCT status FROM app.outbox WHERE tenant_id = ANY($1)", [[ta, tb]])).rows;
  assert.deepEqual(states, [{ status: "CLAIMED" }]);

  // Lease vencido: se reclama de nuevo (at-least-once) con attempts = 2.
  await admin.query("ALTER TABLE app.outbox DISABLE TRIGGER outbox_envelope_immutable");
  await admin.query("UPDATE app.outbox SET claimed_at = now() - interval '1 hour' WHERE tenant_id = $1", [ta]);
  await admin.query("ALTER TABLE app.outbox ENABLE ALWAYS TRIGGER outbox_envelope_immutable");
  const again = await claimOutbox(worker, 100, 60);
  assert.deepEqual(mine(again).map((e) => [e.envelope.tenantRef, e.attempts]), [[ta, 2]]);

  // El sobre es inmutable incluso para el superusuario.
  await assert.rejects(() => admin.query("UPDATE app.outbox SET payload = '{}'::jsonb"), (e: unknown) => codeOf(e) === "23000");
});
