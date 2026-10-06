// Gobierna: CA-124 (PR-B), db/migrations/0002_ledger.sql y 0003_outbox.sql, ADR-002 §2/§8,
// ADR-006 §4-§6, common.spec.yaml ledgerEnvelope, INV-CM-01 (append-only), INV-CM-02/INV-3.
// TEST-CNS-787 (RLS/grants), 788 (append-only), 789 (CHECK/UNIQUE), 790 (sin tenant y A->B sobre
// tablas reales), 791 (claim del worker). Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgLedgerAdapter } from "../../../src/infra/adapters/postgres/ledger.adapter.ts";
import { claimOutbox, createPgOutboxAdapter, readOutboxEnvelope } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
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
  // 0013: todo INSERT lleva eslabon (CHECK audit_event_chain_required); la BD no recomputa el hash.
  await admin.query(
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload,
                                         chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES ($1, 'Revocation', $2, 1, 'REVOCATION_REQUESTED', 'HUMAN', '{}'::jsonb, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '0000000000000000000000000000000000000000000000000000000000000000', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`,
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
    // X8 dec. 3 (0027): el ledger pertenece a integrity_owner; el outbox sigue en consent_owner.
    assert.deepEqual(rel, { rls: true, force: true, owner: schema === "integrity" ? "integrity_owner" : "consent_owner" }, `${schema}.${table}`);

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
    // worker: SELECT solo del outbox (filtrado por tenant via policy); INSERT nunca. platform_rw: nada.
    for (const role of ["worker", "platform_rw"]) {
      for (const privilege of ["SELECT", "INSERT"]) {
        const expected = role === "worker" && privilege === "SELECT" && table === "outbox";
        const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, $2, $3) AS p", [role, `${schema}.${table}`, privilege])).rows[0];
        assert.equal(r?.p, expected, `${role} ${privilege} ${schema}.${table}`);
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
      // 0013 (P2-1): audit_event deja INSERT por columna en environment; la base lo valida (CHECK = catalogo), no el grant.
      if (schema === "integrity" && column === "environment") continue;
      const p = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', $1, $2, 'INSERT') AS p", [`${schema}.${table}`, column])).rows[0];
      assert.equal(p?.p, false, `app_rw no debe poder insertar ${schema}.${table}.${column}`);
    }
  }

  // P2-1: TODA policy de tablas con RLS exige app.current_tenant_id(); unica excepcion explicita:
  // las del claim, solo TO outbox_claimer. Ninguna policy abierta al dueno.
  const CLAIM_ALLOWLIST = new Map([["app.outbox/outbox_claim_select", ["outbox_claimer"]], ["app.outbox/outbox_claim_update", ["outbox_claimer"]]]);
  const all = (await admin.query<{ k: string; roles: string[]; qual: string | null; with_check: string | null }>(
    `SELECT p.schemaname || '.' || p.tablename || '/' || p.policyname AS k, p.roles::text[] AS roles, p.qual, p.with_check
       FROM pg_policies p JOIN pg_class c ON c.oid = (p.schemaname || '.' || p.tablename)::regclass
      WHERE c.relrowsecurity`,
  )).rows;
  assert.ok(all.length >= 6);
  for (const p of all) {
    const allowed = CLAIM_ALLOWLIST.get(p.k);
    if (allowed) {
      assert.deepEqual(p.roles, allowed, `${p.k}: solo ${allowed.join(",")}`);
      continue;
    }
    assert.match(`${p.qual ?? ""} ${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/, `${p.k} sin app.current_tenant_id()`);
  }
  assert.deepEqual(all.filter((p) => p.roles.includes("consent_owner") || p.roles.includes("public")).map((p) => p.k), [], "ninguna policy para el dueno ni PUBLIC");

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
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, environment,
                                           chain_seq, payload_hash, previous_event_hash, event_hash)
       VALUES ($1, 'A', 'b', 1, 'CONSENT_GRANTED', 'HUMAN', '{}'::jsonb, 'DEV', 1, repeat('a', 64), repeat('0', 64), repeat('a', 64))`,
      [fixtureUuid("t787")],
    ),
    (e: unknown) => codeOf(e) === "23514", // 0013 (P2-1): el grant existe pero el CHECK fija environment = catalogo
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
    const cols = { tenant_id: `'${t}'`, aggregate_type: "'A'", aggregate_id: "'agg789'", sequence: "1", event_type: "'CONSENT_GRANTED'", actor_type: "'HUMAN'", payload: "'{}'::jsonb",
      chain_seq: "1", payload_hash: "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", previous_event_hash: "'0000000000000000000000000000000000000000000000000000000000000000'", event_hash: "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", ...over };
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
        "INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES ($1, 'A', 'x', 1, 'CONSENT_GRANTED', 'HUMAN', '{}'::jsonb)",
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
    const inA = await uow.withTenantTx(ta, (tx) => createPgLedgerAdapter(tx).listByAggregate(ta, "Revocation", agg));
    assert.equal(inA.length, 1);
    const inB = await uow.withTenantTx(tb, async (tx) => {
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

const ENV_INPUT = (t: string, key: string) => ({
  tenantId: t, eventType: "consent.revoked" as const, contextRef: "BETA_2026_01", subjectRef: fixtureUuid(`s-${key}`),
  occurredAt: "2026-09-30T12:00:00.000Z", payload: { revocationRef: fixtureUuid(`r-${key}`), scope: "ALL" as const, effectiveAt: "2026-09-30T12:00:00.000Z" },
  dedupeKey: key,
});

pgTest("TEST-CNS-791 pg: claim del worker via SECURITY DEFINER del rol outbox_claimer: cruza tenants, solo (tenant_id, event_id), lease fijo, EXECUTE solo worker", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const ta = fixtureUuid("t791-a");
  const tb = fixtureUuid("t791-b");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const [t, key] of [[ta, "k1"], [tb, "k2"]] as const) {
      await uow.withTenantTx(t, (tx) => createPgOutboxAdapter(tx).enqueue(ENV_INPUT(t, `791-${key}`)));
    }
  } finally {
    await pool.end();
  }

  // Definicion: SECURITY DEFINER, dueno outbox_claimer (NOLOGIN/NOBYPASSRLS), search_path fijo, firma de un solo
  // parametro (sin lease del llamador), sin EXECUTE de PUBLIC, solo worker.
  const def = (await admin.query<{ secdef: boolean; cfg: string[] | null; owner: string; bypass: boolean; login: boolean; pub: boolean; args: string; ret: string }>(
    `SELECT p.prosecdef AS secdef, p.proconfig AS cfg, pg_get_userbyid(p.proowner) AS owner,
            r.rolbypassrls AS bypass, r.rolcanlogin AS login,
            COALESCE((SELECT bool_or(a.grantee = 0) FROM aclexplode(p.proacl) a), false) AS pub,
            pg_get_function_arguments(p.oid) AS args, pg_get_function_result(p.oid) AS ret
       FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.oid = 'app.outbox_claim(integer)'::regprocedure`,
  )).rows[0];
  assert.deepEqual(def, {
    secdef: true, cfg: ["search_path=pg_catalog, pg_temp"], owner: "outbox_claimer", bypass: false, login: false, pub: false,
    args: "p_limit integer", ret: "TABLE(tenant_id uuid, event_id uuid)",
  });
  const execs = (await admin.query<{ g: string }>(
    "SELECT pg_get_userbyid(a.grantee) AS g FROM pg_proc p, aclexplode(p.proacl) a WHERE p.oid = 'app.outbox_claim(integer)'::regprocedure AND a.privilege_type = 'EXECUTE'",
  )).rows.map((r) => r.g).sort();
  assert.deepEqual(execs, ["outbox_claimer", "worker"]);

  for (const role of ["app_rw", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(() => claimOutbox(c, 10), (e: unknown) => codeOf(e) === "42501", role);
  }
  const worker = await ctx.connectAs("worker");
  await assert.rejects(() => worker.query("UPDATE app.outbox SET status = 'DELIVERED'"), (e: unknown) => codeOf(e) === "42501");
  // Sin tenant el worker no ve filas del outbox (policy por tenant).
  assert.equal((await worker.query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox")).rows[0]?.n, 0);

  // La base del archivo es compartida con otros tests (789/790 dejan filas PENDING): se filtra por tenants propios.
  const mine = (refs: Awaited<ReturnType<typeof claimOutbox>>) => refs.filter((e) => e.tenantId === ta || e.tenantId === tb);
  const first = await claimOutbox(worker, 100);
  assert.deepEqual(mine(first).map((e) => e.tenantId).sort(), [ta, tb].sort(), "cruza tenants");
  assert.ok(first.every((e) => Object.keys(e).sort().join() === "eventId,tenantId"), "solo refs, sin sobre");

  // P2-2: otro worker no puede robar un claim vigente (el lease no es parametro del llamador).
  const worker2 = await ctx.connectAs("worker");
  assert.equal((await claimOutbox(worker2, 100)).length, 0, "dentro del lease no se reclama");

  const states = (await admin.query<{ status: string }>("SELECT DISTINCT status FROM app.outbox WHERE tenant_id = ANY($1)", [[ta, tb]])).rows;
  assert.deepEqual(states, [{ status: "CLAIMED" }]);

  // Lease vencido: se reclama de nuevo (at-least-once) con attempts = 2.
  await admin.query("ALTER TABLE app.outbox DISABLE TRIGGER outbox_envelope_immutable");
  await admin.query("UPDATE app.outbox SET claimed_at = now() - interval '1 hour' WHERE tenant_id = $1", [ta]);
  await admin.query("ALTER TABLE app.outbox ENABLE ALWAYS TRIGGER outbox_envelope_immutable");
  assert.deepEqual(mine(await claimOutbox(worker2, 100)).map((e) => e.tenantId), [ta]);
  const attempts = (await admin.query<{ attempts: number }>("SELECT attempts FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = '791-k1'", [ta])).rows[0]?.attempts;
  assert.equal(attempts, 2);

  // El sobre es inmutable incluso para el superusuario.
  await assert.rejects(() => admin.query("UPDATE app.outbox SET payload = '{}'::jsonb"), (e: unknown) => codeOf(e) === "23000");
});

pgTest("TEST-CNS-792 pg: el worker lee el sobre solo dentro de inTenant de su tenant; refs de otro tenant dan null", async (ctx) => {
  const ta = fixtureUuid("t792-a");
  const tb = fixtureUuid("t792-b");
  const app = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const workerPool = createPool({ connectionString: ctx.urlFor("worker"), max: 1 });
  try {
    const appUow = new PgUnitOfWork(app);
    await appUow.withTenantTx(ta, (tx) => createPgOutboxAdapter(tx).enqueue(ENV_INPUT(ta, "792-a")));
    await appUow.withTenantTx(tb, (tx) => createPgOutboxAdapter(tx).enqueue(ENV_INPUT(tb, "792-b")));

    const workerUow = new PgUnitOfWork(workerPool);
    const refs = (await claimOutbox(await ctx.connectAs("worker"), 100)).filter((r) => r.tenantId === ta || r.tenantId === tb);
    assert.equal(refs.length, 2);
    const refA = refs.find((r) => r.tenantId === ta)!;
    const refB = refs.find((r) => r.tenantId === tb)!;

    const envA = await workerUow.withTenantTx(ta, (tx) => readOutboxEnvelope(tx, refA.eventId));
    assert.equal(envA?.tenantRef, ta);
    assert.equal(envA?.eventId, refA.eventId);
    assert.equal(envA?.payload.revocationRef, fixtureUuid("r-792-a"));
    // Pidiendo la ref del otro tenant desde la unidad de trabajo de A: RLS => null.
    assert.equal(await workerUow.withTenantTx(ta, (tx) => readOutboxEnvelope(tx, refB.eventId)), null);
    assert.equal((await workerUow.withTenantTx(tb, (tx) => readOutboxEnvelope(tx, refB.eventId)))?.tenantRef, tb);
    // El worker no puede escribir sobre el outbox ni siquiera con tenant.
    await assert.rejects(
      () => workerUow.withTenantTx(ta, (tx) => tx.query("UPDATE app.outbox SET status = 'DELIVERED'")),
      (e: unknown) => codeOf(e) === "42501",
    );
  } finally {
    await app.end();
    await workerPool.end();
  }
});

pgTest("TEST-CNS-793 pg: outbox_claimer es NOLOGIN/NOBYPASSRLS, sin membresias, con privilegios minimos por columna y el migrador no hereda", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const role = (await admin.query<{ rolcanlogin: boolean; rolbypassrls: boolean; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean }>(
    "SELECT rolcanlogin, rolbypassrls, rolsuper, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles WHERE rolname = 'outbox_claimer'",
  )).rows[0];
  assert.deepEqual(role, { rolcanlogin: false, rolbypassrls: false, rolsuper: false, rolcreaterole: false, rolcreatedb: false, rolreplication: false });

  const memberOf = (await admin.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM pg_auth_members m WHERE m.member = 'outbox_claimer'::regrole",
  )).rows[0]?.n;
  assert.equal(memberOf, 0, "outbox_claimer no es miembro de ningun rol");
  const members = (await admin.query<{ m: string; inherit: boolean; set: boolean }>(
    "SELECT pg_get_userbyid(member) AS m, inherit_option AS inherit, set_option AS set FROM pg_auth_members WHERE roleid = 'outbox_claimer'::regrole",
  )).rows;
  assert.deepEqual(members, [{ m: "consent_migrator", inherit: false, set: true }]);
  // P2-5: consent_owner no hereda los privilegios de tenant_resolve_owner (solo SET).
  const tro = (await admin.query<{ inherit: boolean; set: boolean }>(
    "SELECT inherit_option AS inherit, set_option AS set FROM pg_auth_members WHERE roleid = 'tenant_resolve_owner'::regrole AND member = 'consent_owner'::regrole",
  )).rows[0];
  assert.deepEqual(tro, { inherit: false, set: true });

  const cols = async (priv: string): Promise<string[]> =>
    (await admin.query<{ c: string }>(
      "SELECT attname AS c FROM pg_attribute WHERE attrelid = 'app.outbox'::regclass AND attnum > 0 AND NOT attisdropped AND has_column_privilege('outbox_claimer', 'app.outbox', attname, $1) ORDER BY attname",
      [priv],
    )).rows.map((r) => r.c);
  assert.deepEqual(await cols("SELECT"), ["attempts", "claimed_at", "created_at", "event_id", "status", "tenant_id"]);
  assert.deepEqual(await cols("UPDATE"), ["attempts", "claimed_at", "status"]);
  assert.deepEqual(await cols("INSERT"), []);
  for (const priv of ["DELETE", "TRUNCATE"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege('outbox_claimer', 'app.outbox', $1) AS p", [priv])).rows[0]?.p, false);
  }
  assert.equal((await admin.query<{ p: boolean }>("SELECT has_schema_privilege('outbox_claimer', 'app', 'CREATE') AS p")).rows[0]?.p, false);
  assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege('outbox_claimer', 'integrity.audit_event', 'SELECT') AS p")).rows[0]?.p, false);
});
