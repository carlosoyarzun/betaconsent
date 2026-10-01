// Gobierna: CA-124 (PR-E), db/migrations/0012_idempotency.sql, common.spec.yaml GRD-CM-08/ERR-CM-07,
// ADR-006 §4-§6, DEC-BR-014 §4 (solo sinteticos), SEC-CNS-012 (P1-5). TEST-CNS-865..867: esquema, RLS,
// grants y CHECK de app.idempotency_key; TTL P-33 (sin default de produccion, fail-closed) y
// serializacion de dos requests con la misma clave. Requiere Postgres real (harness.ts).

import assert from "node:assert/strict";

import { IdempotencyPolicyMissingError } from "../../../src/infra/adapters/postgres/idempotency.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);
const resp = (label: string) => ({ payloadHash: hex(`p:${label}`), status: 201, body: { ref: fixtureUuid(label) } });

pgTest("TEST-CNS-865 pg: app.idempotency_key con FORCE RLS, policies por app.current_tenant_id() solo TO app_rw, sin DELETE/TRUNCATE, grants minimos por columna y CHECK (SYNTHETIC, 2xx, forma de hashes)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
    "SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = 'app.idempotency_key'::regclass",
  )).rows[0];
  assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" });

  const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
    "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'app' AND tablename = 'idempotency_key'",
  )).rows;
  assert.deepEqual(policies.map((p) => p.cmd).sort(), ["INSERT", "SELECT", "UPDATE"]);
  for (const p of policies) {
    assert.deepEqual(p.roles, ["app_rw"]);
    assert.match(`${p.qual ?? ""}${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/);
  }
  for (const role of ["app_rw", "worker", "platform_rw"]) {
    for (const privilege of ["DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'app.idempotency_key', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege}`);
    }
  }
  for (const role of ["worker", "platform_rw"]) {
    for (const privilege of ["SELECT", "INSERT", "UPDATE"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, 'app.idempotency_key', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege}`);
    }
  }
  const cols = async (privilege: string): Promise<string[]> =>
    (await admin.query<{ attname: string }>(
      `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'app.idempotency_key'::regclass AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege('app_rw', a.attrelid, a.attnum, $1) ORDER BY a.attname`,
      [privilege],
    )).rows.map((r) => r.attname);
  assert.deepEqual(await cols("INSERT"), ["body", "expires_at", "payload_hash", "scope_key_hash", "status", "tenant_id"]);
  assert.deepEqual(await cols("UPDATE"), ["body", "expires_at", "payload_hash", "status"], "tenant_id y la clave son inmutables");

  const T = fixtureUuid("t865");
  const expectFail = async (label: string, values: unknown[], constraint: string): Promise<void> => {
    await admin.query("SAVEPOINT s");
    await assert.rejects(
      () => admin.query("INSERT INTO app.idempotency_key (tenant_id, scope_key_hash, payload_hash, status, body, expires_at) VALUES ($1, $2, $3, $4, $5::jsonb, now())", values),
      (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === constraint,
      label,
    );
    await admin.query("ROLLBACK TO SAVEPOINT s");
  };
  await admin.query("BEGIN");
  await expectFail("hash de clave mal formado", [T, "no-es-hex", hex("p"), 201, "{}"], "idempotency_scope_key_hash_shape");
  await expectFail("hash de payload mal formado", [T, hex("k"), "XYZ", 201, "{}"], "idempotency_payload_hash_shape");
  await expectFail("solo 2xx", [T, hex("k"), hex("p"), 422, "{}"], "idempotency_status_2xx");
  await expectFail("body objeto", [T, hex("k"), hex("p"), 201, "[]"], "idempotency_body_object");
  await admin.query("SAVEPOINT s");
  await assert.rejects(
    () => admin.query("INSERT INTO app.idempotency_key (tenant_id, scope_key_hash, payload_hash, status, body, expires_at, data_class) VALUES ($1, $2, $3, 201, '{}', now(), 'REAL')", [T, hex("k"), hex("p")]),
    (e: unknown) => constraintOf(e) === "idempotency_data_class_synthetic",
  );
  await admin.query("ROLLBACK TO SAVEPOINT s");
  await admin.query("ROLLBACK");
});

pgTest("TEST-CNS-866 pg: TTL P-33 sin default de produccion (sin politica el adaptador falla cerrado); una entrada vencida no se encuentra y se reemplaza; una vigente no se pisa", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const admin = await ctx.connectAsSuperuser();
  const T = fixtureUuid("t866");
  try {
    const noPolicy = new PgUnitOfWork(pool);
    await assert.rejects(() => noPolicy.inTenant(T, (tx) => tx.idempotency.find(T, hex("k866"))), IdempotencyPolicyMissingError);
    await assert.rejects(() => noPolicy.inTenant(T, (tx) => tx.idempotency.store(T, hex("k866"), resp("a866"))), IdempotencyPolicyMissingError);

    const uow = new PgUnitOfWork(pool, { idempotencyPolicy: { ttlMs: 60_000 } });
    const key = hex("k866");
    await uow.inTenant(T, (tx) => tx.idempotency.store(T, key, resp("a866")));
    const ttl = (await admin.query<{ s: number }>("SELECT extract(epoch FROM expires_at - created_at)::int AS s FROM app.idempotency_key WHERE tenant_id = $1", [T])).rows[0]?.s;
    assert.ok(ttl !== undefined && ttl >= 59 && ttl <= 61, `expires_at = ahora + ttl (${ttl}s)`);

    // Vence: ya no se encuentra...
    await admin.query("UPDATE app.idempotency_key SET expires_at = now() - interval '1 second' WHERE tenant_id = $1", [T]);
    assert.equal(await uow.inTenant(T, (tx) => tx.idempotency.find(T, key)), null);
    // ... y la nueva respuesta la reemplaza.
    const fresh = resp("b866");
    await uow.inTenant(T, (tx) => tx.idempotency.store(T, key, fresh));
    assert.deepEqual(await uow.inTenant(T, (tx) => tx.idempotency.find(T, key)), fresh);
    assert.equal((await admin.query("SELECT 1 FROM app.idempotency_key WHERE tenant_id = $1", [T])).rows.length, 1);
    // Una vigente nunca se pisa.
    await uow.inTenant(T, (tx) => tx.idempotency.store(T, key, resp("c866")));
    assert.deepEqual(await uow.inTenant(T, (tx) => tx.idempotency.find(T, key)), fresh);
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-867 pg: dos requests concurrentes con la misma Idempotency-Key se serializan: una ejecuta y la otra reproduce la respuesta (find + ejecutar + store en la misma tx)", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 8 });
  const T = fixtureUuid("t867");
  try {
    const uow = new PgUnitOfWork(pool, { idempotencyPolicy: { ttlMs: 60_000 } });
    for (let round = 0; round < 10; round += 1) {
      const key = hex(`k867-${round}`);
      let executions = 0;
      const request = (): Promise<string> =>
        uow.inTenant(T, async (tx) => {
          const stored = await tx.idempotency.find(T, key);
          if (stored) return "replay";
          executions += 1;
          await new Promise((resolve) => setTimeout(resolve, 15)); // ventana de carrera
          await tx.idempotency.store(T, key, resp(`r867-${round}`));
          return "executed";
        });
      const results = await Promise.all([request(), request(), request()]);
      assert.deepEqual([...results].sort(), ["executed", "replay", "replay"], `ronda ${round}`);
      assert.equal(executions, 1, `ronda ${round}: una sola ejecucion`);
    }
  } finally {
    await pool.end();
  }
});
