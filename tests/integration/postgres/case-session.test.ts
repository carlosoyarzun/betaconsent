// Gobierna: CA-139 (SEC-CNS-018 rev. 2 D-3, P1-1 de CA-138), db/migrations/0022_case_session.sql, INV-CM-02, ADR-006 §4-§6. Contra Postgres real (harness.ts):
// TEST-CNS-1161/1162 (misma suite de contrato que in-memory, via PgUnitOfWork + app_rw) y TEST-CNS-1172 (esquema: FORCE RLS, grants
// minimos, revocacion de un solo sentido, DELETE solo de expiradas, sin PII, aislamiento cross-tenant a nivel SQL). Solo sinteticos.

import assert from "node:assert/strict";

import { createPgCaseSessionStore } from "../../../src/infra/adapters/postgres/case-session.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { runCaseSessionStoreContract } from "../../contract/ports/case-session-store.contract.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

runCaseSessionStoreContract((name, body) => {
  pgTest(name, async (ctx) => {
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
    try {
      await body(createPgCaseSessionStore(new PgUnitOfWork(pool, {})));
    } finally {
      await pool.end();
    }
  });
});

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);

pgTest("TEST-CNS-1172 pg: app.case_session con FORCE RLS por tenant, grants minimos (sin roles nuevos), revocacion de un solo sentido, DELETE solo de filas expiradas, CHECK sin PII y aislamiento cross-tenant", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
    "SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = 'app.case_session'::regclass",
  )).rows[0];
  assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" });

  const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
    "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'app' AND tablename = 'case_session'",
  )).rows;
  assert.deepEqual(policies.map((p) => p.cmd).sort(), ["DELETE", "INSERT", "SELECT", "UPDATE"]);
  for (const p of policies) {
    assert.deepEqual(p.roles, ["app_rw"]);
    assert.match(`${p.qual ?? ""}${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/);
  }
  assert.match(policies.find((p) => p.cmd === "DELETE")?.qual ?? "", /expires_at < now\(\)/);
  for (const role of ["worker", "platform_rw"]) {
    for (const privilege of ["SELECT", "INSERT", "UPDATE"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, 'app.case_session', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege}`);
    }
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'app.case_session', 'DELETE') AS p", [role])).rows[0]?.p, false, `${role} DELETE`);
  }
  for (const privilege of ["TRUNCATE", "REFERENCES", "TRIGGER"]) {
    const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege('app_rw', 'app.case_session', $1) AS p", [privilege])).rows[0];
    assert.equal(r?.p, false, `app_rw ${privilege}`);
  }
  const cols = async (privilege: string): Promise<string[]> =>
    (await admin.query<{ attname: string }>(
      `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'app.case_session'::regclass AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege('app_rw', a.attrelid, a.attnum, $1) ORDER BY a.attname`,
      [privilege],
    )).rows.map((r) => r.attname);
  assert.deepEqual(await cols("INSERT"), ["case_ref", "expires_at", "issued_at", "last_seen_at", "principal_ref", "role", "sid_hash", "tenant_id"]);
  assert.deepEqual(await cols("UPDATE"), ["last_seen_at", "revoked_at"], "tenant, sid, caso, principal, rol y vida son inmutables");
  // sin PII por construccion: las unicas columnas de texto son hash, ref opaca, rol y data_class
  const textCols = (await admin.query<{ attname: string }>(
    "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'app.case_session'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.atttypid = 'text'::regtype ORDER BY a.attname",
  )).rows.map((r) => r.attname);
  assert.deepEqual(textCols, ["case_ref", "data_class", "principal_ref", "role", "sid_hash"]);

  const T = fixtureUuid("t1172");
  const expectFail = async (label: string, values: unknown[], constraint: string): Promise<void> => {
    await admin.query("SAVEPOINT s");
    await assert.rejects(
      () => admin.query("INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at) VALUES ($1, $2, 'case-1172', $3, $4, now(), now() + interval '1 hour', now())", values),
      (e: unknown) => codeOf(e) === "23514" && (e as { constraint?: string }).constraint === constraint,
      label,
    );
    await admin.query("ROLLBACK TO SAVEPOINT s");
  };
  await admin.query("BEGIN");
  await expectFail("sid en claro / forma", [T, "no-es-un-hash", "staff-synthetic-01", "RIGHTS_OPERATOR"], "case_session_sid_hash_shape");
  await expectFail("principal con PII (email)", [T, hex("a"), "persona@ejemplo.cl", "RIGHTS_OPERATOR"], "case_session_principal_ref_shape");
  await expectFail("principal con RUT", [T, hex("a"), "12.345.678-5", "RIGHTS_OPERATOR"], "case_session_principal_ref_shape");
  await expectFail("rol fuera del enum", [T, hex("a"), "staff-synthetic-01", "ROOT"], "case_session_role_enum");
  await expectFail("TENANT_ADMIN no es rol CASE", [T, hex("a"), "staff-synthetic-01", "TENANT_ADMIN"], "case_session_role_enum");
  await admin.query("ROLLBACK");
  // case_ref: ni vacio ni de mas de 100 caracteres
  await admin.query("BEGIN");
  for (const bad of ["", "x".repeat(101)]) {
    await admin.query("SAVEPOINT c");
    await assert.rejects(
      () => admin.query("INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at) VALUES ($1, $2, $3, 'staff-synthetic-01', 'RIGHTS_OPERATOR', now(), now() + interval '1 hour', now())", [T, hex("a"), bad]),
      (e: unknown) => codeOf(e) === "23514" && (e as { constraint?: string }).constraint === "case_session_case_ref_len",
    );
    await admin.query("ROLLBACK TO SAVEPOINT c");
  }
  await admin.query("ROLLBACK");

  // Como app_rw: aislamiento por tenant (RLS FORCE), revocacion de un solo sentido y DELETE solo de expiradas.
  const A = fixtureUuid("tenant-a-1172");
  const B = fixtureUuid("tenant-b-1172");
  const rw = await ctx.connectAs("app_rw");
  const asTenant = async (tenant: string, fn: () => Promise<void>): Promise<void> => {
    await rw.query("BEGIN");
    try {
      await rw.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
      await fn();
    } finally {
      await rw.query("ROLLBACK");
    }
  };
  const ins = (tenant: string, sid: string, ttl: string) =>
    rw.query(
      `INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at)
       VALUES ($1, $2, 'case-1172', 'staff-synthetic-01', 'RIGHTS_OPERATOR', now() - interval '2 days', now() + $3::interval, now() - interval '2 days')`,
      [tenant, hex(sid), ttl],
    );
  await asTenant(A, async () => {
    await ins(A, "vigente", "1 hour");
    await ins(A, "vencida", "-1 hour");
    await assert.rejects(() => rw.query("SAVEPOINT x").then(() => ins(B, "ajena", "1 hour")), (e: unknown) => codeOf(e) === "42501", "no se inserta en otro tenant (RLS)");
    await rw.query("ROLLBACK TO SAVEPOINT x");
    assert.equal((await rw.query("SELECT 1 FROM app.case_session")).rowCount, 2, "solo ve las suyas");
    // revocacion de un solo sentido
    await rw.query("UPDATE app.case_session SET revoked_at = now() WHERE sid_hash = $1", [hex("vigente")]);
    await rw.query("SAVEPOINT y");
    await assert.rejects(() => rw.query("UPDATE app.case_session SET revoked_at = NULL WHERE sid_hash = $1", [hex("vigente")]), (e: unknown) => codeOf(e) === "23000");
    await rw.query("ROLLBACK TO SAVEPOINT y");
    // DELETE: la vigente (revocada o no) nunca; la vencida si
    assert.equal((await rw.query("DELETE FROM app.case_session WHERE sid_hash = $1", [hex("vigente")])).rowCount, 0);
    assert.equal((await rw.query("DELETE FROM app.case_session WHERE sid_hash = $1", [hex("vencida")])).rowCount, 1);
  });
  await asTenant(B, async () => {
    assert.equal((await rw.query("SELECT 1 FROM app.case_session")).rowCount, 0, "B no ve nada de A");
    assert.equal((await rw.query("UPDATE app.case_session SET revoked_at = now()")).rowCount, 0);
    assert.equal((await rw.query("DELETE FROM app.case_session")).rowCount, 0);
  });
  // sin tenant fijado: fail-closed
  await rw.query("BEGIN");
  assert.equal((await rw.query("SELECT 1 FROM app.case_session")).rowCount, 0);
  await rw.query("ROLLBACK");
  await rw.end();
  await admin.end();
});

pgTest("TEST-CNS-1173 pg: CHECK last_seen_at dentro de [issued_at, expires_at]: app_rw no puede dejar la ultima actividad en el futuro lejano ni antes de la emision", async (ctx) => {
  const T = fixtureUuid("t1173");
  const rw = await ctx.connectAs("app_rw");
  try {
    await rw.query("BEGIN");
    await rw.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    await rw.query(
      `INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at)
       VALUES ($1, $2, 'case-1172', 'staff-synthetic-01', 'RIGHTS_OPERATOR', now(), now() + interval '8 hours', now())`,
      [T, hex("ok")],
    );
    for (const [label, value] of [["futuro lejano", "now() + interval '100 years'"], ["pasado la exp", "now() + interval '9 hours'"], ["antes de la emision", "now() - interval '1 day'"]] as const) {
      await rw.query("SAVEPOINT s");
      await assert.rejects(
        () => rw.query(`UPDATE app.case_session SET last_seen_at = ${value} WHERE sid_hash = $1`, [hex("ok")]),
        (e: unknown) => codeOf(e) === "23514" && (e as { constraint?: string }).constraint === "case_session_last_seen_in_life",
        label,
      );
      await rw.query("ROLLBACK TO SAVEPOINT s");
    }
    await rw.query("SAVEPOINT s");
    await assert.rejects(
      () => rw.query(
        `INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at)
         VALUES ($1, $2, 'case-1172', 'staff-synthetic-01', 'RIGHTS_OPERATOR', now(), now() + interval '8 hours', now() + interval '100 years')`,
        [T, hex("fut")],
      ),
      (e: unknown) => codeOf(e) === "23514",
    );
    await rw.query("ROLLBACK TO SAVEPOINT s");
    await rw.query("ROLLBACK");
  } finally {
    await rw.end();
  }
});

pgTest("TEST-CNS-1175 pg: validateAndTouch solo escribe last_seen_at si esta atrasada mas que la granularidad (60 s); dentro de la ventana valida sin escribir; revocada no valida", async (ctx) => {
  const T = fixtureUuid("t1175");
  const admin = await ctx.connectAsSuperuser();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const store = createPgCaseSessionStore(new PgUnitOfWork(pool, {}));
    const now = Date.now();
    const sidHash = hex("g");
    await store.create({ tenantId: T, sidHash, caseRef: "case-1175", principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR", issuedAtMs: now, expiresAtMs: now + 8 * 3_600_000 });
    const lastSeen = async (): Promise<number> => Number((await admin.query<{ ms: string }>("SELECT (extract(epoch FROM last_seen_at) * 1000)::bigint::text AS ms FROM app.case_session WHERE sid_hash = $1", [sidHash])).rows[0]?.ms);
    const v = (nowMs: number) => store.validateAndTouch({ tenantId: T, sidHash, caseRef: "case-1175", principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR", nowMs, idleTimeoutMs: 30 * 60_000 });
    const before = await lastSeen();
    assert.equal(await v(now + 10_000), true);
    assert.equal(await lastSeen(), before, "dentro de 60 s no se escribe");
    assert.equal(await v(now + 59_000), true);
    assert.equal(await lastSeen(), before);
    assert.equal(await v(now + 61_000), true);
    assert.equal(await lastSeen(), now + 61_000, "pasada la granularidad se avanza");
    assert.equal(await v(now + 61_000 + 30 * 60_000 + 1), false, "inactividad correcta con esa granularidad");
    await store.revoke(T, sidHash, now + 62_000);
    assert.equal(await v(now + 70_000), false, "revocada no valida aunque este dentro de la ventana");
  } finally {
    await pool.end();
    await admin.end();
  }
});
