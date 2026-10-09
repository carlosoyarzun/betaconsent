// Gobierna: CA-141 (decision de Carlos, 2026-10-06; D-1 sin purga en IT0, D-5 app_rw solo INSERT), db/migrations/0023_session_ref.sql,
// 0024_case_session_case_ref_uuidv4.sql y 0025_ops_security_event.sql, specs/session.spec.yaml GRD-SE-14 / GRD-SE-11 / INV-SE-05 / INV-SE-06,
// INV-CM-01/02, ADR-006 §4-§6. Contra Postgres real (harness.ts): TEST-CNS-1189 (esquema: RLS FORCE, policies, grants exactos por columna,
// triggers ENABLE ALWAYS), 1190 (append-only incluido el dueno/superusuario y replica; app_rw no lee), 1191 (CHECK por familia, sin PII,
// columnas que fija la base, y equivalencia de los CHECK de las tablas de sesion con los de security_event), 1192 (RLS por tenant) y
// 1193 (session_ref: DEFAULT, UNIQUE por tenant, sin grant, inmutable; case_ref UUIDv4). Solo datos sinteticos.

import assert from "node:assert/strict";
import type { Client } from "pg";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);
const SESSION_REF = fixtureUuid("sr-1191");
const CASE_REF = fixtureUuid("case-1191");

const EVENT_COLUMNS = ["tenant_id", "event_type", "actor_ref", "actor_role", "session_kind", "session_ref", "case_ref"];
// 0029 (SEC-CNS-021 PR-1): columnas de la familia OTP / RECOVERY / MANAGEMENT.
const OTP_FAMILY_COLUMNS = ["verification_ref", "otp_scope", "scope_class", "channel_ref", "key_kind", "window_kind", "chain_ref", "recovery_ref", "trigger_kind"];

pgTest("TEST-CNS-1189 pg: ops.security_event con FORCE RLS, una sola policy INSERT por tenant, grants exactos por columna (sin SELECT para app_rw), nada para worker/platform_rw y triggers ENABLE ALWAYS", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
    "SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = 'ops.security_event'::regclass",
  )).rows[0];
  assert.deepEqual(rel, { rls: true, force: true, owner: "security_event_owner" }); // 0029 (SEC-CNS-021 PR-1, INV-21-06)

  const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
    "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'ops' AND tablename = 'security_event'",
  )).rows;
  assert.deepEqual(policies.map((p) => p.cmd), ["INSERT"], "D-5: sin policy SELECT/UPDATE/DELETE");
  assert.deepEqual(policies[0]!.roles, ["app_rw"]);
  assert.match(policies[0]!.with_check ?? "", /app\.current_tenant_id\(\)/);

  for (const role of ["app_rw", "worker", "platform_rw"]) {
    for (const privilege of ["SELECT", "UPDATE"]) {
      assert.equal((await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, 'ops.security_event', $2) AS p", [role, privilege])).rows[0]?.p, false, `${role} ${privilege}`);
    }
    for (const privilege of ["DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
      assert.equal((await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'ops.security_event', $2) AS p", [role, privilege])).rows[0]?.p, false, `${role} ${privilege}`);
    }
  }
  for (const role of ["worker", "platform_rw"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, 'ops.security_event', 'INSERT') AS p", [role])).rows[0]?.p, false, `${role} INSERT`);
  }
  const insertable = (await admin.query<{ attname: string }>(
    `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'ops.security_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped
        AND has_column_privilege('app_rw', a.attrelid, a.attnum, 'INSERT') ORDER BY a.attname`,
  )).rows.map((r) => r.attname);
  assert.deepEqual(insertable, [...EVENT_COLUMNS, ...OTP_FAMILY_COLUMNS].sort(), "app_rw solo inserta las columnas de refs; la base fija id, seq, version, instante, entorno y clase");

  // Cero PII por construccion: ninguna columna de sid, hash, cookie, csrf, ip, user-agent, correo, nombre o texto libre.
  const columns = (await admin.query<{ attname: string }>(
    "SELECT attname FROM pg_attribute WHERE attrelid = 'ops.security_event'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attname",
  )).rows.map((r) => r.attname);
  assert.deepEqual(columns, ["actor_ref", "actor_role", "case_ref", "chain_ref", "channel_ref", "data_class", "environment", "event_id", "event_seq", "event_type", "key_kind", "occurred_at", "otp_scope", "recovery_ref", "schema_version", "scope_class", "session_kind", "session_ref", "tenant_id", "trigger_kind", "verification_ref", "window_kind"]);
  assert.ok(!columns.some((c) => /sid|hash|cookie|csrf|ip|agent|mail|name|rut|detail|message|payload/.test(c)));

  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>(
    "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'ops.security_event'::regclass AND NOT tgisinternal ORDER BY tgname",
  )).rows;
  assert.deepEqual(triggers.map((t) => t.tgname), ["security_event_no_truncate", "security_event_no_update_delete"]);
  assert.ok(triggers.every((t) => t.tgenabled === "A"), "ENABLE ALWAYS");
});

const baseRow = { tenant_id: fixtureUuid("t-1190"), event_type: "STAFF_LOGIN", actor_ref: "staff-synthetic-01", actor_role: "TENANT_ADMIN", session_kind: "STAFF", session_ref: SESSION_REF, case_ref: null as string | null };
async function insertEvent(client: Client, over: Partial<typeof baseRow> = {}): Promise<unknown> {
  const r = { ...baseRow, ...over };
  return client.query(
    "INSERT INTO ops.security_event (tenant_id, event_type, actor_ref, actor_role, session_kind, session_ref, case_ref) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [r.tenant_id, r.event_type, r.actor_ref, r.actor_role, r.session_kind, r.session_ref, r.case_ref],
  );
}

pgTest("TEST-CNS-1190 pg: ops.security_event es append-only tambien para el superusuario y con session_replication_role=replica; app_rw no puede leer (D-5)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  await insertEvent(admin);
  for (const sql of ["UPDATE ops.security_event SET actor_role = 'APPROVER'", "DELETE FROM ops.security_event", "TRUNCATE ops.security_event"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", sql);
    await admin.query("SET session_replication_role = replica");
    try {
      await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `${sql} (replica)`);
    } finally {
      await admin.query("SET session_replication_role = DEFAULT");
    }
  }
  const migrator = await ctx.connectAs("consent_migrator");
  // El migrador (FORCE RLS, sin tenant) no ve filas, asi que UPDATE/DELETE no tocan nada; TRUNCATE si llega al trigger de sentencia o al permiso.
  await assert.rejects(() => migrator.query("TRUNCATE ops.security_event"), (e: unknown) => ["23000", "42501"].includes(codeOf(e) ?? ""), "migrador: TRUNCATE");
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event")).rowCount, 1, "la fila sigue intacta");

  const rw = await ctx.connectAs("app_rw");
  await rw.query("BEGIN");
  try {
    await rw.query("SELECT set_config('app.tenant_id', $1, true)", [baseRow.tenant_id]);
    await assert.rejects(() => rw.query("SELECT 1 FROM ops.security_event"), (e: unknown) => codeOf(e) === "42501", "app_rw no tiene SELECT (D-5)");
  } finally {
    await rw.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1191 pg: CHECK de enum de tipo, forma por familia (STAFF/CASE/rotacion), refs sin PII y columnas que fija la base; los CHECK de las tablas de sesion equivalen a los de security_event (INV-SE-06)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const expectFail = async (label: string, over: Partial<typeof baseRow>, constraint: string | string[]): Promise<void> => {
    const accepted = Array.isArray(constraint) ? constraint : [constraint];
    await admin.query("BEGIN");
    try {
      await assert.rejects(() => insertEvent(admin, over), (e: unknown) => codeOf(e) === "23514" && accepted.includes(constraintOf(e) ?? ""), label);
    } finally {
      await admin.query("ROLLBACK");
    }
  };
  await expectFail("tipo fuera del enum", { event_type: "OTP_REVEALED" }, ["security_event_otp_shape", "security_event_type_enum"]); // dos CHECK violables: orden no garantizado
  await expectFail("OTP_ISSUED con columnas de sesion y sin refs OTP (0029: la forma por familia la cubre TEST-CNS-1305)", { event_type: "OTP_ISSUED" }, "security_event_otp_shape");
  await expectFail("STAFF con case_ref", { case_ref: CASE_REF }, "security_event_session_shape");
  await expectFail("STAFF con session_kind CASE", { session_kind: "CASE" }, "security_event_session_shape");
  await expectFail("sin actor", { actor_ref: null as unknown as string }, "security_event_session_shape");
  await expectFail("sin session_ref", { session_ref: null as unknown as string }, "security_event_session_shape");
  await expectFail("CASE sin case_ref", { event_type: "CASE_LOGIN", session_kind: "CASE", actor_role: "RIGHTS_OPERATOR" }, "security_event_session_shape");
  await expectFail("CASE con TENANT_ADMIN", { event_type: "CASE_LOGOUT", session_kind: "CASE", actor_role: "TENANT_ADMIN", case_ref: CASE_REF }, "security_event_session_shape");
  await expectFail("CASE con session_kind STAFF", { event_type: "CASE_LOGIN", session_kind: "STAFF", actor_role: "APPROVER", case_ref: CASE_REF }, "security_event_session_shape");
  await expectFail("rotacion CASE sin case_ref", { event_type: "SESSION_REVOKED_BY_ROTATION", session_kind: "CASE", actor_role: "APPROVER" }, "security_event_session_shape");
  await expectFail("rotacion STAFF con case_ref", { event_type: "SESSION_REVOKED_BY_ROTATION", case_ref: CASE_REF }, "security_event_session_shape");
  await expectFail("rotacion CASE con TENANT_ADMIN", { event_type: "SESSION_REVOKED_BY_ROTATION", session_kind: "CASE", case_ref: CASE_REF }, "security_event_session_shape");
  for (const bad of ["persona@ejemplo.cl", "12.345.678-5", "Maria Perez", "staff-synthetic-1"]) await expectFail(`actor_ref ${bad}`, { actor_ref: bad }, "security_event_actor_ref_shape");
  await expectFail("actor_role fuera del enum", { actor_role: "ROOT" }, "security_event_actor_role_enum");
  await expectFail("session_ref no UUIDv4", { session_ref: "11111111-1111-1111-8111-111111111111" }, "security_event_session_ref_uuidv4");
  await expectFail("case_ref no UUIDv4", { event_type: "CASE_LOGIN", session_kind: "CASE", actor_role: "APPROVER", case_ref: "case-1" }, "security_event_case_ref_uuidv4");
  // las tres familias validas entran
  await admin.query("BEGIN");
  try {
    await insertEvent(admin);
    await insertEvent(admin, { event_type: "CASE_LOGOUT", session_kind: "CASE", actor_role: "APPROVER", case_ref: CASE_REF });
    await insertEvent(admin, { event_type: "SESSION_REVOKED_BY_ROTATION", session_kind: "STAFF", actor_role: "RIGHTS_OPERATOR" });
    await insertEvent(admin, { event_type: "SESSION_REVOKED_BY_ROTATION", session_kind: "CASE", actor_role: "RIGHTS_OPERATOR", case_ref: CASE_REF });
    const row = (await admin.query<{ schema_version: string; environment: string; data_class: string; occurred_at: Date; event_id: string }>("SELECT schema_version, environment, data_class, occurred_at, event_id FROM ops.security_event LIMIT 1")).rows[0]!;
    assert.deepEqual([row.schema_version, row.environment, row.data_class], ["1.0.0", "LOCAL", "SYNTHETIC"]);
    assert.match(row.event_id, /^[0-9a-f-]{36}$/);
  } finally {
    await admin.query("ROLLBACK");
  }

  // app_rw no fija lo que decide la base
  const rw = await ctx.connectAs("app_rw");
  for (const column of ["environment", "data_class", "occurred_at", "event_id", "schema_version"]) {
    const value = column === "occurred_at" ? "now()" : column === "event_id" ? "gen_random_uuid()" : column === "schema_version" ? "'9.9.9'" : column === "environment" ? "'PRODUCTION'" : "'SYNTHETIC'";
    await rw.query("BEGIN");
    try {
      await rw.query("SELECT set_config('app.tenant_id', $1, true)", [baseRow.tenant_id]);
      await assert.rejects(
        () => rw.query(`INSERT INTO ops.security_event (tenant_id, event_type, actor_ref, actor_role, session_kind, session_ref, ${column}) VALUES ($1, 'STAFF_LOGIN', 'staff-synthetic-01', 'TENANT_ADMIN', 'STAFF', $2, ${value})`, [baseRow.tenant_id, SESSION_REF]),
        (e: unknown) => codeOf(e) === "42501",
        column,
      );
    } finally {
      await rw.query("ROLLBACK");
    }
  }

  // INV-SE-06: toda fila de sesion se proyecta a un evento valido => cada CHECK del evento tiene su equivalente en las tablas de sesion.
  const def = async (table: string, constraint: string): Promise<string> =>
    (await admin.query<{ d: string }>("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2", [table, constraint])).rows[0]!.d;
  const regexOf = (d: string): string => /'(\^[^']+\$)'/.exec(d)![1]!;
  const eventActor = regexOf(await def("ops.security_event", "security_event_actor_ref_shape"));
  assert.equal(regexOf(await def("app.staff_session", "staff_session_principal_ref_shape")), eventActor);
  assert.equal(regexOf(await def("app.case_session", "case_session_principal_ref_shape")), eventActor);
  const eventSessionRef = regexOf(await def("ops.security_event", "security_event_session_ref_uuidv4"));
  assert.equal(regexOf(await def("app.staff_session", "staff_session_session_ref_uuidv4")), eventSessionRef);
  assert.equal(regexOf(await def("app.case_session", "case_session_session_ref_uuidv4")), eventSessionRef);
  assert.equal(regexOf(await def("app.case_session", "case_session_case_ref_uuidv4")), regexOf(await def("ops.security_event", "security_event_case_ref_uuidv4")));
  const roles = (d: string): string[] => [...d.matchAll(/'([A-Z_]+)'::text/g)].map((m) => m[1]!).sort();
  assert.deepEqual(roles(await def("app.staff_session", "staff_session_role_enum")), roles(await def("ops.security_event", "security_event_actor_role_enum")));
  assert.deepEqual(roles(await def("app.case_session", "case_session_role_enum")), ["APPROVER", "RIGHTS_OPERATOR"], "los roles CASE son un subconjunto de los del evento");
});

pgTest("TEST-CNS-1192 pg: RLS de ops.security_event: app_rw solo inserta en el tenant de la tx (otro tenant o sin tenant: 42501) y nada queda en el tenant ajeno", async (ctx) => {
  const A = fixtureUuid("t1192-a");
  const B = fixtureUuid("t1192-b");
  const admin = await ctx.connectAsSuperuser();
  const rw = await ctx.connectAs("app_rw");
  const asTenant = async (tenant: string | null, fn: () => Promise<void>): Promise<void> => {
    await rw.query("BEGIN");
    try {
      if (tenant !== null) await rw.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
      await fn();
      await rw.query("COMMIT");
    } catch (e) {
      await rw.query("ROLLBACK");
      throw e;
    }
  };
  await asTenant(A, () => insertEvent(rw, { tenant_id: A }).then(() => undefined));
  await assert.rejects(() => asTenant(A, () => insertEvent(rw, { tenant_id: B }).then(() => undefined)), (e: unknown) => codeOf(e) === "42501", "otro tenant");
  await assert.rejects(() => asTenant(null, () => insertEvent(rw, { tenant_id: A }).then(() => undefined)), (e: unknown) => codeOf(e) === "42501", "sin tenant");
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event WHERE tenant_id = $1", [A])).rowCount, 1);
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event WHERE tenant_id = $1", [B])).rowCount, 0);
});

pgTest("TEST-CNS-1193 pg: session_ref de app.staff_session y app.case_session: DEFAULT UUIDv4 de la base, UNIQUE por tenant, sin grant para app_rw e inmutable (trigger, incluido el dueno); case_ref de la sesion CASE es UUIDv4", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const A = fixtureUuid("t1193-a");
  const B = fixtureUuid("t1193-b");
  const insertStaff = (tenant: string, sid: string, extra = ""): Promise<unknown> =>
    admin.query(`INSERT INTO app.staff_session (tenant_id, sid_hash, principal_ref, role, issued_at, expires_at, last_seen_at${extra ? ", session_ref" : ""}) VALUES ($1, $2, 'staff-synthetic-01', 'TENANT_ADMIN', now(), now() + interval '1 hour', now()${extra ? `, '${extra}'` : ""})`, [tenant, hex(sid)]);
  const insertCase = (tenant: string, sid: string, caseRef: string, extra = ""): Promise<unknown> =>
    admin.query(`INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at${extra ? ", session_ref" : ""}) VALUES ($1, $2, $3, 'staff-synthetic-01', 'RIGHTS_OPERATOR', now(), now() + interval '1 hour', now()${extra ? `, '${extra}'` : ""})`, [tenant, hex(sid), caseRef]);
  await insertStaff(A, "s1");
  await insertStaff(A, "s2");
  await insertCase(A, "c1", fixtureUuid("case-1193"));
  await insertCase(A, "c2", fixtureUuid("case-1193"));
  for (const table of ["app.staff_session", "app.case_session"]) {
    const refs = (await admin.query<{ session_ref: string }>(`SELECT session_ref FROM ${table} WHERE tenant_id = $1`, [A])).rows.map((r) => r.session_ref);
    assert.equal(new Set(refs).size, 2, `${table}: un session_ref distinto por fila`);
    for (const ref of refs) assert.match(ref, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }
  // UNIQUE (tenant_id, session_ref): repetido en el mismo tenant falla; en otro tenant es otra clave y no falla
  const dup = (await admin.query<{ session_ref: string }>("SELECT session_ref FROM app.staff_session WHERE tenant_id = $1 LIMIT 1", [A])).rows[0]!.session_ref;
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => insertStaff(A, "s3", dup), (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "staff_session_tenant_session_ref_key");
  } finally {
    await admin.query("ROLLBACK");
  }
  await insertStaff(B, "s4", dup);
  const dupCase = (await admin.query<{ session_ref: string }>("SELECT session_ref FROM app.case_session WHERE tenant_id = $1 LIMIT 1", [A])).rows[0]!.session_ref;
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => insertCase(A, "c3", fixtureUuid("case-1193"), dupCase), (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "case_session_tenant_session_ref_key");
  } finally {
    await admin.query("ROLLBACK");
  }
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => insertStaff(A, "s5", "11111111-1111-1111-8111-111111111111"), (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === "staff_session_session_ref_uuidv4");
  } finally {
    await admin.query("ROLLBACK");
  }
  // case_ref: ya no basta la longitud (P1-1); debe ser UUIDv4
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => insertCase(A, "c4", "case-1163"), (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === "case_session_case_ref_uuidv4");
  } finally {
    await admin.query("ROLLBACK");
  }
  // sin grant: app_rw no inserta ni actualiza session_ref
  for (const table of ["app.staff_session", "app.case_session"]) {
    for (const privilege of ["INSERT", "UPDATE"]) {
      const r = (await admin.query<{ p: boolean }>(`SELECT has_column_privilege('app_rw', '${table}', 'session_ref', $1) AS p`, [privilege])).rows[0];
      assert.equal(r?.p, false, `${table} ${privilege}(session_ref)`);
    }
  }
  const rw = await ctx.connectAs("app_rw");
  await rw.query("BEGIN");
  try {
    await rw.query("SELECT set_config('app.tenant_id', $1, true)", [A]);
    await assert.rejects(() => rw.query("UPDATE app.staff_session SET session_ref = gen_random_uuid() WHERE sid_hash = $1", [hex("s1")]), (e: unknown) => codeOf(e) === "42501");
  } finally {
    await rw.query("ROLLBACK");
  }
  // inmutable aun para el dueno/superusuario (P2-3: dentro del trigger de inmutabilidad)
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => admin.query("UPDATE app.staff_session SET session_ref = gen_random_uuid() WHERE sid_hash = $1", [hex("s1")]), (e: unknown) => codeOf(e) === "23000");
  } finally {
    await admin.query("ROLLBACK");
  }
  await admin.query("BEGIN");
  try {
    await admin.query("SAVEPOINT u");
    await assert.rejects(() => admin.query("UPDATE app.case_session SET session_ref = gen_random_uuid() WHERE sid_hash = $1", [hex("c1")]), (e: unknown) => codeOf(e) === "23000");
    await admin.query("ROLLBACK TO SAVEPOINT u");
    await admin.query("SET LOCAL session_replication_role = replica");
    await assert.rejects(() => admin.query("UPDATE app.case_session SET session_ref = gen_random_uuid() WHERE sid_hash = $1", [hex("c1")]), (e: unknown) => codeOf(e) === "23000", "tambien con replica");
  } finally {
    await admin.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1193 (0024) pg: la migracion 0024 elimina las sesiones CASE previas con case_ref no UUIDv4 (sin evento) y deja el CHECK VALIDADO; el DELETE funciona aun con FORCE RLS y el dueno", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const T = fixtureUuid("t0024");
  // Estado previo a 0024: sin el CHECK y con una sesion efimera de case_ref no UUID mas una valida.
  await admin.query("ALTER TABLE app.case_session DROP CONSTRAINT case_session_case_ref_uuidv4");
  const ins = (sid: string, caseRef: string): Promise<unknown> =>
    admin.query("INSERT INTO app.case_session (tenant_id, sid_hash, case_ref, principal_ref, role, issued_at, expires_at, last_seen_at) VALUES ($1, $2, $3, 'staff-synthetic-01', 'RIGHTS_OPERATOR', now(), now() + interval '1 hour', now())", [T, hex(sid), caseRef]);
  await ins("viejo", "case-1163");
  await ins("bueno", fixtureUuid("case-0024"));
  const events = (await admin.query("SELECT 1 FROM ops.security_event")).rowCount;
  // Se ejecuta el SQL de la migracion como el migrador/dueno (FORCE RLS aplica al dueno): SET ROLE consent_owner como en el runner.
  const migrator = await ctx.connectAs("consent_migrator");
  const sql = readFileSync(join(MIGRATIONS_DIR, "0024_case_session_case_ref_uuidv4.sql"), "utf8");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query(sql);
    await migrator.query("COMMIT");
  } catch (e) {
    await migrator.query("ROLLBACK");
    throw e;
  }
  const left = (await admin.query<{ sid_hash: string }>("SELECT sid_hash FROM app.case_session WHERE tenant_id = $1", [T])).rows.map((r) => r.sid_hash);
  assert.deepEqual(left, [hex("bueno")], "la fila previa no UUID desaparecio y la valida se conserva");
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event")).rowCount, events, "cerrarlas no escribe evento");
  const c = (await admin.query<{ convalidated: boolean }>("SELECT convalidated FROM pg_constraint WHERE conrelid = 'app.case_session'::regclass AND conname = 'case_session_case_ref_uuidv4'")).rows[0];
  assert.equal(c?.convalidated, true, "CHECK validado (sin NOT VALID)");
  const rel = (await admin.query<{ force: boolean }>("SELECT relforcerowsecurity AS force FROM pg_class WHERE oid = 'app.case_session'::regclass")).rows[0];
  assert.equal(rel?.force, true, "FORCE RLS restaurado");
  await admin.query("BEGIN");
  try {
    await assert.rejects(() => ins("nuevo", "case-1"), (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === "case_session_case_ref_uuidv4");
  } finally {
    await admin.query("ROLLBACK");
  }
});
