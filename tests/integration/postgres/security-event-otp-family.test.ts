// Gobierna: SEC-CNS-021 PR-1 (aceptada por Carlos 2026-10-08; CA-146 / P-34), db/migrations/0028_security_event_owner_role.sql y
// 0029_security_event_otp_family.sql, INV-21-04 / INV-21-05 / INV-21-06, SEC-CNS-006 rev. 5, ADR-010 rev. 3 §4.1, INV-CM-01 / INV-CM-02.
// TEST-CNS-1326 (el nuevo dueno tampoco puede mutar; usa SET ROLE security_event_owner: ruta en la allowlist del checker). Contra Postgres real (harness.ts; skip fuera de CI sin entorno): TEST-CNS-1305 (CHECK por familia: cada tipo con columnas faltantes o
// sobrantes -> 23514), TEST-CNS-1306 (matriz de app_rw: INSERT solo en su tenant y por columnas; sin SELECT/UPDATE/DELETE/TRUNCATE; worker y
// platform_rw sin DML) y TEST-CNS-1307 (duenos: security_event_owner dueno de la tabla y su funcion, ningun rol de runtime es miembro,
// triggers ENABLE ALWAYS y FORCE RLS). Solo datos sinteticos. Estos tests NO se corrieron localmente (sin Docker/Postgres): los corre el CI.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Client } from "pg";

import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;

const TENANT = fixtureUuid("t-1305");
const VERIFICATION = fixtureUuid("v-1305");
const CHANNEL = fixtureUuid("ch-1305");
const CHAIN = fixtureUuid("cn-1305");
const RECOVERY = fixtureUuid("rc-1305");

type Row = Record<string, string | null>;
const NULLS: Row = {
  verification_ref: null, otp_scope: null, scope_class: null, channel_ref: null, key_kind: null, window_kind: null,
  chain_ref: null, recovery_ref: null, trigger_kind: null, actor_ref: null, actor_role: null, session_kind: null, session_ref: null, case_ref: null,
};
const COLUMNS = ["tenant_id", "event_type", ...Object.keys(NULLS)];

function row(event_type: string, over: Row = {}): Row {
  return { tenant_id: TENANT, event_type, ...NULLS, ...over };
}
function insert(client: Client, r: Row): Promise<unknown> {
  return client.query(`INSERT INTO ops.security_event (${COLUMNS.join(", ")}) VALUES (${COLUMNS.map((_, i) => `$${i + 1}`).join(", ")})`, COLUMNS.map((c) => r[c] ?? null));
}

const VALID: Array<[string, Row]> = [
  ["OTP_ISSUED", row("OTP_ISSUED", { verification_ref: VERIFICATION, otp_scope: "DECISION", channel_ref: CHANNEL })],
  ["OTP_FAILED", row("OTP_FAILED", { verification_ref: VERIFICATION, otp_scope: "REVOCATION" })],
  ["OTP_LOCKED", row("OTP_LOCKED", { verification_ref: VERIFICATION, otp_scope: "MANAGE" })],
  ["OTP_EXPIRED", row("OTP_EXPIRED", { verification_ref: VERIFICATION, otp_scope: "DECISION" })],
  ["OTP_BUDGET_EXHAUSTED CHANNEL/DECISION/DAY_1", row("OTP_BUDGET_EXHAUSTED", { verification_ref: VERIFICATION, scope_class: "DECISION", key_kind: "CHANNEL", window_kind: "DAY_1" })],
  ["OTP_BUDGET_EXHAUSTED INVITATION/DECISION/DAY_1", row("OTP_BUDGET_EXHAUSTED", { verification_ref: VERIFICATION, scope_class: "DECISION", key_kind: "INVITATION", window_kind: "DAY_1" })],
  ["OTP_BUDGET_EXHAUSTED CHAIN/RIGHTS/DAY_1", row("OTP_BUDGET_EXHAUSTED", { verification_ref: VERIFICATION, scope_class: "RIGHTS", key_kind: "CHAIN", window_kind: "DAY_1" })],
  ["OTP_BUDGET_EXHAUSTED CHAIN/RIGHTS/DAYS_30", row("OTP_BUDGET_EXHAUSTED", { verification_ref: VERIFICATION, scope_class: "RIGHTS", key_kind: "CHAIN", window_kind: "DAYS_30" })],
  ["RECOVERY_TOKEN_ISSUED", row("RECOVERY_TOKEN_ISSUED", { recovery_ref: RECOVERY, trigger_kind: "REQUESTER_ASKED" })],
  ["MANAGEMENT_TOKEN_ROTATED", row("MANAGEMENT_TOKEN_ROTATED", { chain_ref: CHAIN, trigger_kind: "FAILURE_CAP" })],
];

pgTest("TEST-CNS-1305 pg: CHECK por familia de ops.security_event (OTP_*, RECOVERY, MANAGEMENT): cada tipo con columnas faltantes o sobrantes, refs no UUIDv4 o enums fuera de rango da 23514 (INV-21-04)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const expectFail = async (label: string, r: Row, constraint: string): Promise<void> => {
    await admin.query("BEGIN");
    try {
      await assert.rejects(() => insert(admin, r), (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === constraint, label);
    } finally {
      await admin.query("ROLLBACK");
    }
  };

  // Las formas validas entran (como superusuario: RLS no interviene, los CHECK si).
  await admin.query("BEGIN");
  try {
    for (const [label, r] of VALID) await assert.doesNotReject(() => insert(admin, r), label);
    const meta = (await admin.query<{ schema_version: string; environment: string; data_class: string }>("SELECT schema_version, environment, data_class FROM ops.security_event LIMIT 1")).rows[0];
    assert.deepEqual([meta?.schema_version, meta?.environment, meta?.data_class], ["1.0.0", "LOCAL", "SYNTHETIC"]);
  } finally {
    await admin.query("ROLLBACK");
  }

  const SHAPE = "security_event_otp_shape";
  // Columnas faltantes, una por una, en cada tipo.
  for (const [label, valid] of VALID) {
    for (const [col, value] of Object.entries(valid)) {
      if (col === "tenant_id" || col === "event_type" || value === null) continue;
      await expectFail(`${label} sin ${col}`, { ...valid, [col]: null }, SHAPE);
    }
    // Columnas sobrantes: cualquier columna que el tipo deja en NULL, rellenada con un valor valido de su dominio.
    const fillers: Row = {
      verification_ref: VERIFICATION, otp_scope: "DECISION", scope_class: "DECISION", channel_ref: CHANNEL, key_kind: "CHANNEL", window_kind: "DAY_1",
      chain_ref: CHAIN, recovery_ref: RECOVERY, trigger_kind: "FAILURE_CAP",
      actor_ref: "staff-synthetic-01", actor_role: "TENANT_ADMIN", session_kind: "STAFF", session_ref: fixtureUuid("sr-1305"), case_ref: fixtureUuid("ca-1305"),
    };
    for (const [col, value] of Object.entries(valid)) {
      if (value !== null || !(col in fillers)) continue;
      await expectFail(`${label} con ${col} sobrante`, { ...valid, [col]: fillers[col] ?? null }, SHAPE);
    }
  }
  // Combinaciones prohibidas de OTP_BUDGET_EXHAUSTED (CFG-OT-BUDGET).
  const budget = (over: Row): Row => row("OTP_BUDGET_EXHAUSTED", { verification_ref: VERIFICATION, scope_class: "DECISION", key_kind: "CHANNEL", window_kind: "DAY_1", ...over });
  await expectFail("INVITATION en RIGHTS", budget({ scope_class: "RIGHTS", key_kind: "INVITATION" }), SHAPE);
  await expectFail("CHAIN en DECISION", budget({ key_kind: "CHAIN" }), SHAPE);
  await expectFail("DAYS_30 en DECISION", budget({ window_kind: "DAYS_30" }), SHAPE);
  await expectFail("DAYS_30 en RIGHTS/CHANNEL", budget({ scope_class: "RIGHTS", window_kind: "DAYS_30" }), SHAPE);
  // Disparadores por familia.
  await expectFail("RECOVERY con disparador de management", row("RECOVERY_TOKEN_ISSUED", { recovery_ref: RECOVERY, trigger_kind: "FAILURE_CAP" }), SHAPE);
  await expectFail("MANAGEMENT con disparador de recovery", row("MANAGEMENT_TOKEN_ROTATED", { chain_ref: CHAIN, trigger_kind: "CASE_CONTACT" }), SHAPE);
  // Refs que no son UUIDv4 (cero correo / nombre / RUT en las columnas de ref) y enums fuera de rango.
  // Correo, RUT y nombre no son uuid: el cast falla con 22P02 ANTES de llegar al CHECK (la columna uuid ya los hace imposibles).
  // Un uuid bien formado pero no v4 si llega al CHECK *_uuidv4 (23514).
  const expectInvalidUuid = async (label: string, r: Row): Promise<void> => {
    await admin.query("BEGIN");
    try {
      await assert.rejects(() => insert(admin, r), (e: unknown) => codeOf(e) === "22P02", label);
    } finally {
      await admin.query("ROLLBACK");
    }
  };
  for (const bad of ["persona@ejemplo.cl", "12.345.678-5", "Maria Perez"]) {
    await expectInvalidUuid(`verification_ref ${bad}`, { ...VALID[0]![1], verification_ref: bad });
    await expectInvalidUuid(`channel_ref ${bad}`, { ...VALID[0]![1], channel_ref: bad });
    await expectInvalidUuid(`chain_ref ${bad}`, { ...VALID[9]![1], chain_ref: bad });
    await expectInvalidUuid(`recovery_ref ${bad}`, { ...VALID[8]![1], recovery_ref: bad });
  }
  const notV4 = "11111111-1111-1111-8111-111111111111";
  await expectFail("verification_ref no v4", { ...VALID[0]![1], verification_ref: notV4 }, "security_event_verification_ref_uuidv4");
  await expectFail("channel_ref no v4", { ...VALID[0]![1], channel_ref: notV4 }, "security_event_channel_ref_uuidv4");
  await expectFail("chain_ref no v4", { ...VALID[9]![1], chain_ref: notV4 }, "security_event_chain_ref_uuidv4");
  await expectFail("recovery_ref no v4", { ...VALID[8]![1], recovery_ref: notV4 }, "security_event_recovery_ref_uuidv4");
  await expectFail("otp_scope fuera del enum", { ...VALID[1]![1], otp_scope: "ROOT" }, "security_event_otp_scope_enum");
  await expectFail("scope_class fuera del enum", { ...VALID[4]![1], scope_class: "ALL" }, "security_event_otp_shape"); // otp_shape se evalua antes (orden por nombre)
  await expectFail("key_kind fuera del enum", { ...VALID[4]![1], key_kind: "EMAIL" }, "security_event_key_kind_enum");
  await expectFail("window_kind fuera del enum", { ...VALID[4]![1], window_kind: "HOURS_1" }, "security_event_otp_shape"); // otp_shape se evalua antes (orden por nombre)
  await expectFail("trigger_kind fuera del enum", { ...VALID[8]![1], trigger_kind: "WHENEVER" }, "security_event_otp_shape"); // otp_shape se evalua antes (orden por nombre)
  await expectFail("tipo fuera del enum", row("OTP_REVEALED", { verification_ref: VERIFICATION, otp_scope: "DECISION" }), "security_event_otp_shape"); // Postgres evalua los CHECK por nombre y otp_shape (ELSE false) salta antes que type_enum
  // Los tipos de sesion con columnas OTP/recovery -> 23514 (otp_shape); su forma propia sigue en security_event_session_shape (TEST-CNS-1191).
  await expectFail(
    "STAFF_LOGIN con verification_ref",
    row("STAFF_LOGIN", { actor_ref: "staff-synthetic-01", actor_role: "TENANT_ADMIN", session_kind: "STAFF", session_ref: fixtureUuid("sr-1305"), verification_ref: VERIFICATION }),
    SHAPE,
  );
});

pgTest("TEST-CNS-1306 pg: app_rw inserta la familia OTP/RECOVERY/MANAGEMENT solo en su tenant y por columnas; sin SELECT/UPDATE/DELETE/TRUNCATE; worker y platform_rw sin DML (INV-21-05)", async (ctx) => {
  const OTHER = fixtureUuid("t-1306-b");
  const admin = await ctx.connectAsSuperuser();
  const rw = await ctx.connectAs("app_rw");
  const asTenant = async (tenant: string | null, fn: () => Promise<unknown>): Promise<void> => {
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

  // Escribe todos los tipos de la familia en su tenant.
  for (const [label, r] of VALID) await assert.doesNotReject(() => asTenant(TENANT, () => insert(rw, r)), label);
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event WHERE tenant_id = $1 AND event_type = ANY($2)", [TENANT, VALID.map(([, r]) => r.event_type)])).rowCount, VALID.length);
  // Los tipos de sesion siguen escribiendo como antes (transitorio hasta ADR-010 PR-5).
  const session = row("STAFF_LOGIN", { actor_ref: "staff-synthetic-01", actor_role: "TENANT_ADMIN", session_kind: "STAFF", session_ref: fixtureUuid("sr-1306") });
  await assert.doesNotReject(() => asTenant(TENANT, () => insert(rw, session)));

  // Otro tenant / sin tenant: 42501 (RLS WITH CHECK), INV-CM-02.
  const mine = VALID[0]![1];
  await assert.rejects(() => asTenant(TENANT, () => insert(rw, { ...mine, tenant_id: OTHER })), (e: unknown) => codeOf(e) === "42501", "otro tenant");
  await assert.rejects(() => asTenant(null, () => insert(rw, mine)), (e: unknown) => codeOf(e) === "42501", "sin tenant");
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event WHERE tenant_id = $1", [OTHER])).rowCount, 0);

  // Lo que fija la base no lo fija app_rw.
  for (const [column, value] of [["environment", "'PRODUCTION'"], ["data_class", "'SYNTHETIC'"], ["occurred_at", "now()"], ["event_id", "gen_random_uuid()"], ["schema_version", "'9.9.9'"]] as const) {
    await assert.rejects(
      () => asTenant(TENANT, () => rw.query(`INSERT INTO ops.security_event (tenant_id, event_type, verification_ref, otp_scope, ${column}) VALUES ($1, 'OTP_FAILED', $2, 'DECISION', ${value})`, [TENANT, VERIFICATION])),
      (e: unknown) => codeOf(e) === "42501",
      column,
    );
  }

  // Sin SELECT / UPDATE / DELETE / TRUNCATE (D-5).
  for (const sql of [
    "SELECT 1 FROM ops.security_event",
    "UPDATE ops.security_event SET trigger_kind = 'FAILURE_CAP'",
    "DELETE FROM ops.security_event",
    "TRUNCATE ops.security_event",
  ]) {
    await assert.rejects(() => asTenant(TENANT, () => rw.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
  }

  // Grants exactos: policy unica de INSERT, columnas insertables de app_rw, nada para worker/platform_rw.
  const policies = (await admin.query<{ polname: string; cmd: string; roles: string[]; with_check: string | null }>(
    "SELECT policyname AS polname, cmd, roles::text[] AS roles, with_check FROM pg_policies WHERE schemaname = 'ops' AND tablename = 'security_event'",
  )).rows;
  assert.deepEqual(policies.map((p) => [p.polname, p.cmd, p.roles]), [["security_event_app_rw_insert", "INSERT", ["app_rw"]]]);
  assert.match(policies[0]!.with_check ?? "", /app\.current_tenant_id\(\)/);
  const insertable = (await admin.query<{ attname: string }>(
    `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'ops.security_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped
        AND has_column_privilege('app_rw', a.attrelid, a.attnum, 'INSERT') ORDER BY a.attname`,
  )).rows.map((r) => r.attname);
  assert.deepEqual(insertable, [...COLUMNS].sort());
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
    const c = await ctx.connectAs(role as "worker" | "platform_rw");
    await assert.rejects(() => c.query("SELECT 1 FROM ops.security_event"), (e: unknown) => codeOf(e) === "42501", `${role} SELECT`);
    await assert.rejects(() => c.query("INSERT INTO ops.security_event (tenant_id, event_type) VALUES ($1, 'OTP_FAILED')", [TENANT]), (e: unknown) => codeOf(e) === "42501", `${role} INSERT`);
  }
});

pgTest("TEST-CNS-1307 pg: security_event_owner es dueno de ops.security_event y su funcion; consent_owner es miembro INHERIT false/SET true; ningun rol de runtime es miembro; triggers ENABLE ALWAYS y FORCE RLS (INV-21-06)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const role = (await admin.query<Record<string, boolean>>(
    "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin FROM pg_roles WHERE rolname = 'security_event_owner'",
  )).rows[0];
  assert.deepEqual(role, { rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false, rolreplication: false, rolcanlogin: false });

  const members = (await admin.query<{ member: string; inherit_option: boolean; set_option: boolean }>(
    `SELECT m.rolname AS member, a.inherit_option, a.set_option
       FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member
      WHERE r.rolname = 'security_event_owner'`,
  )).rows;
  assert.deepEqual(members, [{ member: "consent_owner", inherit_option: false, set_option: true }]);
  for (const runtime of ["app_rw", "worker", "platform_rw"]) {
    assert.equal((await admin.query<{ m: boolean }>("SELECT pg_has_role($1, 'security_event_owner', 'MEMBER') AS m", [runtime])).rows[0]?.m, false, `${runtime} es miembro`);
  }

  const owners = (await admin.query<{ what: string; owner: string }>(
    `SELECT 'table' AS what, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = 'ops.security_event'::regclass
      UNION ALL SELECT 'function', pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'ops.security_event_immutable()'::regprocedure
      UNION ALL SELECT 'identity sequence', pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.relnamespace = 'ops'::regnamespace AND c.relkind = 'S' AND c.relname LIKE 'security\\_event%'
      UNION ALL SELECT 'index', pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.relnamespace = 'ops'::regnamespace AND c.relkind = 'i' AND c.relname LIKE 'security\\_event%'`,
  )).rows;
  assert.ok(owners.length >= 4, "tabla, funcion, secuencia e indices");
  for (const o of owners) assert.equal(o.owner, "security_event_owner", o.what);
  // El esquema ops NO se transfiere (R-21-1 / F-2, aceptado IT0b) y security_event_owner no conserva CREATE.
  assert.equal((await admin.query<{ o: string }>("SELECT pg_get_userbyid(nspowner) AS o FROM pg_namespace WHERE nspname = 'ops'")).rows[0]?.o, "consent_owner");
  const schemaPrivs = (await admin.query<{ usage: boolean; create: boolean }>("SELECT has_schema_privilege('security_event_owner', 'ops', 'USAGE') AS usage, has_schema_privilege('security_event_owner', 'ops', 'CREATE') AS \"create\"")).rows[0];
  assert.deepEqual(schemaPrivs, { usage: true, create: false });
  // EXECUTE por defecto no llega a PUBLIC para lo que cree security_event_owner (ALTER DEFAULT PRIVILEGES de 0029).
  const defaults = (await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_default_acl d JOIN pg_roles r ON r.oid = d.defaclrole
      WHERE r.rolname = 'security_event_owner' AND d.defaclobjtype = 'f' AND d.defaclnamespace = 0
        AND NOT EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')`,
  )).rows[0];
  assert.equal(defaults?.n, 1);

  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>(
    "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'ops.security_event'::regclass AND NOT tgisinternal ORDER BY tgname",
  )).rows;
  assert.deepEqual(triggers, [{ tgname: "security_event_no_truncate", tgenabled: "A" }, { tgname: "security_event_no_update_delete", tgenabled: "A" }]);
  const rel = (await admin.query<{ rls: boolean; force: boolean }>("SELECT relrowsecurity AS rls, relforcerowsecurity AS force FROM pg_class WHERE oid = 'ops.security_event'::regclass")).rows[0];
  assert.deepEqual(rel, { rls: true, force: true });

  // El migrador (consent_owner sin SET ROLE) ya no tiene privilegios sobre la tabla.
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    for (const sql of ["SELECT 1 FROM ops.security_event", "ALTER TABLE ops.security_event DISABLE TRIGGER ALL", "ALTER TABLE ops.security_event NO FORCE ROW LEVEL SECURITY"]) {
      await migrator.query("SAVEPOINT s");
      await assert.rejects(() => migrator.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
      await migrator.query("ROLLBACK TO s");
    }
  } finally {
    await migrator.query("ROLLBACK");
  }

  // R-21-1 / F-2 (P2, aceptado IT0b): consent_owner es dueno del ESQUEMA ops, asi que SI puede DROP de la tabla aunque no sea su dueno.
  // Aserto positivo para que este test cambie cuando ADR-010 §4.5 cierre el residual.
  const dropper = await ctx.connectAs("consent_migrator");
  await dropper.query("BEGIN");
  try {
    await dropper.query("SET LOCAL ROLE consent_owner");
    await dropper.query("SAVEPOINT d");
    await assert.doesNotReject(() => dropper.query("DROP TABLE ops.security_event"), "R-21-1: el dueno del esquema puede DROP");
    await dropper.query("ROLLBACK TO d");
  } finally {
    await dropper.query("ROLLBACK");
  }

  // 0028 es idempotente: una segunda corrida (superusuario, como el runner de alcance cluster) deja el mismo estado.
  const sql0028 = readFileSync(join(MIGRATIONS_DIR, "0028_security_event_owner_role.sql"), "utf8");
  await admin.query(sql0028);
  const again = (await admin.query<{ member: string; inherit_option: boolean; set_option: boolean }>(
    `SELECT m.rolname AS member, a.inherit_option, a.set_option FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member WHERE r.rolname = 'security_event_owner'`,
  )).rows;
  assert.deepEqual(again, [{ member: "consent_owner", inherit_option: false, set_option: true }]);

  // El arranque del runtime sigue pasando con el nuevo owner en la lista (startup-checks.ts).
  const startup = await runStartupChecks(await ctx.connectAs("app_rw"), { expectedEnvironment: "LOCAL", expectedRole: "app_rw" });
  assert.deepEqual(startup, { ok: true, failures: [] });
});

pgTest("TEST-CNS-1326 pg: como consent_owner -> SET ROLE security_event_owner, TRUNCATE da error del trigger y UPDATE/DELETE afectan 0 filas (FORCE RLS sin policy): el nuevo dueno tampoco puede mutar (INV-21-07 parcial; la purga llega en PR-3)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  await insert(admin, VALID[0]![1]);
  const migrator = await ctx.connectAs("consent_migrator");
  for (const [sql, expectRows] of [["UPDATE ops.security_event SET otp_scope = 'MANAGE'", 0], ["DELETE FROM ops.security_event", 0]] as const) {
    await migrator.query("BEGIN");
    try {
      await migrator.query("SET LOCAL ROLE consent_owner");
      await migrator.query("SET LOCAL ROLE security_event_owner");
      assert.equal((await migrator.query(sql)).rowCount, expectRows, sql);
    } finally {
      await migrator.query("ROLLBACK");
    }
  }
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("SET LOCAL ROLE security_event_owner");
    await assert.rejects(() => migrator.query("TRUNCATE ops.security_event"), (e: unknown) => codeOf(e) === "23000", "TRUNCATE: trigger append-only");
  } finally {
    await migrator.query("ROLLBACK");
  }
  assert.equal((await admin.query("SELECT 1 FROM ops.security_event")).rowCount, 1, "la fila sigue intacta");
});
