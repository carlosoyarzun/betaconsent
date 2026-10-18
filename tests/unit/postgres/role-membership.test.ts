// Gobierna: ADR-010 rev. 4 §4.1.1 y §7 PR-2, specs/db-roles.spec.yaml (membershipAssertion, INV-DBR-01, INV-DBR-03), Q-18/Q-19 (Carlos, 2026-10-11).
// TEST-CNS-1343 (lista exacta por modo, resolucion del modo), TEST-CNS-1345 (aserción posterior al cluster en migrate.ts), TEST-CNS-1346 (0034).
// Sin Postgres: dobles del superusuario.

import test from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyClusterPostScope, applyClusterScope, loadMigrations, MigrationError, parseMigration } from "../../../src/infra/adapters/postgres/migrate.ts";
import {
  BREAKGLASS_OWNER_ROLES,
  CONSENT_OWNER_SET_ROLES,
  diffMemberships,
  EXPECTED_MEMBERSHIPS,
  GOVERNED_ROLES,
  OWNER_ROLES,
  resolveDbRoleMode,
  RoleModeError,
} from "../../../src/infra/adapters/postgres/role-membership.ts";
import { databaseLevelRows, FakeClient } from "./fakes.ts";
import type { MembershipEdge } from "../../../src/infra/adapters/postgres/role-membership.ts";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "db", "migrations");
const edge = (member: string, role: string, inherit: boolean, set: boolean, admin = false): MembershipEdge => ({ member, role, inherit, set, admin });

test("TEST-CNS-1343 la lista exacta de IT0B_SYNTHETIC cubre Q-19 y no incluye lo de PR-5/PR-7; REAL_DATA queda definido", () => {
  const it0b = EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC;
  // Q-19: security_event_owner, tenant_resolve_owner, staff_roster_owner y outbox_claimer entran en la aserción.
  for (const role of ["security_event_owner", "tenant_resolve_owner", "staff_roster_owner"]) {
    assert.ok(it0b.some((e) => e.member === "consent_owner" && e.role === role && !e.inherit && e.set), role);
  }
  assert.ok(it0b.some((e) => e.member === "consent_migrator" && e.role === "outbox_claimer" && !e.inherit && e.set));
  assert.ok(it0b.some((e) => e.member === "consent_migrator" && e.role === "consent_owner" && e.inherit && e.set));
  assert.ok(it0b.some((e) => e.member === "app_rw" && e.role === "staff_roster_reader" && !e.inherit && e.set));
  // Owners nuevos de PR-2 (Q15 c), incluido transition_owner (Q-18): consent_owner SET sin INHERIT. PR-7d (C-1): integrity_owner ya NO (revocado en ambos modos).
  for (const role of ["platform_schema_owner", "grant_owner", "membership_owner", "case_state_owner", "transition_owner"]) {
    assert.ok(CONSENT_OWNER_SET_ROLES.includes(role), role);
  }
  assert.ok(!CONSENT_OWNER_SET_ROLES.includes("integrity_owner") && !it0b.some((e) => e.role === "integrity_owner" && e.member === "consent_owner"));
  // ADR-010 rev. 5 PR-b (LG-8, F-PR6-11): ledger_gen_owner y ledger_writer suman dos owners con SET sin INHERIT.
  for (const role of ["ledger_gen_owner", "ledger_writer", "rights_case_lookup_owner"]) assert.ok(CONSENT_OWNER_SET_ROLES.includes(role) && OWNER_ROLES.includes(role), role);
  // 1 (migrator->consent_owner) + 1 (migrator->outbox_claimer) + 12 (consent_owner -> owners; ADR-010 6d parte 1 suma rights_case_lookup_owner) + 1 (app_rw -> reader).
  assert.equal(it0b.length, 36); // 20 de PR-7c - integrity_owner (C-1) + 17 de ddl_breakglass (PR-7d, 0086)
  assert.ok(it0b.some((e) => e.member === "platform_rw" && e.role === "rights_operator" && !e.inherit && e.set));
  // ddl_breakglass: INHERIT FALSE, SET TRUE, sin ADMIN sobre OWNER_ROLES menos consent_owner, en ambos modos (F-PR7-06: lista derivada, no "diez" ni "doce").
  for (const mode of ["IT0B_SYNTHETIC", "REAL_DATA"] as const) {
    const bg = EXPECTED_MEMBERSHIPS[mode].filter((e) => e.member === "ddl_breakglass");
    assert.deepEqual(bg.map((e) => e.role).sort(), OWNER_ROLES.filter((r) => r !== "consent_owner").sort(), mode);
    assert.ok(bg.every((e) => !e.inherit && e.set && !e.admin));
  }
  assert.equal(BREAKGLASS_OWNER_ROLES.length, 17);
  // Ninguna membresía de runtime en un owner.
  assert.ok(!it0b.some((e) => ["app_rw", "platform_rw", "worker", "integrity_verifier"].includes(e.member) && OWNER_ROLES.includes(e.role)));
  assert.ok(OWNER_ROLES.every((r) => GOVERNED_ROLES.includes(r)) && GOVERNED_ROLES.includes("integrity_verifier") && GOVERNED_ROLES.includes("rights_operator"));
  // REAL_DATA (activo como modo verificable desde PR-7d; no autoriza datos reales): consent_owner sin ningun owner de §4.1.1.
  assert.ok(!EXPECTED_MEMBERSHIPS.REAL_DATA.some((e) => e.member === "consent_owner"));
  assert.ok(!EXPECTED_MEMBERSHIPS.REAL_DATA.some((e) => e.member === "consent_migrator" && e.role !== "consent_owner"));
});

test("TEST-CNS-1343 diffMemberships: igualdad exacta (extra, faltante, opciones distintas); resolveDbRoleMode: por defecto IT0B, desconocido y REAL_DATA fallan cerrado", () => {
  const ok = [...EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC];
  assert.deepEqual(diffMemberships(ok, "IT0B_SYNTHETIC"), []);
  assert.equal(diffMemberships([...ok, edge("worker", "grant_owner", false, true)], "IT0B_SYNTHETIC").length, 1);
  assert.equal(diffMemberships(ok.slice(1), "IT0B_SYNTHETIC").length, 1);
  assert.equal(diffMemberships(ok.map((e) => (e.role === "grant_owner" && e.member === "consent_owner" ? edge(e.member, e.role, true, true) : e)), "IT0B_SYNTHETIC").length, 2);
  // P1-1: admin_option cuenta; P2-4: multiconjunto (fila duplicada = diferencia).
  assert.equal(diffMemberships(ok.map((e) => (e.role === "grant_owner" && e.member === "consent_owner" ? edge(e.member, e.role, e.inherit, e.set, true) : e)), "IT0B_SYNTHETIC").length, 2);
  assert.ok(ok.every((e) => e.admin === false), "ADMIN OPTION esperado false en toda fila");
  assert.deepEqual(diffMemberships([...ok, ok[0] as MembershipEdge], "IT0B_SYNTHETIC").map((p) => /duplicada/.test(p)), [true]);
  // P1-3: modo vacio = IT0B solo en LOCAL/DEV; en STAGING o sin entorno es error; valor desconocido o REAL_DATA (no activado) tambien.
  assert.equal(resolveDbRoleMode({}, "LOCAL"), "IT0B_SYNTHETIC");
  assert.equal(resolveDbRoleMode({ CNS_DB_ROLE_MODE: "" }, "DEV"), "IT0B_SYNTHETIC");
  assert.throws(() => resolveDbRoleMode({}, "STAGING"), RoleModeError);
  assert.throws(() => resolveDbRoleMode({}, undefined), RoleModeError);
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "" }, "STAGING"), RoleModeError);
  assert.equal(resolveDbRoleMode({ CNS_DB_ROLE_MODE: "IT0B_SYNTHETIC" }, "STAGING"), "IT0B_SYNTHETIC");
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "REAL_DATA" }, "LOCAL"), RoleModeError);
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "otro" }, "LOCAL"), RoleModeError);
});

/** `applied`: versiones ya registradas en ops.schema_migration (el runner calcula con ellas si hay migraciones de base pendientes, F-PR7D-09). Por defecto la base esta al dia (0001). */
function fakeSuperuser(rows: readonly MembershipEdge[], mode: "IT0B_SYNTHETIC" | "REAL_DATA" = "IT0B_SYNTHETIC", applied: readonly string[] = ["0001"]): FakeClient {
  return new FakeClient((text) => {
    if (text.includes("to_regclass('ops.schema_migration')")) return { rows: [{ present: true }] };
    if (text.includes("FROM ops.schema_migration")) return { rows: applied.map((version) => ({ version })) };
    return text.includes("u.rolname AS member")
      ? { rows: rows.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin })) }
      : databaseLevelRows(text, mode);
  });
}

test("TEST-CNS-1345 applyClusterScope: tras las migraciones de cluster afirma la membresía exacta y aborta (fail-closed) con cualquier diferencia o modo no activado", async () => {
  const migrations = [parseMigration("0000_roles.sql", "-- scope: cluster\nSELECT 1;\n"), parseMigration("0001_db.sql", "-- scope: database\nSELECT 2;\n")];
  const good = fakeSuperuser(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC);
  assert.deepEqual(await applyClusterScope(good, migrations, { mode: "IT0B_SYNTHETIC" }), ["0000"]);
  // La aserción corre DESPUES de la última migración de cluster y DENTRO del advisory lock.
  const iCluster = good.queries.findIndex((q) => q.text === "-- scope: cluster\nSELECT 1;\n");
  const iAssert = good.queries.findIndex((q) => q.text.includes("u.rolname AS member"));
  const iUnlock = good.queries.findIndex((q) => q.text.includes("pg_advisory_unlock"));
  assert.ok(iCluster >= 0 && iAssert > iCluster && iUnlock > iAssert, good.queries.map((q) => q.text).join(" | "));

  const extra = fakeSuperuser([...EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC, edge("app_rw", "security_event_owner", false, true)]);
  await assert.rejects(() => applyClusterScope(extra, migrations, { mode: "IT0B_SYNTHETIC" }), (e: unknown) => e instanceof MigrationError && /INV-DBR-03.*app_rw -> security_event_owner/.test(e.message));
  assert.ok(extra.queries.some((q) => q.text.includes("pg_advisory_unlock")), "el lock se libera aunque la aserción falle");
  const missing = fakeSuperuser(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.filter((e) => e.role !== "staff_roster_owner"));
  await assert.rejects(() => applyClusterScope(missing, migrations, { mode: "IT0B_SYNTHETIC" }), /falta la membresía.*staff_roster_owner/);
  // PR-7d: REAL_DATA esta activo como modo verificable: su lista exacta pasa y la de IT0B no.
  assert.deepEqual(await applyClusterScope(fakeSuperuser(EXPECTED_MEMBERSHIPS.REAL_DATA, "REAL_DATA"), migrations, { mode: "REAL_DATA" }), ["0000"]);
  await assert.rejects(() => applyClusterScope(fakeSuperuser(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC, "REAL_DATA"), migrations, { mode: "REAL_DATA" }), /INV-DBR-03.*consent_owner -> /);
  // Una ceremonia abierta (ddl_breakglass con LOGIN): las PRECONDICIONES fallan ANTES de la fase cluster (F-PR7D-07: nada se aplica, ni BEGIN ni SQL de cluster) y, si el LOGIN aparece despues, la aserción final
  // (FUERA de la transaccion, que ya confirmo) lo detecta (INV-DBR-09).
  const base = (text: string): Partial<import("pg").QueryResult> | undefined => {
    if (text.includes("to_regclass('ops.schema_migration')")) return { rows: [{ present: true }] };
    if (text.includes("FROM ops.schema_migration")) return { rows: [{ version: "0001" }] };
    if (text.includes("u.rolname AS member")) return { rows: EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin })) };
    return undefined;
  };
  const preOpen = new FakeClient((text) => (text.includes("AS can_login") ? { rows: [{ can_login: true, ceremony_table: false }] } : (base(text) ?? databaseLevelRows(text))));
  await assert.rejects(() => applyClusterScope(preOpen, migrations, { mode: "IT0B_SYNTHETIC" }), /Precondición del deploy no cumplida \(nada se aplicó\).*ddl_breakglass tiene LOGIN/);
  assert.ok(!preOpen.queries.some((q) => q.text === "BEGIN" || q.text.includes("-- scope: cluster")), "ninguna fase se ejecuto");
  const openOpenRow = new FakeClient((text) => (text.includes("AS can_login") ? { rows: [{ can_login: false, ceremony_table: true }] } : text.includes("FROM breakglass.ceremony WHERE closed_at IS NULL") ? { rows: [{ n: "1" }] } : (base(text) ?? databaseLevelRows(text))));
  await assert.rejects(() => applyClusterScope(openOpenRow, migrations, { mode: "IT0B_SYNTHETIC" }), /ceremonia de break-glass sin cerrar/);
  const lateOpen = new FakeClient((text) => {
    const r = databaseLevelRows(text);
    if (r?.rows !== undefined && text.includes("'db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass')")) return { rows: r.rows.map((x) => (x.rolname === "ddl_breakglass" ? { ...x, rolcanlogin: true } : x)) };
    return base(text) ?? r;
  });
  await assert.rejects(() => applyClusterScope(lateOpen, migrations, { mode: "IT0B_SYNTHETIC" }), /ddl_breakglass tiene LOGIN fuera de una ceremonia/);
  const iCommit = lateOpen.queries.findIndex((q) => q.text === "COMMIT");
  const iAssertQuery = lateOpen.queries.findIndex((q) => q.text.includes("u.rolname AS member"));
  assert.ok(iCommit >= 0 && iAssertQuery > iCommit, "la aserción corre DESPUES del COMMIT (un fallo de aserción ya no deshace el REVOKE; F-PR7D-07)");
  // deferPost: sin aserción ni archivos cluster-post (se hacen despues de las migraciones de base).
  const post = [parseMigration("0000_roles.sql", "-- scope: cluster\nSELECT 1;\n"), parseMigration("0002_post.sql", "-- scope: cluster-post\nSELECT 3;\n")];
  const deferred = fakeSuperuser([]);
  assert.deepEqual(await applyClusterScope(deferred, post, { mode: "IT0B_SYNTHETIC", deferPost: true }), ["0000"]);
  assert.ok(!deferred.queries.some((q) => q.text.includes("SELECT 3;")));
  assert.deepEqual(await applyClusterPostScope(fakeSuperuser(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC), post, { mode: "IT0B_SYNTHETIC" }), ["0002"]);
});

test("TEST-CNS-1346 0034 es de alcance cluster, idempotente y sin secretos: roles NOLOGIN NOBYPASSRLS, integrity_verifier LOGIN, membresías solo de consent_owner con INHERIT FALSE", () => {
  const m = loadMigrations(MIGRATIONS_DIR).find((x) => x.version === "0034");
  assert.ok(m !== undefined);
  assert.equal(m.scope, "cluster");
  const sql = m.sql.replace(/--[^\n]*/g, "");
  for (const role of ["platform_schema_owner", "membership_owner", "grant_owner", "case_state_owner", "transition_owner", "rights_operator"]) {
    assert.ok(sql.includes(`'${role}'`), role);
  }
  assert.match(sql, /IF NOT EXISTS \(SELECT 1 FROM pg_catalog\.pg_roles WHERE rolname = r\)/);
  assert.match(sql, /CREATE ROLE %I NOLOGIN/);
  assert.match(sql, /ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(sql, /ALTER ROLE integrity_verifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.doesNotMatch(sql, /\bPASSWORD\b/i);
  assert.doesNotMatch(sql, /INHERIT TRUE|WITH ADMIN/i);
  // P1-1: REVOKE ADMIN OPTION condicional; P2-2: GRANT de SET condicionado al GUC cns.db_role_mode; P2-1: platform_rw/rights_operator fuera del REVOKE de runtime.
  assert.match(sql, /m\.admin_option\) THEN\s+EXECUTE pg_catalog\.format\('REVOKE ADMIN OPTION FOR %I FROM consent_owner'/);
  assert.match(sql, /current_setting\('cns\.db_role_mode', true\)[^;]*<> 'REAL_DATA' THEN\s+GRANT platform_schema_owner/);
  assert.match(sql, /FOREACH u IN ARRAY ARRAY\['app_rw', 'worker', 'integrity_verifier', 'consent_migrator'\]/);
  assert.doesNotMatch(sql, /FOREACH u IN ARRAY[^;]*platform_rw/);
  assert.equal([...sql.matchAll(/GRANT (\w+) TO consent_owner WITH INHERIT FALSE, SET TRUE;/g)].length, 5);
  assert.doesNotMatch(sql, /\bGRANT\b[^;]*\bTO\b[^;]*\b(app_rw|worker|platform_rw|integrity_verifier|consent_migrator)\b/);
});
