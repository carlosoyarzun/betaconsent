// Gobierna: ADR-010 rev. 4 §4.1.1 y §7 PR-2, specs/db-roles.spec.yaml (membershipAssertion, INV-DBR-01, INV-DBR-03), Q-18/Q-19 (Carlos, 2026-10-11).
// TEST-CNS-1343 (lista exacta por modo, resolucion del modo), TEST-CNS-1345 (aserción posterior al cluster en migrate.ts), TEST-CNS-1346 (0034).
// Sin Postgres: dobles del superusuario.

import test from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyClusterScope, loadMigrations, MigrationError, parseMigration } from "../../../src/infra/adapters/postgres/migrate.ts";
import {
  CONSENT_OWNER_SET_ROLES,
  diffMemberships,
  EXPECTED_MEMBERSHIPS,
  GOVERNED_ROLES,
  OWNER_ROLES,
  resolveDbRoleMode,
  RoleModeError,
} from "../../../src/infra/adapters/postgres/role-membership.ts";
import { FakeClient } from "./fakes.ts";
import type { MembershipEdge } from "../../../src/infra/adapters/postgres/role-membership.ts";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "db", "migrations");
const edge = (member: string, role: string, inherit: boolean, set: boolean): MembershipEdge => ({ member, role, inherit, set });

test("TEST-CNS-1343 la lista exacta de IT0B_SYNTHETIC cubre Q-19 y no incluye lo de PR-5/PR-7; REAL_DATA queda definido", () => {
  const it0b = EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC;
  // Q-19: security_event_owner, tenant_resolve_owner, staff_roster_owner y outbox_claimer entran en la aserción.
  for (const role of ["security_event_owner", "tenant_resolve_owner", "staff_roster_owner"]) {
    assert.ok(it0b.some((e) => e.member === "consent_owner" && e.role === role && !e.inherit && e.set), role);
  }
  assert.ok(it0b.some((e) => e.member === "consent_migrator" && e.role === "outbox_claimer" && !e.inherit && e.set));
  assert.ok(it0b.some((e) => e.member === "consent_migrator" && e.role === "consent_owner" && e.inherit && e.set));
  assert.ok(it0b.some((e) => e.member === "app_rw" && e.role === "staff_roster_reader" && !e.inherit && e.set));
  // Owners nuevos de PR-2 (Q15 c), incluido transition_owner (Q-18): consent_owner SET sin INHERIT.
  for (const role of ["platform_schema_owner", "grant_owner", "membership_owner", "case_state_owner", "transition_owner", "integrity_owner"]) {
    assert.ok(CONSENT_OWNER_SET_ROLES.includes(role), role);
  }
  // 1 (migrator->consent_owner) + 1 (migrator->outbox_claimer) + 9 (consent_owner -> owners) + 1 (app_rw -> reader).
  assert.equal(it0b.length, 12);
  // Aun no existen: platform_rw -> rights_operator (PR-5) y ddl_breakglass (PR-7).
  assert.ok(!it0b.some((e) => e.member === "platform_rw" || e.member === "ddl_breakglass" || e.role === "rights_operator"));
  // Ninguna membresía de runtime en un owner.
  assert.ok(!it0b.some((e) => ["app_rw", "platform_rw", "worker", "integrity_verifier"].includes(e.member) && OWNER_ROLES.includes(e.role)));
  assert.ok(OWNER_ROLES.every((r) => GOVERNED_ROLES.includes(r)) && GOVERNED_ROLES.includes("integrity_verifier") && GOVERNED_ROLES.includes("rights_operator"));
  // REAL_DATA: consent_owner sin ningun owner de §4.1.1 (definido, sin activar).
  assert.ok(!EXPECTED_MEMBERSHIPS.REAL_DATA.some((e) => e.member === "consent_owner"));
  assert.ok(!EXPECTED_MEMBERSHIPS.REAL_DATA.some((e) => e.member === "consent_migrator" && e.role !== "consent_owner"));
});

test("TEST-CNS-1343 diffMemberships: igualdad exacta (extra, faltante, opciones distintas); resolveDbRoleMode: por defecto IT0B, desconocido y REAL_DATA fallan cerrado", () => {
  const ok = [...EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC];
  assert.deepEqual(diffMemberships(ok, "IT0B_SYNTHETIC"), []);
  assert.equal(diffMemberships([...ok, edge("worker", "grant_owner", false, true)], "IT0B_SYNTHETIC").length, 1);
  assert.equal(diffMemberships(ok.slice(1), "IT0B_SYNTHETIC").length, 1);
  assert.equal(diffMemberships(ok.map((e) => (e.role === "grant_owner" ? edge(e.member, e.role, true, true) : e)), "IT0B_SYNTHETIC").length, 2);
  assert.equal(resolveDbRoleMode({}), "IT0B_SYNTHETIC");
  assert.equal(resolveDbRoleMode({ CNS_DB_ROLE_MODE: "" }), "IT0B_SYNTHETIC");
  assert.equal(resolveDbRoleMode({ CNS_DB_ROLE_MODE: "IT0B_SYNTHETIC" }), "IT0B_SYNTHETIC");
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "REAL_DATA" }), RoleModeError);
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "otro" }), RoleModeError);
});

function fakeSuperuser(rows: readonly MembershipEdge[]): FakeClient {
  return new FakeClient((text) =>
    text.includes("u.rolname AS member")
      ? { rows: rows.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set })) }
      : undefined,
  );
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
  await assert.rejects(() => applyClusterScope(fakeSuperuser(EXPECTED_MEMBERSHIPS.REAL_DATA), migrations, { mode: "REAL_DATA" }), /no está activado/);
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
  assert.equal([...sql.matchAll(/GRANT (\w+) TO consent_owner WITH INHERIT FALSE, SET TRUE;/g)].length, 5);
  assert.doesNotMatch(sql, /\bGRANT\b[^;]*\bTO\b[^;]*\b(app_rw|worker|platform_rw|integrity_verifier|consent_migrator)\b/);
});
