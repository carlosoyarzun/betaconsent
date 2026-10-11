// Gobierna: ADR-010 rev. 4 §4.1, §4.1.1 y §7 PR-2; specs/db-roles.spec.yaml (INV-DBR-01, INV-DBR-03); decisiones de Carlos del 2026-10-11 (Q-15 c, Q-18, Q-19).
// TEST-CNS-1348: atributos y membresias de los roles de 0034 (owners nuevos, rights_operator, integrity_verifier) y 0034 idempotente.
// TEST-CNS-1349: la aserción de membresia exacta (la que usa el runner y startup-checks) coincide con el catalogo real y detecta una fila extra.
// TEST-CNS-1350: integrity_verifier sin privilegios sobre objetos de dominio ni cambio de rol a un owner.
// Requiere Postgres real (harness.ts); skip sin entorno. No se pudo ejecutar en la sesion de implementacion (sin Postgres).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkRoleMemberships, EXPECTED_MEMBERSHIPS, OWNER_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { MIGRATIONS_DIR, pgTest } from "./harness.ts";

const NEW_OWNERS = ["platform_schema_owner", "membership_owner", "grant_owner", "case_state_owner", "transition_owner"];
const NOLOGIN_FLAGS = { rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false, rolreplication: false, rolcanlogin: false };
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

pgTest("TEST-CNS-1348 pg: owners nuevos y rights_operator NOLOGIN/NOSUPERUSER/NOBYPASSRLS; integrity_verifier LOGIN sin membresias; consent_owner SET sin INHERIT sobre los owners nuevos; 0034 idempotente", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const attrs = async (names: readonly string[]): Promise<Array<Record<string, unknown>>> =>
    (await admin.query<Record<string, unknown>>(
      "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname",
      [[...names]],
    )).rows;

  const nologin = [...NEW_OWNERS, "rights_operator"];
  assert.deepEqual(
    await attrs(nologin),
    [...nologin].sort().map((rolname) => ({ rolname, ...NOLOGIN_FLAGS })),
  );
  // Q-18: transition_owner es NOLOGIN (incluido arriba); integrity_verifier es el unico LOGIN nuevo.
  assert.deepEqual(await attrs(["integrity_verifier"]), [{ rolname: "integrity_verifier", ...NOLOGIN_FLAGS, rolcanlogin: true }]);
  const timeout = (await admin.query<{ cfg: string[] }>(
    "SELECT s.setconfig AS cfg FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = 'integrity_verifier' AND s.setdatabase = 0",
  )).rows[0];
  assert.deepEqual(timeout?.cfg, ["idle_in_transaction_session_timeout=10s"]);

  const edges = async (where: string, values: readonly unknown[]): Promise<Array<{ member: string; role: string; inherit_option: boolean; set_option: boolean }>> =>
    (await admin.query<{ member: string; role: string; inherit_option: boolean; set_option: boolean }>(
      `SELECT u.rolname AS member, r.rolname AS role, m.inherit_option, m.set_option
         FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE ${where} ORDER BY 1, 2`,
      [...values],
    )).rows;
  assert.deepEqual(await edges("u.rolname = 'integrity_verifier'", []), [], "integrity_verifier no es miembro de nadie");
  assert.deepEqual(await edges("u.rolname = ANY($1)", [nologin]), [], "los owners nuevos y rights_operator no son miembros de nadie");
  assert.deepEqual(await edges("r.rolname = 'rights_operator'", []), [], "rights_operator sin miembros hasta PR-5");
  assert.deepEqual(
    await edges("r.rolname = ANY($1)", [NEW_OWNERS]),
    NEW_OWNERS.map((role) => ({ member: "consent_owner", role, inherit_option: false, set_option: true })).sort((a, b) => a.role.localeCompare(b.role)),
  );
  for (const owner of NEW_OWNERS) {
    assert.equal((await admin.query<{ r: boolean }>("SELECT pg_has_role('consent_owner', $1, 'USAGE') AS r", [owner])).rows[0]?.r, false, `consent_owner hereda ${owner}`);
    assert.equal((await admin.query<{ r: boolean }>("SELECT pg_has_role('consent_owner', $1, 'SET') AS r", [owner])).rows[0]?.r, true, `consent_owner sin SET sobre ${owner}`);
    // El migrador solo llega por consent_owner: sin membresia directa.
    assert.equal((await edges("u.rolname = 'consent_migrator' AND r.rolname = $1", [owner])).length, 0);
  }
  // Ni los owners ni el verifier son duenos de nada todavia (PR-3..PR-5 les asignan objetos).
  const owned = (await admin.query<{ n: number }>(
    "SELECT (SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = ANY($1)) + (SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE r.rolname = ANY($1)) + (SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE r.rolname = ANY($1)) AS n",
    [[...NEW_OWNERS, "rights_operator", "integrity_verifier"]],
  )).rows[0];
  assert.equal(Number(owned?.n), 0);

  // 0034 es idempotente: una segunda corrida (superusuario, como el runner de alcance cluster) deja el mismo estado.
  const before = await edges("r.rolname = ANY($1) OR u.rolname = ANY($1)", [[...OWNER_ROLES, "integrity_verifier", "rights_operator"]]);
  await admin.query(readFileSync(join(MIGRATIONS_DIR, "0034_adr010_cluster_roles.sql"), "utf8"));
  assert.deepEqual(await edges("r.rolname = ANY($1) OR u.rolname = ANY($1)", [[...OWNER_ROLES, "integrity_verifier", "rights_operator"]]), before);
  assert.deepEqual(await attrs(nologin), [...nologin].sort().map((rolname) => ({ rolname, ...NOLOGIN_FLAGS })));
});

pgTest("TEST-CNS-1349 pg: la aserción de membresia exacta de IT0B_SYNTHETIC coincide con el catalogo; detecta fila extra/faltante; REAL_DATA falla cerrado; el arranque de app_rw sigue pasando", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), []);
  assert.equal(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.length, 12);
  assert.equal((await checkRoleMemberships(admin, "REAL_DATA")).length, 1, "REAL_DATA no esta activado hasta PR-7");

  // Fila extra (rolled back: las membresias son transaccionales y no se tocan para otros archivos de test).
  // El SQL se arma con variables (no con literales GRANT <owner>) para no ampliar las allowlists de los checkers de owners (CA-142, TEST-CNS-1347).
  const extras: Array<[role: string, member: string, options: string, pattern: RegExp]> = [
    ["transition_owner", "app_rw", "", /app_rw -> transition_owner/],
    ["outbox_claimer", "worker", "", /worker -> outbox_claimer/],
    ["grant_owner", "integrity_verifier", "", /integrity_verifier -> grant_owner/],
    ["rights_operator", "platform_rw", " WITH INHERIT FALSE, SET TRUE", /platform_rw -> rights_operator/],
    ["security_event_owner", "consent_migrator", " WITH INHERIT FALSE, SET TRUE", /consent_migrator -> security_event_owner/],
    ["tenant_resolve_owner", "consent_owner", " WITH INHERIT TRUE, SET TRUE", /tenant_resolve_owner \{inherit: true/],
  ];
  for (const [role, member, options, pattern] of extras) {
    await admin.query("BEGIN");
    try {
      await admin.query(`GRANT ${role} TO ${member}${options}`);
      const problems = await checkRoleMemberships(admin, "IT0B_SYNTHETIC");
      assert.ok(problems.some((p) => pattern.test(p)), `${role} -> ${member} :: ${problems.join(" | ")}`);
    } finally {
      await admin.query("ROLLBACK");
    }
  }
  // Fila faltante.
  await admin.query("BEGIN");
  try {
    await admin.query("REVOKE staff_roster_owner FROM consent_owner");
    assert.ok((await checkRoleMemberships(admin, "IT0B_SYNTHETIC")).some((p) => /falta la membresía.*consent_owner -> staff_roster_owner/.test(p)));
  } finally {
    await admin.query("ROLLBACK");
  }
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), [], "los ROLLBACK dejaron el cluster intacto");

  // startup-checks (con las listas nuevas) sigue pasando como app_rw.
  const startup = await runStartupChecks(await ctx.connectAs("app_rw"), { expectedEnvironment: "LOCAL", expectedRole: "app_rw" });
  assert.deepEqual(startup, { ok: true, failures: [] });
});

pgTest("TEST-CNS-1350 pg: integrity_verifier no puede crear objetos, cambiar de rol a un owner ni leer/escribir tablas de dominio todavia (privilegios de PR-4 en adelante)", async (ctx) => {
  const verifier = await ctx.connectAs("integrity_verifier");
  const me = (await verifier.query<{ u: string }>("SELECT current_user AS u")).rows[0];
  assert.equal(me?.u, "integrity_verifier");
  for (const ddl of ["CREATE TABLE public.x (i int)", "CREATE SCHEMA nuevo", "SET session_replication_role = replica"]) {
    await assert.rejects(() => verifier.query(ddl), (e: unknown) => codeOf(e) === "42501", ddl);
  }
  for (const owner of [...OWNER_ROLES, "rights_operator", "staff_roster_reader"]) {
    await assert.rejects(() => verifier.query(`SET ROLE ${owner}`), (e: unknown) => codeOf(e) === "42501", `SET ROLE ${owner}`);
  }
  for (const sql of [
    "SELECT 1 FROM app.revocation",
    "SELECT 1 FROM app.rights_case",
    "SELECT 1 FROM integrity.audit_event",
    "INSERT INTO app.outbox (tenant_id) VALUES (gen_random_uuid())",
    "SELECT 1 FROM ops.security_event",
  ]) {
    await assert.rejects(() => verifier.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
  }
});
