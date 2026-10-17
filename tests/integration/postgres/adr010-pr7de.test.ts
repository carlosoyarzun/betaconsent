// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7d/7e), §4.5.1-§4.5.4, INV-DBR-03/09, decisiones de Carlos del 2026-10-16 (C-1, C-4, C-5, C-9), F-PR7-03/05/06/07/12, F-PRB-06, F-PR7C-06, F-A10-10/11. Requiere Postgres real
// (harness.ts); skip sin entorno. SYNTHETIC ONLY.
// TEST-CNS-1854 roles de nivel de base y estado a nivel de base por modo (IT0B y REAL_DATA); 1855 breakglass.ceremony (append-only, CHECK, ACL); 1856 el migrador no asume owners (IT0B: 16 menos integrity_owner; REAL_DATA: ninguno)
// y REAL_DATA = lista exacta tras el REVOKE explicito; 1857 fase cluster en UNA transaccion (fallo inyectado sin residuo); 1858 ENSAYO DE CEREMONIA automatizado (abrir -> DDL minimo -> cerrar) con evidencia y vigilancia;
// 1859 lectura de la vigilancia con integrity_chain_verifier.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

import { evaluateBreakglass, readBreakglassSnapshot } from "../../../src/infra/adapters/postgres/breakglass-watch-reader.ts";
import { checkDatabaseLevel, DDL_BREAKGLASS_SETTINGS } from "../../../src/infra/adapters/postgres/database-level.ts";
import { applyClusterScope, loadMigrations } from "../../../src/infra/adapters/postgres/migrate.ts";
import { BREAKGLASS_OWNER_ROLES, checkRoleMemberships, CONSENT_OWNER_SET_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { checkConsentOwnerInventory } from "../../../src/infra/adapters/postgres/consent-owner-inventory.ts";
import { generateCeremonyPassword, scramVerifier } from "../../../tools/ceremony/scram-verifier.ts";
import { MIGRATIONS_DIR, pgTest, withClusterPostApplied } from "./harness.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

pgTest("TEST-CNS-1854 pg: db_owner_nologin, breakglass_log_owner y ddl_breakglass (NOLOGIN, settings exactos, 17 owners SET sin herencia); el estado a nivel de base de IT0B y de REAL_DATA coincide y detecta desvios", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const roles = (await admin.query("SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig FROM pg_roles WHERE rolname IN ('db_owner_nologin','breakglass_log_owner','ddl_breakglass') ORDER BY 1")).rows;
  assert.deepEqual(roles.map((r) => [r.rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls]), [
    ["breakglass_log_owner", false, false, false, false, false, false], ["db_owner_nologin", false, false, false, false, false, false], ["ddl_breakglass", false, false, false, false, false, false],
  ]);
  const bg = roles.find((r) => r.rolname === "ddl_breakglass")!;
  assert.deepEqual([bg.rolinherit, bg.rolconnlimit], [false, 1]);
  assert.deepEqual([...(bg.rolconfig as string[])].sort(), [...DDL_BREAKGLASS_SETTINGS].sort());
  const edges = (await admin.query("SELECT r.rolname AS role, m.inherit_option, m.set_option, m.admin_option FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'ddl_breakglass' ORDER BY 1")).rows;
  assert.deepEqual(edges.map((e) => e.role), [...BREAKGLASS_OWNER_ROLES].sort());
  assert.ok(edges.every((e) => e.inherit_option === false && e.set_option === true && e.admin_option === false));
  assert.equal((await admin.query("SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid WHERE r.rolname IN ('db_owner_nologin','breakglass_log_owner','ddl_breakglass')")).rowCount, 0, "nadie es miembro de los tres roles (la membresia transitoria de breakglass_log_owner se revoco)");
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), []);

  // Estado a nivel de base: la base del test nace de CREATE DATABASE ... OWNER consent_owner (sin pasar por 0086), asi que se aplica la fase cluster-post dentro de una transaccion revertida.
  assert.ok((await checkDatabaseLevel(admin, "IT0B_SYNTHETIC")).some((p) => /dueño de la base es consent_owner/.test(p)), "sin 0086 la base de este test es de consent_owner: lo detecta");
  for (const mode of ["IT0B_SYNTHETIC", "REAL_DATA"] as const) {
    await withClusterPostApplied(ctx, admin, mode, async () => {
      assert.deepEqual(await checkDatabaseLevel(admin, mode, { breakglassMustBeClosed: true }), [], mode);
      assert.equal((await admin.query<{ c: boolean }>("SELECT has_database_privilege('consent_owner', current_database(), 'CREATE') AS c")).rows[0]?.c, mode === "IT0B_SYNTHETIC", "CREATE explicito solo en IT0B (F-PR7-04)");
      assert.equal((await admin.query<{ o: string }>("SELECT pg_get_userbyid(datdba) AS o FROM pg_database WHERE datname = current_database()")).rows[0]?.o, "db_owner_nologin");
      // Desvios (cada uno dentro del ROLLBACK de la fase): PUBLIC con CONNECT, otro dueño, ddl_breakglass con LOGIN, CREATE de mas o de menos, falta de CONNECT explicito, settings.
      const deviations: Array<[string, RegExp]> = [
        ["GRANT CONNECT ON DATABASE %DB% TO PUBLIC", /PUBLIC tiene CONNECT/],
        ["GRANT TEMPORARY ON DATABASE %DB% TO PUBLIC", /PUBLIC tiene TEMPORARY/],
        ["ALTER DATABASE %DB% OWNER TO consent_owner", /dueño de la base es consent_owner/],
        ["ALTER ROLE ddl_breakglass LOGIN", /ddl_breakglass tiene LOGIN fuera de una ceremonia/],
        ["REVOKE CONNECT ON DATABASE %DB% FROM app_rw", /falta CONNECT explicito.*app_rw/],
        ["ALTER ROLE ddl_breakglass SET log_statement = 'all'", /settings de auditoria de sesion/],
        ["ALTER ROLE ddl_breakglass INHERIT", /NOINHERIT y CONNECTION LIMIT 1/],
        [mode === "IT0B_SYNTHETIC" ? "REVOKE CREATE ON DATABASE %DB% FROM consent_owner" : "GRANT CREATE ON DATABASE %DB% TO consent_owner", mode === "IT0B_SYNTHETIC" ? /CREATE explicito en la base en IT0B/ : /no puede tener CREATE en la base en REAL_DATA/],
      ];
      const db = (await admin.query<{ d: string }>("SELECT quote_ident(current_database()) AS d")).rows[0]!.d;
      for (const [sql, pattern] of deviations) {
        await admin.query("SAVEPOINT dev");
        await admin.query(sql.replaceAll("%DB%", db));
        const problems = await checkDatabaseLevel(admin, mode, { breakglassMustBeClosed: true });
        assert.ok(problems.some((p) => pattern.test(p)), `${mode}: ${sql} :: ${problems.join(" | ")}`);
        await admin.query("ROLLBACK TO dev");
      }
    });
  }
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), [], "los ROLLBACK dejaron el cluster intacto");
});

pgTest("TEST-CNS-1855 pg: breakglass.ceremony es de breakglass_log_owner, append-only (solo closed_at una vez), con ventana P-46 <= 60 min, RLS forzada y sin acceso de runtime salvo la lectura por columnas del chain-verifier", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query("SELECT pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls, c.relforcerowsecurity AS force, pg_get_userbyid(n.nspowner) AS schema_owner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'breakglass' AND c.relname = 'ceremony'")).rows[0];
  assert.deepEqual(rel, { owner: "breakglass_log_owner", rls: true, force: true, schema_owner: "breakglass_log_owner" });
  assert.deepEqual((await admin.query("SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'breakglass.ceremony'::regclass AND NOT tgisinternal ORDER BY 1")).rows, [{ tgname: "ceremony_guard", tgenabled: "A" }, { tgname: "ceremony_no_truncate", tgenabled: "A" }]);
  await admin.query("BEGIN");
  try {
    const ins = (ref: string, minutes: number): Promise<unknown> => admin.query("INSERT INTO breakglass.ceremony (ceremony_ref, valid_until, reason_code, ticket_ref) VALUES ($1, now() + make_interval(mins => $2), 'REHEARSAL', 'CA-1')", [ref, minutes]);
    await ins("CER-TEST-0001", 30);
    for (const [ref, minutes, why] of [["CER-TEST-0002", 61, "ventana > 60 min (P-46)"], ["CER-TEST-0003", 0, "ventana vacia"], ["x", 10, "referencia mal formada"]] as const) {
      await admin.query("SAVEPOINT s");
      await assert.rejects(() => ins(ref, minutes), (e: unknown) => codeOf(e) === "23514", why);
      await admin.query("ROLLBACK TO s");
    }
    await admin.query("SAVEPOINT s");
    await assert.rejects(() => admin.query("INSERT INTO breakglass.ceremony (ceremony_ref, valid_until, reason_code, ticket_ref) VALUES ('CER-TEST-0004', now() + interval '5 minutes', 'OTRO', 'CA-1')"), (e: unknown) => codeOf(e) === "23514");
    await admin.query("ROLLBACK TO s");
    for (const sql of ["UPDATE breakglass.ceremony SET reason_code = 'DDL_LEDGER' WHERE ceremony_ref = 'CER-TEST-0001'", "UPDATE breakglass.ceremony SET valid_until = valid_until + interval '1 minute' WHERE ceremony_ref = 'CER-TEST-0001'", "DELETE FROM breakglass.ceremony", "TRUNCATE breakglass.ceremony"]) {
      await admin.query("SAVEPOINT s");
      await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", sql); // ni el superusuario: el trigger es ENABLE ALWAYS
      await admin.query("ROLLBACK TO s");
    }
    await admin.query("UPDATE breakglass.ceremony SET closed_at = now() WHERE ceremony_ref = 'CER-TEST-0001'");
    await admin.query("SAVEPOINT s");
    await assert.rejects(() => admin.query("UPDATE breakglass.ceremony SET closed_at = now() + interval '1 second' WHERE ceremony_ref = 'CER-TEST-0001'"), (e: unknown) => codeOf(e) === "23000", "closed_at solo una vez");
    await admin.query("ROLLBACK TO s");
  } finally {
    await admin.query("ROLLBACK");
  }
  // ACL: solo integrity_chain_verifier (SELECT por columnas y USAGE); nadie escribe; consent_owner ni migrador ven el esquema.
  const sel = async (r: string, p: string): Promise<boolean> => (await admin.query<{ x: boolean }>("SELECT has_any_column_privilege($1, 'breakglass.ceremony'::regclass, $2) AS x", [r, p])).rows[0]!.x;
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_anchor_signer", "consent_migrator", "consent_owner", "ddl_breakglass"]) {
    assert.equal(await sel(r, "SELECT,INSERT,UPDATE,REFERENCES"), false, r);
    assert.equal((await admin.query<{ x: boolean }>("SELECT has_schema_privilege($1, 'breakglass', 'USAGE,CREATE') AS x", [r])).rows[0]!.x, false, `${r}: sin USAGE ni CREATE en breakglass`);
  }
  assert.equal(await sel("integrity_chain_verifier", "SELECT"), true);
  assert.equal(await sel("integrity_chain_verifier", "INSERT,UPDATE,REFERENCES"), false);
  assert.equal((await admin.query<{ x: boolean }>("SELECT has_column_privilege('integrity_chain_verifier', 'breakglass.ceremony', 'reason_code', 'SELECT') AS x")).rows[0]!.x, false, "no lee motivo ni ticket");
  assert.equal((await admin.query<{ x: boolean }>("SELECT has_table_privilege('integrity_chain_verifier', 'breakglass.ceremony', 'DELETE,TRUNCATE,TRIGGER') AS x")).rows[0]!.x, false);
  const ver = await ctx.connectAs("integrity_chain_verifier");
  await assert.rejects(() => ver.query("SELECT reason_code FROM breakglass.ceremony"), (e: unknown) => codeOf(e) === "42501");
  await ver.query("BEGIN READ WRITE"); // el rol es read-only por defecto; en escritura el rechazo es por privilegio
  await assert.rejects(() => ver.query("INSERT INTO breakglass.ceremony (ceremony_ref, valid_until, reason_code, ticket_ref) VALUES ('CER-TEST-0009', now() + interval '5 minutes', 'REHEARSAL', 'CA-1')"), (e: unknown) => codeOf(e) === "42501");
  await ver.query("ROLLBACK");
  const app = await ctx.connectAs("app_rw");
  await assert.rejects(() => app.query("SELECT 1 FROM breakglass.ceremony"), (e: unknown) => codeOf(e) === "42501");
  const mig = await ctx.connectAs("consent_migrator");
  await mig.query("BEGIN");
  await mig.query("SET LOCAL ROLE consent_owner");
  await assert.rejects(() => mig.query("SELECT 1 FROM breakglass.ceremony"), (e: unknown) => codeOf(e) === "42501");
  await mig.query("ROLLBACK");
});

pgTest("TEST-CNS-1856 pg: el migrador (consent_owner) no asume integrity_owner en ningun modo; en IT0B conserva SET sobre 15 owners y en REAL_DATA (REVOKE explicito, incluidos los 4 roles de 0080 y outbox_claimer) sobre ninguno; REAL_DATA = lista exacta e inventario sin filas de funciones ajenas", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const canSet = async (member: string, role: string): Promise<boolean> => (await admin.query<{ x: boolean }>("SELECT pg_has_role($1, $2, 'SET') AS x", [member, role])).rows[0]!.x;
  assert.equal(await canSet("consent_owner", "integrity_owner"), false);
  assert.equal(await canSet("consent_migrator", "integrity_owner"), false);
  for (const r of CONSENT_OWNER_SET_ROLES) assert.equal(await canSet("consent_migrator", r), true, `IT0B: el migrador llega a ${r} (transitorio, Q-15 c)`);
  assert.equal(await canSet("consent_migrator", "outbox_claimer"), true);
  assert.equal(CONSENT_OWNER_SET_ROLES.length, 15);
  // ddl_breakglass: SET sobre cada uno de los 17 owners y nada mas (ni consent_owner, ni roles de runtime, ni el migrador, ni rights_operator).
  for (const r of BREAKGLASS_OWNER_ROLES) assert.equal(await canSet("ddl_breakglass", r), true, r);
  for (const r of ["consent_owner", "consent_migrator", "app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_chain_verifier", "rights_operator", "staff_roster_reader", "db_owner_nologin", "breakglass_log_owner"]) assert.equal(await canSet("ddl_breakglass", r), false, `ddl_breakglass no asume ${r}`);
  for (const runtime of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier"]) {
    for (const r of [...BREAKGLASS_OWNER_ROLES, "consent_owner", "ddl_breakglass", "db_owner_nologin", "breakglass_log_owner"]) assert.equal(await canSet(runtime, r), false, `${runtime} -> ${r}`);
  }
  // REAL_DATA sobre el estado actual del cluster (en una tx revertida): el REVOKE explicito deja SET en ninguno, aunque 0034/0046/0064/0080 o corridas previas en IT0B los hubieran dejado.
  await withClusterPostApplied(ctx, admin, "REAL_DATA", async () => {
    for (const r of [...BREAKGLASS_OWNER_ROLES, "integrity_owner"]) assert.equal(await canSet("consent_owner", r), false, `REAL_DATA: consent_owner -> ${r}`);
    for (const r of BREAKGLASS_OWNER_ROLES) assert.equal(await canSet("consent_migrator", r), false, `REAL_DATA: consent_migrator -> ${r}`);
    for (const r of ["app_schema_owner", "ops_schema_owner", "shared_fn_owner", "revocation_recovery_reader"]) assert.equal(await canSet("consent_owner", r), false, `REAL_DATA: los 4 roles de 0080 (${r}) tampoco (F-PR7C-06)`);
    assert.equal((await admin.query("SELECT 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'consent_owner' AND m.set_option")).rowCount, 0);
    assert.deepEqual((await admin.query("SELECT r.rolname FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member JOIN pg_roles r ON r.oid = m.roleid WHERE u.rolname = 'consent_migrator'")).rows, [{ rolname: "consent_owner" }]);
    assert.deepEqual(await checkRoleMemberships(admin, "REAL_DATA"), []);
    // Inventario por modo: en REAL_DATA sin SET no hay filas V2|fn de otros owners en el alcance de consent_owner (F-PR7-01 sigue abierto por las tablas de app/ops: REAL_DATA_BLOCKERS no cambia).
    assert.deepEqual(await checkConsentOwnerInventory(admin, "REAL_DATA"), []);
  });
  assert.deepEqual(await checkConsentOwnerInventory(admin, "IT0B_SYNTHETIC"), []);
  assert.ok((await checkConsentOwnerInventory(admin, "REAL_DATA")).some((p) => p.includes("V2|fn|")), "el cluster compartido esta en IT0B: con la lista de REAL_DATA sobran las filas V2|fn");
});

pgTest("TEST-CNS-1857 pg: la fase cluster va en UNA transaccion: un fallo inyectado al final no deja ningun cambio (ni SET re-otorgado por 0026 ni roles a medio crear) y el lock de roles se libera", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const before = JSON.stringify((await admin.query("SELECT u.rolname AS m, r.rolname AS r, a.inherit_option, a.set_option, a.admin_option FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles u ON u.oid = a.member ORDER BY 1, 2, 3, 4, 5")).rows);
  const migrations = loadMigrations(MIGRATIONS_DIR);
  const bad = { ...(migrations.find((m) => m.scope === "cluster")!), version: "9999", name: "falla_inyectada", sql: "-- scope: cluster\nSELECT 1/0;\n" };
  await ctx.withRoleCatalogLock(async () => {
    // Antes del fallo corren TODOS los archivos cluster (re-otorgando 0026 y demas) dentro de la transaccion; el ROLLBACK debe borrarlo.
    await assert.rejects(() => applyClusterScope(admin, [...migrations, bad], { mode: "IT0B_SYNTHETIC", deferPost: true }), (e: unknown) => codeOf(e) === "22012");
  });
  assert.equal((await admin.query<{ t: string }>("SELECT current_setting('cns.db_role_mode', true) AS t")).rows[0]?.t ?? "", "", "el GUC de modo se limpia aunque falle");
  assert.equal(JSON.stringify((await admin.query("SELECT u.rolname AS m, r.rolname AS r, a.inherit_option, a.set_option, a.admin_option FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles u ON u.oid = a.member ORDER BY 1, 2, 3, 4, 5")).rows), before);
  assert.equal((await admin.query<{ l: boolean }>("SELECT pg_try_advisory_lock(7240124) AS l")).rows[0]?.l, true, "el lock se libero (reentrante: la misma sesion lo toma otra vez)");
  await admin.query("SELECT pg_advisory_unlock(7240124)");
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), []);
});

/** psql (para los scripts de db/ceremonies, que usan metacomandos): PSQL, el PATH o Postgres.app. En CI (ubuntu-24.04 trae psql) su ausencia es un fallo; fuera de CI se omite con aviso. */
function findPsql(): string | null {
  const candidates = [process.env.PSQL, "psql", "/Applications/Postgres.app/Contents/Versions/latest/bin/psql"].filter((c): c is string => c !== undefined && c !== "");
  for (const c of candidates) if (spawnSync(c, ["--version"], { encoding: "utf8" }).status === 0) return c;
  return null;
}

pgTest("TEST-CNS-1858 pg: ENSAYO DE CEREMONIA (LOCAL, sintetico): abrir con verificador SCRAM -> DDL minimo como ddl_breakglass (SET ROLE de cada owner y nada mas) -> cerrar; la vigilancia ve la ventana y despues el cierre; deja evidencia", async (ctx) => {
  const psql = findPsql();
  if (psql === null) {
    if (process.env.CI === "true") assert.fail("psql no esta disponible en CI: el ensayo de ceremonia no puede correr");
    console.warn("TEST-CNS-1858 omitido: sin psql (defina PSQL)");
    return;
  }
  const superuserUrl = ctx.superuserUrl;
  const asUser = (user: string, password: string): string => {
    const u = new URL(superuserUrl);
    u.username = encodeURIComponent(user);
    u.password = encodeURIComponent(password);
    return u.toString();
  };
  const run = (url: string, args: string[]): { out: string; err: string } => {
    const r = spawnSync(psql, [url, "-v", "ON_ERROR_STOP=1", "-X", ...args], { encoding: "utf8", env: { ...process.env, PGOPTIONS: "" } });
    assert.equal(r.status, 0, `psql ${args.join(" ").replace(/verifier=\S+/, "verifier=<…>")}: ${r.stderr}`);
    return { out: r.stdout, err: r.stderr };
  };
  const admin = await ctx.connectAsSuperuser();
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const ref = `CER-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 6)}`;
  const password = generateCeremonyPassword();
  const verifier = scramVerifier(password);
  const evidence: Record<string, unknown> = { ceremonyRef: ref, kind: "REHEARSAL", environment: "LOCAL", dataClass: "SYNTHETIC", steps: [] as unknown[] };
  const step = (name: string, detail: Record<string, unknown>): void => { (evidence.steps as unknown[]).push({ at: new Date().toISOString(), name, ...detail }); };

  // El lock de roles se mantiene durante todo el ensayo: ningun otro archivo de test aprovisiona (ni aserta el LOGIN de ddl_breakglass) mientras la ceremonia esta abierta.
  await ctx.withRoleCatalogLock(async () => {
   try {
    const state = async (): Promise<{ canlogin: boolean; hasPassword: boolean; scram: boolean; validUntil: string | null; sessions: number }> =>
      (await admin.query("SELECT r.rolcanlogin AS canlogin, a.rolpassword IS NOT NULL AS \"hasPassword\", COALESCE(a.rolpassword LIKE 'SCRAM-SHA-256$%', false) AS scram, r.rolvaliduntil::text AS \"validUntil\", (SELECT count(*)::int FROM pg_stat_activity WHERE usename = 'ddl_breakglass') AS sessions FROM pg_roles r JOIN pg_authid a ON a.oid = r.oid WHERE r.rolname = 'ddl_breakglass'")).rows[0] as { canlogin: boolean; hasPassword: boolean; scram: boolean; validUntil: string | null; sessions: number };
    const closed = await state();
    assert.deepEqual([closed.canlogin, closed.sessions], [false, 0]);
    assert.deepEqual(evaluateBreakglass(await readBreakglassSnapshot(ver)), [], "antes: cerrado y sin ceremonia");
    step("before", { rolcanlogin: closed.canlogin, sessions: closed.sessions, watchFindings: 0 });

    // 1. ABRIR. El servidor solo recibe el verificador (hash salado); la contrasena en texto plano no sale del cliente.
    const open = run(superuserUrl, ["-v", `ceremony_ref=${ref}`, "-v", "reason_code=REHEARSAL", "-v", "ticket_ref=CA-999", "-v", "valid_minutes=30", "-v", `verifier=${verifier}`, "-f", join(ROOT, "db/ceremonies/open.sql")]);
    assert.match(open.out, /ceremonia abierta/);
    const opened = await state();
    assert.deepEqual([opened.canlogin, opened.hasPassword, opened.scram], [true, true, true]);
    assert.ok(opened.validUntil !== null);
    assert.equal((await admin.query<{ p: string }>("SELECT rolpassword AS p FROM pg_authid WHERE rolname = 'ddl_breakglass'")).rows[0]?.p, verifier, "el servidor guarda el verificador calculado en el cliente");
    assert.ok(!(open.out + open.err).includes(password), "la contrasena en texto plano no aparece en la salida de open.sql");
    const row = (await admin.query("SELECT ceremony_ref, reason_code, ticket_ref, closed_at, valid_until - opened_at AS window FROM breakglass.ceremony WHERE ceremony_ref = $1", [ref])).rows[0];
    assert.deepEqual([row?.reason_code, row?.ticket_ref, row?.closed_at], ["REHEARSAL", "CA-999", null]);
    // Una segunda apertura con la ceremonia vigente se rechaza (una sola abierta).
    const second = spawnSpawn(psql, superuserUrl, ["-v", "ON_ERROR_STOP=1", "-v", "ceremony_ref=CER-OTHER-0001", "-v", "reason_code=REHEARSAL", "-v", "ticket_ref=CA-999", "-v", "valid_minutes=5", "-v", `verifier=${verifier}`, "-f", join(ROOT, "db/ceremonies/open.sql")]);
    assert.notEqual(second.status, 0);
    assert.match(second.stdout + second.stderr, /ya hay una ceremonia abierta/);
    step("open", { rolcanlogin: true, scramVerifierStored: true, plaintextOnServer: false, reasonCode: "REHEARSAL", ticketRef: "CA-999", windowMinutes: 30 });
    assert.deepEqual(evaluateBreakglass(await readBreakglassSnapshot(ver)), [], "durante: ceremonia vigente, LOGIN esperado");

    // 2. DDL MINIMO como ddl_breakglass: asume cada owner (SET) y nada mas; sin acceso directo a datos; la sesion usa log_statement = ddl.
    const session = new pg.Client({ connectionString: asUser("ddl_breakglass", password) });
    await session.connect();
    try {
      assert.equal((await session.query<{ u: string }>("SELECT session_user AS u")).rows[0]?.u, "ddl_breakglass");
      assert.equal((await session.query<{ s: string }>("SELECT current_setting('log_statement') AS s")).rows[0]?.s, "ddl");
      assert.equal((await session.query<{ s: string }>("SELECT current_setting('log_parameter_max_length') AS s")).rows[0]?.s, "0");
      for (const r of BREAKGLASS_OWNER_ROLES) {
        await session.query(`SET ROLE ${r}`);
        await session.query("RESET ROLE");
      }
      for (const r of ["consent_owner", "consent_migrator", "app_rw", "db_owner_nologin", "breakglass_log_owner", "rights_operator"]) {
        await assert.rejects(() => session.query(`SET ROLE ${r}`), (e: unknown) => codeOf(e) === "42501", `no asume ${r}`);
      }
      for (const sql of ["SELECT 1 FROM integrity.audit_event", "SELECT 1 FROM breakglass.ceremony", "CREATE ROLE intruso", "CREATE DATABASE intruso", "CREATE SCHEMA intruso"]) {
        await assert.rejects(() => session.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
      }
      await assert.rejects(() => new pg.Client({ connectionString: asUser("ddl_breakglass", password) }).connect(), (e: unknown) => codeOf(e) === "53300", "CONNECTION LIMIT 1");
      assert.equal((await state()).sessions, 1);
      assert.deepEqual(evaluateBreakglass(await readBreakglassSnapshot(ver)), [], "con sesion activa y ceremonia vigente");
    } finally {
      await session.end();
    }
    const ddlFile = join(ROOT, "db/ceremonies/rehearsal-ddl.sql");
    run(asUser("ddl_breakglass", password), ["-f", ddlFile]);
    assert.equal((await admin.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = 'ceremony_rehearsal_probe'")).rowCount, 0, "el DDL del ensayo no deja residuos en integrity");
    step("ddl", { script: "db/ceremonies/rehearsal-ddl.sql", scriptSha256: createHash("sha256").update(readFileSync(ddlFile)).digest("hex"), assumedRole: "integrity_owner", ownersAssumable: BREAKGLASS_OWNER_ROLES.length, deniedRoles: ["consent_owner", "consent_migrator", "app_rw"], logStatement: "ddl", logParameterMaxLength: 0 });

    // 3. CERRAR.
    const close = run(superuserUrl, ["-v", `ceremony_ref=${ref}`, "-f", join(ROOT, "db/ceremonies/close.sql")]);
    assert.match(close.out, /ceremonia cerrada/);
    const after = await state();
    assert.deepEqual([after.canlogin, after.hasPassword, after.sessions], [false, false, 0]);
    const closedRow = (await admin.query("SELECT closed_at IS NOT NULL AS closed FROM breakglass.ceremony WHERE ceremony_ref = $1", [ref])).rows[0];
    assert.equal(closedRow?.closed, true);
    await assert.rejects(() => new pg.Client({ connectionString: asUser("ddl_breakglass", password) }).connect(), "tras el cierre ddl_breakglass no puede iniciar sesion");
    assert.deepEqual(evaluateBreakglass(await readBreakglassSnapshot(ver)), [], "despues: cerrado");
    step("close", { rolcanlogin: false, passwordDiscarded: true, sessions: 0, closedAtRecorded: true, watchFindings: 0 });
    // Cerrar de nuevo la misma ceremonia es idempotente para el rol pero la fila ya esta cerrada (el UPDATE no cambia nada) y el cierre de una ceremonia inexistente falla.
    const missing = spawnSpawn(psql, superuserUrl, ["-v", "ON_ERROR_STOP=1", "-v", "ceremony_ref=CER-NO-EXISTE-1", "-f", join(ROOT, "db/ceremonies/close.sql")]);
    assert.notEqual(missing.status, 0);
    assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), []);
    assert.deepEqual(await checkDatabaseLevel(admin, "IT0B_SYNTHETIC", { breakglassMustBeClosed: true }).then((p) => p.filter((x) => !/dueño de la base|CONNECT|PUBLIC|CREATE explicito/.test(x))), [], "ddl_breakglass vuelve a su estado cerrado exacto");   } finally {
    // Pase lo que pase, la ceremonia no queda abierta en el cluster compartido (el lock de roles sigue tomado).
    await admin.query("ALTER ROLE ddl_breakglass NOLOGIN PASSWORD NULL VALID UNTIL '1970-01-01 00:00:00+00'");
    await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'ddl_breakglass'");
    await admin.query("UPDATE breakglass.ceremony SET closed_at = now() WHERE ceremony_ref = $1 AND closed_at IS NULL", [ref]);
   }
  });

  // Evidencia secundaria (fila de ceremonia + comportamiento de sesion). La evidencia PRIMARIA (ancla firmada antes y despues, Q13) llega con PR-7f (F-R6-1, C-7 pendiente de Carlos); el log de sesion del servidor
  // (log_statement = ddl, conexiones/desconexiones) lo recoge el postgresql.conf del host, no este test.
  evidence.evidenceClass = "SECONDARY";
  evidence.primaryEvidencePending = "ancla firmada antes/despues (PR-7f, F-R6-1/C-7)";
  evidence.serverVersionNum = (await admin.query<{ v: string }>("SELECT current_setting($$server_version_num$$) AS v")).rows[0]?.v;
  evidence.noPlaintextOnServer = true;
  const out = process.env.CNS_EVIDENCE_OUT;
  if (out !== undefined && out !== "") {
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`);
  }
  assert.ok(!JSON.stringify(evidence).includes(password) && !JSON.stringify(evidence).includes(verifier));
});

function spawnSpawn(psql: string, url: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
  return spawnSync(psql, [url, "-X", ...args], { encoding: "utf8" });
}

pgTest("TEST-CNS-1859 pg: breakglass-watch lee con integrity_chain_verifier (LOGIN de ddl_breakglass, sesiones y ceremonias abiertas) y no ve filas cerradas", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const snap = await readBreakglassSnapshot(ver);
  assert.deepEqual([snap.canLogin, snap.openCeremonies.length], [false, 0]);
  assert.ok(Number.isFinite(snap.nowMs));
  assert.deepEqual(evaluateBreakglass(snap), []);
  // pg_stat_activity: el rol del watch debe VER las sesiones de otro rol; si no las ve, el chequeo de sesiones seria ciego. Se prueba con una sesion real de otro rol de runtime.
  const other = await ctx.connectAs("app_rw");
  const seen = await ver.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE usename = 'app_rw'");
  assert.ok((seen.rows[0] as { n: number }).n >= 1, "el chain-verifier ve el usename de las sesiones ajenas (pg_stat_activity)");
  await other.query("SELECT 1");
  // Una ceremonia abierta (insertada por el superusuario, como open.sql) aparece; una cerrada no. Revertido.
  await admin.query("BEGIN");
  try {
    await admin.query("INSERT INTO breakglass.ceremony (ceremony_ref, valid_until, reason_code, ticket_ref) VALUES ('CER-WATCH-0001', now() + interval '10 minutes', 'REHEARSAL', 'CA-1'), ('CER-WATCH-0002', now() + interval '10 minutes', 'REHEARSAL', 'CA-1')");
    await admin.query("UPDATE breakglass.ceremony SET closed_at = now() WHERE ceremony_ref = 'CER-WATCH-0002'");
    const inTx = await readBreakglassSnapshot(admin);
    assert.deepEqual(inTx.openCeremonies.map((c) => c.ceremonyRef), ["CER-WATCH-0001"]);
    assert.deepEqual(evaluateBreakglass({ ...inTx, canLogin: true }), []);
    assert.deepEqual(evaluateBreakglass({ ...inTx, canLogin: true, nowMs: inTx.nowMs + 11 * 60_000 }).map((f) => f.code), ["LOGIN_WITHOUT_CEREMONY", "CEREMONY_OVERDUE"]);
  } finally {
    await admin.query("ROLLBACK");
  }
  assert.ok(existsSync(join(ROOT, "infra/systemd/consent-breakglass-watch.timer")) && /OnUnitActiveSec=1min/.test(readFileSync(join(ROOT, "infra/systemd/consent-breakglass-watch.timer"), "utf8")));
});
