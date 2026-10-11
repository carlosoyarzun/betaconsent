// Gobierna: ADR-010 rev. 4 §4.3 (nonce), §4.4 (esquema platform, membership, role_assignment), §4.6 (authorization_check), §7 fila PR-3;
// specs/db-roles.spec.yaml (platform_schema_owner, membership_owner, grant_owner; INV-DBR-01/03); decisiones de Carlos del 2026-10-11 (Q-17 a, Q-18). Cierra DF-3, DF-11, DF-12.
// TEST-CNS-1353: catalogo del esquema platform (dueños, FORCE RLS, sin privilegios de runtime, funciones SECURITY DEFINER con search_path fijo y EXECUTE exacto,
//   triggers ENABLE ALWAYS, sin columnas con tokens de identificacion personal, startup-checks).
// TEST-CNS-1354: aprovisionamiento de roles de plataforma (cross-tenant): doble control solicitante != aprobador, step-up ATTESTED, nonce de un solo uso.
// TEST-CNS-1355: membership por tenant: via TENANT_ADMIN (web/app_rw, solo su tenant, Q-17) y via PLATFORM (platform_rw, tenant destino).
// TEST-CNS-1356: inmutabilidad (membership, nonce, authorization_check append-only) y cero PII.
// TEST-CNS-1357: action_nonce emitido por la DB: ligado a (tenant, accion, refs, principal), TTL acotado, vencimiento, solo hash, authorize sin consumo.
// El "verifier" de PR-4 (platform.record_assertion) aun no existe: los tests marcan attested_at como superusuario, solo para ejercitar el camino ATTESTED.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { checkRoleMemberships } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const TENANT_X = fixtureUuid("platform-tenant-x");
const TENANT_Y = fixtureUuid("platform-tenant-y");
const P = (label: string): string => fixtureUuid(`platform-principal-${label}`);
const HEX64 = /^[0-9a-f]{64}$/;

/** Una transaccion con el principal (y tenant) del actor fijados como GUC locales; confirma siempre (la evidencia de DENY persiste). */
async function call<T = Record<string, unknown>>(client: Client, principal: string | null, tenant: string | null, sql: string, params: unknown[] = []): Promise<T[]> {
  await client.query("BEGIN");
  try {
    if (principal !== null) await client.query("SELECT set_config('app.principal_ref', $1, true)", [principal]);
    if (tenant !== null) await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
    const r = await client.query(sql, params);
    await client.query("COMMIT");
    return r.rows as T[];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

/** Siembra (superusuario, sin pasar por las funciones) un rol de plataforma ACTIVO: el bootstrap real es una ceremonia (Q10), fuera de PR-3. */
async function seedPlatform(admin: Client, principal: string, role = "PLATFORM"): Promise<void> {
  await admin.query(
    `INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, approver_class, status, requested_by_ref, approved_by_ref, approved_at)
     VALUES ($1, $2, CASE WHEN $2 = 'APPROVER' THEN 'SECURITY' END, 'ACTIVE', $3, $4, now())`,
    [principal, role, P("seed-requester"), P("seed-approver")],
  );
}

async function seedTenantAdmin(admin: Client, tenant: string, principal: string): Promise<void> {
  await admin.query(
    `INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref, approved_by_ref, approved_at)
     VALUES ($1, $2, 'TENANT_ADMIN', 'ACTIVE', $3, $4, now())`,
    [tenant, principal, P("seed-requester"), P("seed-approver")],
  );
}

/** Stand-in del verifier de PR-4: marca el nonce como ATTESTED (el guard permite NULL -> instante una sola vez). */
async function attest(admin: Client, principal: string, action: string): Promise<number> {
  const r = await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE principal_ref = $1 AND action = $2 AND attested_at IS NULL", [principal, action]);
  return r.rowCount ?? 0;
}

async function lastChecks(admin: Client, principal: string, n = 1): Promise<Array<{ check_kind: string; action: string | null; decision: string; reason_code: string }>> {
  return (await admin.query<{ check_kind: string; action: string | null; decision: string; reason_code: string }>(
    "SELECT check_kind, action, decision, reason_code FROM platform.authorization_check WHERE principal_ref = $1 ORDER BY at DESC, check_ref LIMIT $2",
    [principal, n],
  )).rows;
}

const EXPECTED_EXECUTE: Record<string, string[]> = {
  request_membership: ["app_rw", "platform_rw"],
  approve_membership: ["platform_rw"],
  request_role_assignment: ["platform_rw"],
  approve_role_assignment: ["platform_rw"],
  authorize: ["platform_rw"],
  issue_action_nonce: ["platform_rw"],
  authorize_target: ["membership_owner"],
  membership_guard: [],
  membership_no_truncate: [],
  action_nonce_guard: [],
  authorization_check_guard: [],
};
const FUNCTION_OWNERS: Record<string, string> = {
  request_membership: "membership_owner", approve_membership: "membership_owner", request_role_assignment: "membership_owner", approve_role_assignment: "membership_owner",
  membership_guard: "membership_owner", membership_no_truncate: "membership_owner",
  authorize: "grant_owner", issue_action_nonce: "grant_owner", authorize_target: "grant_owner", action_nonce_guard: "grant_owner", authorization_check_guard: "grant_owner",
};
const TABLE_OWNERS: Record<string, string> = {
  tenant_membership: "membership_owner", platform_role_assignment: "membership_owner", action_nonce: "grant_owner", authorization_check: "grant_owner",
};

pgTest("TEST-CNS-1353 pg: esquema platform de platform_schema_owner; 4 tablas de membership_owner/grant_owner con FORCE RLS y sin privilegios de runtime; 11 funciones con dueno, search_path fijo y EXECUTE exacto; triggers ENABLE ALWAYS; sin columnas con tokens de identificacion; startup-checks", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();

  const ns = (await admin.query<{ owner: string }>("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = 'platform'")).rows;
  assert.deepEqual(ns, [{ owner: "platform_schema_owner" }]);
  const rels = (await admin.query<{ relname: string; owner: string; rls: boolean; force: boolean }>(
    `SELECT c.relname, pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls, c.relforcerowsecurity AS force
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relkind = 'r' ORDER BY c.relname`,
  )).rows;
  assert.deepEqual(rels, Object.entries(TABLE_OWNERS).sort(([a], [b]) => a.localeCompare(b)).map(([relname, owner]) => ({ relname, owner, rls: true, force: true })));
  // Indices del mismo dueno que su tabla; ninguna otra clase de relacion.
  assert.equal((await admin.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relkind NOT IN ('r', 'i')")).rowCount, 0);
  assert.equal((await admin.query(
    "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_index i ON i.indexrelid = c.oid JOIN pg_class t ON t.oid = i.indrelid WHERE n.nspname = 'platform' AND c.relowner <> t.relowner",
  )).rowCount, 0);

  // Ningun rol (salvo el dueno) tiene privilegios de tabla ni de columna; PUBLIC tampoco. grant_owner solo SELECT por columnas sobre las tablas de membership.
  const noPrivilege = ["consent_owner", "consent_migrator", "app_rw", "platform_rw", "worker", "integrity_verifier", "tenant_resolve_owner", "transition_owner", "case_state_owner", "platform_schema_owner"];
  for (const table of Object.keys(TABLE_OWNERS)) {
    for (const role of noPrivilege) {
      const r = (await admin.query<{ t: boolean; c: boolean }>(
        `SELECT has_table_privilege($1, $2::regclass, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS t,
                has_any_column_privilege($1, $2::regclass, 'SELECT,INSERT,UPDATE,REFERENCES') AS c`,
        [role, `platform.${table}`],
      )).rows[0];
      assert.deepEqual(r, { t: false, c: false }, `${role} sobre platform.${table}`);
    }
    const publicAcl = (await admin.query("SELECT 1 FROM pg_class c, aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a WHERE c.oid = $1::regclass AND a.grantee = 0", [`platform.${table}`])).rowCount;
    assert.equal(publicAcl, 0, `PUBLIC sobre platform.${table}`);
  }
  for (const table of ["tenant_membership", "platform_role_assignment"]) {
    const g = (await admin.query<{ s: boolean; w: boolean }>(
      "SELECT has_table_privilege('grant_owner', $1::regclass, 'SELECT') AS s, has_any_column_privilege('grant_owner', $1::regclass, 'INSERT,UPDATE,REFERENCES') AS w",
      [`platform.${table}`],
    )).rows[0];
    assert.deepEqual(g, { s: false, w: false }, `grant_owner sobre platform.${table}: solo SELECT por columnas`);
    assert.equal((await admin.query("SELECT 1 FROM information_schema.column_privileges WHERE table_schema = 'platform' AND table_name = $1 AND grantee = 'grant_owner' AND privilege_type = 'SELECT'", [table])).rowCount! > 0, true);
  }
  for (const table of ["action_nonce", "authorization_check"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_any_column_privilege('membership_owner', $1::regclass, 'SELECT,INSERT,UPDATE,REFERENCES') AS p", [`platform.${table}`])).rows[0]?.p, false);
  }

  // Esquema: nadie CREA salvo el dueno; USAGE solo para los dos owners de objetos, app_rw y platform_rw (worker y verifier no, hasta PR-4); PUBLIC nada.
  for (const role of ["membership_owner", "grant_owner", "consent_owner", "consent_migrator", "app_rw", "platform_rw", "worker", "integrity_verifier"]) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_schema_privilege($1, 'platform', 'CREATE') AS p", [role])).rows[0]?.p, false, `${role} CREATE en platform`);
  }
  for (const [role, usage] of [["membership_owner", true], ["grant_owner", true], ["app_rw", true], ["platform_rw", true], ["worker", false], ["integrity_verifier", false], ["consent_owner", false], ["consent_migrator", false]] as const) {
    assert.equal((await admin.query<{ p: boolean }>("SELECT has_schema_privilege($1, 'platform', 'USAGE') AS p", [role])).rows[0]?.p, usage, `${role} USAGE en platform`);
  }
  assert.equal((await admin.query("SELECT 1 FROM pg_namespace n, aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a WHERE n.nspname = 'platform' AND a.grantee = 0")).rowCount, 0);

  // Funciones: conjunto exacto, dueno, SECURITY DEFINER (salvo triggers), search_path fijo exacto, EXECUTE exacto (nadie mas, ni PUBLIC).
  const fns = (await admin.query<{ proname: string; oid: number; owner: string; secdef: boolean; cfg: string[] | null }>(
    `SELECT p.proname, p.oid, pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS cfg
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' ORDER BY p.proname`,
  )).rows;
  assert.deepEqual(fns.map((f) => f.proname), Object.keys(EXPECTED_EXECUTE).sort());
  const roles = ["app_rw", "platform_rw", "worker", "integrity_verifier", "consent_owner", "consent_migrator", "membership_owner", "grant_owner", "transition_owner", "platform_schema_owner"];
  for (const f of fns) {
    assert.equal(f.owner, FUNCTION_OWNERS[f.proname], `dueno de platform.${f.proname}`);
    assert.deepEqual(f.cfg, ["search_path=pg_catalog, pg_temp"], `search_path de platform.${f.proname}`);
    const isTrigger = f.proname.endsWith("guard") || f.proname === "membership_no_truncate";
    assert.equal(f.secdef, !isTrigger, `SECURITY DEFINER de platform.${f.proname}`);
    assert.equal((await admin.query("SELECT 1 FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE p.oid = $1 AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'", [f.oid])).rowCount, 0, `PUBLIC ejecuta platform.${f.proname}`);
    for (const role of roles) {
      if (role === f.owner) continue;
      const can = (await admin.query<{ p: boolean }>("SELECT has_function_privilege($1, $2, 'EXECUTE') AS p", [role, f.oid])).rows[0]?.p;
      assert.equal(can, (EXPECTED_EXECUTE[f.proname] ?? []).includes(role), `EXECUTE de platform.${f.proname} para ${role}`);
    }
  }

  // Triggers: 8, BEFORE, ENABLE ALWAYS.
  const triggers = (await admin.query<{ tgname: string; tgenabled: string; tgtype: number }>(
    `SELECT g.tgname, g.tgenabled, g.tgtype FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'platform' AND NOT g.tgisinternal ORDER BY g.tgname`,
  )).rows;
  assert.deepEqual(triggers.map((t) => t.tgname), [
    "action_nonce_guard", "action_nonce_no_truncate", "authorization_check_append_only", "authorization_check_no_truncate",
    "platform_role_assignment_guard", "platform_role_assignment_no_truncate", "tenant_membership_guard", "tenant_membership_no_truncate",
  ]);
  for (const t of triggers) {
    assert.equal(t.tgenabled, "A", `${t.tgname} ENABLE ALWAYS`);
    assert.equal(t.tgtype & 2, 2, `${t.tgname} BEFORE`);
  }

  // Ninguna columna con tokens de identificacion personal (leccion de PRs previos): ni "rut" ni "run" como token, ni email/nombre.
  const cols = (await admin.query<{ attname: string }>(
    `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'platform' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped`,
  )).rows.map((r) => r.attname);
  assert.ok(cols.length > 20);
  for (const name of cols) {
    const tokens = name.split("_");
    assert.ok(!tokens.some((t) => ["rut", "run", "email", "mail", "name", "phone", "fono"].includes(t)), `columna con token de identificacion: ${name}`);
  }

  // La membresia exacta de roles NO cambia en PR-3 (ningun runtime es miembro de los owners nuevos).
  assert.deepEqual(await checkRoleMemberships(admin), []);
  for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier"]) {
    for (const owner of ["platform_schema_owner", "membership_owner", "grant_owner"]) {
      assert.equal((await admin.query<{ m: boolean }>("SELECT pg_has_role($1, $2, 'MEMBER') AS m", [role, owner])).rows[0]?.m, false, `${role} miembro de ${owner}`);
    }
  }

  // Desde el rol de runtime: tablas inaccesibles, nadie crea objetos, authorize_target y los triggers no son ejecutables.
  for (const role of ["app_rw", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    for (const table of Object.keys(TABLE_OWNERS)) {
      await assert.rejects(c.query(`SELECT 1 FROM platform.${table}`), (e) => codeOf(e) === "42501", `${role} SELECT platform.${table}`);
    }
    await assert.rejects(c.query("DELETE FROM platform.tenant_membership"), (e) => codeOf(e) === "42501");
    await assert.rejects(c.query("CREATE TABLE platform.intruso (a int)"), (e) => codeOf(e) === "42501");
    await assert.rejects(c.query("SELECT platform.authorize_target('REQUEST_MEMBERSHIP', 'x', NULL, false)"), (e) => codeOf(e) === "42501");
    await assert.rejects(c.query("SELECT platform.membership_guard()"), (e) => codeOf(e) === "42501");
  }
  const app = await ctx.connectAs("app_rw");
  for (const sql of ["SELECT platform.approve_membership($1::uuid)", "SELECT platform.approve_role_assignment($1::uuid)"]) {
    await assert.rejects(app.query(sql, [fixtureUuid("x")]), (e) => codeOf(e) === "42501", `app_rw ${sql}`);
  }
  await assert.rejects(app.query("SELECT platform.request_role_assignment($1, 'PLATFORM', NULL)", [P("a")]), (e) => codeOf(e) === "42501");
  await assert.rejects(app.query("SELECT platform.authorize('REQUEST_MEMBERSHIP', 'x')"), (e) => codeOf(e) === "42501");
  await assert.rejects(app.query("SELECT platform.issue_action_nonce('APPROVE_MEMBERSHIP', ARRAY['x'], $1::uuid, 60)", [TENANT_X]), (e) => codeOf(e) === "42501");

  // startup-checks: cada rol de runtime solo expone lo declarado del esquema platform; app_rw arranca limpio.
  const ok = await runStartupChecks(app, { expectedRole: "app_rw", expectedEnvironment: "LOCAL" });
  assert.deepEqual(ok, { ok: true, failures: [] });
  for (const role of ["platform_rw", "worker", "integrity_verifier"] as const) {
    const c = await ctx.connectAs(role);
    const r = await runStartupChecks(c, { expectedRole: role, expectedEnvironment: "LOCAL" });
    assert.deepEqual(r.failures.filter((f) => /platform\.|esquema platform/.test(f)), [], `${role}: ${r.failures.join("; ")}`);
  }
});

pgTest("TEST-CNS-1354 pg: aprovisionamiento de roles de plataforma con doble control: sin step-up no hay efecto (DENY con evidencia), solicitante != aprobador (tambien CHECK), nonce ATTESTED de un solo uso, aprobacion unica", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const plat = await ctx.connectAs("platform_rw");
  const A = P("pa");
  const B = P("pb");
  const C = P("pc");
  await seedPlatform(admin, A);
  await seedPlatform(admin, B);

  // Sin nonce: DENY STEP_UP_MISSING, NULL, y la evidencia queda confirmada (la funcion no lanza).
  let ref = (await call<{ r: string | null }>(plat, A, null, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [C]))[0]?.r;
  assert.equal(ref, null);
  assert.deepEqual(await lastChecks(admin, A), [{ check_kind: "AUTHORIZE", action: "REQUEST_ROLE_ASSIGNMENT", decision: "DENY", reason_code: "STEP_UP_MISSING" }]);
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_role_assignment WHERE principal_ref = $1", [C])).rowCount, 0);

  // Nonce emitido pero aun PENDING (no atestado): sigue sin efecto. El nonce se liga a las refs opacas de la solicitud.
  const resource = `${C}:RIGHTS_OPERATOR:`;
  const nonce = (await call<{ n: string | null }>(plat, A, null, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1::text], NULL, 300) AS n", [resource]))[0]?.n;
  assert.match(nonce ?? "", HEX64);
  assert.equal((await call<{ r: string | null }>(plat, A, null, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [C]))[0]?.r, null);
  assert.equal((await lastChecks(admin, A))[0]?.reason_code, "STEP_UP_MISSING");

  // Atestado por el "verifier" (stand-in de PR-4): la solicitud pasa, queda PENDING y el nonce se consume.
  assert.equal(await attest(admin, A, "REQUEST_ROLE_ASSIGNMENT"), 1);
  ref = (await call<{ r: string | null }>(plat, A, null, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [C]))[0]?.r;
  assert.match(ref ?? "", /^[0-9a-f-]{36}$/);
  assert.deepEqual(await lastChecks(admin, A), [{ check_kind: "AUTHORIZE", action: "REQUEST_ROLE_ASSIGNMENT", decision: "ALLOW", reason_code: "OK" }]);
  const row = (await admin.query("SELECT status, requested_by_ref, approved_by_ref FROM platform.platform_role_assignment WHERE request_ref = $1", [ref])).rows[0];
  assert.deepEqual(row, { status: "PENDING", requested_by_ref: A, approved_by_ref: null });
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE principal_ref = $1 AND consumed_at IS NOT NULL", [A])).rowCount, 1);
  // Reuso del mismo nonce: ya consumido => DENY.
  assert.equal((await call<{ r: string | null }>(plat, A, null, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [C]))[0]?.r, null);
  assert.equal((await lastChecks(admin, A))[0]?.reason_code, "STEP_UP_MISSING");

  // Aprobacion: el solicitante no se aprueba a si mismo (SELF_APPROVAL, incluso con nonce atestado).
  await call(plat, A, null, "SELECT platform.issue_action_nonce('APPROVE_ROLE_ASSIGNMENT', ARRAY[$1::text], NULL, 300)", [ref]);
  assert.equal(await attest(admin, A, "APPROVE_ROLE_ASSIGNMENT"), 1);
  assert.equal((await call<{ r: boolean }>(plat, A, null, "SELECT platform.approve_role_assignment($1::uuid) AS r", [ref]))[0]?.r, false);
  assert.deepEqual(await lastChecks(admin, A), [{ check_kind: "AUTHORIZE", action: "APPROVE_ROLE_ASSIGNMENT", decision: "DENY", reason_code: "SELF_APPROVAL" }]);
  // Un tercero sin rol PLATFORM tampoco (NO_ROLE).
  assert.equal((await call<{ r: boolean }>(plat, C, null, "SELECT platform.approve_role_assignment($1::uuid) AS r", [ref]))[0]?.r, false);
  assert.equal((await lastChecks(admin, C))[0]?.reason_code, "NO_ROLE");
  // Sin step-up, B tampoco aprueba (STEP_UP_MISSING).
  assert.equal((await call<{ r: boolean }>(plat, B, null, "SELECT platform.approve_role_assignment($1::uuid) AS r", [ref]))[0]?.r, false);
  assert.equal((await lastChecks(admin, B))[0]?.reason_code, "STEP_UP_MISSING");
  // B con nonce atestado ligado a la solicitud: aprueba una sola vez.
  await call(plat, B, null, "SELECT platform.issue_action_nonce('APPROVE_ROLE_ASSIGNMENT', ARRAY[$1::text], NULL, 300)", [ref]);
  assert.equal(await attest(admin, B, "APPROVE_ROLE_ASSIGNMENT"), 1);
  assert.equal((await call<{ r: boolean }>(plat, B, null, "SELECT platform.approve_role_assignment($1::uuid) AS r", [ref]))[0]?.r, true);
  assert.deepEqual((await admin.query("SELECT status, approved_by_ref FROM platform.platform_role_assignment WHERE request_ref = $1", [ref])).rows[0], { status: "ACTIVE", approved_by_ref: B });
  assert.equal((await call<{ r: boolean }>(plat, B, null, "SELECT platform.approve_role_assignment($1::uuid) AS r", [ref]))[0]?.r, false, "ya no esta PENDING");
  assert.equal((await lastChecks(admin, B))[0]?.reason_code, "REQUEST_NOT_FOUND");

  // El nonce de A (solicitud ajena) no sirve para otra solicitud: refs distintas => STEP_UP_MISSING.
  const other = (await call<{ n: string | null }>(plat, A, null, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1::text], NULL, 300) AS n", [`${C}:CONTEXT_OWNER:`]))[0]?.n;
  assert.match(other ?? "", HEX64);
  await attest(admin, A, "REQUEST_ROLE_ASSIGNMENT");
  assert.equal((await call<{ r: string | null }>(plat, A, null, "SELECT platform.request_role_assignment($1, 'PLATFORM', NULL) AS r", [C]))[0]?.r, null);
  assert.equal((await lastChecks(admin, A))[0]?.reason_code, "STEP_UP_MISSING");

  // Doble control tambien en la tabla: ACTIVE con aprobador == solicitante viola el CHECK (23514); PENDING con approved_* tambien.
  await assert.rejects(
    admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref, approved_by_ref, approved_at) VALUES ($1, 'PLATFORM', 'ACTIVE', $2, $2, now())", [P("pz"), A]),
    (e) => codeOf(e) === "23514",
  );
  await assert.rejects(
    admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref, approved_by_ref, approved_at) VALUES ($1, 'PLATFORM', 'PENDING', $2, $3, now())", [P("pz"), A, B]),
    (e) => codeOf(e) === "23514",
  );
  // APPROVER exige clase (PRIVACY_LEGAL | SECURITY); las demas, ninguna.
  await assert.rejects(admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'APPROVER', 'PENDING', $2)", [P("pz"), A]), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, approver_class, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'SECURITY', 'PENDING', $2)", [P("pz"), A]), (e) => codeOf(e) === "23514");
});

pgTest("TEST-CNS-1355 pg: membership por tenant: TENANT_ADMIN solicita desde web (app_rw) solo en su tenant y sin step-up (Q-17); PLATFORM solicita y aprueba con tenant destino y step-up; app_rw nunca aprueba", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const web = await ctx.connectAs("app_rw");
  const plat = await ctx.connectAs("platform_rw");
  const ADMIN_X = P("admin-x");
  const PEER = P("peer");
  const NEWBIE = P("newbie");
  const PA = P("m-pa");
  const PB = P("m-pb");
  await seedTenantAdmin(admin, TENANT_X, ADMIN_X);
  await seedPlatform(admin, PA);
  await seedPlatform(admin, PB);

  // Via TENANT_ADMIN: su propio tenant, sin nonce.
  const ref = (await call<{ r: string | null }>(web, ADMIN_X, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_X, NEWBIE]))[0]?.r;
  assert.match(ref ?? "", /^[0-9a-f-]{36}$/);
  assert.deepEqual(await lastChecks(admin, ADMIN_X), [{ check_kind: "AUTHORIZE", action: "REQUEST_MEMBERSHIP", decision: "ALLOW", reason_code: "OK" }]);
  assert.deepEqual((await admin.query("SELECT tenant_id, principal_ref, membership_role, status, requested_by_ref FROM platform.tenant_membership WHERE request_ref = $1", [ref])).rows[0],
    { tenant_id: TENANT_X, principal_ref: NEWBIE, membership_role: "INVITER", status: "PENDING", requested_by_ref: ADMIN_X });
  // Repetir la misma solicitud no duplica (UNIQUE) y no lanza.
  assert.equal((await call<{ r: string | null }>(web, ADMIN_X, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_X, NEWBIE]))[0]?.r, null);
  assert.equal((await admin.query("SELECT 1 FROM platform.tenant_membership WHERE tenant_id = $1 AND principal_ref = $2", [TENANT_X, NEWBIE])).rowCount, 1);

  // Otro tenant: el admin de X con GUC de X pide para Y => TENANT_MISMATCH; con GUC de Y (el actor no es admin de Y) => NO_ROLE. Nada se inserta.
  assert.equal((await call<{ r: string | null }>(web, ADMIN_X, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_Y, NEWBIE]))[0]?.r, null);
  assert.equal((await lastChecks(admin, ADMIN_X))[0]?.reason_code, "TENANT_MISMATCH");
  assert.equal((await call<{ r: string | null }>(web, ADMIN_X, TENANT_Y, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_Y, NEWBIE]))[0]?.r, null);
  assert.equal((await lastChecks(admin, ADMIN_X))[0]?.reason_code, "NO_ROLE");
  assert.equal((await admin.query("SELECT 1 FROM platform.tenant_membership WHERE tenant_id = $1", [TENANT_Y])).rowCount, 0);
  // Quien no es TENANT_ADMIN de X (aunque este PENDING o sea INVITER) no puede solicitar.
  assert.equal((await call<{ r: string | null }>(web, PEER, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_X, P("otro")]))[0]?.r, null);
  assert.equal((await lastChecks(admin, PEER))[0]?.reason_code, "NO_ROLE");
  // Entrada invalida (con '@'): DENY INVALID_RESOURCE sin guardar el valor (cero PII).
  assert.equal((await call<{ r: string | null }>(web, ADMIN_X, TENANT_X, "SELECT platform.request_membership($1::uuid, 'alguien@ejemplo.cl', 'INVITER') AS r", [TENANT_X]))[0]?.r, null);
  assert.deepEqual((await admin.query("SELECT reason_code, resource_ref FROM platform.authorization_check WHERE principal_ref = $1 AND reason_code = 'INVALID_RESOURCE'", [ADMIN_X])).rows, [{ reason_code: "INVALID_RESOURCE", resource_ref: null }]);
  // Sin principal en la transaccion: NO_PRINCIPAL.
  await call(web, null, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER')", [TENANT_X, NEWBIE]);
  assert.equal((await admin.query("SELECT 1 FROM platform.authorization_check WHERE principal_ref IS NULL AND reason_code = 'NO_PRINCIPAL'")).rowCount! >= 1, true);
  // app_rw llamando a la ruta PLATFORM con el principal de un PLATFORM real: CALLER_ROLE/NO_ROLE (la ruta se liga a session_user), nunca ALLOW.
  assert.equal((await call<{ r: string | null }>(web, PA, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'TENANT_ADMIN') AS r", [TENANT_X, P("zz")]))[0]?.r, null);
  assert.equal((await lastChecks(admin, PA))[0]?.reason_code, "NO_ROLE");

  // Via PLATFORM: platform_rw con tenant destino como parametro (F-A10-07) y step-up atestado ligado a (tenant, accion, refs, principal).
  const res = `${P("nuevo-admin")}:TENANT_ADMIN`;
  assert.equal((await call<{ r: string | null }>(plat, PA, null, "SELECT platform.request_membership($1::uuid, $2, 'TENANT_ADMIN') AS r", [TENANT_Y, P("nuevo-admin")]))[0]?.r, null);
  assert.equal((await lastChecks(admin, PA))[0]?.reason_code, "STEP_UP_MISSING");
  // Nonce de otro tenant no sirve: el binding incluye el tenant.
  await call(plat, PA, null, "SELECT platform.issue_action_nonce('REQUEST_MEMBERSHIP', ARRAY[$1::text], $2::uuid, 300)", [res, TENANT_X]);
  await attest(admin, PA, "REQUEST_MEMBERSHIP");
  assert.equal((await call<{ r: string | null }>(plat, PA, null, "SELECT platform.request_membership($1::uuid, $2, 'TENANT_ADMIN') AS r", [TENANT_Y, P("nuevo-admin")]))[0]?.r, null);
  assert.equal((await lastChecks(admin, PA))[0]?.reason_code, "STEP_UP_MISSING");
  await call(plat, PA, null, "SELECT platform.issue_action_nonce('REQUEST_MEMBERSHIP', ARRAY[$1::text], $2::uuid, 300)", [res, TENANT_Y]);
  assert.equal((await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE principal_ref = $1 AND tenant_id = $2 AND attested_at IS NULL", [PA, TENANT_Y])).rowCount, 1);
  const pref = (await call<{ r: string | null }>(plat, PA, null, "SELECT platform.request_membership($1::uuid, $2, 'TENANT_ADMIN') AS r", [TENANT_Y, P("nuevo-admin")]))[0]?.r;
  assert.match(pref ?? "", /^[0-9a-f-]{36}$/);

  // Aprobacion: solo platform_rw, otro PLATFORM, con step-up atestado ligado a la solicitud y al tenant de la solicitud.
  assert.equal((await call<{ r: boolean }>(plat, PA, null, "SELECT platform.approve_membership($1::uuid) AS r", [pref]))[0]?.r, false);
  assert.equal((await lastChecks(admin, PA))[0]?.reason_code, "SELF_APPROVAL");
  await call(plat, PB, null, "SELECT platform.issue_action_nonce('APPROVE_MEMBERSHIP', ARRAY[$1::text], $2::uuid, 300)", [pref, TENANT_Y]);
  await attest(admin, PB, "APPROVE_MEMBERSHIP");
  assert.equal((await call<{ r: boolean }>(plat, PB, null, "SELECT platform.approve_membership($1::uuid) AS r", [pref]))[0]?.r, true);
  assert.deepEqual((await admin.query("SELECT status, approved_by_ref, tenant_id FROM platform.tenant_membership WHERE request_ref = $1", [pref])).rows[0], { status: "ACTIVE", approved_by_ref: PB, tenant_id: TENANT_Y });
  // La solicitud pendiente del admin de X: la aprueba un PLATFORM ajeno al solicitante, con nonce del tenant X.
  await call(plat, PB, null, "SELECT platform.issue_action_nonce('APPROVE_MEMBERSHIP', ARRAY[$1::text], $2::uuid, 300)", [ref, TENANT_X]);
  await attest(admin, PB, "APPROVE_MEMBERSHIP");
  assert.equal((await call<{ r: boolean }>(plat, PB, null, "SELECT platform.approve_membership($1::uuid) AS r", [ref]))[0]?.r, true);
  // Ya activo, el nuevo miembro INVITER de X no puede solicitar membership (no es TENANT_ADMIN): sigue NO_ROLE.
  assert.equal((await call<{ r: string | null }>(web, NEWBIE, TENANT_X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [TENANT_X, P("otro2")]))[0]?.r, null);
  assert.equal((await lastChecks(admin, NEWBIE))[0]?.reason_code, "NO_ROLE");
});

pgTest("TEST-CNS-1356 pg: inmutabilidad: membership solo PENDING -> ACTIVE con approved_*, nonce solo fija attested_at/consumed_at una vez, authorization_check append-only; TRUNCATE y DELETE rechazados incluso al superusuario (ENABLE ALWAYS); cero PII", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const plat = await ctx.connectAs("platform_rw");
  const A = P("i-pa");
  await seedPlatform(admin, A);
  const mref = (await admin.query<{ request_ref: string }>(
    "INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3) RETURNING request_ref",
    [TENANT_X, P("i-m"), P("i-req")],
  )).rows[0]?.request_ref;
  const integrity = (e: unknown): boolean => codeOf(e) === "23000";

  // Membership: DELETE/TRUNCATE rechazados; reescribir campos fijos rechazado; saltarse el aprobador rechazado; ACTIVE no vuelve atras.
  await assert.rejects(admin.query("DELETE FROM platform.tenant_membership WHERE request_ref = $1", [mref]), integrity);
  await assert.rejects(admin.query("TRUNCATE platform.tenant_membership"), integrity);
  await assert.rejects(admin.query("UPDATE platform.tenant_membership SET membership_role = 'TENANT_ADMIN' WHERE request_ref = $1", [mref]), integrity);
  await assert.rejects(admin.query("UPDATE platform.tenant_membership SET status = 'ACTIVE', approved_by_ref = requested_by_ref, approved_at = now() WHERE request_ref = $1", [mref]), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("UPDATE platform.tenant_membership SET status = 'ACTIVE' WHERE request_ref = $1", [mref]), (e) => codeOf(e) === "23514");
  await admin.query("UPDATE platform.tenant_membership SET status = 'ACTIVE', approved_by_ref = $2, approved_at = now() WHERE request_ref = $1", [mref, P("i-appr")]);
  await assert.rejects(admin.query("UPDATE platform.tenant_membership SET status = 'PENDING', approved_by_ref = NULL, approved_at = NULL WHERE request_ref = $1", [mref]), integrity);
  await assert.rejects(admin.query("DELETE FROM platform.platform_role_assignment"), integrity);
  await assert.rejects(admin.query("TRUNCATE platform.platform_role_assignment"), integrity);
  // Forma de las refs: un correo no entra como principal (cero PII).
  await assert.rejects(admin.query("INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, requested_by_ref) VALUES ($1, 'alguien@ejemplo.cl', 'INVITER', $2)", [TENANT_X, P("i-req")]), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, requested_by_ref) VALUES ($1, $2, 'DUENO', $3)", [TENANT_X, P("i-m2"), P("i-req")]), (e) => codeOf(e) === "23514");

  // Nonce: solo attested_at / consumed_at una vez; ni borrar ni truncar; consumed_at exige attested_at; vida acotada.
  await call(plat, A, null, "SELECT platform.issue_action_nonce('APPROVE_ROLE_ASSIGNMENT', ARRAY[$1::text], NULL, 300)", [fixtureUuid("i-req-ref")]);
  const nonce = (await admin.query<{ nonce_hash: string }>("SELECT nonce_hash FROM platform.action_nonce WHERE principal_ref = $1", [A])).rows[0]?.nonce_hash ?? "";
  assert.match(nonce, HEX64);
  await assert.rejects(admin.query("DELETE FROM platform.action_nonce WHERE nonce_hash = $1", [nonce]), integrity);
  await assert.rejects(admin.query("TRUNCATE platform.action_nonce"), integrity);
  await assert.rejects(admin.query("UPDATE platform.action_nonce SET expires_at = expires_at + interval '10 minutes' WHERE nonce_hash = $1", [nonce]), integrity);
  await assert.rejects(admin.query("UPDATE platform.action_nonce SET principal_ref = $2 WHERE nonce_hash = $1", [nonce, P("i-otro")]), integrity);
  await assert.rejects(admin.query("UPDATE platform.action_nonce SET consumed_at = now() WHERE nonce_hash = $1", [nonce]), (e) => codeOf(e) === "23514");
  await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE nonce_hash = $1", [nonce]);
  await assert.rejects(admin.query("UPDATE platform.action_nonce SET attested_at = now() + interval '1 minute' WHERE nonce_hash = $1", [nonce]), integrity);
  await admin.query("UPDATE platform.action_nonce SET consumed_at = now() WHERE nonce_hash = $1", [nonce]);
  await assert.rejects(admin.query("UPDATE platform.action_nonce SET consumed_at = NULL WHERE nonce_hash = $1", [nonce]), integrity);
  await assert.rejects(
    admin.query("INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at) VALUES ($1, 'PLATFORM', NULL, 'APPROVE_ROLE_ASSIGNMENT', $1, $2, now() + interval '2 hours')", [nonce.replace(/^./, "a"), A]),
    (e) => codeOf(e) === "23514",
  );
  await assert.rejects(
    admin.query("INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at) VALUES ($1, 'TENANT', NULL, 'APPROVE_MEMBERSHIP', $1, $2, now() + interval '5 minutes')", [nonce.replace(/^./, "b"), A]),
    (e) => codeOf(e) === "23514",
  );

  // authorization_check: append-only (ni UPDATE, ni DELETE, ni TRUNCATE), reason/decision cerrados y coherentes; sin PII.
  const countBefore = (await admin.query("SELECT 1 FROM platform.authorization_check WHERE principal_ref = $1", [A])).rowCount;
  assert.equal(countBefore, 1, "la emision del nonce deja una fila ISSUE_NONCE");
  await assert.rejects(admin.query("UPDATE platform.authorization_check SET decision = 'DENY', reason_code = 'NO_ROLE' WHERE principal_ref = $1", [A]), integrity);
  await assert.rejects(admin.query("DELETE FROM platform.authorization_check WHERE principal_ref = $1", [A]), integrity);
  await assert.rejects(admin.query("TRUNCATE platform.authorization_check"), integrity);
  await assert.rejects(admin.query("INSERT INTO platform.authorization_check (check_kind, decision, reason_code, policy_version) VALUES ('AUTHORIZE', 'ALLOW', 'NO_ROLE', 'x')"), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.authorization_check (check_kind, decision, reason_code, policy_version) VALUES ('AUTHORIZE', 'DENY', 'OK', 'x')"), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.authorization_check (check_kind, decision, reason_code, policy_version, resource_ref) VALUES ('AUTHORIZE', 'DENY', 'NO_ROLE', 'x', 'a@b.cl')"), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.authorization_check (check_kind, decision, reason_code, policy_version, principal_ref) VALUES ('AUTHORIZE', 'DENY', 'NO_ROLE', 'x', 'persona@correo.cl')"), (e) => codeOf(e) === "23514");
  // Ningun valor almacenado en platform contiene '@' ni parece un RUT.
  for (const table of ["tenant_membership", "platform_role_assignment", "action_nonce", "authorization_check"]) {
    const rows = (await admin.query<{ doc: string }>(`SELECT to_jsonb(t)::text AS doc FROM platform.${table} t`)).rows;
    for (const r of rows) assert.ok(!r.doc.includes("@") && !/\b\d{7,8}-[0-9kK]\b/.test(r.doc), `PII en platform.${table}`);
  }
});

pgTest("TEST-CNS-1357 pg: action_nonce emitido por la DB: solo hash (el nonce en claro no se guarda), TTL 1..3600 s, ligado a (tenant, accion, refs, principal), solo PLATFORM activo desde platform_rw, vence, authorize no consume", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const plat = await ctx.connectAs("platform_rw");
  const A = P("n-pa");
  const NOROLE = P("n-none");
  await seedPlatform(admin, A);
  const issue = async (principal: string | null, action: string, refs: string[] | null, tenant: string | null, ttl: number | null): Promise<string | null> =>
    (await call<{ n: string | null }>(plat, principal, null, "SELECT platform.issue_action_nonce($1, $2::text[], $3::uuid, $4::integer) AS n", [action, refs, tenant, ttl]))[0]?.n ?? null;

  // Emision correcta: 64 hex, solo su hash en la tabla, binding completo, aun no atestado ni consumido.
  const ref = fixtureUuid("n-ref");
  const nonce = await issue(A, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 120);
  assert.match(nonce ?? "", HEX64);
  const stored = (await admin.query<Record<string, unknown>>(
    "SELECT nonce_hash, scope, tenant_id, action, principal_ref, attested_at, consumed_at, expires_at - issued_at AS life FROM platform.action_nonce WHERE principal_ref = $1", [A])).rows;
  assert.equal(stored.length, 1);
  assert.notEqual(stored[0]?.nonce_hash, nonce, "no se guarda el nonce en claro");
  assert.deepEqual({ ...stored[0], nonce_hash: undefined, life: undefined }, { nonce_hash: undefined, scope: "TENANT", tenant_id: TENANT_X, action: "APPROVE_MEMBERSHIP", principal_ref: A, attested_at: null, consumed_at: null, life: undefined });
  assert.equal((await admin.query<{ m: boolean }>("SELECT encode(sha256(convert_to($1, 'UTF8')), 'hex') = $2 AS m", [nonce, stored[0]?.nonce_hash])).rows[0]?.m, true);
  assert.equal(String(JSON.stringify(stored)).includes(nonce ?? "zzz"), false);
  assert.deepEqual((await lastChecks(admin, A))[0], { check_kind: "ISSUE_NONCE", action: "APPROVE_MEMBERSHIP", decision: "ALLOW", reason_code: "OK" });
  // Dos emisiones nunca repiten nonce.
  const again = await issue(A, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 120);
  assert.notEqual(again, nonce);

  // Rechazos (DENY con evidencia, NULL, sin excepcion).
  const denied: Array<[string, () => Promise<string | null>, string]> = [
    ["accion desconocida", () => issue(A, "BORRAR_TODO", [ref], TENANT_X, 60), "UNKNOWN_ACTION"],
    ["ttl 0", () => issue(A, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 0), "INVALID_TTL"],
    ["ttl 3601", () => issue(A, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 3601), "INVALID_TTL"],
    ["ttl nulo", () => issue(A, "APPROVE_MEMBERSHIP", [ref], TENANT_X, null), "INVALID_TTL"],
    ["accion de tenant sin tenant", () => issue(A, "APPROVE_MEMBERSHIP", [ref], null, 60), "TENANT_SCOPE"],
    ["accion de plataforma con tenant", () => issue(A, "APPROVE_ROLE_ASSIGNMENT", [ref], TENANT_X, 60), "TENANT_SCOPE"],
    ["refs vacias", () => issue(A, "APPROVE_MEMBERSHIP", [], TENANT_X, 60), "INVALID_RESOURCE"],
    ["refs con correo", () => issue(A, "APPROVE_MEMBERSHIP", ["alguien@ejemplo.cl"], TENANT_X, 60), "INVALID_RESOURCE"],
    ["refs nulas", () => issue(A, "APPROVE_MEMBERSHIP", null, TENANT_X, 60), "INVALID_RESOURCE"],
    ["sin principal", () => issue(null, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 60), "NO_PRINCIPAL"],
    ["principal sin rol PLATFORM", () => issue(NOROLE, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 60), "NO_ROLE"],
  ];
  for (const [label, run, reason] of denied) {
    const before = (await admin.query("SELECT 1 FROM platform.action_nonce")).rowCount;
    assert.equal(await run(), null, label);
    assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce")).rowCount, before, `${label}: no emite nonce`);
    const reasons = (await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.authorization_check WHERE check_kind = 'ISSUE_NONCE' AND decision = 'DENY' ORDER BY at DESC, check_ref LIMIT 1")).rows;
    assert.equal(reasons[0]?.reason_code, reason, label);
  }
  // Un PLATFORM PENDING no es PLATFORM activo.
  const PEND = P("n-pending");
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'PENDING', $2)", [PEND, A]);
  assert.equal(await issue(PEND, "APPROVE_MEMBERSHIP", [ref], TENANT_X, 60), null);
  assert.equal((await lastChecks(admin, PEND))[0]?.reason_code, "NO_ROLE");

  // authorize(): decide y deja evidencia sin consumir el nonce (dry-run). Atestado el nonce de la solicitud, authorize da ALLOW dos veces.
  // La solicitud no existe: antes de eso, REQUEST_NOT_FOUND.
  assert.equal((await call<{ a: boolean }>(plat, A, TENANT_X, "SELECT platform.authorize('APPROVE_MEMBERSHIP', $1) AS a", [ref]))[0]?.a, false);
  assert.equal((await lastChecks(admin, A))[0]?.reason_code, "REQUEST_NOT_FOUND");
  const reqRef = (await admin.query<{ request_ref: string }>(
    "INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3) RETURNING request_ref",
    [TENANT_X, P("n-subject"), P("n-requester")],
  )).rows[0]?.request_ref ?? "";
  const PB = P("n-pb");
  await seedPlatform(admin, PB);
  assert.match((await issue(PB, "APPROVE_MEMBERSHIP", [reqRef], TENANT_X, 120)) ?? "", HEX64);
  assert.equal((await call<{ a: boolean }>(plat, PB, TENANT_X, "SELECT platform.authorize('APPROVE_MEMBERSHIP', $1) AS a", [reqRef]))[0]?.a, false, "no atestado");
  assert.equal((await lastChecks(admin, PB))[0]?.reason_code, "STEP_UP_MISSING");
  await attest(admin, PB, "APPROVE_MEMBERSHIP");
  for (let i = 0; i < 2; i++) {
    assert.equal((await call<{ a: boolean }>(plat, PB, TENANT_X, "SELECT platform.authorize('APPROVE_MEMBERSHIP', $1) AS a", [reqRef]))[0]?.a, true);
  }
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE principal_ref = $1 AND consumed_at IS NOT NULL", [PB])).rowCount, 0, "authorize no consume el nonce");
  // Sin tenant en la transaccion, una accion de tenant no se decide (TENANT_SCOPE).
  assert.equal((await call<{ a: boolean }>(plat, PB, null, "SELECT platform.authorize('APPROVE_MEMBERSHIP', $1) AS a", [reqRef]))[0]?.a, false);
  assert.equal((await lastChecks(admin, PB))[0]?.reason_code, "TENANT_SCOPE");
  // Otro tenant en la transaccion: la solicitud no existe para el (aislamiento).
  assert.equal((await call<{ a: boolean }>(plat, PB, TENANT_Y, "SELECT platform.authorize('APPROVE_MEMBERSHIP', $1) AS a", [reqRef]))[0]?.a, false);
  assert.equal((await lastChecks(admin, PB))[0]?.reason_code, "REQUEST_NOT_FOUND");
  // El consumo ocurre en la funcion de efecto: la aprobacion usa el nonce y deja de servir.
  assert.equal((await call<{ r: boolean }>(plat, PB, null, "SELECT platform.approve_membership($1::uuid) AS r", [reqRef]))[0]?.r, true);
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE principal_ref = $1 AND consumed_at IS NOT NULL", [PB])).rowCount, 1);

  // Vencimiento: ttl 1 s => tras 1,3 s ya no vale aunque este atestado.
  const PC = P("n-pc");
  await seedPlatform(admin, PC);
  const req2 = (await admin.query<{ request_ref: string }>(
    "INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3) RETURNING request_ref",
    [TENANT_X, P("n-subject2"), P("n-requester")],
  )).rows[0]?.request_ref ?? "";
  assert.match((await issue(PC, "APPROVE_MEMBERSHIP", [req2], TENANT_X, 1)) ?? "", HEX64);
  await attest(admin, PC, "APPROVE_MEMBERSHIP");
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal((await call<{ r: boolean }>(plat, PC, null, "SELECT platform.approve_membership($1::uuid) AS r", [req2]))[0]?.r, false);
  assert.equal((await lastChecks(admin, PC))[0]?.reason_code, "STEP_UP_MISSING");
});
