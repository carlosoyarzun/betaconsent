// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §2 (filas web/app_rw "No puede", platform_rw, rights_operator, worker), §4.2.a (EXECUTE de apply_revocation solo worker), §4.2.d (funciones de operador fuera de
// app_rw), §10 fila 6d; db/migrations/0068-0071; INV-DBR-06; F-A10-26 (cierre por privilegio), F-A10-28. SYNTHETIC ONLY. Requiere Postgres real (harness.ts).
// TEST-CNS-1701: app_rw (web) NO tiene EXECUTE de ninguna funcion de operador, de SYSTEM (R4 / alerta de caso / apply_revocation / current_sequence), de siembra local ni de `platform.*`, ni acceso alguno a
// app.case_session; las llamadas reales con app_rw fallan con 42501; el EXECUTE de cada funcion queda exactamente en su rol (rights_operator, platform_rw, worker).
// Este archivo revoca las siembras locales a app_rw en SU base (el harness las concede a los tests de contrato), por eso vive aparte.

import assert from "node:assert/strict";
import { pgTest, revokeLocalSeedFromAppRw } from "./harness.ts";

const OPERATOR_FUNCTIONS = [
  "case_state.propose_case_verification(text, text, text, integer, integer)",
  "case_state.approve_case_verification(text, text, integer, integer)",
  "case_state.withdraw_case_verification_proposal(text, text, integer, integer)",
  "case_state.record_case_confirmation(text)",
  "case_state.cosign_case_confirmation(text)",
  "case_state.close_case(text, text)",
  "case_state.alert_apply_exhausted(text)",
] as const;
const SYSTEM_FUNCTIONS = [
  "case_state.apply_revocation(text, integer)",
  "case_state.r4_apply(text, integer)",
  "case_state.current_sequence(text)",
  "case_state.seed_local_revocation(uuid, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text)",
  "case_state.seed_local_rights_case(uuid, text, text, text, text, text, text)",
] as const;
const PLATFORM_ACTOR_FUNCTIONS = [
  "platform.require_case_actor(text, text)",
  "platform.require_platform_actor(text, text)",
  "platform.record_rh2_approval(text, text, text, text, text)",
  "platform.consume_step_up(text, text, text, integer, integer)",
  "platform.validate_session(text, text)",
  "platform.revoke_session(text, text)",
] as const;
const FORBIDDEN_NAME = /propose_case|approve_case|withdraw_case|record_case|cosign_case|close_case|alert_apply|apply_revocation|r4_apply|seed_local|current_sequence/;

pgTest("TEST-CNS-1701 pg: app_rw sin EXECUTE de funciones de operador/SYSTEM/siembra/platform ni acceso a app.case_session (42501 en llamadas reales); EXECUTE exacto en rights_operator, platform_rw y worker", async (ctx) => {
  await revokeLocalSeedFromAppRw(ctx);
  const admin = await ctx.fixtureAdmin();
  const can = async (role: string, fn: string): Promise<boolean> => (await admin.query<{ ok: boolean }>("SELECT has_function_privilege($1, $2::regprocedure, 'EXECUTE') AS ok", [role, fn])).rows[0]!.ok;

  for (const fn of [...OPERATOR_FUNCTIONS, ...SYSTEM_FUNCTIONS, ...PLATFORM_ACTOR_FUNCTIONS]) assert.equal(await can("app_rw", fn), false, `app_rw no ejecuta ${fn}`);
  // Barrido por catalogo: ninguna funcion de case_state con nombre de operador/SYSTEM/siembra es ejecutable por app_rw, y app_rw no ejecuta ninguna funcion del esquema platform fuera de Membership TENANT.
  const all = (await admin.query<{ schema: string; name: string; sig: string; ok: boolean }>(
    `SELECT n.nspname AS schema, p.proname AS name, p.oid::regprocedure::text AS sig, has_function_privilege('app_rw', p.oid, 'EXECUTE') AS ok
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('case_state', 'platform')`,
  )).rows;
  assert.ok(all.length > 30, "el barrido ve las funciones");
  assert.deepEqual(all.filter((r) => r.schema === "case_state" && r.ok && FORBIDDEN_NAME.test(r.name)).map((r) => r.sig), []);
  // (la unica superficie de platform que web conserva es la de Membership TENANT, que no es de caso ni de sesion; fuera de ella, nada.)
  assert.deepEqual(all.filter((r) => r.schema === "platform" && r.ok && !/membership/.test(r.name)).map((r) => r.sig), [], "app_rw no ejecuta nada de platform salvo Membership TENANT");

  // Llamadas reales como app_rw: permiso denegado (42501) antes de evaluar nada.
  const app = await ctx.connectAs("app_rw");
  for (const sql of [
    "SELECT case_state.propose_case_verification('x', 'x', 'x', 1, 60)",
    "SELECT case_state.approve_case_verification('x', 'x', 1, 60)",
    "SELECT case_state.withdraw_case_verification_proposal('x', 'x', 1, 60)",
    "SELECT case_state.record_case_confirmation('x')",
    "SELECT case_state.cosign_case_confirmation('x')",
    "SELECT case_state.close_case('x', 'RESOLVED')",
    "SELECT case_state.alert_apply_exhausted('x')",
    "SELECT case_state.apply_revocation('x', 1)",
    "SELECT platform.require_case_actor('x', 'RIGHTS_OPERATOR')",
    "SELECT platform.validate_session('x', 'CASE')",
    "SELECT * FROM app.case_session",
    "INSERT INTO app.case_session (tenant_id) VALUES (gen_random_uuid())",
    "UPDATE app.case_session SET tenant_id = tenant_id",
    "DELETE FROM app.case_session",
    "SELECT * FROM platform.platform_session",
    "SELECT * FROM platform.case_verification",
  ]) {
    await assert.rejects(() => app.query(sql), (e: unknown) => (e as { code?: string }).code === "42501", sql);
  }
  // app.case_session: ningun privilegio de tabla ni de columna, ninguna policy para app_rw.
  const t = (await admin.query<{ tbl: boolean; col: boolean }>(
    `SELECT has_table_privilege('app_rw', 'app.case_session', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS tbl, has_any_column_privilege('app_rw', 'app.case_session', 'SELECT,INSERT,UPDATE,REFERENCES') AS col`,
  )).rows[0]!;
  assert.deepEqual(t, { tbl: false, col: false });
  assert.equal((await admin.query("SELECT 1 FROM pg_policy p WHERE p.polrelid = 'app.case_session'::regclass AND (SELECT oid FROM pg_roles WHERE rolname = 'app_rw') = ANY (p.polroles)")).rowCount, 0);
  // La policy de eventos de seguridad de app_rw ya no admite CASE_LOGIN/CASE_LOGOUT ni rotacion CASE.
  const expr = (await admin.query<{ e: string }>("SELECT pg_get_expr(polwithcheck, polrelid) AS e FROM pg_policy WHERE polrelid = 'ops.security_event'::regclass AND polname = 'security_event_app_rw_insert'")).rows[0]!.e;
  assert.ok(!expr.includes("CASE_LOGIN") && !expr.includes("CASE_LOGOUT") && expr.includes("STAFF_LOGIN") && expr.includes("CASE"), expr);

  // EXECUTE exacto en el rol que corresponde.
  for (const fn of ["case_state.propose_case_verification(text, text, text, integer, integer)", "case_state.withdraw_case_verification_proposal(text, text, integer, integer)", "case_state.record_case_confirmation(text)",
    "case_state.cosign_case_confirmation(text)", "case_state.close_case(text, text)", "case_state.alert_apply_exhausted(text)"]) {
    assert.equal(await can("rights_operator", fn), true, `rights_operator ejecuta ${fn}`);
    assert.equal(await can("platform_rw", fn), false, `platform_rw no ejecuta directo ${fn} (solo via SET LOCAL ROLE rights_operator)`);
    assert.equal(await can("worker", fn), false);
  }
  assert.equal(await can("platform_rw", "case_state.approve_case_verification(text, text, integer, integer)"), true, "el aprobador RH2 corre con sesion PLATFORM (platform_rw)");
  assert.equal(await can("rights_operator", "case_state.approve_case_verification(text, text, integer, integer)"), false);
  assert.equal(await can("worker", "case_state.apply_revocation(text, integer)"), true, "solo el worker (respaldo) ejecuta apply_revocation");
  assert.equal(await can("platform_rw", "case_state.apply_revocation(text, integer)"), false);
  for (const role of ["app_rw", "platform_rw", "worker", "rights_operator", "integrity_verifier", "integrity_reconciler"]) assert.equal(await can(role, "case_state.r4_apply(text, integer)"), false, `${role} no ejecuta r4_apply (interna)`);
});
