// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §5.2 pasos 5-7, §6 (la sesion CASE vive solo en platform.platform_session), §10 fila 6d; specs/session.spec.yaml GRD-SE-14 / INV-SE-05 (CA-141, fail-closed); db/migrations/0052-0053.
// SYNTHETIC ONLY. Requiere Postgres real (harness.ts). Reemplazan sobre platform los tests de sesion CASE de web que se retiraron (1174 de e2e-http-pg, 1198/1199/1201 de session-security-event-http).
// TEST-CNS-1713: sesion CASE en platform.platform_session (hash del sid, sin sid en claro ni PII); logout revoca en la base; cookie robada, sid de otro caso/tenant o hash del sid no sirven.
// TEST-CNS-1198: eventos de logout por HTTP (CASE y PLATFORM en cascada) escriben exactamente un evento por sesion; el logout repetido, el sid desconocido, el 404 y el origen ajeno no escriben.
// TEST-CNS-1199: si falla la escritura del evento el logout responde 404 uniforme sin borrar cookies, la sesion sigue viva y la accion no se da por hecha; sin el fallo el logout procede.
// TEST-CNS-1201: session_ref nunca aparece en cookie, cuerpo, URL ni logs y nunca autentica (ni como sid, ni su hash).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Client } from "pg";
import { casePath, seedCaseWorld, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import { pgTest } from "./harness.ts";

const sha = (x: string): string => createHash("sha256").update(x, "utf8").digest("hex");
const CASE_LOGOUT = "/platform/case-session/logout";
const PLATFORM_LOGOUT = "/platform/logout";

const eventsOf = async (admin: Client, sessionRef: string): Promise<Array<{ event_type: string; reason_code: string | null }>> =>
  (await admin.query<{ event_type: string; reason_code: string | null }>("SELECT event_type, reason_code FROM platform.session_event WHERE session_ref = $1 ORDER BY at, event_ref", [sessionRef])).rows;
const revoked = async (admin: Client, sessionRef: string): Promise<boolean> =>
  (await admin.query<{ r: boolean }>("SELECT revoked_at IS NOT NULL AS r FROM platform.platform_session WHERE session_ref = $1", [sessionRef])).rows[0]!.r;

pgTest("TEST-CNS-1713 pg platform HTTP: la sesion CASE vive en platform.platform_session (solo hash del sid); logout revoca en la base; cookie robada, sid de otro caso o hash del sid no sirven", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1713");
  const other = await seedCaseWorld(ctx, "1713x");
  const http = await startPlatformHttp(ctx);
  try {
    const row = (await admin.query<{ session_kind: string; sid_hash: string; case_ref: string; tenant_id: string; principal_ref: string }>(
      "SELECT session_kind, sid_hash, case_ref, tenant_id, principal_ref FROM platform.platform_session WHERE session_ref = $1", [w.op1.caseSession.sessionRef])).rows[0]!;
    assert.deepEqual(row, { session_kind: "CASE", sid_hash: sha(w.op1.caseSession.sid), case_ref: w.caseRef, tenant_id: w.tenantId, principal_ref: w.op1.principal });
    // Ni el sid en claro ni PII en ninguna fila de sesion (ni eventos).
    assert.equal((await admin.query("SELECT 1 FROM platform.platform_session s WHERE s::text LIKE '%' || $1 || '%'", [w.op1.caseSession.sid])).rowCount, 0);
    assert.equal((await admin.query("SELECT 1 FROM platform.session_event e WHERE e::text LIKE '%' || $1 || '%'", [w.op1.caseSession.sid])).rowCount, 0);
    // La app web no tiene la tabla de sesiones CASE de app (retirada): app.case_session sin filas de este caso.
    assert.equal((await admin.query("SELECT 1 FROM app.case_session WHERE case_ref = $1", [w.caseRef])).rowCount, 0);

    const close = casePath(w.caseRef).close;
    // Cookie robada (de otro operador/caso/tenant) sobre este caso, el hash del sid y un sid inventado: 404.
    for (const sid of [other.op1.caseSession.sid, sha(w.op1.caseSession.sid), "0".repeat(64)]) assert.equal((await http.post(close, sid, { outcome: "OTRO" })).status, 404);
    // Con el sid correcto el cuerpo invalido llega al dominio (409), prueba de que la sesion autentica.
    assert.equal((await http.post(close, w.op1.caseSession.sid, { outcome: "OTRO" })).status, 409);

    const out = await http.post(CASE_LOGOUT, w.op1.caseSession.sid, {});
    assert.equal(out.status, 200);
    assert.ok(out.setCookie.some((c) => c.startsWith("__Host-cns-case=;") && c.includes("Max-Age=0")), "cookie CASE borrada");
    assert.equal(await revoked(admin, w.op1.caseSession.sessionRef), true);
    assert.equal((await http.post(close, w.op1.caseSession.sid, { outcome: "OTRO" })).status, 404, "tras el logout el sid ya no sirve");
    assert.equal(await revoked(admin, w.op2.caseSession.sessionRef), false, "otra sesion CASE del mismo caso sigue viva");
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1198 pg platform HTTP: logout CASE/PLATFORM escribe exactamente un evento por sesion (la PLATFORM arrastra a sus CASE); el logout repetido, el sid desconocido, el 404 y el origen ajeno no escriben", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1198");
  const http = await startPlatformHttp(ctx);
  try {
    const sid1 = w.op1.caseSession;
    // Antes: sin eventos de logout de la sesion.
    assert.deepEqual((await eventsOf(admin, sid1.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), []);
    // 404 y origen ajeno: nada.
    assert.equal((await http.post(CASE_LOGOUT, sid1.sid, {}, { headers: { origin: "https://evil.example" } })).status, 404);
    assert.equal((await http.post(CASE_LOGOUT, "no-es-un-sid", {})).status, 404);
    assert.equal((await http.post(CASE_LOGOUT, null, {})).status, 404);
    assert.deepEqual((await eventsOf(admin, sid1.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), []);
    // Un sid con forma valida pero desconocido: 200 idempotente, sin evento ni efecto.
    const before = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM platform.session_event")).rows[0]!.n;
    assert.equal((await http.post(CASE_LOGOUT, "f".repeat(64), {})).status, 200);
    assert.equal((await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM platform.session_event")).rows[0]!.n, before);
    // Logout CASE: exactamente un evento con el session_ref de la fila, el principal y el caso.
    assert.equal((await http.post(CASE_LOGOUT, sid1.sid, {})).status, 200);
    assert.deepEqual((await eventsOf(admin, sid1.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), [{ event_type: "CASE_LOGOUT", reason_code: "USER_LOGOUT" }]);
    const full = (await admin.query("SELECT principal_ref, case_ref, session_kind FROM platform.session_event WHERE session_ref = $1 AND event_type = 'CASE_LOGOUT'", [sid1.sessionRef])).rows[0];
    assert.deepEqual(full, { principal_ref: w.op1.principal, case_ref: w.caseRef, session_kind: "CASE" });
    // Repetido: idempotente, sin segundo evento.
    assert.equal((await http.post(CASE_LOGOUT, sid1.sid, {})).status, 200);
    assert.equal((await eventsOf(admin, sid1.sessionRef)).filter((e) => e.event_type === "CASE_LOGOUT").length, 1);
    // Logout PLATFORM de op2: un PLATFORM_LOGOUT y, en cascada, un CASE_LOGOUT PARENT_REVOKED de su sesion CASE.
    assert.equal((await http.post(PLATFORM_LOGOUT, w.op2.platform.sid, {}, { kind: "PLATFORM" })).status, 200);
    assert.deepEqual((await eventsOf(admin, w.op2.platform.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), [{ event_type: "PLATFORM_LOGOUT", reason_code: "USER_LOGOUT" }]);
    assert.deepEqual((await eventsOf(admin, w.op2.caseSession.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), [{ event_type: "CASE_LOGOUT", reason_code: "PARENT_REVOKED" }]);
    assert.equal(await revoked(admin, w.op2.caseSession.sessionRef), true);
    assert.equal(await revoked(admin, w.op1.platform.sessionRef), false, "la sesion PLATFORM de op1 no se toca");
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1199 pg platform HTTP: fallo del evento = logout 404 uniforme sin Set-Cookie ni borrado de cookies, la sesion sigue viva y no hay evento parcial; sin el fallo el logout procede", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1199");
  const http = await startPlatformHttp(ctx);
  const logs: string[] = [];
  const realError = console.error;
  console.error = (...a: unknown[]) => { logs.push(a.join(" ")); };
  try {
    await admin.query("CREATE SCHEMA IF NOT EXISTS qa_inject");
    await admin.query("GRANT USAGE ON SCHEMA qa_inject TO PUBLIC");
    await admin.query(`CREATE OR REPLACE FUNCTION qa_inject.fail_event() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'evento inyectado' USING ERRCODE = 'XX000'; END $f$`);
    await admin.query("GRANT EXECUTE ON FUNCTION qa_inject.fail_event() TO PUBLIC");
    await admin.query(`CREATE TRIGGER f1199_trg BEFORE INSERT ON platform.session_event FOR EACH ROW WHEN (NEW.principal_ref = '${w.op1.principal}' AND NEW.event_type LIKE '%LOGOUT') EXECUTE FUNCTION qa_inject.fail_event()`);
    const res = await http.post(CASE_LOGOUT, w.op1.caseSession.sid, {});
    assert.equal(res.status, 404, res.body);
    assert.deepEqual(res.setCookie, [], "sin borrado de cookies: el navegador no cree que cerro sesion");
    assert.ok(!/logged_out/.test(res.body), "sin acuse de exito");
    assert.equal(await revoked(admin, w.op1.caseSession.sessionRef), false, "la sesion sigue viva");
    assert.deepEqual((await eventsOf(admin, w.op1.caseSession.sessionRef)).filter((e) => e.event_type.endsWith("LOGOUT")), []);
    assert.equal((await http.post(casePath(w.caseRef).close, w.op1.caseSession.sid, { outcome: "OTRO" })).status, 409, "la sesion sigue autenticando");
    assert.ok(logs.every((l) => !l.includes(w.op1.caseSession.sid) && !l.includes(w.op1.principal)), "ningun log lleva sid ni principal");
    await admin.query("DROP TRIGGER f1199_trg ON platform.session_event");
    assert.equal((await http.post(CASE_LOGOUT, w.op1.caseSession.sid, {})).status, 200);
    assert.equal(await revoked(admin, w.op1.caseSession.sessionRef), true);
    assert.equal((await eventsOf(admin, w.op1.caseSession.sessionRef)).filter((e) => e.event_type === "CASE_LOGOUT").length, 1);
  } finally {
    console.error = realError;
    await http.close();
  }
});

pgTest("TEST-CNS-1201 pg platform HTTP: session_ref nunca aparece en cookie, cuerpo, URL ni logs y nunca autentica (ni como sid ni su hash)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1201");
  const http = await startPlatformHttp(ctx);
  const logs: string[] = [];
  const realError = console.error;
  const realLog = console.log;
  console.error = (...a: unknown[]) => { logs.push(a.join(" ")); };
  console.log = (...a: unknown[]) => { logs.push(a.join(" ")); };
  try {
    const ref = w.op1.caseSession.sessionRef;
    const surfaces: string[] = [];
    const record = (r: { body: string; setCookie: string[] }): void => { surfaces.push(r.body, ...r.setCookie); };
    const close = casePath(w.caseRef).close;
    // Como sid (en forma de uuid y rellenado a 64 hex), como hash y como parte del cuerpo/URL: nunca autentica.
    for (const sid of [ref, ref.replaceAll("-", "").repeat(2), sha(ref)]) {
      const r = await http.post(close, sid, { outcome: "RESOLVED" });
      assert.equal(r.status, 404, `session_ref como sid (${sid.length} chars)`);
      record(r);
    }
    record(await http.post(close, w.op1.caseSession.sid, { outcome: "OTRO", sessionRef: ref }));
    record(await http.post(`/platform/rights-cases/${w.caseRef}/confirmation/cosign`, w.op2.caseSession.sid, { sessionRef: ref }));
    record(await http.post(CASE_LOGOUT, w.op1.caseSession.sid, {}));
    record(await http.post(PLATFORM_LOGOUT, w.op2.platform.sid, {}, { kind: "PLATFORM" }));
    for (const s of surfaces) assert.ok(!s.includes(ref) && !s.includes(ref.replaceAll("-", "")), "session_ref ausente de cuerpos y Set-Cookie");
    assert.ok(logs.every((l) => !l.includes(ref) && !l.includes(w.op1.caseSession.sid)), "session_ref y sid ausentes de los logs");
    // El session_ref solo existe en la fila y en el evento (nunca como credencial): la sesion sigue siendo la unica via.
    assert.equal((await admin.query("SELECT 1 FROM platform.platform_session WHERE sid_hash = $1 OR sid_hash = $2", [ref, sha(ref)])).rowCount, 0);
  } finally {
    console.error = realError;
    console.log = realLog;
    await http.close();
  }
});
