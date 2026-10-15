// Gobierna: ADR-010 rev. 5 §5.1/§5.2/§5.4 (PR-6b), decisiones G-5 (reautenticacion), G-6 (P-48, P-51, P-53), G-7 (aserciones LOGIN de 5 min desde auth_time, un solo uso, ligada a operador y operacion),
// G-8 (state verificado en la base); FINDINGs F-PR6-01/02/15/16/17/18/26/27/31; db/migrations/0050 y 0051.
// TEST-CNS-1500: begin/complete/exchange_status: state de un solo uso, ajeno/vencido/malformado no encola, secretos por estado, P-53 y P-51.
// TEST-CNS-1501: record_login_assertion: la base resuelve el principal (no lo devuelve), sin sub_hmac persistido, NO_MAPPING/ROLE_INACTIVE/auth_time (G-5)/NOT_CONFIGURED, vida desde auth_time (P-52).
// TEST-CNS-1502: LOGIN_CASE: mismo principal que oidc_exchange.principal_ref (rechazo + evento), target_ref_hash; consume_login_assertion (state, kind, operacion, un solo uso, vencimiento).
// TEST-CNS-1503: P-48 cuenta solo los fallos del principal resuelto (los ATTESTED no cuentan), rechazo temporal con evento sin IP.
// TEST-CNS-1504: privilegios: ACL exacta, sin acceso de tabla, consume_login_assertion interna, enqueue_oidc_exchange retirada, principal_identity versionada (F-PR6-16).
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos. Los tests de un archivo comparten base: todo se filtra por refs propias.

import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const P = (label: string): string => fixtureUuid(`pr6b-principal-${label}`);
const SEED_REQ = P("seed-requester");
const SEED_APR = P("seed-approver");
const PKCE = "B".repeat(64);
const NOT_LIMITED = { max: 1000, window: 3600 };

async function call<T = Record<string, unknown>>(client: Client, principal: string | null, sql: string, params: unknown[] = []): Promise<T[]> {
  await client.query("BEGIN");
  try {
    if (principal !== null) await client.query("SELECT set_config('app.principal_ref', $1, true)", [principal]);
    const r = await client.query(sql, params);
    await client.query("COMMIT");
    return r.rows as T[];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function seedOperator(admin: Client, principal: string, role = "PLATFORM", version = 1): Promise<string> {
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, $2, 'PENDING', $3)", [principal, role, SEED_REQ]);
  await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $3, approved_at = now() WHERE principal_ref = $1 AND platform_role = $2", [principal, role, SEED_APR]);
  const subHmac = sha(`sub-${principal}-${version}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, $3)", [principal, subHmac, version]);
  return subHmac;
}

interface Flow { ref: string; state: string; stateHash: string; binding: string; target: string | null }

async function begin(platform: Client, kind: string, principal: string | null, opts: { target?: string | null; maxAwaiting?: number | null; ttl?: number; p51?: { max: number; window: number } } = {}): Promise<Flow | null> {
  const state = randomBytes(24).toString("base64url");
  const binding = sha(randomUUID());
  const target = opts.target ?? null;
  const p51 = opts.p51 ?? NOT_LIMITED;
  const ref = (await call<{ r: string | null }>(platform, principal, "SELECT platform.begin_oidc_authorization($1, $2, $3, $4, $5, $6, $7, $8, $9) AS r", [
    kind, sha(state), binding, PKCE, target, opts.ttl ?? 300, opts.maxAwaiting ?? null, kind === "STEP_UP" ? p51.max : null, kind === "STEP_UP" ? p51.window : null,
  ]))[0]?.r;
  return typeof ref === "string" ? { ref, state, stateHash: sha(state), binding, target } : null;
}

const complete = async (platform: Client, state: string, code = `code-${randomUUID()}`): Promise<string | null> =>
  (await call<{ r: string | null }>(platform, null, "SELECT platform.complete_oidc_callback($1, $2) AS r", [state, code]))[0]?.r ?? null;

/** Toma las solicitudes pendientes de toda la base y devuelve solo las propias (la cola es global). */
async function claimOwn(verifier: Client, refs: string[]): Promise<Array<{ o_exchange_ref: string; o_kind: string; o_principal_ref: string | null }>> {
  const own: Array<{ o_exchange_ref: string; o_kind: string; o_principal_ref: string | null }> = [];
  for (let i = 0; i < 200; i++) {
    const rows = await call<{ o_exchange_ref: string; o_kind: string; o_principal_ref: string | null }>(verifier, null, "SELECT o_exchange_ref, o_kind, o_principal_ref FROM platform.claim_oidc_exchange(60)");
    if (rows.length === 0) break;
    own.push(...rows.filter((r) => refs.includes(r.o_exchange_ref)));
  }
  return own;
}

interface Rec { sub: string; version?: number; authTime: Date | string; max?: number | null; window?: number | null; life?: number | null }
async function recordLogin(verifier: Client, ref: string, r: Rec): Promise<boolean | undefined> {
  return (await call<{ ok: boolean }>(verifier, null, "SELECT platform.record_login_assertion($1::uuid, 'ATTESTED', NULL, $2, $3::smallint, $4, $5::timestamptz, $6, $7::text[], $8, $9, $10) AS ok", [
    ref, r.sub, r.version ?? 1, sha(`token-${ref}`), typeof r.authTime === "string" ? r.authTime : r.authTime.toISOString(), "urn:synthetic:test-mfa", ["pwd"],
    r.max === undefined ? 5 : r.max, r.window === undefined ? 900 : r.window, r.life === undefined ? 300 : r.life,
  ]))[0]?.ok;
}

/** Camino completo hasta PENDING + claim del propio flujo (el lease es de 60 s). */
async function toClaimed(platform: Client, verifier: Client, flow: Flow): Promise<void> {
  assert.equal(await complete(platform, flow.state), flow.ref);
  assert.equal((await claimOwn(verifier, [flow.ref])).length, 1, "el verifier toma el flujo");
}

const consume = async (admin: Client, flow: Flow, state: string, kind: string, target: string | null): Promise<string | null> =>
  (await admin.query<{ p: string | null }>("SELECT platform.consume_login_assertion($1::uuid, $2, $3, $4) AS p", [flow.ref, state, kind, target])).rows[0]?.p ?? null;

const lastEvents = async (admin: Client, principal: string): Promise<Array<Record<string, unknown>>> =>
  (await admin.query("SELECT event_type, reason_code, kind, limit_kind, window_seconds, peer_principal_ref FROM platform.session_event WHERE principal_ref = $1 ORDER BY at, event_ref", [principal])).rows;

pgTest("TEST-CNS-1500 pg: begin/complete: state de un solo uso; ajeno, malformado, reusado o vencido no encola; secretos por estado; status exige (ref, state); P-53 y P-51", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const app = await ctx.connectAs("app_rw");
  const A = P("t1500-a");
  await seedOperator(admin, A, "RIGHTS_OPERATOR");

  // LOGIN_PLATFORM nace sin principal, AWAITING_CALLBACK, con PKCE y sin code, y el state solo existe como hash.
  const f = (await begin(platform, "LOGIN_PLATFORM", null))!;
  assert.ok(f !== null);
  const row = (await admin.query("SELECT kind, status, principal_ref, target_ref_hash, code IS NULL AS no_code, pkce_verifier IS NOT NULL AS has_pkce, state_hash FROM platform.oidc_exchange WHERE exchange_ref = $1", [f.ref])).rows[0];
  assert.deepEqual(row, { kind: "LOGIN_PLATFORM", status: "AWAITING_CALLBACK", principal_ref: null, target_ref_hash: null, no_code: true, has_pkce: true, state_hash: f.stateHash });
  assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange x WHERE strpos(x::text, $1) > 0", [f.state])).rowCount, 0, "el state en claro no se persiste");

  // status: sin state correcto no se revela nada; con el correcto, el estado.
  const status = async (ref: string, state: string): Promise<string | null> => (await call<{ s: string | null }>(platform, null, "SELECT platform.exchange_status($1::uuid, $2) AS s", [ref, state]))[0]?.s ?? null;
  assert.equal(await status(f.ref, f.state), "AWAITING_CALLBACK");
  assert.equal(await status(f.ref, randomBytes(24).toString("base64url")), null);
  assert.equal(await status(f.ref, "corto"), null);

  // complete: state ajeno / malformado / code invalido => NULL y la fila sigue AWAITING_CALLBACK.
  assert.equal(await complete(platform, randomBytes(24).toString("base64url")), null);
  assert.equal(await complete(platform, "x"), null);
  assert.equal(await complete(platform, f.state, "code con espacio"), null);
  assert.equal((await admin.query("SELECT status FROM platform.oidc_exchange WHERE exchange_ref = $1", [f.ref])).rows[0]?.status, "AWAITING_CALLBACK");
  // state correcto: PENDING con code; el state NO se puede reusar.
  assert.equal(await complete(platform, f.state), f.ref);
  assert.equal((await admin.query("SELECT status, code IS NOT NULL AS has_code FROM platform.oidc_exchange WHERE exchange_ref = $1", [f.ref])).rows[0]?.status, "PENDING");
  assert.equal(await complete(platform, f.state, "otro-code"), null, "state reusado");
  assert.equal(await status(f.ref, f.state), "PENDING");

  // Vencido: no completa.
  const exp = (await begin(platform, "LOGIN_PLATFORM", null, { ttl: 1 }))!;
  await new Promise((r) => setTimeout(r, 1200));
  assert.equal(await complete(platform, exp.state), null, "vencido");
  assert.equal(await status(exp.ref, exp.state), null, "vencido no se informa");

  // Reglas de principal por kind: LOGIN_PLATFORM no admite principal; LOGIN_CASE y STEP_UP lo exigen (con rol ACTIVE); target solo en LOGIN_CASE.
  assert.equal(await begin(platform, "LOGIN_PLATFORM", A), null);
  assert.equal(await begin(platform, "LOGIN_CASE", null, { target: sha("caso") }), null);
  assert.equal(await begin(platform, "LOGIN_CASE", P("sin-rol"), { target: sha("caso") }), null);
  assert.equal(await begin(platform, "LOGIN_CASE", A, { target: null }), null, "LOGIN_CASE exige target_ref_hash");
  assert.ok(await begin(platform, "LOGIN_CASE", A, { target: sha("caso") }));
  assert.equal(await begin(platform, "LOGIN_PLATFORM", null, { target: sha("x") }), null, "target solo en LOGIN_CASE");
  assert.equal(await begin(platform, "NO_EXISTE", null), null);

  // P-53: tope global de AWAITING_CALLBACK vigentes; excedido => rechazo con evento (sin principal ni IP).
  const awaiting = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.oidc_exchange WHERE status = 'AWAITING_CALLBACK' AND expires_at > now()")).rows[0]!.n);
  const before = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE limit_kind = 'P-53'")).rows[0]!.n);
  assert.equal(await begin(platform, "LOGIN_PLATFORM", null, { maxAwaiting: awaiting }), null);
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE limit_kind = 'P-53'")).rows[0]!.n), before + 1);
  assert.ok(await begin(platform, "LOGIN_PLATFORM", null, { maxAwaiting: awaiting + 1 }));

  // P-51: 2 inicios de STEP_UP por operador por ventana; el tercero se rechaza con evento. Sin configuracion valida, rechazo.
  const B = P("t1500-b");
  await seedOperator(admin, B);
  const issue = async (): Promise<string> => (await call<{ n: string }>(platform, B, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [`${P(`tgt-${randomUUID()}`)}:CONTEXT_OWNER`]))[0]!.n;
  const stepUp = async (p51: { max: number; window: number } | null): Promise<string | null> => {
    const nonce = await issue();
    const state = randomBytes(24).toString("base64url");
    const r = (await call<{ r: string | null }>(platform, B, "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, 300, NULL, $4, $5) AS r", [sha(state), sha(nonce), PKCE, p51?.max ?? null, p51?.window ?? null]))[0]?.r;
    return r ?? null;
  };
  assert.equal(await stepUp(null), null, "P-51 sin configuracion: fail-closed");
  assert.ok(await stepUp({ max: 2, window: 600 }));
  assert.ok(await stepUp({ max: 2, window: 600 }));
  assert.equal(await stepUp({ max: 2, window: 600 }), null);
  assert.deepEqual((await lastEvents(admin, B)).filter((e) => e.event_type === "LIMIT_EXCEEDED"), [{ event_type: "LIMIT_EXCEEDED", reason_code: null, kind: "STEP_UP", limit_kind: "P-51", window_seconds: 600, peer_principal_ref: null }]);

  // app_rw no puede iniciar flujos ni completar.
  await assert.rejects(app.query("SELECT platform.begin_oidc_authorization('LOGIN_PLATFORM', $1, $2, $3, NULL, 60, NULL, NULL, NULL)", [sha("s"), sha("n"), PKCE]), (e) => codeOf(e) === "42501");
  await assert.rejects(app.query("SELECT platform.complete_oidc_callback($1, 'c')", [randomBytes(24).toString("base64url")]), (e) => codeOf(e) === "42501");
});

pgTest("TEST-CNS-1501 pg: record_login_assertion: la base resuelve el principal y no lo devuelve; sin sub_hmac persistido; NO_MAPPING, rol inactivo, auth_time (G-5), NOT_CONFIGURED; vida 5 min desde auth_time (P-52)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("t1501-a");
  const subA = await seedOperator(admin, A);

  // Camino feliz: ATTESTED; la funcion devuelve boolean, no el principal; la fila de aserciones lleva el principal resuelto por la base.
  const f1 = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, f1);
  const created = (await admin.query<{ t: string }>("SELECT created_at::text AS t FROM platform.oidc_exchange WHERE exchange_ref = $1", [f1.ref])).rows[0]!.t;
  const authTime = await admin.query<{ t: string }>("SELECT (created_at + interval '10 seconds')::text AS t FROM platform.oidc_exchange WHERE exchange_ref = $1", [f1.ref]);
  void created;
  assert.equal(await recordLogin(verifier, f1.ref, { sub: subA, authTime: authTime.rows[0]!.t }), true);
  const la = (await admin.query("SELECT decision, reason_code, principal_ref, kind, state_hash, target_ref_hash, consumed_at, (expires_at = auth_time + interval '300 seconds') AS life_from_auth_time FROM platform.login_assertion WHERE exchange_ref = $1", [f1.ref])).rows[0];
  assert.deepEqual(la, { decision: "ATTESTED", reason_code: null, principal_ref: A, kind: "LOGIN_PLATFORM", state_hash: f1.stateHash, target_ref_hash: null, consumed_at: null, life_from_auth_time: true });
  assert.deepEqual((await admin.query("SELECT status, code, pkce_verifier FROM platform.oidc_exchange WHERE exchange_ref = $1", [f1.ref])).rows, [{ status: "ATTESTED", code: null, pkce_verifier: null }]);
  // El principal solo puede salir de la base por la aserción: la funcion devuelve boolean.
  assert.equal((await verifier.query("SELECT pg_typeof(platform.record_login_assertion('00000000-0000-4000-8000-000000000000'::uuid, 'REJECTED', 'INVALID_CLAIMS', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) AS t")).rows[0]?.t, "boolean");

  // Sin mapeo (sub desconocido): REJECTED NO_MAPPING; ni el sub_hmac ni ningun principal se persisten; no se crea principal (sin JIT).
  const unknownSub = sha(`sub-desconocido-${randomUUID()}`);
  const f2 = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, f2);
  assert.equal(await recordLogin(verifier, f2.ref, { sub: unknownSub, authTime: new Date() }), false);
  assert.deepEqual((await admin.query("SELECT decision, reason_code, principal_ref FROM platform.login_assertion WHERE exchange_ref = $1", [f2.ref])).rows, [{ decision: "REJECTED", reason_code: "NO_MAPPING", principal_ref: null }]);
  for (const t of ["login_assertion", "session_event", "oidc_exchange", "grant_assertion", "authorization_check", "principal_identity"]) {
    assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [unknownSub])).rowCount, 0, `${t} no contiene el sub_hmac rechazado`);
  }
  assert.equal((await admin.query("SELECT 1 FROM platform.principal_identity WHERE sub_hmac = $1", [unknownSub])).rowCount, 0);
  // Una key_version no registrada tambien falla cerrado.
  const f2b = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, f2b);
  assert.equal(await recordLogin(verifier, f2b.ref, { sub: subA, version: 2, authTime: new Date() }), false);
  assert.equal((await admin.query("SELECT reason_code FROM platform.login_assertion WHERE exchange_ref = $1", [f2b.ref])).rows[0]?.reason_code, "NO_MAPPING");

  // Rol inactivo (identidad sin asignacion ACTIVE): REJECTED ROLE_INACTIVE con evento y principal.
  const Z = P("t1501-z");
  const subZ = sha(`sub-${Z}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [Z, subZ]);
  const f3 = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, f3);
  assert.equal(await recordLogin(verifier, f3.ref, { sub: subZ, authTime: new Date() }), false);
  assert.deepEqual((await admin.query("SELECT reason_code, principal_ref FROM platform.login_assertion WHERE exchange_ref = $1", [f3.ref])).rows, [{ reason_code: "ROLE_INACTIVE", principal_ref: Z }]);
  assert.deepEqual(await lastEvents(admin, Z), [{ event_type: "LOGIN_REJECTED", reason_code: "ROLE_INACTIVE", kind: "LOGIN_PLATFORM", limit_kind: null, window_seconds: null, peer_principal_ref: null }]);

  // G-5: auth_time anterior a la creacion del flujo (menos skew) => AUTH_TIME_INVALID (sesion vieja del IdP reutilizada); futuro tambien; igual a la creacion, aceptado.
  const stale = async (offset: string, expected: boolean, label: string): Promise<void> => {
    const f = (await begin(platform, "LOGIN_PLATFORM", null))!;
    await toClaimed(platform, verifier, f);
    const t = (await admin.query<{ t: string }>(`SELECT (created_at ${offset})::text AS t FROM platform.oidc_exchange WHERE exchange_ref = $1`, [f.ref])).rows[0]!.t;
    // auth_time debe ademas dejar la aserción vigente (vida desde auth_time): se usa life 300 y se mide contra now().
    assert.equal(await recordLogin(verifier, f.ref, { sub: subA, authTime: t }), expected, label);
    if (!expected) assert.equal((await admin.query("SELECT reason_code FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.reason_code, "AUTH_TIME_INVALID", label);
  };
  await stale("- interval '121 seconds'", false, "anterior a created_at - skew");
  await stale("- interval '1 hour'", false, "una hora antes");
  await stale("+ interval '10 minutes'", false, "futuro");
  await stale("- interval '60 seconds'", true, "dentro del skew");
  await stale("+ interval '0 seconds'", true, "igual a la creacion");

  // P-52: auth_time viejo que deja la asercion ya vencida (auth_time + life <= now) se rechaza.
  const f4 = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, f4);
  assert.equal(await recordLogin(verifier, f4.ref, { sub: subA, authTime: new Date(Date.now() - 20_000), life: 5 }), false, "auth_time + P-52 ya vencido");

  // Fail-closed sin configuracion valida: P-52 NULL, 0 o > 300; P-48 NULL o fuera de rango => REJECTED NOT_CONFIGURED.
  for (const [label, over] of [["P-52 NULL", { life: null }], ["P-52 0", { life: 0 }], ["P-52 301", { life: 301 }], ["P-48 NULL", { max: null }], ["P-48 ventana NULL", { window: null }], ["P-48 ventana 10", { window: 10 }]] as const) {
    const f = (await begin(platform, "LOGIN_PLATFORM", null))!;
    await toClaimed(platform, verifier, f);
    assert.equal(await recordLogin(verifier, f.ref, { sub: subA, authTime: new Date(), ...over }), false, label);
    assert.equal((await admin.query("SELECT reason_code FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.reason_code, "NOT_CONFIGURED", label);
  }
  // El CHECK de la tabla fija el techo de vida en 5 min aunque alguien intente insertar mas.
  await assert.rejects(
    admin.query("INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, principal_ref, decision, assertion_hash, auth_time, expires_at) VALUES ($1, 'LOGIN_PLATFORM', $2, $3, 'ATTESTED', $4, now(), now() + interval '6 minutes')", [randomUUID(), sha("x"), A, sha("y")]),
    (e) => codeOf(e) === "23514",
  );
  // Un flujo STEP_UP o ya decidido no se atesta por record_login_assertion (EXCHANGE_NOT_FOUND => false, sin efecto).
  assert.equal(await recordLogin(verifier, f1.ref, { sub: subA, authTime: new Date() }), false);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM platform.login_assertion WHERE exchange_ref = $1", [f1.ref])).rows[0]?.n, 1);
});

pgTest("TEST-CNS-1502 pg: LOGIN_CASE exige el mismo principal que oidc_exchange.principal_ref y liga la operacion (target_ref_hash); consume_login_assertion verifica state, kind, operacion, vigencia y es de un solo uso", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("t1502-a");
  const B = P("t1502-b");
  const subA = await seedOperator(admin, A, "RIGHTS_OPERATOR");
  const subB = await seedOperator(admin, B, "RIGHTS_OPERATOR");
  const caseA = sha("case-a");
  const caseB = sha("case-b");

  // B se autentica en el flujo LOGIN_CASE iniciado por la sesion de A: REJECTED PRINCIPAL_MISMATCH + evento con ambos refs.
  const fm = (await begin(platform, "LOGIN_CASE", A, { target: caseA }))!;
  await toClaimed(platform, verifier, fm);
  assert.equal(await recordLogin(verifier, fm.ref, { sub: subB, authTime: new Date() }), false);
  assert.deepEqual((await admin.query("SELECT reason_code, principal_ref FROM platform.login_assertion WHERE exchange_ref = $1", [fm.ref])).rows, [{ reason_code: "PRINCIPAL_MISMATCH", principal_ref: B }]);
  assert.deepEqual(await lastEvents(admin, B), [{ event_type: "LOGIN_PRINCIPAL_MISMATCH", reason_code: "PRINCIPAL_MISMATCH", kind: "LOGIN_CASE", limit_kind: null, window_seconds: null, peer_principal_ref: A }]);

  // A en su propio flujo: ATTESTED, ligada a la operacion.
  const f = (await begin(platform, "LOGIN_CASE", A, { target: caseA }))!;
  await toClaimed(platform, verifier, f);
  assert.equal(await recordLogin(verifier, f.ref, { sub: subA, authTime: new Date() }), true);
  assert.equal((await admin.query("SELECT target_ref_hash FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.target_ref_hash, caseA);

  // consume: state ajeno, kind equivocado, operacion distinta (la asercion no sirve para otro caso), exchange_ref ajeno => NULL y NO consume.
  assert.equal(await consume(admin, f, randomBytes(24).toString("base64url"), "LOGIN_CASE", caseA), null, "state ajeno");
  assert.equal(await consume(admin, f, f.state, "LOGIN_PLATFORM", null), null, "kind equivocado");
  assert.equal(await consume(admin, f, f.state, "LOGIN_CASE", caseB), null, "otra operacion");
  assert.equal(await consume(admin, f, f.state, "LOGIN_CASE", null), null, "sin operacion");
  assert.equal(await consume(admin, { ...f, ref: randomUUID() }, f.state, "LOGIN_CASE", caseA), null, "ref ajeno");
  assert.equal((await admin.query("SELECT consumed_at FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.consumed_at, null);
  // consume correcto: devuelve el principal de la aserción, y es de UN solo uso (replay => NULL).
  assert.equal(await consume(admin, f, f.state, "LOGIN_CASE", caseA), A);
  assert.equal(await consume(admin, f, f.state, "LOGIN_CASE", caseA), null, "replay");
  assert.ok((await admin.query<{ c: Date | null }>("SELECT consumed_at AS c FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.c instanceof Date);
  // La aserción consumida no se puede "des-consumir" ni borrar (guard).
  await assert.rejects(admin.query("UPDATE platform.login_assertion SET consumed_at = NULL WHERE exchange_ref = $1", [f.ref]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref]), (e) => codeOf(e) === "23000");

  // LOGIN_PLATFORM: consume sin operacion; vencimiento (expires_at = auth_time + life): con life 1 s, vencida a los 2 s.
  const fp = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, fp);
  assert.equal(await recordLogin(verifier, fp.ref, { sub: subA, authTime: new Date(), life: 2 }), true);
  await new Promise((r) => setTimeout(r, 2300));
  assert.equal(await consume(admin, fp, fp.state, "LOGIN_PLATFORM", null), null, "aserción vencida");
  const fq = (await begin(platform, "LOGIN_PLATFORM", null))!;
  await toClaimed(platform, verifier, fq);
  assert.equal(await recordLogin(verifier, fq.ref, { sub: subA, authTime: new Date() }), true);
  assert.equal(await consume(admin, fq, fq.state, "LOGIN_PLATFORM", null), A);
});

pgTest("TEST-CNS-1503 pg: P-48 cuenta solo los fallos del principal resuelto en la ventana (los ATTESTED legitimos no cuentan); excedido => rechazo con evento sin IP; no afecta a otro principal", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("t1503-a");
  const subA = await seedOperator(admin, A);
  const OTHER = P("t1503-other");
  const subO = await seedOperator(admin, OTHER);
  const run = async (sub: string, authTime: Date | string, over: Partial<Rec> = {}): Promise<{ ok: boolean | undefined; reason: string | null }> => {
    const f = (await begin(platform, "LOGIN_PLATFORM", null))!;
    await toClaimed(platform, verifier, f);
    const ok = await recordLogin(verifier, f.ref, { sub, authTime, max: 3, window: 900, ...over });
    return { ok, reason: ((await admin.query<{ r: string | null }>("SELECT reason_code AS r FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.r) ?? null };
  };
  // Muchos ATTESTED legitimos seguidos (mas que el maximo): ninguno cuenta.
  for (let i = 0; i < 5; i++) assert.deepEqual(await run(subA, new Date()), { ok: true, reason: null }, `attested ${i}`);
  // Tres fallos reales (auth_time viejo): AUTH_TIME_INVALID los tres.
  const old = new Date(Date.now() - 3_600_000);
  for (let i = 0; i < 3; i++) assert.deepEqual(await run(subA, old), { ok: false, reason: "AUTH_TIME_INVALID" }, `fallo ${i}`);
  // Cuarto intento, ahora legitimo: bloqueado temporalmente (RATE_LIMITED) con evento P-48 sin IP.
  assert.deepEqual(await run(subA, new Date()), { ok: false, reason: "RATE_LIMITED" });
  const ev = (await lastEvents(admin, A)).filter((e) => e.event_type === "LIMIT_EXCEEDED");
  assert.deepEqual(ev, [{ event_type: "LIMIT_EXCEEDED", reason_code: null, kind: "LOGIN_PLATFORM", limit_kind: "P-48", window_seconds: 900, peer_principal_ref: null }]);
  // Otro principal no se ve afectado.
  assert.deepEqual(await run(subO, new Date()), { ok: true, reason: null });
  // El rechazo por RATE_LIMITED no extiende el bloqueo (no cuenta como fallo): con ventana minima (60 s) y los fallos recientes sigue bloqueado; con max mayor se libera.
  assert.deepEqual(await run(subA, new Date(), { max: 4 }), { ok: true, reason: null }, "con un maximo mayor al de fallos reales, entra");
  // Ningun evento ni fila contiene IP: columnas sin tokens de red.
  const cols = (await admin.query<{ attname: string }>("SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relname IN ('session_event', 'login_assertion') AND a.attnum > 0 AND NOT a.attisdropped")).rows.map((r) => r.attname);
  assert.ok(!cols.some((c) => /(^|_)(ip|addr|address|remote|host)(_|$)/.test(c)), `columnas con tokens de red: ${cols.join(",")}`);
});

pgTest("TEST-CNS-1504 pg: privilegios de PR-6b: ACL exacta, sin acceso de tabla para runtime, consume_login_assertion interna, enqueue_oidc_exchange retirada, record_limit_event solo P-49/P-50, principal_identity versionada", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const app = await ctx.connectAs("app_rw");
  const worker = await ctx.connectAs("worker");
  const verifier = await ctx.connectAs("integrity_verifier");
  const execAcl = async (fn: string): Promise<string> =>
    (await admin.query<{ acl: string | null }>(
      `SELECT string_agg(pg_get_userbyid(a.grantee), ',' ORDER BY pg_get_userbyid(a.grantee)) AS acl
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE n.nspname = 'platform' AND p.proname = $1 AND a.grantee <> p.proowner`, [fn])).rows[0]?.acl ?? "";
  assert.equal(await execAcl("begin_oidc_authorization"), "platform_rw");
  assert.equal(await execAcl("complete_oidc_callback"), "platform_rw");
  assert.equal(await execAcl("exchange_status"), "platform_rw");
  assert.equal(await execAcl("record_limit_event"), "platform_rw");
  assert.equal(await execAcl("record_login_assertion"), "integrity_verifier");
  assert.equal(await execAcl("consume_login_assertion"), "");
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.proname = 'enqueue_oidc_exchange'")).rowCount, 0);
  // Ningun runtime ejecuta la funcion interna ni lee las tablas nuevas.
  for (const c of [platform, app, worker, verifier]) {
    await assert.rejects(c.query("SELECT platform.consume_login_assertion($1::uuid, 'x', 'LOGIN_PLATFORM', NULL)", [randomUUID()]), (e) => codeOf(e) === "42501");
    for (const t of ["login_assertion", "session_event", "oidc_exchange"]) await assert.rejects(c.query(`SELECT 1 FROM platform.${t}`), (e) => codeOf(e) === "42501", t);
  }
  // Cada runtime solo ejecuta lo suyo.
  await assert.rejects(platform.query("SELECT platform.record_login_assertion($1::uuid, 'REJECTED', 'INVALID_CLAIMS', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)", [randomUUID()]), (e) => codeOf(e) === "42501");
  await assert.rejects(verifier.query("SELECT platform.begin_oidc_authorization('LOGIN_PLATFORM', $1, $2, $3, NULL, 60, NULL, NULL, NULL)", [sha("s"), sha("n"), PKCE]), (e) => codeOf(e) === "42501");
  await assert.rejects(verifier.query("SELECT platform.complete_oidc_callback($1, 'c')", [randomBytes(24).toString("base64url")]), (e) => codeOf(e) === "42501");
  // record_limit_event: solo P-49/P-50 (P-48/P-51/P-53 los escribe la base); sin principal o con principal valido.
  const before = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'LIMIT_EXCEEDED' AND limit_kind IN ('P-49', 'P-50')")).rows[0]!.n);
  await call(platform, null, "SELECT platform.record_limit_event('P-49', 900)");
  await call(platform, P("t1504-a"), "SELECT platform.record_limit_event('P-50', 60)");
  await call(platform, null, "SELECT platform.record_limit_event('P-48', 900)");
  await call(platform, null, "SELECT platform.record_limit_event('P-49', 0)");
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.session_event WHERE event_type = 'LIMIT_EXCEEDED' AND limit_kind IN ('P-49', 'P-50')")).rows[0]!.n), before + 2);
  assert.equal((await admin.query("SELECT 1 FROM platform.session_event WHERE limit_kind = 'P-49' AND principal_ref IS NOT NULL")).rowCount, 0, "el evento anonimo no lleva principal ni IP");
  // session_event y login_assertion son append-only / un solo uso.
  await assert.rejects(admin.query("UPDATE platform.session_event SET reason_code = 'X'"), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.session_event"), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("TRUNCATE platform.session_event"), (e) => codeOf(e) === "23000");
  // principal_identity versionada (F-PR6-16): PK (principal_ref, key_version), UNIQUE (key_version, sub_hmac); doble HMAC del mismo sub en versiones distintas para el mismo principal.
  const Q = P("t1504-q");
  const s1 = sha(`q1-${randomUUID()}`);
  const s2 = sha(`q2-${randomUUID()}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, 1), ($1, $3, 2)", [Q, s1, s2]);
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, 1)", [Q, sha("otro")]), (e) => codeOf(e) === "23505");
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, 1)", [P("t1504-r"), s1]), (e) => codeOf(e) === "23505");
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, 2)", [P("t1504-r"), s1]); // mismo hmac en otra version: permitido
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac, key_version) VALUES ($1, $2, 0)", [P("t1504-s"), sha("z")]), (e) => codeOf(e) === "23514");
  // action_nonce amplia su enum con las acciones de caso (§5.1).
  for (const action of ["PROPOSE_CASE_VERIFICATION", "APPROVE_CASE_VERIFICATION", "WITHDRAW_CASE_VERIFICATION", "REQUEST_GRANT", "APPROVE_GRANT"]) {
    await admin.query("INSERT INTO platform.action_nonce (nonce_hash, scope, action, refs_digest, principal_ref, expires_at) VALUES ($1, 'PLATFORM', $2, $3, $4, now() + interval '5 minutes')", [sha(randomUUID()), action, sha(action), Q]);
  }
});
