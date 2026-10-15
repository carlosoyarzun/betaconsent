// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7, §5.3, §6, §10 fila PR-6c; G-5..G-8; revision de seguridad de 6b (F-PR6-32/36/37); db/migrations/0052-0054.
// TEST-CNS-1550: open_platform_session: consume la asercion EN LA MISMA tx (state, un solo uso), el principal sale de la asercion, rol ACTIVE re-chequeado (F-PR6-37), sid generado por la base (solo su hash),
//   PLATFORM_LOGIN, rotacion, rangos.
// TEST-CNS-1551: open_case_session: sesion PLATFORM vigente del MISMO principal, asercion ligada al caso (target_ref_hash), RIGHTS_OPERATOR ACTIVE, grant vigente; vida acotada por grant y sesion PLATFORM; CASE_LOGIN.
// TEST-CNS-1552: validate_session revalida rol, grant y sesion PLATFORM en cada llamada; vencimiento absoluto e inactividad; avance de actividad con granularidad.
// TEST-CNS-1553: revoke_session (logout en servidor, en cascada PLATFORM -> CASE), eventos, append-only (guard), sin reactivacion.
// TEST-CNS-1554: begin LOGIN_CASE valida EN LA BASE la platform_session PLATFORM vigente (F-PR6-36): sin sid, revocada, vencida, de otra clase o con principal declarado distinto = DENY.
// TEST-CNS-1555: privilegios (ACL exacta, sin acceso de tabla), funciones internas sin EXECUTE, ninguna funcion de sesion toca el ledger (compatible con TEST-CNS-1470), sin principal como parametro.
// TEST-CNS-1560: extremo a extremo con adaptadores reales (platform_rw e integrity_verifier) + IdP sintetico: login PLATFORM -> sesion -> login CASE con esa sesion -> sesion CASE -> logout en cascada; cero sid/state en claro.
// TEST-CNS-1556: carrera: N open_platform_session concurrentes con la misma asercion abren exactamente una sesion.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos. Los tests de un archivo comparten base: todo se filtra por refs propias.

import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Client } from "pg";
import { createPgOidcAuthorization, createPgOidcExchangeStore, nonceBinding } from "../../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPgPlatformSessionStore } from "../../../src/infra/adapters/postgres/platform-session.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { computeSubHmac } from "../../../src/server/modules/step-up/id-token.ts";
import { runVerifierCycle } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { loginFlow, seedOperator, sha, call } from "../../helpers/pg-login-flow.ts";
import type { LoginFlow } from "../../helpers/pg-login-flow.ts";
import { pgTest } from "./harness.ts";
import type { PgRole, PgTestContext } from "./harness.ts";

// Una conexion por (base, rol) para TODO el archivo: el service container de CI tiene max_connections=100 y los archivos corren en paralelo.
const shared = new Map<string, Promise<Client>>();
const connect = (ctx: PgTestContext, role: PgRole): Promise<Client> => {
  const key = `${ctx.dbName}|${role}`;
  let c = shared.get(key);
  if (c === undefined) { c = ctx.connectAs(role); shared.set(key, c); }
  return c;
};

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const P = (label: string): string => fixtureUuid(`pr6c-principal-${label}`);
const CASE_A = fixtureUuid("pr6c-case-a");
const CASE_B = fixtureUuid("pr6c-case-b");
const TENANT = fixtureUuid("pr6c-tenant");
const HEX64 = /^[0-9a-f]{64}$/;

const openPlatform = async (platform: Client, flow: Pick<LoginFlow, "ref" | "state">, o: { abs?: number; idle?: number; prev?: string | null } = {}): Promise<string | null> =>
  (await call<{ s: string | null }>(platform, null, "SELECT platform.open_platform_session($1::uuid, $2, $3, $4, $5) AS s", [flow.ref, flow.state, o.abs ?? 3600, o.idle ?? 600, o.prev ?? null]))[0]?.s ?? null;

const openCase = async (platform: Client, flow: Pick<LoginFlow, "ref" | "state">, caseRef: string, platformSid: string, o: { abs?: number; idle?: number; prev?: string | null } = {}): Promise<string | null> =>
  (await call<{ s: string | null }>(platform, null, "SELECT platform.open_case_session($1::uuid, $2, $3, $4, $5, $6, $7) AS s", [flow.ref, flow.state, caseRef, platformSid, o.abs ?? 3600, o.idle ?? 600, o.prev ?? null]))[0]?.s ?? null;

const validate = async (platform: Client, sid: string, kind: string): Promise<Array<{ o_session_kind: string; o_principal_ref: string; o_case_ref: string | null }>> =>
  call(platform, null, "SELECT o_session_kind, o_principal_ref, o_case_ref FROM platform.validate_session($1, $2)", [sid, kind]);

const events = async (admin: Client, principal: string): Promise<string[]> =>
  (await admin.query<{ e: string }>(
    "SELECT event_type || '|' || coalesce(reason_code, '') || '|' || coalesce(session_kind, '') || '|' || CASE WHEN case_ref IS NOT NULL THEN 'case' ELSE '' END AS e FROM platform.session_event WHERE principal_ref = $1 ORDER BY 1",
    [principal],
  )).rows.map((r) => r.e);

const sessionRow = async (admin: Client, sid: string): Promise<Record<string, unknown> | undefined> =>
  (await admin.query("SELECT session_kind, principal_ref, parent_session_ref, tenant_id, case_ref, grant_ref, revoke_cause, revoked_at IS NOT NULL AS revoked, expires_at, idle_seconds FROM platform.platform_session WHERE sid_hash = $1", [sha(sid)])).rows[0];

async function grantFor(admin: Client, principal: string, caseRef: string, seconds = 3600): Promise<string> {
  return (await admin.query<{ grant_ref: string }>(
    "INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4)) RETURNING grant_ref",
    [TENANT, caseRef, principal, seconds],
  )).rows[0]!.grant_ref;
}

/** Siembra (superusuario) una asercion ATTESTED + su canje para un principal arbitrario (p. ej. sin rol): el camino real no atesta a quien no tiene rol, pero el rol puede dejar de estar ACTIVE despues. */
async function seedAttested(admin: Client, kind: "LOGIN_PLATFORM" | "LOGIN_CASE", principal: string, target: string | null): Promise<LoginFlow> {
  const state = randomBytes(24).toString("base64url");
  const ex = (await admin.query<{ exchange_ref: string }>(
    `INSERT INTO platform.oidc_exchange (binding, principal_ref, kind, state_hash, target_ref_hash, status, expires_at, decided_at)
     VALUES ($1, $2, $3, $4, $5, 'ATTESTED', now() + interval '10 minutes', now()) RETURNING exchange_ref`,
    [sha(randomUUID()), kind === "LOGIN_PLATFORM" ? null : principal, kind, sha(state), target],
  )).rows[0]!;
  await admin.query(
    `INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, target_ref_hash, principal_ref, decision, assertion_hash, auth_time, expires_at)
     VALUES ($1, $2, $3, $4, $5, 'ATTESTED', $6, now(), now() + interval '5 minutes')`,
    [ex.exchange_ref, kind, sha(state), target, principal, sha(`token-${ex.exchange_ref}`)],
  );
  return { ref: ex.exchange_ref, state };
}

pgTest("TEST-CNS-1550 pg: open_platform_session consume la asercion en la misma tx; principal de la asercion; rol ACTIVE re-chequeado; sid de la base (solo hash); PLATFORM_LOGIN; rotacion; rangos", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const app = await ctx.connectAs("app_rw");
  const A = P("1550-a");
  const subA = await seedOperator(admin, A, "PLATFORM");

  // Estado ajeno: NULL y la asercion NO se consume.
  const f = (await loginFlow({ platform, verifier }, "LOGIN_PLATFORM", subA))!;
  assert.ok(f !== null);
  assert.equal(await openPlatform(platform, { ref: f.ref, state: randomBytes(24).toString("base64url") }), null, "state ajeno");
  assert.equal(await openPlatform(platform, { ref: randomUUID(), state: f.state }), null, "ref ajeno");
  assert.equal((await admin.query("SELECT consumed_at FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.consumed_at, null, "un fallo antes de consumir no quema la asercion");
  // Rangos: fuera de rango no abre ni consume.
  for (const o of [{ abs: 59 }, { abs: 28801 }, { idle: 59 }, { idle: 1801 }, { abs: 100, idle: 200 }]) assert.equal(await openPlatform(platform, f, o), null, JSON.stringify(o));
  assert.equal((await admin.query("SELECT consumed_at FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.consumed_at, null);
  // app_rw no ejecuta la funcion.
  await assert.rejects(app.query("SELECT platform.open_platform_session($1::uuid, $2, 3600, 600, NULL)", [f.ref, f.state]), (e) => codeOf(e) === "42501");

  // Camino feliz: sid de 64 hex generado por la base; solo se persiste su hash; la asercion queda consumida con la sesion.
  const sid = (await openPlatform(platform, f))!;
  assert.match(sid, HEX64);
  const row = await sessionRow(admin, sid);
  assert.deepEqual({ k: row?.session_kind, p: row?.principal_ref, parent: row?.parent_session_ref, c: row?.case_ref, idle: row?.idle_seconds, revoked: row?.revoked }, { k: "PLATFORM", p: A, parent: null, c: null, idle: 600, revoked: false });
  assert.ok((await admin.query<{ c: Date | null }>("SELECT consumed_at AS c FROM platform.login_assertion WHERE exchange_ref = $1", [f.ref])).rows[0]?.c instanceof Date, "asercion consumida");
  assert.deepEqual((await admin.query("SELECT 1 FROM platform.platform_session s JOIN platform.login_assertion a ON a.assertion_ref = s.assertion_ref WHERE a.exchange_ref = $1 AND s.sid_hash = $2", [f.ref, sha(sid)])).rowCount, 1);
  for (const t of ["platform_session", "session_event", "login_assertion", "oidc_exchange"]) {
    assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [sid])).rowCount, 0, `el sid en claro no se persiste (${t})`);
  }
  assert.ok((await events(admin, A)).includes("PLATFORM_LOGIN||PLATFORM|"), "PLATFORM_LOGIN escrito en la misma tx");
  // Un solo uso: el mismo (ref, state) no abre otra sesion.
  assert.equal(await openPlatform(platform, f), null, "replay");
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_session WHERE principal_ref = $1", [A])).rowCount, 1);

  // Rotacion: la sesion previa se revoca (ROTATION) y se registra.
  const f2 = (await loginFlow({ platform, verifier }, "LOGIN_PLATFORM", subA))!;
  const sid2 = (await openPlatform(platform, f2, { prev: sid }))!;
  assert.match(sid2, HEX64);
  assert.notEqual(sid2, sid);
  assert.deepEqual({ c: (await sessionRow(admin, sid))?.revoke_cause, r: (await sessionRow(admin, sid))?.revoked }, { c: "ROTATION", r: true });
  assert.equal((await sessionRow(admin, sid2))?.revoked, false);
  assert.ok((await events(admin, A)).includes("SESSION_ROTATED|ROTATION|PLATFORM|"));
  assert.equal((await validate(platform, sid, "PLATFORM")).length, 0, "la sesion rotada ya no valida");

  // F-PR6-37: sin rol ACTIVE al abrir (aserción atestada por un principal sin rol): rechazo con evento y la asercion queda consumida (no se reintenta).
  const NR = P("1550-sin-rol");
  const fr = await seedAttested(admin, "LOGIN_PLATFORM", NR, null);
  assert.equal(await openPlatform(platform, fr), null);
  assert.deepEqual(await events(admin, NR), ["LOGIN_REJECTED|ROLE_INACTIVE||"]);
  assert.ok((await admin.query<{ c: Date | null }>("SELECT consumed_at AS c FROM platform.login_assertion WHERE exchange_ref = $1", [fr.ref])).rows[0]?.c instanceof Date);
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_session WHERE principal_ref = $1", [NR])).rowCount, 0);
  assert.equal(await openPlatform(platform, fr), null);
  // El principal solo puede salir de la asercion: la firma no tiene parametro de principal.
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.proname IN ('open_platform_session', 'open_case_session') AND pg_get_function_arguments(p.oid) ~* 'principal'")).rowCount, 0);

  await app.end();
});

pgTest("TEST-CNS-1551 pg: open_case_session exige sesion PLATFORM vigente del mismo principal, asercion LOGIN_CASE ligada al caso, RIGHTS_OPERATOR ACTIVE y grant vigente; vida <= grant y <= sesion PLATFORM; CASE_LOGIN", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const clients = { platform, verifier };
  const R = P("1551-r");
  const B = P("1551-b");
  const C = P("1551-c");
  const subR = await seedOperator(admin, R, "RIGHTS_OPERATOR");
  const subB = await seedOperator(admin, B, "RIGHTS_OPERATOR");
  const subC = await seedOperator(admin, C, "PLATFORM");
  void subC;
  const platformSid = async (sub: string): Promise<string> => (await openPlatform(platform, (await loginFlow(clients, "LOGIN_PLATFORM", sub))!))!;
  const sidR = await platformSid(subR);
  const sidB = await platformSid(subB);
  const sidC = await platformSid(subC);
  await grantFor(admin, R, CASE_A);
  const caseFlow = async (sid: string, sub: string, caseRef: string): Promise<LoginFlow> => (await loginFlow(clients, "LOGIN_CASE", sub, { sid, targetRefHash: sha(caseRef) }))!;

  // Sesion PLATFORM ajena / inexistente: NO_SESSION / PRINCIPAL_MISMATCH con evento del principal de la asercion; la asercion queda consumida.
  assert.equal(await openCase(platform, await caseFlow(sidR, subR, CASE_A), CASE_A, randomBytes(32).toString("hex")), null);
  assert.equal(await openCase(platform, await caseFlow(sidR, subR, CASE_A), CASE_A, sidB), null);
  assert.deepEqual((await events(admin, R)).filter((e) => e.startsWith("LOGIN_REJECTED")), ["LOGIN_REJECTED|NO_SESSION||case", "LOGIN_REJECTED|PRINCIPAL_MISMATCH||case"]);
  // La asercion es de ESTE caso: con otro case_ref la base no la consume (NULL, sin evento) y sigue usable para el caso correcto.
  const fa = await caseFlow(sidR, subR, CASE_A);
  assert.equal(await openCase(platform, fa, CASE_B, sidR), null, "otra operacion");
  assert.equal((await admin.query("SELECT consumed_at FROM platform.login_assertion WHERE exchange_ref = $1", [fa.ref])).rows[0]?.consumed_at, null);
  // Sin grant para el caso: NO_GRANT. Con rol PLATFORM (no RIGHTS_OPERATOR): ROLE_INACTIVE.
  assert.equal(await openCase(platform, await caseFlow(sidR, subR, CASE_B), CASE_B, sidR), null);
  assert.ok((await events(admin, R)).includes("LOGIN_REJECTED|NO_GRANT||case"));
  // (el rol PLATFORM no llega a ATTESTED por el camino real de LOGIN_CASE; se siembra la asercion para ejercitar el re-chequeo de open_case_session)
  assert.equal(await openCase(platform, await seedAttested(admin, "LOGIN_CASE", C, sha(CASE_A)), CASE_A, sidC), null);
  assert.deepEqual((await events(admin, C)).filter((e) => e.startsWith("LOGIN_REJECTED")), ["LOGIN_REJECTED|ROLE_INACTIVE||case"]);
  // Sin sesiones CASE hasta aqui.
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_session WHERE session_kind = 'CASE' AND principal_ref = ANY($1)", [[R, B, C]])).rowCount, 0);

  // Exito: la sesion CASE cuelga de la PLATFORM, hereda tenant/grant, y vence a lo sumo con el grant.
  const sidCase = (await openCase(platform, fa, CASE_A, sidR))!;
  assert.match(sidCase, HEX64);
  const row = await sessionRow(admin, sidCase);
  assert.equal(row?.session_kind, "CASE");
  assert.equal(row?.principal_ref, R);
  assert.equal(row?.case_ref, CASE_A);
  assert.equal(row?.tenant_id, TENANT);
  assert.equal(row?.parent_session_ref, (await admin.query<{ r: string }>("SELECT session_ref AS r FROM platform.platform_session WHERE sid_hash = $1", [sha(sidR)])).rows[0]!.r);
  assert.ok((await admin.query<{ ok: boolean }>("SELECT s.expires_at <= g.expires_at AND s.expires_at <= p.expires_at AS ok FROM platform.platform_session s JOIN platform.rights_case_grant g ON g.grant_ref = s.grant_ref JOIN platform.platform_session p ON p.session_ref = s.parent_session_ref WHERE s.sid_hash = $1", [sha(sidCase)])).rows[0]?.ok);
  assert.ok((await events(admin, R)).includes("CASE_LOGIN||CASE|case"));
  assert.equal(await openCase(platform, fa, CASE_A, sidR), null, "un solo uso");
  // Los sids de las dos clases no se intercambian.
  assert.equal((await validate(platform, sidCase, "PLATFORM")).length, 0);
  assert.equal((await validate(platform, sidR, "CASE")).length, 0);

  // Grant corto: la sesion CASE vence con el grant aunque la vida solicitada sea mayor.
  await grantFor(admin, B, CASE_B, 90);
  const sb = (await openCase(platform, await caseFlow(sidB, subB, CASE_B), CASE_B, sidB, { abs: 3600 }))!;
  const left = (await admin.query<{ s: string }>("SELECT extract(epoch FROM expires_at - now())::int::text AS s FROM platform.platform_session WHERE sid_hash = $1", [sha(sb)])).rows[0]!.s;
  assert.ok(Number(left) <= 90 && Number(left) > 60, `vida acotada por el grant (${left})`);
  // Grant revocado: ya no se abre otra.
  await admin.query("UPDATE platform.rights_case_grant SET revoked_at = now() WHERE operator_principal_ref = $1", [B]);
  assert.equal(await openCase(platform, await caseFlow(sidB, subB, CASE_B), CASE_B, sidB), null);
  // Rotacion de sesion CASE.
  await grantFor(admin, R, CASE_B);
  const prev = (await openCase(platform, await caseFlow(sidR, subR, CASE_B), CASE_B, sidR))!;
  const next = (await openCase(platform, await caseFlow(sidR, subR, CASE_B), CASE_B, sidR, { prev }))!;
  assert.notEqual(prev, next);
  assert.deepEqual({ c: (await sessionRow(admin, prev))?.revoke_cause }, { c: "ROTATION" });
  assert.ok((await events(admin, R)).includes("SESSION_ROTATED|ROTATION|CASE|case"));
});

pgTest("TEST-CNS-1552 pg: validate_session revalida rol, grant y sesion PLATFORM en cada llamada; vencimiento absoluto e inactividad; avance de actividad con granularidad", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const app = await ctx.connectAs("app_rw");
  const R = P("1552-r");
  const subR = await seedOperator(admin, R, "RIGHTS_OPERATOR");
  const sidR = (await openPlatform(platform, (await loginFlow({ platform, verifier }, "LOGIN_PLATFORM", subR))!))!;
  const grant = await grantFor(admin, R, CASE_A);
  const sidCase = (await openCase(platform, (await loginFlow({ platform, verifier }, "LOGIN_CASE", subR, { sid: sidR, targetRefHash: sha(CASE_A) }))!, CASE_A, sidR))!;

  assert.deepEqual(await validate(platform, sidR, "PLATFORM"), [{ o_session_kind: "PLATFORM", o_principal_ref: R, o_case_ref: null }]);
  assert.deepEqual(await validate(platform, sidCase, "CASE"), [{ o_session_kind: "CASE", o_principal_ref: R, o_case_ref: CASE_A }]);
  for (const bad of ["x", "", randomBytes(32).toString("hex"), "G".repeat(64)]) assert.equal((await validate(platform, bad, "PLATFORM")).length, 0);
  assert.equal((await validate(platform, sidR, "OTRA")).length, 0);
  await assert.rejects(app.query("SELECT * FROM platform.validate_session($1, 'PLATFORM')", [sidR]), (e) => codeOf(e) === "42501");

  // Rol: una sesion de un principal SIN rol ACTIVE no valida (revalidacion; el principal nunca tuvo rol en este fixture).
  const NR = P("1552-sin-rol");
  const fix = await seedAttested(admin, "LOGIN_PLATFORM", NR, null);
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'PENDING', $2)", [NR, P("1552-req")]);
  // (rol PENDING: no cuenta como ACTIVE)
  assert.equal(await openPlatform(platform, fix), null);

  // Grant revocado: la sesion CASE deja de validar de inmediato; la PLATFORM sigue.
  await admin.query("UPDATE platform.rights_case_grant SET revoked_at = now() WHERE grant_ref = $1", [grant]);
  assert.equal((await validate(platform, sidCase, "CASE")).length, 0, "grant revocado");
  assert.equal((await validate(platform, sidR, "PLATFORM")).length, 1);

  // Vencimiento absoluto e inactividad (filas sembradas en el pasado; last_seen nunca retrocede por UPDATE).
  const past = async (label: string, o: { issuedAgo: number; lastSeenAgo: number; ttl: number; idle: number }): Promise<string> => {
    const sid = randomBytes(32).toString("hex");
    const ref = randomUUID();
    await admin.query(
      `INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, principal_ref, decision, assertion_hash, auth_time, expires_at, consumed_at)
       VALUES ($1, 'LOGIN_PLATFORM', $2, $3, 'ATTESTED', $4, now(), now() + interval '5 minutes', now())`, [ref, sha(`s-${label}`), R, sha(`a-${label}`)]);
    await admin.query(
      `INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, issued_at, expires_at, idle_seconds, last_seen_at)
       SELECT $1, 'PLATFORM', $2, assertion_ref, now() - make_interval(secs => $3), now() - make_interval(secs => $3) + make_interval(secs => $4), $5, now() - make_interval(secs => $6)
         FROM platform.login_assertion WHERE exchange_ref = $7`,
      [sha(sid), R, o.issuedAgo, o.ttl, o.idle, o.lastSeenAgo, ref],
    );
    return sid;
  };
  assert.equal((await validate(platform, await past("abs", { issuedAgo: 7200, lastSeenAgo: 10, ttl: 3600, idle: 600 }), "PLATFORM")).length, 0, "vencida (absoluta)");
  assert.equal((await validate(platform, await past("idle", { issuedAgo: 7200, lastSeenAgo: 3600, ttl: 28800, idle: 600 }), "PLATFORM")).length, 0, "vencida (inactividad)");
  const stale = await past("touch", { issuedAgo: 7200, lastSeenAgo: 120, ttl: 28800, idle: 600 });
  assert.equal((await validate(platform, stale, "PLATFORM")).length, 1);
  const seen = async (sid: string): Promise<number> => Number((await admin.query<{ a: string }>("SELECT extract(epoch FROM now() - last_seen_at)::int::text AS a FROM platform.platform_session WHERE sid_hash = $1", [sha(sid)])).rows[0]!.a);
  assert.ok((await seen(stale)) < 5, "la actividad atrasada mas de 60 s se avanza");
  const fresh = await past("fresh", { issuedAgo: 7200, lastSeenAgo: 20, ttl: 28800, idle: 600 });
  assert.equal((await validate(platform, fresh, "PLATFORM")).length, 1);
  assert.ok((await seen(fresh)) >= 19, "dentro de la granularidad no se escribe");

  await app.end();
});

pgTest("TEST-CNS-1553 pg: revoke_session revoca en servidor (PLATFORM en cascada a CASE), registra eventos, es idempotente; platform_session es append-only y una sesion revocada no se reactiva", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const worker = await ctx.connectAs("worker");
  const R = P("1553-r");
  const subR = await seedOperator(admin, R, "RIGHTS_OPERATOR");
  const clients = { platform, verifier };
  const sidR = (await openPlatform(platform, (await loginFlow(clients, "LOGIN_PLATFORM", subR))!))!;
  await grantFor(admin, R, CASE_A);
  await grantFor(admin, R, CASE_B);
  const caseSid = async (c: string): Promise<string> => (await openCase(platform, (await loginFlow(clients, "LOGIN_CASE", subR, { sid: sidR, targetRefHash: sha(c) }))!, c, sidR))!;
  const sidA = await caseSid(CASE_A);
  const sidB = await caseSid(CASE_B);
  const revoke = async (sid: string, kind: string): Promise<boolean> => (await call<{ r: boolean }>(platform, null, "SELECT platform.revoke_session($1, $2) AS r", [sid, kind]))[0]!.r;

  // Clase equivocada o sid desconocido: false y sin efecto.
  assert.equal(await revoke(sidA, "PLATFORM"), false);
  assert.equal(await revoke(randomBytes(32).toString("hex"), "CASE"), false);
  assert.equal(await revoke("corto", "CASE"), false);
  // Logout de UNA sesion CASE: solo esa.
  assert.equal(await revoke(sidA, "CASE"), true);
  assert.equal(await revoke(sidA, "CASE"), false, "idempotente");
  assert.deepEqual({ c: (await sessionRow(admin, sidA))?.revoke_cause }, { c: "USER_LOGOUT" });
  assert.equal((await validate(platform, sidB, "CASE")).length, 1);
  assert.ok((await events(admin, R)).includes("CASE_LOGOUT|USER_LOGOUT|CASE|case"));
  // Logout de la PLATFORM: cae la sesion CASE restante (PARENT_REVOKED) con su evento.
  assert.equal(await revoke(sidR, "PLATFORM"), true);
  assert.equal((await validate(platform, sidR, "PLATFORM")).length, 0);
  assert.equal((await validate(platform, sidB, "CASE")).length, 0);
  assert.deepEqual({ c: (await sessionRow(admin, sidB))?.revoke_cause }, { c: "PARENT_REVOKED" });
  const ev = await events(admin, R);
  assert.ok(ev.includes("PLATFORM_LOGOUT|USER_LOGOUT|PLATFORM|") && ev.includes("CASE_LOGOUT|PARENT_REVOKED|CASE|case"));

  // Append-only: no se reactiva, no se edita, no se borra, no se trunca; session_event inmutable.
  await assert.rejects(admin.query("UPDATE platform.platform_session SET revoked_at = NULL, revoke_cause = NULL WHERE sid_hash = $1", [sha(sidR)]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.platform_session SET principal_ref = $2 WHERE sid_hash = $1", [sha(sidR), P("1553-otro")]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.platform_session SET expires_at = expires_at + interval '1 hour' WHERE sid_hash = $1", [sha(sidR)]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.platform_session SET last_seen_at = last_seen_at - interval '1 hour' WHERE sid_hash = $1", [sha(sidB)]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.platform_session WHERE sid_hash = $1", [sha(sidR)]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("TRUNCATE platform.platform_session"), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.session_event SET reason_code = 'X' WHERE principal_ref = $1", [R]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.rights_case_grant WHERE operator_principal_ref = $1", [R]), (e) => codeOf(e) === "23000");
  // Ningun otro rol ve las tablas ni revoca.
  await assert.rejects(worker.query("SELECT platform.revoke_session($1, 'PLATFORM')", [sidR]), (e) => codeOf(e) === "42501");

  await worker.end();
});

pgTest("TEST-CNS-1554 pg: begin LOGIN_CASE valida EN LA BASE la platform_session PLATFORM vigente (F-PR6-36): sin sid, revocada, vencida, de otra clase o con principal declarado distinto = DENY", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const verifier = await connect(ctx, "integrity_verifier");
  const R = P("1554-r");
  const O = P("1554-otro");
  const subR = await seedOperator(admin, R, "RIGHTS_OPERATOR");
  await seedOperator(admin, O, "RIGHTS_OPERATOR");
  const sidR = (await openPlatform(platform, (await loginFlow({ platform, verifier }, "LOGIN_PLATFORM", subR))!))!;
  const begin = async (kind: string, o: { principal?: string | null; sid?: string | null; target?: string | null }): Promise<string | null> =>
    (await call<{ r: string | null }>(platform, o.principal ?? null, "SELECT platform.begin_oidc_authorization($1, $2, $3, $4, $5, 300, NULL, NULL, NULL) AS r",
      [kind, sha(randomUUID()), sha(randomUUID()), "E".repeat(64), o.target === undefined ? sha(CASE_A) : o.target], o.sid ?? null))[0]?.r ?? null;

  // Principal DECLARADO sin sesion (el comportamiento de 6b): ya no alcanza.
  assert.equal(await begin("LOGIN_CASE", { principal: R }), null, "principal declarado sin sesion");
  assert.equal(await begin("LOGIN_CASE", { sid: randomBytes(32).toString("hex") }), null, "sid desconocido");
  assert.equal(await begin("LOGIN_CASE", { sid: "no-es-hex" }), null);
  // Con la sesion vigente: el principal sale de la FILA de la sesion (el llamador no lo declara).
  const ref = await begin("LOGIN_CASE", { sid: sidR });
  assert.ok(ref !== null);
  assert.equal((await admin.query("SELECT principal_ref, kind FROM platform.oidc_exchange WHERE exchange_ref = $1", [ref])).rows[0]?.principal_ref, R);
  // Un principal declarado distinto del de la sesion invalida la solicitud; el mismo es indiferente.
  assert.equal(await begin("LOGIN_CASE", { sid: sidR, principal: O }), null);
  assert.ok(await begin("LOGIN_CASE", { sid: sidR, principal: R }));
  // LOGIN_PLATFORM no admite sesion ni principal.
  assert.equal(await begin("LOGIN_PLATFORM", { sid: sidR, target: null }), null);
  // Sesion CASE (otra clase) no sirve como sesion PLATFORM.
  await grantFor(admin, R, CASE_A);
  const sidCase = (await openCase(platform, (await loginFlow({ platform, verifier }, "LOGIN_CASE", subR, { sid: sidR, targetRefHash: sha(CASE_A) }))!, CASE_A, sidR))!;
  assert.equal(await begin("LOGIN_CASE", { sid: sidCase }), null, "una sesion CASE no inicia LOGIN_CASE");
  // Revocada: DENY. Con el evento de rechazo (sin sub_hmac, sin IP).
  await call(platform, null, "SELECT platform.revoke_session($1, 'PLATFORM')", [sidR]);
  assert.equal(await begin("LOGIN_CASE", { sid: sidR }), null, "sesion revocada");
  assert.ok((await admin.query("SELECT 1 FROM platform.session_event WHERE event_type = 'LOGIN_REJECTED' AND reason_code = 'NO_SESSION' AND kind = 'LOGIN_CASE'")).rowCount! >= 1);
  // Vencida por inactividad.
  const ref2 = randomUUID();
  await admin.query("INSERT INTO platform.login_assertion (exchange_ref, kind, state_hash, principal_ref, decision, assertion_hash, auth_time, expires_at, consumed_at) VALUES ($1, 'LOGIN_PLATFORM', $2, $3, 'ATTESTED', $4, now(), now() + interval '5 minutes', now())", [ref2, sha("idle-1554"), R, sha("idle-1554a")]);
  const idleSid = randomBytes(32).toString("hex");
  await admin.query(
    `INSERT INTO platform.platform_session (sid_hash, session_kind, principal_ref, assertion_ref, issued_at, expires_at, idle_seconds, last_seen_at)
     SELECT $1, 'PLATFORM', $2, assertion_ref, now() - interval '2 hours', now() + interval '1 hour', 60, now() - interval '1 hour' FROM platform.login_assertion WHERE exchange_ref = $3`, [sha(idleSid), R, ref2]);
  assert.equal(await begin("LOGIN_CASE", { sid: idleSid }), null, "sesion inactiva");
});

pgTest("TEST-CNS-1555 pg: privilegios de las sesiones: ACL exacta, sin acceso de tabla, funciones internas sin EXECUTE, ninguna funcion toca el ledger (TEST-CNS-1470), sin principal como parametro", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platform = await connect(ctx, "platform_rw");
  const app = await ctx.connectAs("app_rw");
  const worker = await ctx.connectAs("worker");
  const verifier = await connect(ctx, "integrity_verifier");

  const exec = async (role: string, sig: string): Promise<boolean> => (await admin.query<{ p: boolean }>("SELECT has_function_privilege($1, to_regprocedure($2), 'EXECUTE') AS p", [role, sig])).rows[0]!.p;
  const SIGS: Record<string, string> = {
    open_platform_session: "platform.open_platform_session(uuid, text, integer, integer, text)",
    open_case_session: "platform.open_case_session(uuid, text, text, text, integer, integer, text)",
    validate_session: "platform.validate_session(text, text)",
    revoke_session: "platform.revoke_session(text, text)",
    revoke_session_internal: "platform.revoke_session_internal(text, text, text)",
    consume_login_assertion: "platform.consume_login_assertion(uuid, text, text, text)",
  };
  for (const [name, sig] of Object.entries(SIGS)) {
    const expected = ["open_platform_session", "open_case_session", "validate_session", "revoke_session"].includes(name) ? ["platform_rw"] : [];
    for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier", "consent_owner", "consent_migrator", "transition_owner", "membership_owner"]) {
      assert.equal(await exec(role, sig), expected.includes(role), `EXECUTE de ${name} para ${role}`);
    }
    assert.equal((await admin.query("SELECT 1 FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE p.oid = to_regprocedure($1) AND a.grantee = 0", [sig])).rowCount, 0, `PUBLIC en ${name}`);
  }
  // Sin acceso de tabla para ningun rol de runtime.
  for (const c of [platform, app, worker, verifier]) {
    for (const t of ["platform_session", "rights_case_grant", "session_event", "login_assertion"]) {
      await assert.rejects(c.query(`SELECT 1 FROM platform.${t}`), (e) => codeOf(e) === "42501", t);
    }
  }
  await assert.rejects(platform.query("INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')", [TENANT, CASE_A, P("1555")]), (e) => codeOf(e) === "42501");
  await assert.rejects(platform.query("SELECT platform.revoke_session_internal($1, 'PLATFORM', 'USER_LOGOUT')", [sha("x")]), (e) => codeOf(e) === "42501");
  await assert.rejects(platform.query("SELECT platform.consume_login_assertion($1::uuid, $2, 'LOGIN_PLATFORM', NULL)", [randomUUID(), randomBytes(24).toString("base64url")]), (e) => codeOf(e) === "42501");
  // Ledger: ninguna funcion de sesion de platform lo menciona (TEST-CNS-1470 solo admite las declaradas); fuera de la lista de funciones que hacen append.
  const touching = (await admin.query<{ proname: string }>(
    "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.prosrc ~* '(ledger_append|audit_event)' ORDER BY 1",
  )).rows;
  assert.deepEqual(touching, []);
  // Todas son SECURITY DEFINER con search_path fijo, dueno grant_owner, sin SQL dinamico.
  const defs = (await admin.query<{ proname: string; owner: string; secdef: boolean; cfg: string[]; dyn: boolean }>(
    `SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS cfg, p.prosrc ~* '\\mexecute\\M' AS dyn
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.proname = ANY($1) ORDER BY 1`,
    [Object.keys(SIGS)],
  )).rows;
  assert.equal(defs.length, 6);
  for (const d of defs) assert.deepEqual({ o: d.owner, s: d.secdef, c: d.cfg, dyn: d.dyn }, { o: "grant_owner", s: true, c: ["search_path=pg_catalog, pg_temp"], dyn: false }, d.proname);

  await app.end();
  await worker.end();
});

pgTest("TEST-CNS-1556 pg carrera: N open_platform_session concurrentes con la misma asercion abren exactamente una sesion", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const verifier = await connect(ctx, "integrity_verifier");
  const clients: Client[] = [];
  const pool: Client[] = [await connect(ctx, "platform_rw")];
  pool.push(await ctx.connectAs("platform_rw"));
  clients.push(...pool);
  const A = P("1556-a");
  const subA = await seedOperator(admin, A, "PLATFORM");
  const f = (await loginFlow({ platform: clients[0]!, verifier }, "LOGIN_PLATFORM", subA))!;
  const results = await Promise.all(clients.map((c) => openPlatform(c, f)));
  assert.equal(results.filter((r) => r !== null).length, 1, "exactamente una sesion de 5 concurrentes");
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_session WHERE principal_ref = $1", [A])).rowCount, 1);
  assert.equal((await events(admin, A)).filter((e) => e.startsWith("PLATFORM_LOGIN")).length, 1);

  await Promise.all(pool.slice(1).map((c) => c.end()));
});

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const K_SUB = randomBytes(32);
const config: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", subHmacKey: K_SUB };
const LIFE = { absoluteSeconds: 3600, idleSeconds: 600 };

pgTest("TEST-CNS-1560 pg e2e: login PLATFORM -> sesion PLATFORM -> login CASE con esa sesion -> sesion CASE (grant) -> logout en cascada; sin sid ni state en claro", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platformPool = createPool({ connectionString: ctx.urlFor("platform_rw"), max: 1 });
  const verifierPool = createPool({ connectionString: ctx.urlFor("integrity_verifier"), max: 1 });
  try {
    const A = fixtureUuid("pr6c-e2e-a");
    const SUB = "sub-synthetic-pr6c-a";
    const CASE = fixtureUuid("pr6c-e2e-case");
    await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'RIGHTS_OPERATOR', 'PENDING', $2)", [A, fixtureUuid("pr6c-e2e-req")]);
    await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $2, approved_at = now() WHERE principal_ref = $1", [A, fixtureUuid("pr6c-e2e-apr")]);
    await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [A, computeSubHmac(K_SUB, ISSUER, SUB)]);
    await admin.query("INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')", [fixtureUuid("pr6c-e2e-tenant"), CASE, A]);
    const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
    const authz = createPgOidcAuthorization(platformPool);
    const store = createPgOidcExchangeStore(verifierPool);
    const sessions = createPgPlatformSessionStore(platformPool);

    const login = async (input: { kind: "LOGIN_PLATFORM" | "LOGIN_CASE"; sessionSid?: string; targetRefHash?: string }): Promise<{ ref: string; state: string }> => {
      const state = randomBytes(24).toString("base64url");
      const nonce = randomBytes(24).toString("base64url");
      const { code, pkceVerifier } = idp.simulateAuthorization({ sub: SUB, nonce, acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "persona@example.invalid" });
      const ref = await authz.begin({ ...input, state, bindingHex: nonceBinding(nonce), pkceVerifier, ttlSeconds: 300, maxAwaiting: null });
      assert.equal(await authz.complete({ state, code }), ref);
      assert.equal(await runVerifierCycle({ store, idp, config }), "ATTESTED");
      return { ref, state };
    };

    const f1 = await login({ kind: "LOGIN_PLATFORM" });
    // El state ajeno no abre; el correcto abre y la sesion valida con el principal que resolvio la base.
    assert.equal(await sessions.openPlatformSession({ exchangeRef: f1.ref, state: randomBytes(24).toString("base64url"), lifetime: LIFE }), null);
    const platformSid = (await sessions.openPlatformSession({ exchangeRef: f1.ref, state: f1.state, lifetime: LIFE }))!;
    assert.match(platformSid, /^[0-9a-f]{64}$/);
    assert.equal(await sessions.openPlatformSession({ exchangeRef: f1.ref, state: f1.state, lifetime: LIFE }), null, "un solo uso");
    const v = (await sessions.validate({ sid: platformSid, kind: "PLATFORM" }))!;
    assert.deepEqual({ k: v.kind, p: v.principalRef, c: v.caseRef }, { k: "PLATFORM", p: A, c: null });
    assert.equal(await sessions.validate({ sid: platformSid, kind: "CASE" }), null);

    // LOGIN_CASE: la base valida la sesion (sid); el principal NO se declara.
    await assert.rejects(authz.begin({ kind: "LOGIN_CASE", principalRef: A, state: "x".repeat(32), bindingHex: nonceBinding("n"), pkceVerifier: "p".repeat(64), targetRefHash: createHash("sha256").update(CASE).digest("hex"), ttlSeconds: 300, maxAwaiting: null }));
    await assert.rejects(authz.begin({ kind: "LOGIN_CASE", sessionSid: "a".repeat(64), state: randomBytes(24).toString("base64url"), bindingHex: nonceBinding("n2"), pkceVerifier: "p".repeat(64), targetRefHash: createHash("sha256").update(CASE).digest("hex"), ttlSeconds: 300, maxAwaiting: null }), "sid ajeno");
    const target = createHash("sha256").update(CASE).digest("hex");
    const f2 = await login({ kind: "LOGIN_CASE", sessionSid: platformSid, targetRefHash: target });
    assert.equal(await sessions.openCaseSession({ exchangeRef: f2.ref, state: f2.state, caseRef: fixtureUuid("pr6c-e2e-otro-caso"), platformSid, lifetime: LIFE }), null, "la asercion no sirve para otro caso");
    const caseSid = (await sessions.openCaseSession({ exchangeRef: f2.ref, state: f2.state, caseRef: CASE, platformSid, lifetime: LIFE }))!;
    assert.match(caseSid, /^[0-9a-f]{64}$/);
    const vc = (await sessions.validate({ sid: caseSid, kind: "CASE" }))!;
    assert.deepEqual({ k: vc.kind, p: vc.principalRef, c: vc.caseRef }, { k: "CASE", p: A, c: CASE });

    // Logout PLATFORM: cae tambien la sesion CASE.
    assert.equal(await sessions.revoke({ sid: platformSid, kind: "PLATFORM" }), true);
    assert.equal(await sessions.validate({ sid: platformSid, kind: "PLATFORM" }), null);
    assert.equal(await sessions.validate({ sid: caseSid, kind: "CASE" }), null);
    assert.equal(await sessions.revoke({ sid: platformSid, kind: "PLATFORM" }), false);

    // Cero secretos/PII en claro.
    for (const t of ["platform_session", "session_event", "login_assertion", "oidc_exchange"]) {
      for (const needle of [platformSid, caseSid, f1.state, f2.state, SUB, "example.invalid", CASE.replace(/-/g, "").slice(0, 0) + "persona@"]) {
        assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [needle])).rowCount, 0, `${t} contiene ${needle.slice(0, 8)}`);
      }
    }
    assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange x WHERE strpos(x::text, $1) > 0", [CASE])).rowCount, 0, "el case_ref en claro no esta en oidc_exchange (solo su hash)");
  } finally {
    await platformPool.end();
    await verifierPool.end();
  }
});
