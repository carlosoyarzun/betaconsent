// Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4), §4.4, §7 fila PR-4 (DF-4, F-X8-15); specs/db-roles.spec.yaml (integrity_verifier, platform_rw, worker, grant_owner, membership_owner);
// db/migrations/0036_adr010_verifier_assertions.sql; findings F-A10-12; decision 6 de Carlos del 2026-10-11 (nadie aprueba su propio acceso).
// TEST-CNS-1363: principal_ref UUIDv4 estricto (sin staff-synthetic-) y principal_identity (UNIQUE sub_hmac <-> principal_ref, append-only).
// TEST-CNS-1364: decision 6: CHECK approved_by_ref <> principal_ref en membership y role_assignment, y SELF_ACCESS en authorize_target (aparte de SELF_APPROVAL).
// TEST-CNS-1365: flujo real nonce -> begin/complete_oidc_authorization -> claim -> record_assertion -> ALLOW con consumo; record_assertion es la unica via de attested_at.
// TEST-CNS-1366: N6 en la base: sub_hmac no mapeado/distinto => REJECTED/SUB_MISMATCH aunque el verifier pida ATTESTED; entradas invalidas; sin replay.
// TEST-CNS-1367: oidc_exchange: secretos anulados al decidir, lease, sin SELECT para ningun runtime, guard (solo lease/cierre/borrado de vencidas), purga del worker.
// TEST-CNS-1368: bootstrap LOCAL sintetico del primer PLATFORM (db/fixtures/local/0002): dos principals ACTIVE, idempotente, el doble control se completa con ellos.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos. Los tests de un archivo comparten base: los conteos se filtran por refs propias.

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";
import { applyLocalFixtures, loadLocalFixtures } from "../../../src/infra/adapters/postgres/local-fixtures.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { enqueueStepUp } from "../../helpers/step-up-enqueue.ts";
import { pgTest } from "./harness.ts";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "db", "fixtures", "local");
const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const TENANT = fixtureUuid("pr4-tenant");
const P = (label: string): string => fixtureUuid(`pr4-principal-${label}`);
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const SEED_REQ = P("seed-requester");
const SEED_APR = P("seed-approver");
const PKCE = "A".repeat(43);

/** Una transaccion con el principal fijado como GUC local; confirma siempre (la evidencia de DENY persiste). */
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

async function seedPlatform(admin: Client, principal: string, role = "PLATFORM"): Promise<void> {
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, $2, 'PENDING', $3)", [principal, role, SEED_REQ]);
  await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $3, approved_at = now() WHERE principal_ref = $1 AND platform_role = $2", [principal, role, SEED_APR]);
}

async function bindIdentity(admin: Client, principal: string): Promise<string> {
  const subHmac = sha(`sub-${principal}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [principal, subHmac]);
  return subHmac;
}

/** Siembra un nonce ya ATTESTED (stand-in solo para los tests de reglas de decision que no son del verifier). */
async function seedAttestedNonce(admin: Client, principal: string, action: string, tenant: string | null, resource: string): Promise<void> {
  // El guard de action_nonce (0036) exige que un nonce nazca sin atestar: se inserta y luego se fija attested_at con UPDATE (stand-in del verifier, solo en tests).
  const hash = sha(randomUUID());
  await admin.query(
    `INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at)
     VALUES ($1, $2, $3::uuid, $4, $5, $6, now() + interval '5 minutes')`,
    [hash, tenant === null ? "PLATFORM" : "TENANT", tenant, action, sha(resource), principal],
  );
  await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE nonce_hash = $1", [hash]);
}

async function lastCheck(admin: Client, principal: string, kind?: string): Promise<{ check_kind: string; decision: string; reason_code: string } | undefined> {
  return (await admin.query<{ check_kind: string; decision: string; reason_code: string }>(
    "SELECT check_kind, decision, reason_code FROM platform.authorization_check WHERE principal_ref = $1 AND ($2::text IS NULL OR check_kind = $2) ORDER BY at DESC, check_ref LIMIT 1",
    [principal, kind ?? null],
  )).rows[0];
}

/**
 * claim_oidc_exchange toma LA MAS ANTIGUA de toda la base (los tests de un archivo la comparten): se llama en bucle hasta vaciar la cola y se devuelven solo las filas del
 * principal dado (no basta con filtrar la salida del claim: el LIMIT 1 ya se aplico). Las ajenas quedan con lease; no se cierran ni se leen.
 */
async function claimOwn(verifier: Client, principal: string, lease: number): Promise<Array<{ o_exchange_ref: string; o_code: string; o_pkce_verifier: string; o_binding: string }>> {
  const own: Array<{ o_exchange_ref: string; o_code: string; o_pkce_verifier: string; o_binding: string; o_principal_ref: string }> = [];
  for (let i = 0; i < 100; i++) {
    const rows = await call<{ o_exchange_ref: string; o_code: string; o_pkce_verifier: string; o_binding: string; o_principal_ref: string }>(verifier, null, "SELECT * FROM platform.claim_oidc_exchange($1)", [lease]);
    if (rows.length === 0) break;
    own.push(...rows.filter((r) => r.o_principal_ref === principal));
  }
  return own;
}

/** Camino real hasta ATTESTED: issue_action_nonce (A, platform_rw) -> begin/complete_oidc_authorization -> claim (verifier). Devuelve lo necesario para registrar la asercion. */
async function startStepUp(platform: Client, verifier: Client, principal: string, action: string, resource: string, tenant: string | null): Promise<{ exchangeRef: string; nonce: string }> {
  const nonce = (await call<{ n: string | null }>(platform, principal, "SELECT platform.issue_action_nonce($1, $2::text[], $3::uuid, 300) AS n", [action, [resource], tenant]))[0]?.n;
  assert.ok(typeof nonce === "string" && nonce.length >= 32, "nonce emitido");
  const exchangeRef = await enqueueStepUp(platform, principal, sha(nonce), `code-${randomUUID()}`, PKCE);
  assert.ok(typeof exchangeRef === "string", "solicitud encolada");
  const claimed = (await claimOwn(verifier, principal, 30)).map((r) => r.o_exchange_ref);
  assert.ok(claimed.includes(exchangeRef!), "el verifier toma la solicitud");
  return { exchangeRef: exchangeRef!, nonce };
}

const record = (verifier: Client, exchangeRef: string, decision: string, reason: string | null, subHmac: string | null, authTime: Date | null = new Date()): Promise<Array<{ ok: boolean }>> =>
  call<{ ok: boolean }>(verifier, null, "SELECT platform.record_assertion($1::uuid, $2, $3, $4, $5, $6::timestamptz, $7, $8::text[]) AS ok", [
    exchangeRef, decision, reason, subHmac, subHmac === null ? null : sha(`token-${exchangeRef}`), authTime === null ? null : authTime.toISOString(), "urn:synthetic:acr", ["pwd"],
  ]);

pgTest("TEST-CNS-1363 pg: principal_ref UUIDv4 estricto (sin staff-synthetic-) y principal_identity con UNIQUE sub_hmac <-> principal_ref, append-only y sin acceso de runtime (F-A10-12)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const A = P("t1363-a");
  const B = P("t1363-b");

  // Ninguna constraint ni funcion admite la forma staff-synthetic-.
  assert.equal((await admin.query("SELECT 1 FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace WHERE n.nspname = 'platform' AND pg_get_constraintdef(k.oid) ILIKE '%staff-synthetic%'")).rowCount, 0);
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.prosrc ILIKE '%staff-synthetic%'")).rowCount, 0);
  // Insercion directa con la forma vieja: CHECK de forma.
  await assert.rejects(
    admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ('staff-synthetic-01', 'PLATFORM', 'PENDING', $1)", [SEED_REQ]),
    (e) => codeOf(e) === "23514",
  );
  // Como actor: NO_PRINCIPAL (la forma vieja ya no es un principal) y como objetivo: INVALID_RESOURCE; la forma vieja nunca se guarda en la evidencia.
  await seedPlatform(admin, A);
  const r1 = await call<{ r: string | null }>(platform, "staff-synthetic-01", "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [B]);
  assert.equal(r1[0]?.r, null);
  const r2 = await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment('staff-synthetic-02', 'RIGHTS_OPERATOR', NULL) AS r");
  assert.equal(r2[0]?.r, null);
  assert.deepEqual(await lastCheck(admin, A), { check_kind: "AUTHORIZE", decision: "DENY", reason_code: "INVALID_RESOURCE" });
  assert.equal((await admin.query("SELECT 1 FROM platform.authorization_check WHERE principal_ref ILIKE 'staff-synthetic%' OR resource_ref ILIKE 'staff-synthetic%'")).rowCount, 0);

  // principal_identity: un principal <-> un sub_hmac, en ambos sentidos.
  await bindIdentity(admin, A);
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [A, sha("otro-sub")]), (e) => codeOf(e) === "23505");
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [B, sha(`sub-${A}`)]), (e) => codeOf(e) === "23505" && constraintOf(e) === "principal_identity_version_sub_hmac_unique");
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, 'no-es-hex')", [B]), (e) => codeOf(e) === "23514");
  await assert.rejects(admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ('staff-synthetic-03', $1)", [sha("x")]), (e) => codeOf(e) === "23514");
  // Append-only: ni UPDATE ni DELETE ni TRUNCATE (ENABLE ALWAYS: tampoco el superusuario).
  await assert.rejects(admin.query("UPDATE platform.principal_identity SET sub_hmac = $2 WHERE principal_ref = $1", [A, sha("nuevo")]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.principal_identity WHERE principal_ref = $1", [A]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("TRUNCATE platform.principal_identity"), (e) => codeOf(e) === "23000");
  // Ningun runtime lee ni escribe la tabla; no tiene columna con el sub en claro.
  for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(c.query("SELECT sub_hmac FROM platform.principal_identity"), (e) => codeOf(e) === "42501", role);
    await assert.rejects(c.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [B, sha("y")]), (e) => codeOf(e) === "42501", role);
  }
  const cols = (await admin.query<{ attname: string }>("SELECT attname FROM pg_attribute WHERE attrelid = 'platform.principal_identity'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum")).rows.map((r) => r.attname);
  assert.deepEqual(cols, ["principal_ref", "sub_hmac", "created_at", "data_class", "key_version"]);
});

pgTest("TEST-CNS-1364 pg: decision 6 de Carlos: CHECK approved_by_ref <> principal_ref en las dos tablas y SELF_ACCESS en authorize_target (aparte del solicitante <> aprobador)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const X = P("t1364-x");
  const Y = P("t1364-y");
  const Z = P("t1364-z");
  for (const p of [X, Y, Z]) await seedPlatform(admin, p);

  // CHECK de tabla (solo esta constraint se viola: el solicitante es distinto del aprobador).
  await admin.query("INSERT INTO platform.tenant_membership (tenant_id, principal_ref, membership_role, status, requested_by_ref) VALUES ($1, $2, 'INVITER', 'PENDING', $3)", [TENANT, Y, X]);
  await assert.rejects(
    admin.query("UPDATE platform.tenant_membership SET status = 'ACTIVE', approved_by_ref = principal_ref, approved_at = now() WHERE tenant_id = $1 AND principal_ref = $2", [TENANT, Y]),
    (e) => codeOf(e) === "23514" && constraintOf(e) === "tenant_membership_no_self_approval",
  );
  const T = P("t1364-target");
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'CONTEXT_OWNER', 'PENDING', $2)", [T, X]);
  await assert.rejects(
    admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = principal_ref, approved_at = now() WHERE principal_ref = $1 AND platform_role = 'CONTEXT_OWNER'", [T]),
    (e) => codeOf(e) === "23514" && constraintOf(e) === "platform_role_assignment_no_self_approval",
  );

  // authorize_target, membership: X solicita acceso para Y (Y es PLATFORM activo); Y no puede aprobar su propio acceso. Z si.
  const memReq = `${Y}:INVITER`;
  await seedAttestedNonce(admin, X, "REQUEST_MEMBERSHIP", TENANT, memReq);
  const reqRef = (await call<{ r: string | null }>(platform, X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [fixtureUuid("t1364-tenant-2"), Y]))[0]?.r;
  assert.equal(reqRef, null, "el tenant del nonce es otro: step-up no coincide");
  await seedAttestedNonce(admin, X, "REQUEST_MEMBERSHIP", fixtureUuid("t1364-tenant-2"), memReq);
  const memRef = (await call<{ r: string | null }>(platform, X, "SELECT platform.request_membership($1::uuid, $2, 'INVITER') AS r", [fixtureUuid("t1364-tenant-2"), Y]))[0]?.r;
  assert.ok(typeof memRef === "string");
  await seedAttestedNonce(admin, Y, "APPROVE_MEMBERSHIP", fixtureUuid("t1364-tenant-2"), memRef!);
  assert.equal((await call<{ ok: boolean | null }>(platform, Y, "SELECT platform.approve_membership($1::uuid) AS ok", [memRef]))[0]?.ok, false);
  assert.deepEqual(await lastCheck(admin, Y), { check_kind: "AUTHORIZE", decision: "DENY", reason_code: "SELF_ACCESS" });
  await seedAttestedNonce(admin, Z, "APPROVE_MEMBERSHIP", fixtureUuid("t1364-tenant-2"), memRef!);
  assert.equal((await call<{ ok: boolean | null }>(platform, Z, "SELECT platform.approve_membership($1::uuid) AS ok", [memRef]))[0]?.ok, true);

  // authorize_target, role_assignment: X solicita rol para Y; Y no puede aprobarlo; Z si. Y tampoco puede aprobar si ademas fuera el solicitante (SELF_APPROVAL).
  const roleReq = `${Y}:RIGHTS_OPERATOR`;
  await seedAttestedNonce(admin, X, "REQUEST_ROLE_ASSIGNMENT", null, roleReq);
  const roleRef = (await call<{ r: string | null }>(platform, X, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [Y]))[0]?.r;
  assert.ok(typeof roleRef === "string");
  await seedAttestedNonce(admin, Y, "APPROVE_ROLE_ASSIGNMENT", null, roleRef!);
  assert.equal((await call<{ ok: boolean | null }>(platform, Y, "SELECT platform.approve_role_assignment($1::uuid) AS ok", [roleRef]))[0]?.ok, false);
  assert.deepEqual(await lastCheck(admin, Y), { check_kind: "AUTHORIZE", decision: "DENY", reason_code: "SELF_ACCESS" });
  await seedAttestedNonce(admin, X, "APPROVE_ROLE_ASSIGNMENT", null, roleRef!);
  assert.equal((await call<{ ok: boolean | null }>(platform, X, "SELECT platform.approve_role_assignment($1::uuid) AS ok", [roleRef]))[0]?.ok, false);
  assert.deepEqual(await lastCheck(admin, X), { check_kind: "AUTHORIZE", decision: "DENY", reason_code: "SELF_APPROVAL" });
  await seedAttestedNonce(admin, Z, "APPROVE_ROLE_ASSIGNMENT", null, roleRef!);
  assert.equal((await call<{ ok: boolean | null }>(platform, Z, "SELECT platform.approve_role_assignment($1::uuid) AS ok", [roleRef]))[0]?.ok, true);
  const active = (await admin.query<{ approved_by_ref: string }>("SELECT approved_by_ref FROM platform.platform_role_assignment WHERE principal_ref = $1 AND platform_role = 'RIGHTS_OPERATOR'", [Y])).rows;
  assert.deepEqual(active, [{ approved_by_ref: Z }]);
});

pgTest("TEST-CNS-1365 pg: flujo real nonce -> begin/complete_oidc_authorization -> claim -> record_assertion ATTESTED -> la accion se autoriza y consume el nonce; record_assertion es la unica via de attested_at", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("t1365-a");
  const TARGET = P("t1365-target");
  await seedPlatform(admin, A);
  const subHmac = await bindIdentity(admin, A);
  const resource = `${TARGET}:RIGHTS_OPERATOR`;

  // Sin step-up atestado la accion falla cerrada.
  assert.equal((await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [TARGET]))[0]?.r, null);
  assert.equal((await lastCheck(admin, A, "AUTHORIZE"))?.reason_code, "STEP_UP_MISSING");

  const { exchangeRef, nonce } = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource, null);
  // Encolado y tomado, pero NO atestado: sigue sin autorizar.
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE nonce_hash = $1 AND attested_at IS NULL", [sha(nonce)])).rowCount, 1);
  assert.equal((await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [TARGET]))[0]?.r, null);

  assert.equal((await record(verifier, exchangeRef, "ATTESTED", null, subHmac))[0]?.ok, true);
  const n = (await admin.query<{ attested_at: Date | null; consumed_at: Date | null }>("SELECT attested_at, consumed_at FROM platform.action_nonce WHERE nonce_hash = $1", [sha(nonce)])).rows[0];
  assert.ok(n?.attested_at instanceof Date && n.consumed_at === null);
  // Evidencia y secretos: solicitud cerrada y SIN code ni PKCE; asercion con claims minimos.
  const ex = (await admin.query<{ status: string; code: string | null; pkce_verifier: string | null; decided_at: Date | null }>("SELECT status, code, pkce_verifier, decided_at FROM platform.oidc_exchange WHERE exchange_ref = $1", [exchangeRef])).rows[0];
  assert.equal(ex?.status, "ATTESTED");
  assert.equal(ex?.code, null);
  assert.equal(ex?.pkce_verifier, null);
  assert.ok(ex?.decided_at instanceof Date);
  const ga = (await admin.query<{ decision: string; reason_code: string | null; sub_hmac: string; assertion_hash: string; acr: string; amr: string[] }>("SELECT decision, reason_code, sub_hmac, assertion_hash, acr, amr FROM platform.grant_assertion WHERE exchange_ref = $1", [exchangeRef])).rows;
  assert.equal(ga.length, 1);
  assert.equal(ga[0]?.decision, "ATTESTED");
  assert.equal(ga[0]?.reason_code, null);
  assert.equal(ga[0]?.sub_hmac, subHmac);
  assert.match(ga[0]!.assertion_hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(await lastCheck(admin, A, "RECORD_ASSERTION"), { check_kind: "RECORD_ASSERTION", decision: "ALLOW", reason_code: "OK" });
  // Replay: la misma solicitud no se vuelve a registrar.
  assert.equal((await record(verifier, exchangeRef, "ATTESTED", null, subHmac))[0]?.ok, false);
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_assertion WHERE exchange_ref = $1", [exchangeRef])).rowCount, 1);

  // Ahora si: la accion se autoriza UNA vez (consume el nonce) y la segunda falla.
  const reqRef = (await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [TARGET]))[0]?.r;
  assert.ok(typeof reqRef === "string");
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE nonce_hash = $1 AND consumed_at IS NOT NULL", [sha(nonce)])).rowCount, 1);
  assert.equal((await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment($1, 'CONTEXT_OWNER', NULL) AS r", [TARGET]))[0]?.r, null);

  // Ningun runtime fija attested_at por tabla; solo el verifier ejecuta record_assertion y solo platform_rw emite/encola.
  for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(c.query("UPDATE platform.action_nonce SET attested_at = now()"), (e) => codeOf(e) === "42501", `${role} UPDATE action_nonce`);
  }
  for (const role of ["app_rw", "platform_rw", "worker"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(c.query("SELECT platform.record_assertion($1::uuid, 'ATTESTED', NULL, $2, $2, now(), NULL, NULL)", [exchangeRef, subHmac]), (e) => codeOf(e) === "42501", `${role} record_assertion`);
    await assert.rejects(c.query("SELECT * FROM platform.claim_oidc_exchange(30)"), (e) => codeOf(e) === "42501", `${role} claim`);
  }
  for (const sql of ["SELECT platform.issue_action_nonce('APPROVE_ROLE_ASSIGNMENT', ARRAY['x'], NULL, 60)", "SELECT platform.begin_oidc_authorization('STEP_UP', 'x', 'y', 'z', NULL, 60, NULL, 5, 600)", "SELECT platform.authorize('REQUEST_ROLE_ASSIGNMENT', 'x')", "SELECT platform.purge_expired_oidc_exchange()"]) {
    await assert.rejects(verifier.query(sql), (e) => codeOf(e) === "42501", sql);
  }
});

pgTest("TEST-CNS-1366 pg: N6 en la base: un sub_hmac no mapeado o distinto degrada a REJECTED/SUB_MISMATCH aunque el verifier pida ATTESTED; entradas invalidas se rechazan y el nonce no se atesta", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const A = P("t1366-a");
  const U = P("t1366-unmapped");
  await seedPlatform(admin, A);
  await seedPlatform(admin, U);
  const subA = await bindIdentity(admin, A);
  const resource = (t: string): string => `${t}:APPROVER:SECURITY`;
  const nonceAttested = async (nonce: string): Promise<boolean> => (await admin.query("SELECT 1 FROM platform.action_nonce WHERE nonce_hash = $1 AND attested_at IS NOT NULL", [sha(nonce)])).rowCount === 1;

  // 1. sub_hmac distinto del mapeado.
  const s1 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t1")), null);
  assert.equal((await record(verifier, s1.exchangeRef, "ATTESTED", null, sha("sub-de-otro-humano")))[0]?.ok, false);
  assert.equal(await nonceAttested(s1.nonce), false);
  const g1 = (await admin.query<{ decision: string; reason_code: string }>("SELECT decision, reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [s1.exchangeRef])).rows;
  assert.deepEqual(g1, [{ decision: "REJECTED", reason_code: "SUB_MISMATCH" }]);
  assert.deepEqual(await lastCheck(admin, A, "RECORD_ASSERTION"), { check_kind: "RECORD_ASSERTION", decision: "DENY", reason_code: "SUB_MISMATCH" });
  const ex1 = (await admin.query<{ status: string; code: string | null; pkce_verifier: string | null }>("SELECT status, code, pkce_verifier FROM platform.oidc_exchange WHERE exchange_ref = $1", [s1.exchangeRef])).rows[0];
  assert.deepEqual(ex1, { status: "REJECTED", code: null, pkce_verifier: null });

  // 2. principal sin vinculo en principal_identity.
  const s2 = await startStepUp(platform, verifier, U, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t2")), null);
  assert.equal((await record(verifier, s2.exchangeRef, "ATTESTED", null, sha("sub-cualquiera")))[0]?.ok, false);
  assert.equal(await nonceAttested(s2.nonce), false);
  assert.equal((await lastCheck(admin, U, "RECORD_ASSERTION"))?.reason_code, "SUB_MISMATCH");

  // 3. entrada invalida (decision desconocida, hash mal formado, auth_time futuro): REJECTED/INVALID_CLAIMS, nonce intacto.
  const s3 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t3")), null);
  assert.equal((await record(verifier, s3.exchangeRef, "MAYBE", null, subA))[0]?.ok, false);
  assert.deepEqual((await admin.query("SELECT decision, reason_code, sub_hmac FROM platform.grant_assertion WHERE exchange_ref = $1", [s3.exchangeRef])).rows, [{ decision: "REJECTED", reason_code: "INVALID_CLAIMS", sub_hmac: null }]);
  const s4 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t4")), null);
  assert.equal((await record(verifier, s4.exchangeRef, "ATTESTED", null, subA, new Date(Date.now() + 3600_000)))[0]?.ok, false);
  assert.equal((await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [s4.exchangeRef])).rows[0]?.reason_code, "INVALID_CLAIMS");
  const s5 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t5")), null);
  assert.equal((await call<{ ok: boolean }>(verifier, null, "SELECT platform.record_assertion($1::uuid, 'ATTESTED', NULL, 'no-hex', 'no-hex', now(), NULL, NULL) AS ok", [s5.exchangeRef]))[0]?.ok, false);
  assert.equal((await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [s5.exchangeRef])).rows[0]?.reason_code, "INVALID_CLAIMS");
  for (const s of [s3, s4, s5]) assert.equal(await nonceAttested(s.nonce), false);

  // 4. REJECTED pedido por el verifier: motivo cerrado; un motivo fuera de la lista se cierra como INVALID_CLAIMS.
  const s6 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t6")), null);
  assert.equal((await record(verifier, s6.exchangeRef, "REJECTED", "EXCHANGE_FAILED", null, null))[0]?.ok, false);
  assert.equal((await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [s6.exchangeRef])).rows[0]?.reason_code, "EXCHANGE_FAILED");
  const s7 = await startStepUp(platform, verifier, A, "REQUEST_ROLE_ASSIGNMENT", resource(P("t1366-t7")), null);
  assert.equal((await record(verifier, s7.exchangeRef, "REJECTED", "porque-si", null, null))[0]?.ok, false);
  assert.equal((await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [s7.exchangeRef])).rows[0]?.reason_code, "INVALID_CLAIMS");

  // 5. solicitud inexistente o ya cerrada: false con evidencia, sin efectos.
  assert.equal((await record(verifier, randomUUID(), "ATTESTED", null, subA))[0]?.ok, false);
  assert.equal((await record(verifier, s1.exchangeRef, "ATTESTED", null, subA))[0]?.ok, false);
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_assertion WHERE exchange_ref = $1", [s1.exchangeRef])).rowCount, 1);

  // 5b. record_assertion exige un lease VIGENTE: sin claim previo, o con el lease vencido, la asercion no se registra (el timeout HTTP del IdP debe ser menor que el lease).
  const noClaim = await call<{ n: string }>(platform, A, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [resource(P("t1366-lease"))]);
  const noClaimRef = (await enqueueStepUp(platform, A, sha(noClaim[0]!.n), "code-lease", PKCE))!;
  assert.equal((await record(verifier, noClaimRef, "ATTESTED", null, subA))[0]?.ok, false, "sin claim no hay lease");
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_assertion WHERE exchange_ref = $1", [noClaimRef])).rowCount, 0);
  assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE nonce_hash = $1 AND attested_at IS NOT NULL", [sha(noClaim[0]!.n)])).rowCount, 0);
  const leased = await claimOwn(verifier, A, 1);
  assert.ok(leased.some((r) => r.o_exchange_ref === noClaimRef));
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal((await record(verifier, noClaimRef, "ATTESTED", null, subA))[0]?.ok, false, "lease vencido");
  assert.equal((await claimOwn(verifier, A, 30)).some((r) => r.o_exchange_ref === noClaimRef), true, "vuelve a estar disponible");
  assert.equal((await record(verifier, noClaimRef, "ATTESTED", null, subA))[0]?.ok, true, "con lease vigente si");

  // 5c. tope de reencolados de un mismo nonce tras REJECTED (placeholder de 3): el cuarto intento es DENY RETRY_LIMIT.
  const retryNonce = (await call<{ n: string }>(platform, A, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 300) AS n", [resource(P("t1366-retry"))]))[0]!.n;
  for (let i = 0; i < 3; i++) {
    const r = await enqueueStepUp(platform, A, sha(retryNonce), `code-retry-${i}`, PKCE);
    assert.ok(typeof r === "string", `intento ${i + 1} se encola`);
    assert.ok((await claimOwn(verifier, A, 30)).some((x) => x.o_exchange_ref === r));
    assert.equal((await record(verifier, r!, "REJECTED", "EXCHANGE_FAILED", null, null))[0]?.ok, false);
  }
  assert.equal(await enqueueStepUp(platform, A, sha(retryNonce), "code-retry-4", PKCE), null);
  assert.equal((await lastCheck(admin, A, "ENQUEUE_EXCHANGE"))?.reason_code, "RETRY_LIMIT");

  // 6. un principal no puede encolar con el nonce de otro: NONCE_NOT_FOUND.
  const nonceOfA = (await call<{ n: string | null }>(platform, A, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 60) AS n", [resource(P("t1366-t8"))]))[0]?.n as string;
  assert.equal(await enqueueStepUp(platform, U, sha(nonceOfA), "code-x", PKCE), null);
  assert.equal((await lastCheck(admin, U, "ENQUEUE_EXCHANGE"))?.reason_code, "NONCE_NOT_FOUND");
});

pgTest("TEST-CNS-1367 pg: oidc_exchange: code y PKCE anulados al decidir, lease del claim, sin SELECT para ningun runtime, guard (lease, cierre, borrado solo de vencidas) y purga del worker", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");
  const worker = await ctx.connectAs("worker");
  const A = P("t1367-a");
  const B = P("t1367-b");
  await seedPlatform(admin, A);
  await seedPlatform(admin, B);
  const res = (t: string): string => `${t}:CONTEXT_OWNER`;
  const issue = async (p: string, ref: string): Promise<string> => (await call<{ n: string }>(platform, p, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1], NULL, 120) AS n", [res(ref)]))[0]!.n;
  const enqueue = async (p: string, nonce: string, code: string, pkce = PKCE, ttl = 60): Promise<string | null> =>
    await enqueueStepUp(platform, p, sha(nonce), code, pkce, ttl);
  const lastReason = async (p: string): Promise<string | undefined> => (await lastCheck(admin, p, "ENQUEUE_EXCHANGE"))?.reason_code;

  const n1 = await issue(A, P("t1367-1"));
  // Entradas invalidas: TTL fuera de rango, code con espacio o vacio, PKCE corto, binding mal formado.
  assert.equal(await enqueue(A, n1, "code-ok", PKCE, 0), null);
  assert.equal(await lastReason(A), "INVALID_TTL");
  assert.equal(await enqueue(A, n1, "code-ok", PKCE, 601), null);
  // PR-6b: el code se valida en complete_oidc_callback (no en begin): un code invalido deja la fila AWAITING_CALLBACK sin code (no avanza a PENDING).
  const nCode = await issue(A, P("t1367-code"));
  assert.equal(await enqueue(A, nCode, "code con espacio"), null);
  assert.deepEqual((await admin.query("SELECT status, code IS NULL AS no_code FROM platform.oidc_exchange WHERE binding = $1", [sha(nCode)])).rows, [{ status: "AWAITING_CALLBACK", no_code: true }]);
  assert.equal(await enqueue(A, n1, "code-ok", "corto"), null);
  assert.equal(await enqueueStepUp(platform, A, "no-hex", "c", PKCE), null);
  assert.equal(await enqueueStepUp(platform, null, sha(n1), "c", PKCE), null, "sin principal");
  // OK, y un segundo PENDING con el mismo nonce es DUPLICATE_EXCHANGE.
  const code1 = `code-${randomUUID()}`;
  const ref1 = await enqueue(A, n1, code1);
  assert.ok(typeof ref1 === "string");
  assert.equal(await enqueue(A, n1, "otro-code"), null);
  assert.equal(await lastReason(A), "DUPLICATE_EXCHANGE");

  // Claim: devuelve los secretos una vez; durante el lease no se entrega de nuevo; vencido el lease vuelve a estar disponible.
  const claim = (lease: number): ReturnType<typeof claimOwn> => claimOwn(verifier, A, lease);
  const c1 = await claim(1);
  assert.equal(c1.length, 1);
  assert.equal(c1[0]?.o_exchange_ref, ref1);
  assert.equal(c1[0]?.o_code, code1);
  assert.equal(c1[0]?.o_binding, sha(n1));
  assert.equal(c1[0]?.o_pkce_verifier, PKCE);
  assert.equal((await claim(1)).length, 0, "lease activo");
  await new Promise((resolve) => setTimeout(resolve, 1200));
  assert.equal((await claim(30)).length, 1, "lease vencido: disponible de nuevo");
  // Parametro de lease fuera de rango: sin filas.
  assert.equal((await call(verifier, null, "SELECT * FROM platform.claim_oidc_exchange(0)")).length, 0);

  // Ningun runtime lee la tabla; ni el code ni el PKCE aparecen en otra tabla de platform.
  for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(c.query("SELECT code FROM platform.oidc_exchange"), (e) => codeOf(e) === "42501", role);
    await assert.rejects(c.query("UPDATE platform.oidc_exchange SET code = NULL"), (e) => codeOf(e) === "42501", role);
    await assert.rejects(c.query("DELETE FROM platform.oidc_exchange"), (e) => codeOf(e) === "42501", role);
  }
  for (const t of ["authorization_check", "grant_assertion", "action_nonce"]) {
    assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE x::text LIKE '%' || $1 || '%' OR x::text LIKE '%' || $2 || '%'`, [code1, PKCE])).rowCount, 0, `${t} no contiene secretos`);
  }

  // Cierre: secretos NULL. CHECK: decidida con secretos o PENDING sin ellos es imposible.
  const subA = await bindIdentity(admin, A);
  assert.equal((await record(verifier, ref1!, "ATTESTED", null, subA))[0]?.ok, true);
  assert.deepEqual((await admin.query("SELECT status, code, pkce_verifier FROM platform.oidc_exchange WHERE exchange_ref = $1", [ref1])).rows, [{ status: "ATTESTED", code: null, pkce_verifier: null }]);
  const n2 = await issue(B, P("t1367-2"));
  await assert.rejects(
    admin.query("INSERT INTO platform.oidc_exchange (binding, principal_ref, kind, state_hash, code, pkce_verifier, status, decided_at, expires_at) VALUES ($1, $2, 'STEP_UP', encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 'c', $3, 'ATTESTED', now(), now() + interval '1 minute')", [sha(n2), B, PKCE]),
    (e) => codeOf(e) === "23514",
  );
  await assert.rejects(
    admin.query("INSERT INTO platform.oidc_exchange (binding, principal_ref, kind, state_hash, code, pkce_verifier, expires_at) VALUES ($1, $2, 'STEP_UP', encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 'c', $3, now() + interval '11 minutes')", [sha(n2), B, PKCE]),
    (e) => codeOf(e) === "23514",
  );
  const ref2 = await enqueue(B, n2, "code-b");
  assert.ok(typeof ref2 === "string");

  // Guard: ENABLE ALWAYS (tampoco el superusuario): no se reescribe, no se borra una fila vigente, no hay TRUNCATE ni resurreccion de una decidida.
  await assert.rejects(admin.query("UPDATE platform.oidc_exchange SET code = 'otro' WHERE exchange_ref = $1", [ref2]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.oidc_exchange SET binding = $2 WHERE exchange_ref = $1", [ref2, sha("x")]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("UPDATE platform.oidc_exchange SET status = 'PENDING', code = 'c', pkce_verifier = $2, decided_at = NULL WHERE exchange_ref = $1", [ref1, PKCE]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.oidc_exchange WHERE exchange_ref = $1", [ref2]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("TRUNCATE platform.oidc_exchange"), (e) => codeOf(e) === "23000");
  // grant_assertion es append-only.
  await assert.rejects(admin.query("UPDATE platform.grant_assertion SET decision = 'REJECTED', reason_code = 'INVALID_CLAIMS' WHERE exchange_ref = $1", [ref1]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("DELETE FROM platform.grant_assertion WHERE exchange_ref = $1", [ref1]), (e) => codeOf(e) === "23000");
  await assert.rejects(admin.query("TRUNCATE platform.grant_assertion"), (e) => codeOf(e) === "23000");

  // Purga del worker: solo vencidas (la fila vigente ref2 sobrevive); el verifier y platform_rw no la ejecutan.
  const expired = (await admin.query<{ exchange_ref: string }>(
    "INSERT INTO platform.oidc_exchange (binding, principal_ref, kind, state_hash, code, pkce_verifier, created_at, expires_at) VALUES ($1, $2, 'STEP_UP', encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 'c', $3, now() - interval '5 minutes', now() - interval '1 minute') RETURNING exchange_ref",
    [sha(randomUUID()), B, PKCE],
  )).rows[0]!.exchange_ref;
  assert.equal((await claim(30)).length, 0);
  const purged = (await call<{ n: number }>(worker, null, "SELECT platform.purge_expired_oidc_exchange() AS n"))[0]?.n;
  assert.ok(typeof purged === "number" && purged >= 1);
  assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange WHERE exchange_ref = $1", [expired])).rowCount, 0);
  assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange WHERE exchange_ref = $1", [ref2])).rowCount, 1);
  for (const c of [verifier, platform]) await assert.rejects(c.query("SELECT platform.purge_expired_oidc_exchange()"), (e) => codeOf(e) === "42501");
});

pgTest("TEST-CNS-1368 pg: bootstrap LOCAL sintetico del primer PLATFORM (fixture db/fixtures/local/0002): dos principals ACTIVE con aprobador distinto, idempotente, y con ellos se completa el doble control; fail-closed fuera de LOCAL", async (ctx) => {
  const fixtures = loadLocalFixtures(FIXTURES_DIR);
  assert.ok(fixtures.some((f) => f.name === "0002_platform_bootstrap.sql"));
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" });
  await applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" }); // idempotente
  await assert.rejects(() => applyLocalFixtures(migrator, fixtures, { environment: "STAGING" }));

  const admin = await ctx.connectAsSuperuser();
  const A = "580ddfe4-9026-486f-becc-19f561a20106";
  const Bp = "44bb73f9-d898-479f-bfcd-d70c3f8ca624";
  const rows = (await admin.query<{ principal_ref: string; status: string; requested_by_ref: string; approved_by_ref: string }>(
    "SELECT principal_ref, status, requested_by_ref, approved_by_ref FROM platform.platform_role_assignment WHERE principal_ref = ANY($1) AND platform_role = 'PLATFORM' ORDER BY principal_ref",
    [[A, Bp]],
  )).rows;
  assert.equal(rows.length, 2);
  for (const r of rows) {
    assert.equal(r.status, "ACTIVE");
    assert.notEqual(r.approved_by_ref, r.principal_ref);
    assert.notEqual(r.approved_by_ref, r.requested_by_ref);
  }
  assert.equal((await admin.query("SELECT 1 FROM platform.principal_identity WHERE principal_ref = ANY($1)", [[A, Bp]])).rowCount, 2);

  // Con los dos bootstrap se completa el doble control: A solicita un rol, B lo aprueba (step-up sembrado: el verifier se prueba en 1365).
  const platform = await ctx.connectAs("platform_rw");
  const T = P("t1368-target");
  await seedAttestedNonce(admin, A, "REQUEST_ROLE_ASSIGNMENT", null, `${T}:RIGHTS_OPERATOR`);
  const ref = (await call<{ r: string | null }>(platform, A, "SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [T]))[0]?.r;
  assert.ok(typeof ref === "string");
  await seedAttestedNonce(admin, A, "APPROVE_ROLE_ASSIGNMENT", null, ref!);
  assert.equal((await call<{ ok: boolean }>(platform, A, "SELECT platform.approve_role_assignment($1::uuid) AS ok", [ref]))[0]?.ok, false, "A no aprueba su propia solicitud");
  await seedAttestedNonce(admin, Bp, "APPROVE_ROLE_ASSIGNMENT", null, ref!);
  assert.equal((await call<{ ok: boolean }>(platform, Bp, "SELECT platform.approve_role_assignment($1::uuid) AS ok", [ref]))[0]?.ok, true);

  // El propio SQL del fixture aborta si ops.db_catalog no es LOCAL/SYNTHETIC (aunque el entorno del proceso diga LOCAL). Base de este archivo: se rompe el catalogo solo para el caso negativo.
  const extra = fixtureUuid("t1368-no-debe-entrar");
  await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER USER");
  await admin.query("UPDATE ops.db_catalog SET environment = 'DEV'");
  const sqlOnly = [{ name: "9999_probe.sql", sql: `-- scope: local-fixture\n${fixtures.find((f) => f.name === "0002_platform_bootstrap.sql")!.sql.replace(/580ddfe4-9026-486f-becc-19f561a20106/g, extra)}` }];
  await assert.rejects(() => applyLocalFixtures(migrator, sqlOnly, { environment: "LOCAL" }), (e: unknown) => /LOCAL\/SYNTHETIC/.test((e as Error).message));
  assert.equal((await admin.query("SELECT 1 FROM platform.platform_role_assignment WHERE principal_ref = $1", [extra])).rowCount, 0, "el SQL abortó antes de insertar");
});
