// Gobierna: ADR-010 rev. 4, decision de Carlos del 2026-10-12 (registrada bajo PR-4 #87): "(1) P-36 step-up exige reautenticacion fresca (auth_time >= issued_at del nonce - skew)";
// db/migrations/0040_adr010_record_assertion_fresh_auth.sql; plan PR-6-0; F-A10-20 (parcial), F-PR6-03.
// TEST-CNS-1394: platform.record_assertion rechaza (REJECTED / INVALID_CLAIMS, nonce sin atestar, sin consumo) un auth_time anterior a action_nonce.issued_at - skew;
//   igual o posterior se acepta (ATTESTED); la tolerancia (2 min, constante de la funcion) admite un auth_time apenas anterior; el rechazo de auth_time futuro se mantiene.
// El valor numerico de P-36 (edad maxima) NO se prueba: sigue PENDING. Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.
// Los tests de un archivo comparten base: todo se filtra por refs propias (principal y nonce de cada caso).

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import type { Client } from "pg";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { enqueueStepUp } from "../../helpers/step-up-enqueue.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const P = (label: string): string => fixtureUuid(`pr6-0-principal-${label}`);
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const SEED_REQ = P("seed-requester");
const SEED_APR = P("seed-approver");
const PKCE = "A".repeat(43);
const SKEW_S = 120; // c_skew de record_assertion (0040); SIN aprobar (F-PR6-07)

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

async function seedPrincipal(admin: Client, principal: string): Promise<string> {
  await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'PENDING', $2)", [principal, SEED_REQ]);
  await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $3, approved_at = now() WHERE principal_ref = $1 AND platform_role = $2", [principal, "PLATFORM", SEED_APR]);
  const subHmac = sha(`sub-${principal}`);
  await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [principal, subHmac]);
  return subHmac;
}

/** Toma TODAS las solicitudes pendientes (la cola es de toda la base) y devuelve solo las del principal. */
async function claimOwn(verifier: Client, principal: string): Promise<string[]> {
  const own: string[] = [];
  for (let i = 0; i < 100; i++) {
    const rows = await call<{ o_exchange_ref: string; o_principal_ref: string }>(verifier, null, "SELECT * FROM platform.claim_oidc_exchange(30)");
    if (rows.length === 0) break;
    own.push(...rows.filter((r) => r.o_principal_ref === principal).map((r) => r.o_exchange_ref));
  }
  return own;
}

interface Flow { exchangeRef: string; nonce: string; nonceHash: string; subHmac: string; principal: string }

async function startFlow(admin: Client, platform: Client, verifier: Client, label: string): Promise<Flow> {
  const principal = P(label);
  const subHmac = await seedPrincipal(admin, principal);
  const nonce = (await call<{ n: string | null }>(platform, principal, "SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', $1::text[], NULL, 300) AS n", [[`${P(`${label}-target`)}:RIGHTS_OPERATOR`]]))[0]?.n;
  assert.ok(typeof nonce === "string" && nonce.length >= 32, "nonce emitido");
  const exchangeRef = await enqueueStepUp(platform, principal, sha(nonce), `code-${randomUUID()}`, PKCE);
  assert.ok(typeof exchangeRef === "string", "solicitud encolada");
  assert.ok((await claimOwn(verifier, principal)).includes(exchangeRef!), "el verifier toma la solicitud");
  return { exchangeRef: exchangeRef!, nonce, nonceHash: sha(nonce), subHmac, principal };
}

/** issued_at exacto del nonce (microsegundos, tal como lo guarda la base) desplazado en segundos; devuelto como texto para no perder precision en JS. */
async function shifted(admin: Client, f: Flow, seconds: number): Promise<string> {
  return (await admin.query<{ t: string }>("SELECT (issued_at + make_interval(secs => $2))::text AS t FROM platform.action_nonce WHERE nonce_hash = $1", [f.nonceHash, seconds])).rows[0]!.t;
}

const record = async (verifier: Client, f: Flow, authTime: Date | string): Promise<boolean | undefined> =>
  (await call<{ ok: boolean }>(verifier, null, "SELECT platform.record_assertion($1::uuid, 'ATTESTED', NULL, $2, $3, $4::timestamptz, $5, $6::text[]) AS ok", [
    f.exchangeRef, f.subHmac, sha(`token-${f.exchangeRef}`), typeof authTime === "string" ? authTime : authTime.toISOString(), "urn:synthetic:test-mfa", ["pwd"],
  ]))[0]?.ok;

async function assertRejected(admin: Client, f: Flow, label: string): Promise<void> {
  const ga = (await admin.query<{ decision: string; reason_code: string | null }>("SELECT decision, reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [f.exchangeRef])).rows;
  assert.deepEqual(ga, [{ decision: "REJECTED", reason_code: "INVALID_CLAIMS" }], `${label}: aserciones`);
  assert.deepEqual((await admin.query("SELECT attested_at, consumed_at FROM platform.action_nonce WHERE nonce_hash = $1", [f.nonceHash])).rows, [{ attested_at: null, consumed_at: null }], `${label}: el nonce no se atesta ni se consume`);
  const ex = (await admin.query<{ status: string; code: string | null }>("SELECT status, code FROM platform.oidc_exchange WHERE exchange_ref = $1", [f.exchangeRef])).rows[0];
  assert.deepEqual(ex, { status: "REJECTED", code: null }, `${label}: solicitud cerrada sin secretos`);
  const chk = (await admin.query<{ decision: string; reason_code: string }>("SELECT decision, reason_code FROM platform.authorization_check WHERE principal_ref = $1 AND check_kind = 'RECORD_ASSERTION'", [f.principal])).rows;
  assert.deepEqual(chk, [{ decision: "DENY", reason_code: "INVALID_CLAIMS" }], `${label}: evidencia`);
}

async function assertAttested(admin: Client, f: Flow, label: string): Promise<void> {
  assert.ok((await admin.query<{ attested_at: Date | null }>("SELECT attested_at FROM platform.action_nonce WHERE nonce_hash = $1", [f.nonceHash])).rows[0]?.attested_at instanceof Date, `${label}: nonce atestado`);
  assert.deepEqual((await admin.query("SELECT decision, reason_code FROM platform.grant_assertion WHERE exchange_ref = $1", [f.exchangeRef])).rows, [{ decision: "ATTESTED", reason_code: null }], `${label}: asercion`);
}

pgTest("TEST-CNS-1394 pg: record_assertion exige reautenticacion fresca (auth_time >= issued_at del nonce - skew): anterior rechazado INVALID_CLAIMS; igual o posterior aceptado; skew y auth_time futuro", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platform = await ctx.connectAs("platform_rw");
  const verifier = await ctx.connectAs("integrity_verifier");

  // Contrato de la funcion: misma firma, dueno grant_owner, SECURITY DEFINER, search_path fijo, EXECUTE solo para integrity_verifier.
  const fn = (await admin.query<{ owner: string; prosecdef: boolean; proconfig: string[]; acl: string }>(
    `SELECT pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig,
            (SELECT string_agg(pg_get_userbyid(a.grantee), ',' ORDER BY pg_get_userbyid(a.grantee)) FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner) AS acl
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'platform' AND p.proname = 'record_assertion'`)).rows;
  assert.deepEqual(fn, [{ owner: "grant_owner", prosecdef: true, proconfig: ["search_path=pg_catalog, pg_temp"], acl: "integrity_verifier" }]);

  // (a) auth_time anterior al nonce (mas alla del skew): rechazado.
  const a = await startFlow(admin, platform, verifier, "a-old");
  assert.equal(await record(verifier, a, await shifted(admin, a, -SKEW_S - 1)), false);
  await assertRejected(admin, a, "anterior al nonce - skew");

  // (b) auth_time muy anterior (sesion vieja del IdP reutilizada): rechazado.
  const b = await startFlow(admin, platform, verifier, "b-stale");
  assert.equal(await record(verifier, b, await shifted(admin, b, -3600)), false);
  await assertRejected(admin, b, "una hora antes");

  // (c) igual a la emision del nonce: aceptado.
  const c = await startFlow(admin, platform, verifier, "c-equal");
  assert.equal(await record(verifier, c, await shifted(admin, c, 0)), true);
  await assertAttested(admin, c, "igual");

  // (d) posterior a la emision: aceptado.
  const d = await startFlow(admin, platform, verifier, "d-later");
  assert.equal(await record(verifier, d, await shifted(admin, d, 5)), true);
  await assertAttested(admin, d, "posterior");

  // (e) dentro del skew (apenas anterior): aceptado; la tolerancia es la constante de la funcion.
  const e = await startFlow(admin, platform, verifier, "e-skew");
  assert.equal(await record(verifier, e, await shifted(admin, e, -SKEW_S + 5)), true);
  await assertAttested(admin, e, "dentro del skew");

  // (f) se mantiene el rechazo de auth_time futuro (mas alla del skew).
  const f = await startFlow(admin, platform, verifier, "f-future");
  assert.equal(await record(verifier, f, new Date(Date.now() + 600_000)), false);
  await assertRejected(admin, f, "futuro");

  // (g) el rechazo es definitivo: la misma solicitud no se reabre con un auth_time valido (sin replay).
  assert.equal(await record(verifier, a, await shifted(admin, a, 1)), false);
  assert.equal((await admin.query("SELECT 1 FROM platform.grant_assertion WHERE exchange_ref = $1", [a.exchangeRef])).rowCount, 1);

  // (h) reintento: tras el rechazo el nonce sigue vigente; un exchange NUEVO sobre el mismo nonce con auth_time fresco lo atesta.
  const retryRef = await enqueueStepUp(platform, a.principal, a.nonceHash, `code-${randomUUID()}`, PKCE);
  assert.ok(typeof retryRef === "string" && retryRef !== a.exchangeRef, "nuevo exchange para el mismo nonce");
  assert.ok((await claimOwn(verifier, a.principal)).includes(retryRef!), "el verifier toma el reintento");
  assert.equal(await record(verifier, { ...a, exchangeRef: retryRef! }, await shifted(admin, a, 1)), true);
  await assertAttested(admin, { ...a, exchangeRef: retryRef! }, "reintento fresco");
});
