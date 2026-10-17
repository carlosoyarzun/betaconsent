// Gobierna: ADR-010 rev. 6 §1 (rol integrity_chain_verifier: 17 columnas, policy unica cross-tenant, FORCE RLS, sin DML/EXECUTE), §2 (recomputo en una tx RR READ ONLY, asserts C5/C6, exit 0/2/1, aislamiento C8, log sin PII),
// §3 fila PR-6f, F-PR6E-06, SEC-06-1/3/4/5, INV-DBR-01/02/03; db/migrations/0072-0073; specs/db-roles.spec.yaml. SYNTHETIC ONLY.
// TEST-CNS-1739 (forma exacta 0072/0073 e idempotencia), 1740 (cross-tenant sin GUC; app_rw aislado), 1741 (cadena real integra: exit 0 por el entrypoint), 1753 (paridad canonical_json SQL ≡ TS),
// 1742 (payload/sobre alterado, hueco: exit 2), 1743 (aislamiento por tenant), 1751 (MALFORMED_PAYLOAD), 1752 (aggregate_id hostil no forja lineas), 1744 (sin DML, sin SET ROLE, sin CREATE),
// 1747 (sin DML ni en tx READ WRITE), 1748 (sin SELECT en otras tablas/secuencias/funciones/esquemas), 1749 (event_id/evidentiary/data_class y SELECT * = 42501), 1745 (regresion: el reconciler sigue con 7 columnas),
// 1757 (sesion read-only y application_name; sin pg_authid), 1756 (trip-wire CHECK SYNTHETIC), 1738 pg (arranque con rol equivocado), 1750 (policy/FORCE RLS/privilegios alterados = exit 1), 1758 (exit 1 sin filtrar detalles).
// Los tests que corrompen el ledger usan tenants propios y van al final. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Client } from "pg";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { ChainVerifierPreconditionError } from "../../../src/infra/adapters/postgres/chain-verifier-reader.ts";
import { openProcessPool, ProcessRoleError } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { canonicalJson } from "../../../src/server/modules/common/ledger-chain.ts";
import { startChainVerifierProcess } from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";
import { CHAIN_VERIFIER_EXIT, exitCodeFor, formatChainReport } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { ChainAuditReport } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest, type PgTestContext } from "./harness.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const CHAIN_COLS = ["tenant_id", "chain_seq", "aggregate_type", "aggregate_id", "sequence", "event_type", "actor_type", "actor_role", "recorded_by_ref", "cosigned_by_ref", "idempotency_key_hash",
  "occurred_at", "environment", "payload", "payload_hash", "previous_event_hash", "event_hash"];
const SCHEMAS = "('app', 'ops', 'platform', 'integrity', 'case_state', 'ledger_gen', 'tenant_resolve', 'pii')";

async function withApp<T>(ctx: PgTestContext, fn: (uow: PgUnitOfWork) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    return await fn(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

/** Invitacion legitima por el camino real (triggers de ledger_gen): DRAFT -> READY -> SENT. */
async function driveInvitation(ctx: PgTestContext, T: string, key: string): Promise<string> {
  const inv = fixtureUuid(`inv-${key}`);
  const base: InvitationRecord = { invitationRef: inv, tenantId: T, contextRef: "C", productRef: "P", subjectRef: fixtureUuid(`sub-${key}`), state: "DRAFT", enrollmentRef: fixtureUuid(`en-${key}`), participationRef: fixtureUuid(`pa-${key}`) };
  const ready: InvitationRecord = { ...base, state: "READY", consentVersion: "v1", expiresAt: new Date("2030-02-03T04:05:06.789Z"), recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: "a@example.invalid" };
  const sent: InvitationRecord = { ...ready, state: "SENT", tokenHash: sha(`tok-${key}`), deliveryChannel: "CONSENT_APP_EMAIL" };
  await withApp(ctx, async (uow) => {
    for (const s of [base, ready, sent]) await uow.inTenant(T, (tx) => tx.invitationRepo.save(s));
  });
  return inv;
}

const envFor = (ctx: PgTestContext, extra: Record<string, string> = {}): Record<string, string> => ({ CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_chain_verifier"), ...extra });

async function runVerifier(ctx: PgTestContext): Promise<ChainAuditReport> {
  const proc = await startChainVerifierProcess({ env: envFor(ctx) });
  try {
    return await proc.run();
  } finally {
    await proc.stop();
  }
}

/** Ejecuta el entrypoint real (main.ts) como subproceso con entorno minimo: devuelve exit code y salidas. */
function runMain(ctx: PgTestContext, extra: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [join(ROOT, "src/server/entrypoints/chain-verifier/main.ts")], { env: { PATH: process.env.PATH ?? "", ...envFor(ctx, extra) }, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
const resultOf = (r: ChainAuditReport, t: string) => r.results.find((x) => x.tenantId === t);

/** Corrompe el ledger de la base DESCARTABLE del archivo: deshabilita el trigger de inmutabilidad solo durante `work` y lo deja ENABLE ALWAYS. Solo tests. */
async function tamper(admin: Client, work: () => Promise<void>): Promise<void> {
  await admin.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER audit_event_no_update_delete");
  try {
    await work();
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete");
  }
}

const A = fixtureUuid("t6f-a");
const B = fixtureUuid("t6f-b");

pgTest("TEST-CNS-1739 pg: 0072/0073: integrity_chain_verifier = LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT sin membresias, read-only y timeouts finitos; SELECT exacto de las 17 columnas; 1 policy; FORCE RLS; idempotente", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const role = (await admin.query<{ rolcanlogin: boolean; rolsuper: boolean; rolbypassrls: boolean; rolcreatedb: boolean; rolcreaterole: boolean; rolreplication: boolean; rolinherit: boolean; rolconfig: string[] }>(
    "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolinherit, rolconfig FROM pg_roles WHERE rolname = 'integrity_chain_verifier'")).rows[0]!;
  assert.deepEqual([role.rolcanlogin, role.rolsuper, role.rolbypassrls, role.rolcreatedb, role.rolcreaterole, role.rolreplication, role.rolinherit], [true, false, false, false, false, false, false]);
  for (const s of ["default_transaction_read_only=on", "idle_in_transaction_session_timeout=120s", "statement_timeout=120s"]) assert.ok(role.rolconfig.includes(s), s);
  assert.equal((await admin.query("SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles x ON x.oid = m.member WHERE r.rolname = 'integrity_chain_verifier' OR x.rolname = 'integrity_chain_verifier'")).rowCount, 0);
  const cols = (await admin.query<{ c: string }>(
    `SELECT string_agg(a.attname, ',' ORDER BY a.attname COLLATE "C") AS c FROM pg_attribute a WHERE a.attrelid = 'integrity.audit_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped
        AND has_column_privilege('integrity_chain_verifier', a.attrelid, a.attname, 'SELECT')`)).rows[0]?.c;
  assert.equal(cols, [...CHAIN_COLS].sort((x, y) => (x < y ? -1 : 1)).join(","));
  const pol = (await admin.query<{ polname: string; polcmd: string; polpermissive: boolean; q: string; roles: string[] }>(
    `SELECT p.polname, p.polcmd, p.polpermissive, pg_get_expr(p.polqual, p.polrelid) AS q, ARRAY(SELECT pg_get_userbyid(r)::text FROM unnest(p.polroles) r) AS roles FROM pg_policy p
      WHERE p.polrelid = 'integrity.audit_event'::regclass AND ((SELECT oid FROM pg_roles WHERE rolname = 'integrity_chain_verifier') = ANY (p.polroles) OR 0 = ANY (p.polroles))`)).rows;
  assert.deepEqual(pol.map((p) => [p.polname, p.polcmd, p.polpermissive, p.q, p.roles]), [["audit_event_chain_verifier_select", "r", true, "true", ["integrity_chain_verifier"]]]);
  assert.equal((await admin.query("SELECT 1 FROM pg_policy WHERE (SELECT oid FROM pg_roles WHERE rolname = 'integrity_chain_verifier') = ANY (polroles)")).rowCount, 1, "una sola policy en todo el catalogo");
  const rls = (await admin.query<{ f: boolean; e: boolean }>("SELECT relforcerowsecurity AS f, relrowsecurity AS e FROM pg_class WHERE oid = 'integrity.audit_event'::regclass")).rows[0]!;
  assert.deepEqual([rls.e, rls.f], [true, true]);
  // Esquemas: USAGE en integrity y ops (app se revoca en 0074, SEC-6F-03); en ningun otro de dominio.
  const usage = (await admin.query<{ nspname: string }>(`SELECT nspname FROM pg_namespace WHERE nspname IN ${SCHEMAS} AND has_schema_privilege('integrity_chain_verifier', oid, 'USAGE') ORDER BY 1`)).rows.map((r) => r.nspname);
  assert.deepEqual(usage, ["integrity", "ops"]);
  // Idempotencia: 0072 (cluster, superusuario) y 0073 (base, migrador) se pueden re-ejecutar sin cambiar el estado.
  const sql72 = readFileSync(join(MIGRATIONS_DIR, "0072_adr010_pr6f_chain_verifier_role.sql"), "utf8");
  const sql73 = readFileSync(join(MIGRATIONS_DIR, "0073_adr010_pr6f_chain_verifier_ledger_select.sql"), "utf8");
  await ctx.withRoleCatalogLock(async () => {
    await admin.query(sql72);
  });
  const migrator = await ctx.connectAs("consent_migrator");
  // PR-7c (0082): app es de app_schema_owner y consent_owner ya no puede re-conceder USAGE; para reproducir el orden real del deploy (0073 -> 0074, cuando app aun era de consent_owner) se devuelve el dueño solo durante el replay.
  await admin.query("ALTER SCHEMA app OWNER TO consent_owner");
  await migrator.query("BEGIN");
  try {
    await migrator.query(sql73);
    await migrator.query(readFileSync(join(MIGRATIONS_DIR, "0074_adr010_pr7a_chain_verifier_no_app_usage.sql"), "utf8")); // 0073 re-concede USAGE de app; 0074 lo revoca (orden real del deploy)
    await migrator.query("COMMIT");
  } catch (e) {
    await migrator.query("ROLLBACK");
    throw e;
  } finally {
    await admin.query("ALTER SCHEMA app OWNER TO app_schema_owner");
      await admin.query("GRANT USAGE, CREATE ON SCHEMA app TO consent_owner"); // ALTER OWNER fusiona/pierde las entradas ACL propias: se restaura la ACL del esquema
  }
  assert.equal((await admin.query("SELECT 1 FROM pg_policy WHERE polname = 'audit_event_chain_verifier_select'")).rowCount, 1);
});

pgTest("TEST-CNS-1740 pg: cross-tenant correcto: el chain-verifier lee todos los tenants SIN GUC; app_rw solo el suyo (y nada sin contexto)", async (ctx) => {
  await driveInvitation(ctx, A, "1740-a");
  await driveInvitation(ctx, B, "1740-b");
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const seen = (await ver.query<{ tenant_id: string }>("SELECT DISTINCT tenant_id FROM integrity.audit_event WHERE tenant_id IN ($1, $2) ORDER BY 1", [A, B])).rows.map((r) => r.tenant_id).sort();
  assert.deepEqual(seen, [A, B].sort());
  assert.equal((await ver.query<{ t: string | null }>("SELECT current_setting('app.tenant_id', true) AS t")).rows[0]?.t ?? "", "");
  const rows = await ver.query(`SELECT ${CHAIN_COLS.join(", ")} FROM integrity.audit_event WHERE tenant_id = $1`, [A]);
  assert.ok(rows.rowCount! >= 3);
  await withApp(ctx, async (uow) => {
    const own = await uow.withTenantTx(A, (tx) => tx.query<{ tenant_id: string }>("SELECT DISTINCT tenant_id FROM integrity.audit_event"));
    assert.deepEqual(own.rows.map((r) => r.tenant_id), [A]);
  });
  assert.equal((await (await ctx.connectAs("app_rw")).query("SELECT 1 FROM integrity.audit_event")).rowCount, 0, "app_rw sin contexto no ve el ledger");
});

pgTest("TEST-CNS-1741 pg: cadena real (escrita por ledger_gen/case_state) integra: el entrypoint real sale con exit 0, con tenants/events/head en el log y sin PII", async (ctx) => {
  await driveInvitation(ctx, A, "1741-a");
  await driveInvitation(ctx, B, "1741-b");
  const report = await runVerifier(ctx);
  assert.equal(report.ok, true, JSON.stringify(report.results.filter((r) => r.broken)));
  assert.equal(exitCodeFor(report), CHAIN_VERIFIER_EXIT.OK);
  assert.ok(report.tenants >= 2 && report.events >= 6);
  for (const t of [A, B]) {
    const r = resultOf(report, t)!;
    assert.equal(r.broken, null);
    assert.equal(r.verified, r.events);
    assert.equal(r.head, r.events, "cabeza = ultimo chain_seq");
  }
  const main = runMain(ctx);
  assert.equal(main.status, 0, main.stderr);
  assert.match(main.stdout.split("\n")[0]!, /^chain_verify_run ok=true tenants=\d+ events=\d+ broken=0 unchained=0$/);
  assert.ok(main.stdout.includes(`chain_verify_tenant tenant=${A} head=`));
  assert.equal(main.stderr, "");
  assert.ok(!/[0-9a-f]{64}/i.test(main.stdout), "sin hashes en el log");
});

/** Muestra de payloads para la paridad TS<->SQL (generador con semilla fija): escapes, controles, U+2028, no-BMP, arrays y anidados. */
function sampleValues(): unknown[] {
  let seed = 0x6f6f6f;
  const rnd = (n: number): number => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % n;
  };
  const pool = ['"', "\\", "/", "\n", "\r", "\t", "\b", "\f", "\u0001", "\u001f", "\u007f", " ", " ", "é", "ñ", "日", "😀", "𝄞", "퟿", "", "￿", "a", "Z", "0", " ", "</", "{", "[", ":"];
  const str = (): string => Array.from({ length: rnd(8) }, () => pool[rnd(pool.length)]).join("");
  const gen = (depth: number): unknown => {
    const k = rnd(depth > 2 ? 5 : 7);
    if (k === 0) return str();
    if (k === 1) return rnd(2) === 0;
    if (k === 2) return null;
    if (k === 3) return rnd(1_000_000) - 500_000;
    if (k === 4) return Number.MAX_SAFE_INTEGER - rnd(10);
    if (k === 5) return Array.from({ length: rnd(4) }, () => gen(depth + 1));
    return Object.fromEntries(Array.from({ length: rnd(5) }, () => [str().replace(/[\ud800-\udfff]/g, "") || "k", gen(depth + 1)]));
  };
  const out: unknown[] = [{}, { a: 1, b: [1, 2, { c: null }] }, { [String.fromCharCode(0xffff)]: 2, [String.fromCharCode(0xe000)]: 1, [String.fromCharCode(0xd7ff)]: 4, b: 3 }];
  for (let i = 0; i < 400; i++) out.push({ v: gen(0), s: str() });
  return out;
}

pgTest("TEST-CNS-1753 pg: paridad property-based canonical_json SQL (ledger_gen y case_state) ≡ canonicalJson TS en 400+ payloads (escapes, controles, U+2028, no-BMP, arrays, anidados)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const samples = sampleValues();
  const mismatches: string[] = [];
  for (const [i, v] of samples.entries()) {
    const ts = canonicalJson(v);
    for (const fn of ["ledger_gen.canonical_json", "case_state.canonical_json"]) {
      const sql = (await admin.query<{ c: string }>(`SELECT ${fn}($1::jsonb) AS c`, [JSON.stringify(v)])).rows[0]?.c;
      if (sql !== ts) mismatches.push(`${fn} #${i}`);
    }
  }
  // Claves fuera del BMP: el SQL las RECHAZA a proposito (orden UTF-16 vs punto de codigo divergente): falla cerrado al escribir, nunca hash distinto.
  for (const fn of ["ledger_gen.canonical_json", "case_state.canonical_json"]) {
    await assert.rejects(() => admin.query(`SELECT ${fn}($1::jsonb)`, [JSON.stringify({ [String.fromCodePoint(0x1f600)]: 1, b: 2 })]), (e: unknown) => codeOf(e) === "22023", fn);
  }
  assert.deepEqual(mismatches, [], "el hash SQL y el hash TS deben coincidir (si no, falso positivo de exit 2)");
});

pgTest("TEST-CNS-1745 pg: regresion de 6e tras 0073: el reconciler sigue con EXACTAMENTE las 7 columnas y 42501 en payload/hashes/refs; verifier OIDC y platform_rw sin SELECT del ledger", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const cols = (await admin.query<{ c: string }>(
    `SELECT string_agg(a.attname, ',' ORDER BY a.attname COLLATE "C") AS c FROM pg_attribute a WHERE a.attrelid = 'integrity.audit_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped
        AND has_column_privilege('integrity_reconciler', a.attrelid, a.attname, 'SELECT')`)).rows[0]?.c;
  assert.equal(cols, "aggregate_id,aggregate_type,chain_seq,event_type,occurred_at,sequence,tenant_id");
  const rec = await ctx.connectAs("integrity_reconciler");
  for (const col of ["payload", "payload_hash", "previous_event_hash", "event_hash", "recorded_by_ref", "cosigned_by_ref", "idempotency_key_hash"]) {
    await assert.rejects(() => rec.query(`SELECT ${col} FROM integrity.audit_event`), (e: unknown) => codeOf(e) === "42501", col);
  }
  for (const r of ["integrity_verifier", "platform_rw", "worker"]) {
    if (r === "worker") continue; // el worker lee por tenant (0042): fuera de este assert
    assert.equal((await admin.query("SELECT has_any_column_privilege($1, 'integrity.audit_event', 'SELECT') AS s", [r])).rows[0]?.s, false, r);
  }
  const verifier = await ctx.connectAs("integrity_verifier");
  await assert.rejects(() => verifier.query("SELECT tenant_id FROM integrity.audit_event"), (e: unknown) => codeOf(e) === "42501");
});

pgTest("TEST-CNS-1744 pg: el chain-verifier da 42501 al escribir (INSERT/UPDATE/DELETE/TRUNCATE) en el ledger y en app.*, al hacer SET ROLE, session_replication_role, ejecutar funciones y crear objetos", async (ctx) => {
  const ver = await ctx.connectAs("integrity_chain_verifier");
  await ver.query("SET default_transaction_read_only = off"); // el CONTROL son los privilegios, no la bandera
  const denied = async (sql: string, label: string): Promise<void> => {
    await assert.rejects(() => ver.query(sql), (e: unknown) => codeOf(e) === "42501", label);
  };
  await denied(`INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES ('${fixtureUuid("t1744")}', 'Tenant', 'x', 1, 'TENANT_SEEDED', 'FIXTURE', '{}')`, "INSERT ledger");
  await denied("UPDATE integrity.audit_event SET payload = '{}'::jsonb", "UPDATE ledger");
  await denied("DELETE FROM integrity.audit_event", "DELETE ledger");
  await denied("TRUNCATE integrity.audit_event", "TRUNCATE ledger");
  await denied("UPDATE app.invitation SET state = 'CANCELLED'", "UPDATE invitation");
  await denied("DELETE FROM app.invitation", "DELETE invitation");
  await denied("INSERT INTO ops.db_catalog (data_class, environment) VALUES ('SYNTHETIC', 'LOCAL')", "INSERT db_catalog");
  await denied("UPDATE ops.db_catalog SET environment = 'DEV'", "UPDATE db_catalog");
  for (const r of ["ledger_writer", "transition_owner", "integrity_owner", "consent_owner", "app_rw", "integrity_verifier", "integrity_reconciler"]) {
    await assert.rejects(() => ver.query(`SET ROLE ${r}`), (e: unknown) => codeOf(e) === "42501", `SET ROLE ${r}`);
  }
  await denied("SET session_replication_role = replica", "session_replication_role");
  await denied("SELECT platform.record_assertion(NULL::text, NULL::text, NULL::text, NULL::text, NULL::text)", "record_assertion");
  await denied("SELECT platform.claim_oidc_exchange(NULL::text)", "claim_oidc_exchange");
  await denied("SELECT case_state.apply_revocation('x', 0)", "apply_revocation");
  await denied("SELECT ledger_gen.seed_local_catalog_event('TENANT_SEEDED', 'x')", "seed_local_catalog_event");
  for (const s of ["app", "ops", "integrity", "public"]) await denied(`CREATE TABLE ${s}.x_1744 (a int)`, `CREATE en ${s}`);
});

pgTest("TEST-CNS-1747 pg: sin UPDATE/DELETE/INSERT/TRUNCATE en audit_event aun en una transaccion READ WRITE (el append-only no es la unica barrera)", async (ctx) => {
  const ver = await ctx.connectAs("integrity_chain_verifier");
  await ver.query("SET default_transaction_read_only = off");
  await ver.query("BEGIN READ WRITE");
  try {
    for (const sql of ["UPDATE integrity.audit_event SET evidentiary = false", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event", "UPDATE integrity.audit_event SET payload = payload"]) {
      await ver.query("SAVEPOINT s");
      await assert.rejects(() => ver.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
      await ver.query("ROLLBACK TO SAVEPOINT s");
    }
  } finally {
    await ver.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1748 pg: sin SELECT en ninguna otra tabla, vista, secuencia o funcion de integrity/app/ops/platform/case_state/ledger_gen (actuales) ni default privileges; esquemas ajenos sin USAGE", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const reads = (await admin.query<{ t: string }>(
    `SELECT n.nspname || '.' || c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ${SCHEMAS} AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND has_any_column_privilege('integrity_chain_verifier', c.oid, 'SELECT') ORDER BY 1`)).rows.map((r) => r.t);
  assert.deepEqual(reads, ["integrity.audit_event", "ops.db_catalog"]);
  const seq = await admin.query(`SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ${SCHEMAS} AND c.relkind = 'S' AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('integrity_chain_verifier', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END`);
  assert.equal(seq.rowCount, 0);
  const fns = await admin.query(`SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND has_function_privilege('integrity_chain_verifier', p.oid, 'EXECUTE')`);
  assert.equal(fns.rowCount, 0, "sin EXECUTE fuera de pg_catalog");
  assert.equal((await admin.query("SELECT 1 FROM pg_default_acl d WHERE d.defaclacl::text LIKE '%integrity_chain_verifier%'")).rowCount, 0, "default privileges vacios para el rol");
  const ver = await ctx.connectAs("integrity_chain_verifier");
  for (const t of ["app.invitation", "app.consent_decision", "app.outbox", "case_state.rights_case", "ops.security_event", "platform.principal_identity", "platform.oidc_exchange", "case_state.x", "pii.x", "tenant_resolve.handle"]) {
    await assert.rejects(() => ver.query(`SELECT 1 FROM ${t}`), (e: unknown) => (t === "case_state.x" || t === "pii.x" ? ["42501", "42P01", "3F000"] : ["42501"]).includes(codeOf(e) ?? ""), t);
  }
  for (const s of ["platform", "case_state", "ledger_gen", "tenant_resolve", "pii"]) {
    assert.equal((await admin.query("SELECT has_schema_privilege('integrity_chain_verifier', oid, 'USAGE') AS u FROM pg_namespace WHERE nspname = $1", [s])).rows[0]?.u ?? false, false, s);
  }
});

pgTest("TEST-CNS-1749 pg: event_id, evidentiary y data_class no son legibles (42501), ni SELECT * ni en WHERE", async (ctx) => {
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const denied = (sql: string) => assert.rejects(() => ver.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
  await denied("SELECT * FROM integrity.audit_event");
  for (const col of ["event_id", "evidentiary", "data_class"]) {
    await denied(`SELECT ${col} FROM integrity.audit_event`);
    await denied(`SELECT count(*) FROM integrity.audit_event WHERE ${col} IS NOT NULL`);
  }
  assert.equal(((await ver.query(`SELECT ${CHAIN_COLS.join(", ")} FROM integrity.audit_event LIMIT 1`)) as unknown as { fields: unknown[] }).fields.length, 17);
});

pgTest("TEST-CNS-1757 pg: la sesion del proceso tiene transaction_read_only=on y application_name=consent-chain-verifier; pg_authid denegado; el rol correcto pasa los chequeos de arranque y los equivocados no (1738)", async (ctx) => {
  const pool = await openProcessPool({ process: "chain-verifier", environment: "LOCAL", env: envFor(ctx), max: 1 });
  try {
    const c = await pool.connect();
    try {
      assert.equal((await c.query<{ v: string }>("SELECT current_setting('transaction_read_only') AS v")).rows[0]?.v, "on");
      assert.equal((await c.query<{ v: string }>("SELECT current_setting('application_name') AS v")).rows[0]?.v, "consent-chain-verifier");
      await assert.rejects(() => c.query("SELECT rolpassword FROM pg_authid"), (e: unknown) => codeOf(e) === "42501");
      assert.equal((await c.query("SELECT polname FROM pg_policy LIMIT 1")).rowCount! >= 0, true, "pg_policy es legible por PUBLIC (C6)");
    } finally {
      c.release();
    }
  } finally {
    await pool.end();
  }
  const ok = await ctx.connectAs("integrity_chain_verifier");
  assert.deepEqual((await runStartupChecks(ok, { expectedRole: "integrity_chain_verifier", expectedEnvironment: "LOCAL" })).failures, []);
  for (const role of ["integrity_verifier", "integrity_reconciler", "app_rw", "worker", "platform_rw", "consent_migrator"] as const) {
    const r = await runStartupChecks(await ctx.connectAs(role), { expectedRole: "integrity_chain_verifier", expectedEnvironment: "LOCAL" });
    assert.equal(r.ok, false, role);
    assert.ok(r.failures.some((f) => f.includes("integrity_chain_verifier")), role);
    await assert.rejects(() => startChainVerifierProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor(role) } }), ProcessRoleError, role);
  }
  const su = await ctx.connectAsSuperuser();
  assert.equal((await runStartupChecks(su, { expectedRole: "integrity_chain_verifier", expectedEnvironment: "LOCAL" })).ok, false);
  await assert.rejects(() => startChainVerifierProcess({ env: { ...envFor(ctx), CNS_ENVIRONMENT: "DEV" } }), /catálogo|catalogo|environment/);
});

pgTest("TEST-CNS-1756 pg: trip-wire C2: mientras integrity_chain_verifier tenga SELECT(payload), audit_event_data_class_synthetic CHECK (data_class = 'SYNTHETIC') debe existir (solo Carlos lo cambia con la DEC-BR de datos reales)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const sees = (await admin.query<{ s: boolean }>("SELECT has_column_privilege('integrity_chain_verifier', 'integrity.audit_event', 'payload', 'SELECT') AS s")).rows[0]?.s;
  const check = (await admin.query<{ d: string }>("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'integrity.audit_event'::regclass AND conname = 'audit_event_data_class_synthetic'")).rows[0]?.d;
  if (sees === true) assert.match(check ?? "", /data_class = 'SYNTHETIC'/, "sin el CHECK SYNTHETIC el chain-verifier leeria seudonimos de datos reales: bloqueado hasta LG-9");
  assert.equal((await admin.query<{ s: boolean }>("SELECT has_any_column_privilege('integrity_verifier', 'integrity.audit_event', 'SELECT') AS s")).rows[0]?.s, false, "el verifier OIDC no lee audit_event");
});

// ---- A partir de aqui se corrompe el ledger (tenants propios). El resultado global es exit 2: se afirma por tenant. ----

const C = fixtureUuid("t6f-c"); // payload alterado
const D = fixtureUuid("t6f-d"); // sobre alterado
const E = fixtureUuid("t6f-e"); // hueco
const F = fixtureUuid("t6f-f"); // payload no canonicalizable
const G = fixtureUuid("t6f-g"); // aggregate_id hostil
const H = fixtureUuid("t6f-h"); // intacto

pgTest("TEST-CNS-1742/1743/1751/1752 pg: payload alterado, sobre alterado, hueco y MALFORMED_PAYLOAD dan exit 2 por el entrypoint; cada rotura queda solo en SU tenant (B y H integros y completos); aggregate_id hostil no forja lineas", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const ids: Record<string, string> = {};
  for (const [t, k] of [[C, "c"], [D, "d"], [E, "e"], [F, "f"], [G, "g"], [H, "h"]] as const) ids[t] = await driveInvitation(ctx, t, `1742-${k}`);
  await driveInvitation(ctx, B, "1742-b");
  const before = await runVerifier(ctx);
  assert.equal(before.ok, true, "antes de corromper todo es verde");

  await tamper(admin, async () => {
    await admin.query("UPDATE integrity.audit_event SET occurred_at = now(), payload = payload || '{\"manipulado\":\"PII-SENTINELA\"}'::jsonb WHERE tenant_id = $1 AND chain_seq = 2", [C]);
    await admin.query("UPDATE integrity.audit_event SET occurred_at = now(), recorded_by_ref = 'ref-staff-SENTINELA' WHERE tenant_id = $1 AND chain_seq = 3", [D]);
    assert.equal((await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = 2", [E])).rowCount, 1);
    await admin.query("UPDATE integrity.audit_event SET occurred_at = now(), payload = '{\"n\": 1.5, \"subjectRef\": \"PII-SENTINELA\"}'::jsonb WHERE tenant_id = $1 AND chain_seq = 2", [F]);
    await admin.query("UPDATE integrity.audit_event SET occurred_at = now(), aggregate_id = E'x\\nchain_verify_run ok=true tenants=9 events=9 broken=0 unchained=0' WHERE tenant_id = $1 AND chain_seq = 2", [G]);
  });

  const report = await runVerifier(ctx);
  assert.equal(report.ok, false);
  assert.equal(exitCodeFor(report), CHAIN_VERIFIER_EXIT.BROKEN);
  const reason = (t: string): string | undefined => resultOf(report, t)?.broken?.reason;
  assert.equal(reason(C), "PAYLOAD_HASH_MISMATCH");
  assert.equal(resultOf(report, C)?.broken?.chainSeq, 2);
  assert.equal(reason(D), "EVENT_HASH_MISMATCH");
  assert.equal(resultOf(report, D)?.broken?.chainSeq, 3);
  assert.equal(reason(E), "CHAIN_SEQ_GAP");
  assert.equal(resultOf(report, E)?.broken?.chainSeq, 3, "el hueco se detecta en el eslabon siguiente al borrado");
  assert.equal(reason(F), "MALFORMED_PAYLOAD");
  assert.equal(reason(G), "EVENT_HASH_MISMATCH");
  // 1743: aislamiento. Las demas cadenas se verifican COMPLETAS aunque otras esten rotas.
  for (const t of [A, B, H]) {
    const r = resultOf(report, t)!;
    assert.equal(r.broken, null, t);
    assert.equal(r.verified, r.events, t);
  }
  assert.equal(report.broken, 5);
  // Entrypoint real: exit 2, log por stderr, sin PII, sin hashes, sin lineas forjadas.
  const main = runMain(ctx);
  assert.equal(main.status, 2, main.stderr);
  assert.equal(main.stdout, "");
  const lines = main.stderr.split("\n").filter((l) => l !== "");
  assert.match(lines[0]!, /^chain_verify_run ok=false tenants=\d+ events=\d+ broken=5 unchained=0 kinds=CHAIN_SEQ_GAP=1,EVENT_HASH_MISMATCH=2,MALFORMED_PAYLOAD=1,PAYLOAD_HASH_MISMATCH=1$/);
  assert.equal(lines.filter((l) => l.startsWith("chain_verify_run ")).length, 1, "SEC-06-5: ninguna linea de resumen forjada");
  assert.ok(lines.some((l) => l.startsWith("chain_verify_break ") && l.includes(`tenant=${G}`) && l.includes("aggregate=?")), "aggregate_id hostil enmascarado");
  assert.ok(lines.includes(`chain_verify_tenant tenant=${H} head=${resultOf(report, H)!.head} events=${resultOf(report, H)!.events} verified=${resultOf(report, H)!.events} status=ok`));
  for (const secret of ["PII-SENTINELA", "ref-staff-SENTINELA", "manipulado", "example.invalid", "a@"]) assert.ok(!main.stderr.includes(secret), `el log filtra ${secret}`);
  assert.ok(!/[0-9a-f]{64}/i.test(main.stderr), "sin hashes");
  assert.ok(formatChainReport(report).every((l) => !/[\u0000-\u001f]/.test(l)));
});

pgTest("TEST-CNS-1750 pg: policy borrada, con USING distinto de true, con una RESTRICTIVE, sin FORCE RLS o sin privilegio de columna = exit 1 (no verde falso); restaurada vuelve a funcionar (SEC-06-3)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1750-a");
  const POL = "audit_event_chain_verifier_select";
  const restore = async (): Promise<void> => {
    await admin.query(`DROP POLICY IF EXISTS ${POL} ON integrity.audit_event`);
    await admin.query(`DROP POLICY IF EXISTS x_restrictive ON integrity.audit_event`);
    await admin.query(`CREATE POLICY ${POL} ON integrity.audit_event FOR SELECT TO integrity_chain_verifier USING (true)`);
    await admin.query("ALTER TABLE integrity.audit_event FORCE ROW LEVEL SECURITY");
    await admin.query("GRANT SELECT (event_hash) ON integrity.audit_event TO integrity_chain_verifier");
  };
  const expectExit1 = async (label: string, code: string): Promise<void> => {
    await assert.rejects(() => runVerifier(ctx), (e: unknown) => e instanceof ChainVerifierPreconditionError && e.code === code, label);
    const main = runMain(ctx);
    assert.equal(main.status, 1, `${label}: ${main.stdout}${main.stderr}`);
    assert.equal(main.stdout, "");
    // 1758: solo name/code; ni tablas, ni policies, ni nombres de roles, ni datos.
    assert.equal(main.stderr.trim(), `chain-verifier: no verifica (name=ChainVerifierPreconditionError code=${code})`, label);
    await restore();
  };
  // SEC-6F-01: mientras la tx del verifier esta abierta, el DDL concurrente sobre la policy / FORCE RLS espera (lock_timeout 55P03): lo asertado no cambia durante la corrida.
  const holder = await ctx.connectAs("integrity_chain_verifier");
  await holder.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  try {
    await holder.query("SELECT tenant_id FROM integrity.audit_event LIMIT 0");
    await admin.query("SET lock_timeout = '300ms'");
    for (const ddl of [`DROP POLICY ${POL} ON integrity.audit_event`, `ALTER POLICY ${POL} ON integrity.audit_event USING (false)`, "ALTER TABLE integrity.audit_event NO FORCE ROW LEVEL SECURITY",
      "CREATE POLICY x_restrictive ON integrity.audit_event AS RESTRICTIVE FOR SELECT TO integrity_chain_verifier USING (false)"]) {
      await assert.rejects(() => admin.query(ddl), (e: unknown) => codeOf(e) === "55P03", ddl);
    }
  } finally {
    await admin.query("RESET lock_timeout");
    await holder.query("ROLLBACK");
  }
  await admin.query(`DROP POLICY ${POL} ON integrity.audit_event`);
  await expectExit1("policy borrada", "POLICY_MISSING_OR_ALTERED");
  await admin.query(`DROP POLICY ${POL} ON integrity.audit_event`);
  await admin.query(`CREATE POLICY ${POL} ON integrity.audit_event FOR SELECT TO integrity_chain_verifier USING (tenant_id = '${A}')`);
  await expectExit1("USING distinto de true (filtra tenants en silencio)", "POLICY_MISSING_OR_ALTERED");
  await admin.query(`CREATE POLICY x_restrictive ON integrity.audit_event AS RESTRICTIVE FOR SELECT TO integrity_chain_verifier USING (tenant_id = '${A}')`);
  await expectExit1("RESTRICTIVE adicional", "POLICY_MISSING_OR_ALTERED");
  await admin.query(`CREATE POLICY x_restrictive ON integrity.audit_event AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false)`);
  await expectExit1("RESTRICTIVE PUBLIC", "POLICY_MISSING_OR_ALTERED");
  await admin.query("ALTER TABLE integrity.audit_event NO FORCE ROW LEVEL SECURITY");
  await expectExit1("sin FORCE RLS", "RLS_NOT_FORCED");
  await admin.query("REVOKE SELECT (event_hash) ON integrity.audit_event FROM integrity_chain_verifier");
  await expectExit1("sin privilegio de columna", "COLUMN_PRIVILEGE_MISSING");
  // Restaurada: vuelve a verificar y la cadena integra (los tenants corrompidos en el test anterior dan exit 2, no 1).
  const after = await runVerifier(ctx);
  assert.ok(after.tenants > 0);
  assert.equal(runMain(ctx).status, 2, "restaurada: vuelve a verificar; los tenants corrompidos del test anterior dan exit 2");
});
