// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: checkpoints y cabeza por tenant persistidos por el chain-verifier con INSERT solo para integrity_chain_verifier; raiz Merkle en el chain-verifier, sin firma; ancla y
// persistencia de la conciliacion como DDL antes del revoke), §4.5.1, F-PR6E-05 (truncamiento de cola), D-4 (retiro del CLI), plan PR-7 v3 (PR-7b: T-2, T-3, T-4, T-6, T-16, T-17), C-10 (Carlos, 2026-10-17), C-7 PENDIENTE
// (sin firma ni publicacion); db/migrations/0075-0079; specs/db-roles.spec.yaml rev. 0.7. SYNTHETIC ONLY.
// TEST-CNS-1774 (forma exacta de 0075-0079: ACL por rol, RLS, triggers ENABLE ALWAYS, funciones; 0079 falla cerrado ante un privilegio de mas), 1775 (la corrida persiste chain_run + checkpoints y la raiz coincide con una
// implementacion independiente; solo el chain-verifier inserta: 42501 para el resto), 1776 (el trigger rechaza cabezas inexistentes, regresivas o con otro hash; append-only incluso para superusuario), 1781 (CHECKs de chain_run;
// precondiciones y falla de escritura = exit 1), 1778 (copia local en StateDirectory 0600: siembra, base por delante, reescritura de checkpoints, archivo laxo), 1779 (reconcile_run: conteos sin PII, solo INSERT del reconciler),
// 1780 (anchor: encadenado, valida contra chain_run exit 0, signer sin acceso al ledger), 1777 (truncamiento de cola, reescritura bajo el testigo y tenant borrado = exit 2).
// Los tests que corrompen el ledger usan tenants propios y van al final. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Client } from "pg";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { ChainVerifierPreconditionError } from "../../../src/infra/adapters/postgres/chain-verifier-reader.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { startChainVerifierProcess } from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";
import { exitCodeFor, RECONCILER_EXIT, startReconcilerProcess } from "../../../src/server/entrypoints/reconciler/reconciler-process.ts";
import { exitCodeFor as chainExitCodeFor, type ChainAuditReport } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest, type PgTestContext } from "./harness.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const HEAD_LEAK = (text: string): boolean => /[0-9a-f]{64}/i.test(text);
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

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

async function runVerifier(ctx: PgTestContext, extra: Record<string, string> = {}): Promise<ChainAuditReport> {
  const proc = await startChainVerifierProcess({ env: envFor(ctx, extra) });
  try {
    return await proc.run();
  } finally {
    await proc.stop();
  }
}

function runMain(ctx: PgTestContext, extra: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [join(ROOT, "src/server/entrypoints/chain-verifier/main.ts")], { env: { PATH: process.env.PATH ?? "", ...envFor(ctx, extra) }, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Raiz Merkle de REFERENCIA, independiente de src/ (RFC 6962 §2.1, hoja = sha256(0x00 || "tenant:seq:hash"), nodo = sha256(0x01 || izq || der)). */
function referenceRoot(heads: Array<{ tenantId: string; chainSeq: number; eventHash: string }>): string {
  const h = (...b: Buffer[]): Buffer => createHash("sha256").update(Buffer.concat(b)).digest();
  const leaves = [...heads].sort((a, b) => (a.tenantId < b.tenantId ? -1 : 1)).map((x) => h(Buffer.from([0]), Buffer.from(`${x.tenantId}:${x.chainSeq}:${x.eventHash}`)));
  const mth = (l: Buffer[]): Buffer => {
    if (l.length === 1) return l[0]!;
    let k = 1;
    while (k * 2 < l.length) k *= 2;
    return h(Buffer.from([1]), mth(l.slice(0, k)), mth(l.slice(k)));
  };
  return (leaves.length === 0 ? h() : mth(leaves)).toString("hex");
}

/** Cabezas del ledger (por tenant) leidas como superusuario. */
async function ledgerHeads(admin: Client): Promise<Array<{ tenantId: string; chainSeq: number; eventHash: string }>> {
  const r = await admin.query<{ tenant_id: string; chain_seq: string; event_hash: string }>(
    "SELECT DISTINCT ON (e.tenant_id) e.tenant_id::text AS tenant_id, e.chain_seq::text AS chain_seq, e.event_hash FROM integrity.audit_event e WHERE e.chain_seq IS NOT NULL ORDER BY e.tenant_id, e.chain_seq DESC",
  );
  return r.rows.map((x) => ({ tenantId: x.tenant_id, chainSeq: Number(x.chain_seq), eventHash: x.event_hash }));
}

/** Corrompe el ledger de la base DESCARTABLE del archivo (trigger de inmutabilidad deshabilitado solo durante `work`). Solo tests. */
async function tamper(admin: Client, work: () => Promise<void>): Promise<void> {
  await admin.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER audit_event_no_update_delete");
  try {
    await work();
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete");
  }
}

const A = fixtureUuid("t7b-a");
const B = fixtureUuid("t7b-b");
const RUN_COLS = "run_id, started_at, environment, tenants, events, exit_code, leaf_count, merkle_root, merkle_format";
const RUN_ZERO = (id: string, root = "a".repeat(64)): unknown[] => [id, new Date().toISOString(), "LOCAL", 1, 3, 0, 1, root, "RFC6962-SHA256-V1"];

/** Ejecuta `work` en una tx READ WRITE del cliente (los roles de integridad son read-only por defecto). */
async function rw<T>(c: Client, work: () => Promise<T>): Promise<T> {
  await c.query("BEGIN READ WRITE");
  try {
    const out = await work();
    await c.query("COMMIT");
    return out;
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  }
}

const ALL_TABLES = ["chain_run", "chain_checkpoint", "reconcile_run", "anchor"];

pgTest("TEST-CNS-1774 pg: forma exacta de 0075-0079: signer NOLOGIN sin membresias y con 3 settings; ACL por rol; RLS FORCE; triggers ENABLE ALWAYS; funciones SECURITY INVOKER sin EXECUTE; 0075 idempotente y 0079 re-ejecutable", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const role = (await admin.query<{ rolcanlogin: boolean; rolsuper: boolean; rolbypassrls: boolean; rolcreatedb: boolean; rolcreaterole: boolean; rolreplication: boolean; rolinherit: boolean; rolconfig: string[] }>(
    "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolinherit, rolconfig FROM pg_roles WHERE rolname = 'integrity_anchor_signer'")).rows[0]!;
  assert.deepEqual([role.rolcanlogin, role.rolsuper, role.rolbypassrls, role.rolcreatedb, role.rolcreaterole, role.rolreplication, role.rolinherit], [false, false, false, false, false, false, false], "NOLOGIN hasta PR-7f (T-17)");
  assert.deepEqual([...role.rolconfig].sort(), ["default_transaction_read_only=on", "idle_in_transaction_session_timeout=30s", "statement_timeout=30s"]);
  assert.equal((await admin.query("SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles x ON x.oid = m.member WHERE r.rolname = 'integrity_anchor_signer' OR x.rolname = 'integrity_anchor_signer'")).rowCount, 0, "sin membresias");
  // Dueno, RLS y triggers.
  for (const t of ALL_TABLES) {
    const c = (await admin.query<{ owner: string; rls: boolean; force: boolean }>(
      "SELECT pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls, c.relforcerowsecurity AS force FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND c.relname = $1", [t])).rows[0]!;
    assert.deepEqual([c.owner, c.rls, c.force], ["integrity_owner", true, true], t);
    const tg = await admin.query<{ tgenabled: string }>("SELECT tgenabled FROM pg_trigger WHERE tgrelid = ('integrity.' || $1)::regclass AND NOT tgisinternal", [t]);
    assert.ok(tg.rowCount! >= 2 && tg.rows.every((x) => x.tgenabled === "A"), `${t}: todos los triggers ENABLE ALWAYS`);
  }
  // Funciones: SECURITY INVOKER, de integrity_owner, sin EXECUTE para ningun rol de runtime.
  const fns = (await admin.query<{ proname: string; prosecdef: boolean; owner: string }>(
    "SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'integrity' AND p.proname IN ('append_only_guard', 'chain_checkpoint_guard', 'reconcile_run_guard', 'anchor_guard') ORDER BY 1")).rows;
  assert.deepEqual(fns.map((f) => [f.proname, f.prosecdef, f.owner]), [["anchor_guard", false, "integrity_owner"], ["append_only_guard", false, "integrity_owner"], ["chain_checkpoint_guard", false, "integrity_owner"], ["reconcile_run_guard", false, "integrity_owner"]]);
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier", "integrity_anchor_signer", "consent_migrator", "consent_owner"]) {
    assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'integrity' AND has_function_privilege($1, p.oid, 'EXECUTE')", [r])).rowCount, 0, `${r}: sin EXECUTE en integrity`);
  }
  // Matriz de privilegios por rol y tabla (cualquier columna). Todo lo no listado esta denegado, incluidos el migrador y los owners.
  const privs = async (r: string, t: string, p: string): Promise<boolean> =>
    (await admin.query<{ x: boolean }>("SELECT has_any_column_privilege($1, ('integrity.' || $2)::regclass, $3) AS x", [r, t, p])).rows[0]!.x;
  const expected: Record<string, Record<string, string[]>> = {
    integrity_chain_verifier: { chain_run: ["INSERT"], chain_checkpoint: ["INSERT", "SELECT"] },
    integrity_reconciler: { reconcile_run: ["INSERT"] },
    integrity_anchor_signer: { chain_run: ["SELECT"], chain_checkpoint: ["SELECT"], anchor: ["INSERT", "SELECT"] },
  };
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier", "integrity_anchor_signer", "consent_migrator", "consent_owner"]) {
    for (const t of ALL_TABLES) {
      for (const p of ["SELECT", "INSERT", "UPDATE", "REFERENCES"]) assert.equal(await privs(r, t, p), (expected[r]?.[t] ?? []).includes(p), `${r} ${p} ${t}`);
      for (const p of ["DELETE", "TRUNCATE", "TRIGGER"]) assert.equal((await admin.query<{ x: boolean }>("SELECT has_table_privilege($1, ('integrity.' || $2)::regclass, $3) AS x", [r, t, p])).rows[0]!.x, false, `${r} ${p} ${t}`);
    }
  }
  assert.equal((await admin.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a WHERE n.nspname = 'integrity' AND c.relname = ANY ($1) AND a.grantee = 0", [ALL_TABLES])).rowCount, 0, "sin grants a PUBLIC");
  // El firmante no toca el ledger ni app/ops.
  assert.equal((await admin.query<{ x: boolean }>("SELECT has_any_column_privilege('integrity_anchor_signer', 'integrity.audit_event', 'SELECT,INSERT,UPDATE,REFERENCES') AS x")).rows[0]!.x, false);
  assert.deepEqual((await admin.query<{ n: string }>("SELECT nspname AS n FROM pg_namespace WHERE nspname IN ('app', 'ops', 'platform', 'case_state', 'ledger_gen') AND has_schema_privilege('integrity_anchor_signer', oid, 'USAGE')")).rows, []);
  // 0075 es idempotente (corre en cada deploy de cluster) y no cambia el estado; 0079 se puede re-ejecutar (solo aserciones).
  const sql75 = readFileSync(join(MIGRATIONS_DIR, "0075_adr010_pr7b_anchor_signer_role.sql"), "utf8");
  await ctx.withRoleCatalogLock(async () => {
    await admin.query(sql75);
    await admin.query(sql75);
  });
  assert.equal((await admin.query<{ rolcanlogin: boolean }>("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'integrity_anchor_signer'")).rows[0]!.rolcanlogin, false);
  const sql79 = readFileSync(join(MIGRATIONS_DIR, "0079_adr010_pr7b_runtime_privilege_assertions.sql"), "utf8");
  await admin.query(sql79);
  // 0079 falla cerrado ante un privilegio de mas (tx revertida).
  for (const [grant, why] of [
    ["GRANT INSERT ON integrity.chain_run TO app_rw", "otro rol con INSERT"],
    ["GRANT SELECT ON integrity.audit_event TO integrity_anchor_signer", "el firmante lee el ledger"],
    ["GRANT EXECUTE ON FUNCTION integrity.anchor_guard() TO integrity_chain_verifier", "EXECUTE en el verifier"],
    ["GRANT UPDATE (anchor_hash) ON integrity.anchor TO integrity_chain_verifier", "UPDATE de columna"],
    ["GRANT SELECT ON integrity.chain_run TO integrity_chain_verifier", "SELECT de chain_run por el verifier"],
    ["GRANT SELECT ON integrity.reconcile_run TO integrity_reconciler", "el reconciler lee su propia tabla"],
    ["GRANT INSERT ON integrity.anchor TO integrity_chain_verifier", "el verifier inserta anclas"],
  ] as const) {
    await admin.query("BEGIN");
    try {
      await admin.query(grant);
      await assert.rejects(() => admin.query(sql79), (e: unknown) => /0079/.test((e as Error).message), why);
    } finally {
      await admin.query("ROLLBACK");
    }
  }
});

pgTest("TEST-CNS-1775 pg: la corrida persiste chain_run + un checkpoint por tenant OK; la raiz Merkle coincide con una implementacion independiente; solo integrity_chain_verifier inserta (42501 para el resto); sin PII ni hashes en el log", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1775-a");
  await driveInvitation(ctx, B, "1775-b");
  const report = await runVerifier(ctx);
  assert.equal(report.ok, true, JSON.stringify(report.anomalies));
  const heads = await ledgerHeads(admin);
  assert.ok(heads.length >= 2);
  const run = (await admin.query<{ run_id: string; environment: string; tenants: number; events: string; exit_code: number; leaf_count: number; merkle_root: string; merkle_format: string; finished_at: Date; started_at: Date }>(
    "SELECT * FROM integrity.chain_run ORDER BY finished_at DESC LIMIT 1")).rows[0]!;
  assert.deepEqual([run.environment, run.exit_code, run.leaf_count, run.tenants, Number(run.events), run.merkle_format], ["LOCAL", 0, heads.length, report.tenants, report.events, "RFC6962-SHA256-V1"]);
  assert.equal(run.merkle_root, referenceRoot(heads), "raiz = implementacion independiente (RFC 6962)");
  const cps = (await admin.query<{ tenant_id: string; head_chain_seq: string; head_event_hash: string; verified_events: string; run_id: string }>(
    "SELECT tenant_id::text, head_chain_seq::text, head_event_hash, verified_events::text, run_id::text FROM integrity.chain_checkpoint WHERE run_id = $1 ORDER BY tenant_id", [run.run_id])).rows;
  assert.deepEqual(cps.map((c) => [c.tenant_id, Number(c.head_chain_seq), c.head_event_hash]), [...heads].sort((a, b) => (a.tenantId < b.tenantId ? -1 : 1)).map((h) => [h.tenantId, h.chainSeq, h.eventHash]));
  for (const c of cps) assert.equal(c.verified_events, c.head_chain_seq, "verified_events = eslabones verificados");
  // Segunda corrida: mismas cabezas -> otra chain_run con la MISMA raiz y otro juego de checkpoints (igual seq e igual hash es valido).
  assert.equal((await runVerifier(ctx)).ok, true);
  const roots = (await admin.query<{ merkle_root: string }>("SELECT merkle_root FROM integrity.chain_run WHERE exit_code = 0 ORDER BY finished_at")).rows.map((r) => r.merkle_root);
  assert.equal(roots.length, 2);
  assert.equal(roots[0], roots[1], "raiz estable sin cambios en el ledger");
  // Crece la cadena de A: la raiz cambia y el checkpoint avanza.
  await driveInvitation(ctx, A, "1775-a2");
  assert.equal((await runVerifier(ctx)).ok, true);
  const roots2 = (await admin.query<{ merkle_root: string }>("SELECT merkle_root FROM integrity.chain_run WHERE exit_code = 0 ORDER BY finished_at")).rows.map((r) => r.merkle_root);
  assert.notEqual(roots2[2], roots[1]);
  assert.equal(roots2[2], referenceRoot(await ledgerHeads(admin)));
  // Entrypoint real: exit 0, sin PII ni hashes ni tenants fuera del formato.
  const main = runMain(ctx);
  assert.equal(main.status, 0, main.stderr);
  assert.ok(!HEAD_LEAK(main.stdout + main.stderr), "sin hashes ni raiz en el log");

  // Solo el chain-verifier inserta: el resto, 42501 (incluidos migrador, owners, reconciler, verifier OIDC y firmante).
  const insRun = `INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ($1, now(), 'LOCAL', 0, 0, 0, 0, $2, 'RFC6962-SHA256-V1')`;
  const insCkp = "INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) VALUES ($1, $2, 1, $3, 1)";
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "consent_migrator"] as const) {
    const c = await ctx.connectAs(r);
    for (const [sql, params] of [[insRun, [randomUUID(), "a".repeat(64)]], [insCkp, [run.run_id, A, "a".repeat(64)]]] as const) {
      await assert.rejects(() => rw(c, () => c.query(sql, [...params])), (e: unknown) => codeOf(e) === "42501", `${r}`);
    }
    await assert.rejects(() => c.query("SELECT 1 FROM integrity.chain_checkpoint"), (e: unknown) => codeOf(e) === "42501", `${r} no lee checkpoints`);
  }
  for (const r of ["consent_owner", "integrity_anchor_signer"]) {
    await admin.query("BEGIN");
    try {
      await admin.query(`SET LOCAL ROLE ${r}`);
      await assert.rejects(() => admin.query(insRun, [randomUUID(), "a".repeat(64)]), (e: unknown) => codeOf(e) === "42501", r);
    } finally {
      await admin.query("ROLLBACK");
    }
  }
  // El verifier no actualiza, borra ni trunca (ni aun en READ WRITE); no lee chain_run (solo INSERT).
  const ver = await ctx.connectAs("integrity_chain_verifier");
  for (const sql of ["UPDATE integrity.chain_checkpoint SET verified_events = 1", "DELETE FROM integrity.chain_checkpoint", "TRUNCATE integrity.chain_checkpoint", "UPDATE integrity.chain_run SET tenants = 0", "DELETE FROM integrity.chain_run", "SELECT run_id FROM integrity.chain_run"]) {
    await assert.rejects(() => rw(ver, () => ver.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
  }
});

pgTest("TEST-CNS-1776 pg: el trigger de chain_checkpoint rechaza cabeza inexistente, regresiva o con otro hash en la misma secuencia; append-only incluso para el superusuario (con y sin session_replication_role)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1776-a");
  const head = (await ledgerHeads(admin)).find((h) => h.tenantId === A)!;
  assert.ok(head.chainSeq >= 3);
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const runId = randomUUID();
  await rw(ver, () => ver.query(`INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ($1, now(), 'LOCAL', 1, 3, 0, 1, $2, 'RFC6962-SHA256-V1')`, [runId, "a".repeat(64)]));
  const ins = (seq: number, hash: string, verified = 1): Promise<unknown> =>
    rw(ver, () => ver.query("INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) VALUES ($1, $2, $3, $4, $5)", [runId, A, seq, hash, verified]));
  const rejected = (label: string, seq: number, hash: string, verified?: number): Promise<void> => assert.rejects(() => ins(seq, hash, verified), (e: unknown) => codeOf(e) === "23514", label);
  await rejected("hash inexistente en esa secuencia", head.chainSeq, "b".repeat(64));
  await rejected("secuencia inexistente (futura)", head.chainSeq + 50, head.eventHash);
  await rejected("secuencia 0 / hash de otra secuencia", 1, head.eventHash);
  await assert.rejects(() => ins(head.chainSeq, head.eventHash, head.chainSeq + 1), (e: unknown) => codeOf(e) === "23514", "verified_events > head_chain_seq");
  await ins(head.chainSeq, head.eventHash, head.chainSeq);
  // Mismo tenant en el mismo run: PK. En otro run: la misma cabeza es valida (igual seq e igual hash).
  await assert.rejects(() => ins(head.chainSeq, head.eventHash, head.chainSeq), (e: unknown) => codeOf(e) === "23505");
  const run2 = randomUUID();
  await rw(ver, () => ver.query(`INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ($1, now(), 'LOCAL', 1, 3, 0, 1, $2, 'RFC6962-SHA256-V1')`, [run2, "c".repeat(64)]));
  await rw(ver, () => ver.query("INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) VALUES ($1, $2, $3, $4, $3)", [run2, A, head.chainSeq, head.eventHash]));
  // Regresion: una cabeza ANTERIOR (existe en el ledger) con un checkpoint posterior ya persistido se rechaza (la cola no puede retroceder).
  const earlier = (await admin.query<{ chain_seq: string; event_hash: string }>("SELECT chain_seq::text, event_hash FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = $2", [A, head.chainSeq - 1])).rows[0]!;
  const run3 = randomUUID();
  await rw(ver, () => ver.query(`INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ($1, now(), 'LOCAL', 1, 3, 0, 1, $2, 'RFC6962-SHA256-V1')`, [run3, "d".repeat(64)]));
  await assert.rejects(
    () => rw(ver, () => ver.query("INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) VALUES ($1, $2, $3, $4, $3)", [run3, A, Number(earlier.chain_seq), earlier.event_hash])),
    (e: unknown) => codeOf(e) === "23514" && /retroceder/.test((e as Error).message),
    "regresion de cabeza",
  );
  // FK: un checkpoint de un run inexistente no entra.
  await assert.rejects(() => rw(ver, () => ver.query("INSERT INTO integrity.chain_checkpoint (run_id, tenant_id, head_chain_seq, head_event_hash, verified_events) VALUES ($1, $2, $3, $4, $3)", [randomUUID(), A, head.chainSeq, head.eventHash])), (e: unknown) => codeOf(e) === "23503");
  // Append-only para el superusuario, tambien con replica (triggers ENABLE ALWAYS) y sin permitir DISABLE accidental.
  for (const replica of [false, true]) {
    if (replica) await admin.query("SET session_replication_role = replica");
    try {
      for (const sql of ["UPDATE integrity.chain_checkpoint SET verified_events = 1", "DELETE FROM integrity.chain_checkpoint", "TRUNCATE integrity.chain_checkpoint", "UPDATE integrity.chain_run SET tenants = 0", "DELETE FROM integrity.chain_run", "TRUNCATE integrity.chain_run"]) {
        await assert.rejects(() => admin.query(sql), (e: unknown) => ["23000", "0A000"].includes(codeOf(e) ?? ""), `superusuario (replica=${replica}): ${sql}`);
      }
    } finally {
      if (replica) await admin.query("SET session_replication_role = origin");
    }
  }
  assert.equal((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.chain_checkpoint WHERE run_id = ANY ($1::uuid[])", [[runId, run2, run3]])).rows[0]!.n, "2", "solo los dos validos entraron");
});

const mkStateDir = async (): Promise<string> => {
  const dir = await mkdtemp(join(tmpdir(), "cns-1778-"));
  await chmod(dir, 0o700);
  return dir;
};

pgTest("TEST-CNS-1781 pg: CHECKs de chain_run (raiz solo con exit 0, hojas <= tenants, enums) y fallas de escritura/precondiciones = exit 1 con name/code, sin sembrar nada", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1781-a");
  const ver = await ctx.connectAs("integrity_chain_verifier");
  const ins = (vals: unknown[]): Promise<unknown> => rw(ver, () => ver.query(`INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, vals));
  const bad = async (label: string, vals: unknown[], code = "23514"): Promise<void> => {
    await assert.rejects(() => ins(vals), (e: unknown) => codeOf(e) === code, label);
  };
  const ok = RUN_ZERO(randomUUID());
  await bad("exit 0 sin raiz", [randomUUID(), ok[1], "LOCAL", 1, 3, 0, 1, null, null]);
  await bad("exit 2 con raiz", [randomUUID(), ok[1], "LOCAL", 1, 3, 2, 0, "a".repeat(64), "RFC6962-SHA256-V1"]);
  await bad("exit 1 (error: no se persiste)", [randomUUID(), ok[1], "LOCAL", 1, 3, 1, 0, null, null]);
  await bad("raiz sin formato", [randomUUID(), ok[1], "LOCAL", 1, 3, 0, 1, "a".repeat(64), null]);
  await bad("raiz no hex", [randomUUID(), ok[1], "LOCAL", 1, 3, 0, 1, "Z".repeat(64), "RFC6962-SHA256-V1"]);
  await bad("hojas > tenants", [randomUUID(), ok[1], "LOCAL", 1, 3, 0, 2, "a".repeat(64), "RFC6962-SHA256-V1"]);
  await bad("exit 2 con hojas", [randomUUID(), ok[1], "LOCAL", 2, 3, 2, 1, null, null]);
  await bad("environment fuera del enum", [randomUUID(), ok[1], "PROD", 1, 3, 0, 1, "a".repeat(64), "RFC6962-SHA256-V1"]);
  await bad("tenants negativo", [randomUUID(), ok[1], "LOCAL", -1, 3, 0, 0, "a".repeat(64), "RFC6962-SHA256-V1"]);
  await ins(ok);
  await bad("run_id duplicado", ok, "23505");
  // finished_at lo fija la base: el verifier no puede insertarlo (42501), ni cambiar el run despues.
  await assert.rejects(() => rw(ver, () => ver.query("INSERT INTO integrity.chain_run (run_id, started_at, finished_at, environment, tenants, events, exit_code, leaf_count) VALUES ($1, now(), now(), 'LOCAL', 0, 0, 2, 0)", [randomUUID()])), (e: unknown) => codeOf(e) === "42501");
  // Un run de exit 2 valido (sin raiz) entra.
  await ins([randomUUID(), ok[1], "LOCAL", 2, 5, 2, 0, null, null]);

  // Precondiciones (exit 1): sin policy de SELECT de chain_checkpoint (verde falso), sin privilegio de INSERT, sin FORCE RLS.
  const expectExit1 = async (label: string, code: string, restore: () => Promise<void>): Promise<void> => {
    try {
      await assert.rejects(() => runVerifier(ctx), (e: unknown) => e instanceof ChainVerifierPreconditionError && e.code === code, label);
      const m = runMain(ctx);
      assert.equal(m.status, 1, `${label}: ${m.stdout}${m.stderr}`);
      assert.equal(m.stdout, "");
      assert.equal(m.stderr.trim(), `chain-verifier: no verifica (name=ChainVerifierPreconditionError code=${code})`, label);
    } finally {
      await restore();
    }
  };
  await admin.query("DROP POLICY chain_checkpoint_verifier_select ON integrity.chain_checkpoint");
  await expectExit1("policy de SELECT de checkpoints borrada", "CHECKPOINT_POLICY_MISSING_OR_ALTERED", () =>
    admin.query("CREATE POLICY chain_checkpoint_verifier_select ON integrity.chain_checkpoint FOR SELECT TO integrity_chain_verifier USING (true)").then(() => undefined));
  await admin.query("ALTER POLICY chain_run_verifier_insert ON integrity.chain_run WITH CHECK (false)");
  await expectExit1("policy de INSERT de chain_run alterada", "CHECKPOINT_POLICY_MISSING_OR_ALTERED", () =>
    admin.query("ALTER POLICY chain_run_verifier_insert ON integrity.chain_run WITH CHECK (true)").then(() => undefined));
  await admin.query("ALTER TABLE integrity.chain_checkpoint NO FORCE ROW LEVEL SECURITY");
  await expectExit1("checkpoints sin FORCE RLS", "RLS_NOT_FORCED", () => admin.query("ALTER TABLE integrity.chain_checkpoint FORCE ROW LEVEL SECURITY").then(() => undefined));
  await admin.query("REVOKE INSERT (merkle_root) ON integrity.chain_run FROM integrity_chain_verifier");
  await expectExit1("sin INSERT de merkle_root", "CHECKPOINT_PRIVILEGE_MISSING", () =>
    admin.query("GRANT INSERT (merkle_root) ON integrity.chain_run TO integrity_chain_verifier").then(() => undefined));
  // Falla de ESCRITURA tras pasar las precondiciones (sin INSERT de chain_checkpoint.verified_events -> la precondicion no lo mira): exit 1 y ni chain_run queda (tx unica).
  const before = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.chain_run")).rows[0]!.n);
  const beforeCkp = Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.chain_checkpoint")).rows[0]!.n);
  await admin.query("REVOKE INSERT (verified_events) ON integrity.chain_checkpoint FROM integrity_chain_verifier");
  try {
    await assert.rejects(() => runVerifier(ctx), (e: unknown) => codeOf(e) === "42501");
    const m = runMain(ctx);
    assert.equal(m.status, 1);
    assert.equal(m.stderr.trim(), "chain-verifier: no verifica (name=error code=42501)");
  } finally {
    await admin.query("GRANT INSERT (verified_events) ON integrity.chain_checkpoint TO integrity_chain_verifier");
  }
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.chain_run")).rows[0]!.n), before, "tx unica: la falla no deja chain_run huerfano");
  assert.equal(Number((await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.chain_checkpoint")).rows[0]!.n), beforeCkp, "ningun checkpoint sembrado");
});

pgTest("TEST-CNS-1778 pg: copia local de cabezas (StateDirectory 0600): LOCAL la siembra; la base por delante (caida entre commit y copia) es valida y se actualiza; una copia lax o corrupta = exit 2 sin sanarse; la copia sigue a la base", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1778-a");
  await driveInvitation(ctx, B, "1778-b");
  const dir = await mkStateDir();
  const file = join(dir, "heads.json");
  const env = { CNS_CHAIN_VERIFIER_STATE_DIR: dir };
  try {
    // Con checkpoints previos en la base y copia ausente, LOCAL resiembra (sin anomalia).
    assert.equal((await runVerifier(ctx)).ok, true, "corrida previa sin copia (crea checkpoints)");
    const r1 = await runVerifier(ctx, env);
    assert.equal(r1.ok, true, JSON.stringify(r1.anomalies));
    assert.equal((await lstat(file)).mode & 0o777, 0o600);
    const doc = JSON.parse(await readFile(file, "utf8")) as { version: number; environment: string; heads: Record<string, { chainSeq: number; eventHash: string }> };
    const heads = await ledgerHeads(admin);
    assert.deepEqual(Object.entries(doc.heads).map(([t, h]) => [t, h.chainSeq, h.eventHash]).sort(), heads.map((h) => [h.tenantId, h.chainSeq, h.eventHash]).sort());
    assert.equal(doc.environment, "LOCAL");
    // La cadena crece: la copia sigue a la base.
    await driveInvitation(ctx, A, "1778-a2");
    assert.equal((await runVerifier(ctx, env)).ok, true);
    const grown = JSON.parse(await readFile(file, "utf8")) as typeof doc;
    assert.ok(grown.heads[A]!.chainSeq > doc.heads[A]!.chainSeq);
    // Base por delante de la copia: la copia conserva una cabeza ANTERIOR valida (el commit llego y la copia no): sin anomalia y se actualiza.
    const earlier = (await admin.query<{ chain_seq: string; event_hash: string }>("SELECT chain_seq::text, event_hash FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = $2", [A, grown.heads[A]!.chainSeq - 1])).rows[0]!;
    const stale = JSON.parse(JSON.stringify(grown)) as typeof doc;
    stale.heads[A] = { chainSeq: Number(earlier.chain_seq), eventHash: earlier.event_hash };
    await rm(file);
    await writeFile(file, JSON.stringify(stale), { mode: 0o600 });
    const lag = await runVerifier(ctx, env);
    assert.equal(lag.ok, true, JSON.stringify(lag.anomalies));
    assert.equal((JSON.parse(await readFile(file, "utf8")) as typeof doc).heads[A]!.chainSeq, grown.heads[A]!.chainSeq, "la copia alcanza a la base");
    // Copia con permisos laxos: UNTRUSTED -> anomalia global, exit 2, NO se reescribe (no se sana sola).
    await chmod(file, 0o644);
    const loose = await runVerifier(ctx, env);
    assert.equal(loose.ok, false);
    assert.deepEqual(loose.anomalies, [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }]);
    assert.equal(chainExitCodeFor(loose), 2);
    assert.equal((await lstat(file)).mode & 0o777, 0o644, "no se reescribio ni se arreglo el modo");
    const m = runMain(ctx, env);
    assert.equal(m.status, 2, m.stderr);
    assert.match(m.stderr, /chain_verify_anomaly kind=CHECKPOINT_STATE_MISMATCH tenant=-/);
    assert.ok(!m.stderr.includes(dir) && !HEAD_LEAK(m.stderr), "sin ruta ni hashes");
    // chain_run de esa corrida: exit 2, sin raiz.
    const last = (await admin.query<{ exit_code: number; merkle_root: string | null }>("SELECT exit_code, merkle_root FROM integrity.chain_run ORDER BY finished_at DESC LIMIT 1")).rows[0]!;
    assert.deepEqual([last.exit_code, last.merkle_root], [2, null]);
    await chmod(file, 0o600);
    assert.equal((await runVerifier(ctx, env)).ok, true, "restaurado el modo vuelve a verde");
    // Copia corrupta (JSON roto): global y sin sanar.
    await writeFile(file, "{no es json", { mode: 0o600 });
    assert.deepEqual((await runVerifier(ctx, env)).anomalies, [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }]);
    assert.equal(await readFile(file, "utf8"), "{no es json", "no se sana sin intervencion humana");
    await rm(file);
    // Directorio inexistente: UNTRUSTED (global), sin crear nada.
    const gone = await runVerifier(ctx, { CNS_CHAIN_VERIFIER_STATE_DIR: join(dir, "nada") });
    assert.deepEqual(gone.anomalies, [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }]);
    // Sin la variable: el proceso opera solo con la base (LOCAL); STATE_DIR relativo no arranca.
    assert.equal((await runVerifier(ctx)).ok, true);
    await assert.rejects(() => startChainVerifierProcess({ env: envFor(ctx, { CNS_CHAIN_VERIFIER_STATE_DIR: "relativo" }) }), /CNS_CHAIN_VERIFIER_STATE_DIR/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

pgTest("TEST-CNS-1779 pg: el reconciler persiste UNA fila de conteos por corrida en reconcile_run (sin ids ni PII); solo el reconciler inserta; el trigger valida claves enum y suma; sin SELECT/UPDATE/DELETE", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1779-a");
  const run = async () => {
    const proc = await startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_reconciler") } });
    try {
      return await proc.run();
    } finally {
      await proc.stop();
    }
  };
  const report = await run();
  assert.equal(exitCodeFor(report), RECONCILER_EXIT.OK, JSON.stringify(report.byKind));
  const rows = (await admin.query<{ environment: string; tenants: number; events: string; divergences: number; divergences_by_code: Record<string, number>; exit_code: number }>("SELECT * FROM integrity.reconcile_run")).rows;
  assert.equal(rows.length, 1);
  assert.deepEqual([rows[0]!.environment, rows[0]!.tenants, Number(rows[0]!.events), rows[0]!.divergences, rows[0]!.divergences_by_code, rows[0]!.exit_code], ["LOCAL", report.tenants, report.events, 0, {}, 0]);
  // La tabla solo tiene columnas de conteo/tiempo: ni tenant, ni agregado, ni detail.
  const cols = (await admin.query<{ attname: string }>("SELECT attname FROM pg_attribute WHERE attrelid = 'integrity.reconcile_run'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum")).rows.map((r) => r.attname);
  assert.deepEqual(cols, ["run_id", "started_at", "finished_at", "environment", "tenants", "events", "divergences", "divergences_by_code", "exit_code"]);
  assert.equal((await run()).ok, true);
  assert.equal((await admin.query("SELECT 1 FROM integrity.reconcile_run")).rowCount, 2, "una fila por corrida");

  // Trigger de validacion (como el reconciler, en READ WRITE).
  const rec = await ctx.connectAs("integrity_reconciler");
  const insert = (divergences: number, byCode: unknown, exit = divergences === 0 ? 0 : 2): Promise<unknown> =>
    rw(rec, () => rec.query("INSERT INTO integrity.reconcile_run (run_id, started_at, environment, tenants, events, divergences, divergences_by_code, exit_code) VALUES ($1, now(), 'LOCAL', 1, 1, $2, $3::jsonb, $4)", [randomUUID(), divergences, JSON.stringify(byCode), exit]));
  await insert(3, { CHAIN_SEQ_GAP: 2, STATE_EVENT_MISMATCH: 1 });
  for (const [label, d, by] of [
    ["clave en minusculas", 1, { chain_seq_gap: 1 }],
    ["clave con id hostil", 1, { "abc-uuid-1234": 1 }],
    ["valor cero", 1, { CHAIN_SEQ_GAP: 0 }],
    ["valor no numerico", 1, { CHAIN_SEQ_GAP: "1" }],
    ["valor anidado", 1, { CHAIN_SEQ_GAP: { a: 1 } }],
    ["suma distinta", 5, { CHAIN_SEQ_GAP: 1 }],
    ["clave de 41 caracteres", 1, { [`${"A".repeat(41)}`]: 1 }],
  ] as const) {
    await assert.rejects(() => insert(d, by), (e: unknown) => codeOf(e) === "23514", label);
  }
  await assert.rejects(() => insert(0, [] as unknown), (e: unknown) => ["22023", "23514"].includes(codeOf(e) ?? ""), "no es objeto");
  await assert.rejects(() => insert(2, { CHAIN_SEQ_GAP: 2 }, 0), (e: unknown) => codeOf(e) === "23514", "exit 0 con divergencias");
  await assert.rejects(() => insert(0, {}, 2), (e: unknown) => codeOf(e) === "23514", "exit 2 sin divergencias");
  // Solo el reconciler inserta; nadie lee ni modifica.
  const stmt = "INSERT INTO integrity.reconcile_run (run_id, started_at, environment, tenants, events, divergences, divergences_by_code, exit_code) VALUES ($1, now(), 'LOCAL', 0, 0, 0, '{}', 0)";
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_chain_verifier", "consent_migrator"] as const) {
    const c = await ctx.connectAs(r);
    await assert.rejects(() => rw(c, () => c.query(stmt, [randomUUID()])), (e: unknown) => codeOf(e) === "42501", r);
  }
  for (const sql of ["SELECT run_id FROM integrity.reconcile_run", "UPDATE integrity.reconcile_run SET tenants = 0", "DELETE FROM integrity.reconcile_run", "TRUNCATE integrity.reconcile_run"]) {
    await assert.rejects(() => rw(rec, () => rec.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
  }
  // `INSERT ... RETURNING` tampoco (sin SELECT): el proceso real no lo usa.
  await assert.rejects(() => rw(rec, () => rec.query(`${stmt} RETURNING run_id`, [randomUUID()])), (e: unknown) => ["42501"].includes(codeOf(e) ?? ""));
  for (const sql of ["UPDATE integrity.reconcile_run SET tenants = 0", "DELETE FROM integrity.reconcile_run", "TRUNCATE integrity.reconcile_run"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario: ${sql}`);
  }
});

pgTest("TEST-CNS-1780 pg: integrity.anchor encadenada: valida contra una chain_run exit 0 (raiz, hojas y entorno), seq = ultima + 1 y prev = hash de la ultima; el firmante no lee el ledger ni columnas ajenas; append-only; (sin firma ni publicacion: C-7 pendiente)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, A, "1780-a");
  assert.equal((await runVerifier(ctx)).ok, true);
  const run = (await admin.query<{ run_id: string; merkle_root: string; leaf_count: number }>("SELECT run_id::text, merkle_root, leaf_count FROM integrity.chain_run WHERE exit_code = 0 ORDER BY finished_at DESC LIMIT 1")).rows[0]!;
  const failed = randomUUID();
  const ver = await ctx.connectAs("integrity_chain_verifier");
  await rw(ver, () => ver.query("INSERT INTO integrity.chain_run (run_id, started_at, environment, tenants, events, exit_code, leaf_count) VALUES ($1, now(), 'LOCAL', 1, 1, 2, 0)", [failed]));
  const SIG = "c2lnbmF0dXJlLXNpbnRldGljYS1zaW4tdmFsb3I=";
  const row = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ anchor_seq: 1, environment: "LOCAL", run_id: run.run_id, leaf_count: run.leaf_count, merkle_root: run.merkle_root, prev_anchor_hash: null, anchor_hash: "1".repeat(64), key_id: "k-synth-1", signature: SIG, format_version: 1, ...over });
  const cols = ["anchor_seq", "environment", "run_id", "leaf_count", "merkle_root", "prev_anchor_hash", "anchor_hash", "key_id", "signature", "format_version"];
  /** Como el firmante (SET LOCAL ROLE desde el superusuario del fixture: el rol es NOLOGIN hasta PR-7f). */
  const asSigner = async <T>(work: () => Promise<T>): Promise<T> => {
    await admin.query("BEGIN READ WRITE");
    try {
      await admin.query("SET LOCAL ROLE integrity_anchor_signer");
      const out = await work();
      await admin.query("COMMIT");
      return out;
    } catch (e) {
      await admin.query("ROLLBACK");
      throw e;
    }
  };
  const insert = (r: Record<string, unknown>): Promise<unknown> => asSigner(() => admin.query(`INSERT INTO integrity.anchor (${cols.join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`, cols.map((c) => r[c])));
  const rejects = async (label: string, r: Record<string, unknown>, code = "23514"): Promise<void> => {
    await assert.rejects(() => insert(r), (e: unknown) => codeOf(e) === code, label);
  };
  await rejects("raiz distinta de la de chain_run", row({ merkle_root: "e".repeat(64) }));
  await rejects("hojas distintas", row({ leaf_count: run.leaf_count + 1 }));
  await rejects("entorno distinto", row({ environment: "DEV" }));
  await rejects("run exit 2", row({ run_id: failed }));
  await rejects("run inexistente", row({ run_id: randomUUID() }));
  await rejects("primera ancla con seq 2", row({ anchor_seq: 2, prev_anchor_hash: "1".repeat(64) }));
  await rejects("primera ancla con prev", row({ prev_anchor_hash: "1".repeat(64) }));
  await rejects("hash no hex", row({ anchor_hash: "Z".repeat(64) }));
  await rejects("key_id invalido", row({ key_id: "con espacio" }));
  await rejects("firma vacia o corta", row({ signature: "abc" }));
  await rejects("format_version 0", row({ format_version: 0 }));
  await insert(row());
  await rejects("seq repetida", row());
  await rejects("seq saltada", row({ anchor_seq: 3, prev_anchor_hash: "1".repeat(64), anchor_hash: "2".repeat(64) }));
  await rejects("prev incorrecto", row({ anchor_seq: 2, prev_anchor_hash: "9".repeat(64), anchor_hash: "2".repeat(64) }));
  await rejects("seq 2 sin prev", row({ anchor_seq: 2, anchor_hash: "2".repeat(64) }));
  await rejects("anchor_hash repetido", row({ anchor_seq: 2, prev_anchor_hash: "1".repeat(64), anchor_hash: "1".repeat(64) }), "23505");
  await insert(row({ anchor_seq: 2, prev_anchor_hash: "1".repeat(64), anchor_hash: "2".repeat(64) }));
  assert.deepEqual((await admin.query<{ anchor_seq: string }>("SELECT anchor_seq::text FROM integrity.anchor ORDER BY 1")).rows.map((r) => r.anchor_seq), ["1", "2"]);

  // El firmante: lee anchor y las columnas concedidas de chain_run/checkpoint; nada del ledger ni columnas ajenas; no inserta chain_run/checkpoint.
  await asSigner(async () => {
    assert.equal((await admin.query("SELECT anchor_seq, signature FROM integrity.anchor")).rowCount, 2);
    assert.ok((await admin.query("SELECT run_id, merkle_root, leaf_count, exit_code, finished_at, environment, merkle_format FROM integrity.chain_run")).rowCount! >= 2);
    assert.ok((await admin.query("SELECT run_id, tenant_id, head_chain_seq, head_event_hash FROM integrity.chain_checkpoint")).rowCount! >= 1);
  });
  const denied = async (label: string, sql: string): Promise<void> => {
    await assert.rejects(() => asSigner(() => admin.query(sql)), (e: unknown) => codeOf(e) === "42501", label);
  };
  await denied("ledger", "SELECT tenant_id FROM integrity.audit_event");
  await denied("started_at de chain_run", "SELECT started_at FROM integrity.chain_run");
  await denied("tenants de chain_run", "SELECT tenants FROM integrity.chain_run");
  await denied("verified_events", "SELECT verified_events FROM integrity.chain_checkpoint");
  await denied("SELECT * de chain_run", "SELECT * FROM integrity.chain_run");
  await denied("INSERT chain_run", `INSERT INTO integrity.chain_run (${RUN_COLS}) VALUES ('${randomUUID()}', now(), 'LOCAL', 0, 0, 0, 0, '${"a".repeat(64)}', 'RFC6962-SHA256-V1')`);
  await denied("UPDATE anchor", "UPDATE integrity.anchor SET key_id = 'x'");
  await denied("DELETE anchor", "DELETE FROM integrity.anchor");
  await denied("esquema app", "SELECT 1 FROM app.invitation");
  await denied("created_at no insertable", `INSERT INTO integrity.anchor (anchor_seq, created_at, environment, run_id, leaf_count, merkle_root, prev_anchor_hash, anchor_hash, key_id, signature, format_version) VALUES (3, now(), 'LOCAL', '${run.run_id}', ${run.leaf_count}, '${run.merkle_root}', '${"2".repeat(64)}', '${"3".repeat(64)}', 'k', '${SIG}', 1)`);
  // Los demas roles no ven ni escriben anclas.
  for (const r of ["app_rw", "worker", "platform_rw", "integrity_verifier", "integrity_reconciler", "integrity_chain_verifier", "consent_migrator"] as const) {
    const c = await ctx.connectAs(r);
    await assert.rejects(() => c.query("SELECT 1 FROM integrity.anchor"), (e: unknown) => codeOf(e) === "42501", r);
    await assert.rejects(() => rw(c, () => c.query(`INSERT INTO integrity.anchor (${cols.join(", ")}) VALUES ($1, 'LOCAL', $2, 0, $3, NULL, $4, 'k', $5, 1)`, [9, run.run_id, run.merkle_root, "8".repeat(64), SIG])), (e: unknown) => codeOf(e) === "42501", r);
  }
  // Append-only tambien para el superusuario.
  for (const sql of ["UPDATE integrity.anchor SET key_id = 'x'", "DELETE FROM integrity.anchor", "TRUNCATE integrity.anchor"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", sql);
  }
});

// ---- A partir de aqui se corrompe el ledger (tenants propios). Los checkpoints son append-only: una anomalia queda persistida para siempre; se afirma por tenant. ----

const T_TRUNC = fixtureUuid("t7b-trunc");
const T_REWRITE = fixtureUuid("t7b-rewrite");
const T_GONE = fixtureUuid("t7b-gone");
const T_OK = fixtureUuid("t7b-ok");

pgTest("TEST-CNS-1778 pg: reescribir a la vez ledger y checkpoints (superusuario) lo detecta la copia local: checkpoints borrados o retrocedidos = CHECKPOINT_STATE_MISMATCH por tenant (exit 2)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const T_X = fixtureUuid("t7b-x");
  const T_Y = fixtureUuid("t7b-y");
  await driveInvitation(ctx, T_X, "1778-x");
  await driveInvitation(ctx, T_Y, "1778-y");
  const dir = await mkStateDir();
  const env = { CNS_CHAIN_VERIFIER_STATE_DIR: dir };
  try {
    assert.equal((await runVerifier(ctx, env)).ok, true);
    assert.equal((await runVerifier(ctx, env)).ok, true);
    // El atacante con superusuario de la base borra TODOS los checkpoints de T_X (deshabilitando el append-only) y de T_Y los vuelve a una cabeza mas vieja (que existe en el ledger).
    await admin.query("ALTER TABLE integrity.chain_checkpoint DISABLE TRIGGER USER");
    try {
      await admin.query("DELETE FROM integrity.chain_checkpoint WHERE tenant_id = $1", [T_X]);
      const older = (await admin.query<{ chain_seq: string; event_hash: string }>("SELECT chain_seq::text, event_hash FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = 1", [T_Y])).rows[0]!;
      await admin.query("UPDATE integrity.chain_checkpoint SET head_chain_seq = $2, head_event_hash = $3, verified_events = 1 WHERE tenant_id = $1", [T_Y, Number(older.chain_seq), older.event_hash]);
    } finally {
      await admin.query("ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_guard");
      await admin.query("ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_no_update_delete");
      await admin.query("ALTER TABLE integrity.chain_checkpoint ENABLE ALWAYS TRIGGER chain_checkpoint_no_truncate");
    }
    const withCopy = await runVerifier(ctx, env);
    const kinds = (t: string): string[] => withCopy.anomalies.filter((a) => a.tenantId === t).map((a) => a.kind);
    assert.deepEqual(kinds(T_X), ["CHECKPOINT_STATE_MISMATCH"]);
    assert.deepEqual(kinds(T_Y), ["CHECKPOINT_STATE_MISMATCH"]);
    assert.equal(chainExitCodeFor(withCopy), 2);
    assert.equal(runMain(ctx, env).status, 2);
    // Sin la copia local esa reescritura pasaba (cada checkpoint existe en el ledger): con ella, no.
    const withoutCopy = await runVerifier(ctx);
    assert.ok(withoutCopy.anomalies.filter((a) => a.tenantId === T_X || a.tenantId === T_Y).length === 0, "solo con la base el atacante no deja rastro (por eso existe la copia local y el ancla externa)");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

pgTest("TEST-CNS-1777 pg: truncamiento de cola (F-PR6E-05), reescritura bajo el testigo y tenant borrado como superusuario = exit 2 por el entrypoint, por tenant, sin raiz Merkle ni checkpoint del tenant afectado, sin PII/hashes en el log", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  for (const [t, k] of [[T_TRUNC, "trunc"], [T_REWRITE, "rewrite"], [T_GONE, "gone"], [T_OK, "ok"]] as const) await driveInvitation(ctx, t, `1777-${k}`);
  const dir = await mkStateDir();
  const env = { CNS_CHAIN_VERIFIER_STATE_DIR: dir };
  try {
    const before = await runVerifier(ctx, env);
    assert.equal(before.ok, true, JSON.stringify(before.anomalies));
    const heads = new Map((await ledgerHeads(admin)).map((h) => [h.tenantId, h]));

    await tamper(admin, async () => {
      // Truncamiento: se borra el ultimo eslabon de T_TRUNC (la cadena restante sigue siendo VALIDA).
      assert.equal((await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = $2", [T_TRUNC, heads.get(T_TRUNC)!.chainSeq])).rowCount, 1);
      // Tenant borrado entero.
      assert.ok((await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1", [T_GONE])).rowCount! >= 3);
    });
    // Reescritura bajo el testigo: se borra el ultimo eslabon de T_REWRITE y se re-escribe la cola con otro contenido (misma secuencia, otro hash) y la cadena sigue creciendo.
    await tamper(admin, async () => {
      assert.equal((await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = $2", [T_REWRITE, heads.get(T_REWRITE)!.chainSeq])).rowCount, 1);
    });
    await driveInvitation(ctx, T_REWRITE, "1777-rewrite-2");

    const report = await runVerifier(ctx, env);
    assert.equal(report.ok, false);
    assert.equal(chainExitCodeFor(report), 2);
    const kinds = (t: string): string[] => report.anomalies.filter((a) => a.tenantId === t).map((a) => a.kind);
    assert.deepEqual(kinds(T_TRUNC), ["TAIL_TRUNCATED_OR_REWRITTEN"], "cola truncada");
    assert.equal(report.results.find((r) => r.tenantId === T_TRUNC)?.broken, null, "la cadena restante es valida: solo el checkpoint la delata");
    assert.deepEqual(kinds(T_GONE), ["TENANT_MISSING"], "tenant borrado");
    assert.ok(!report.results.some((r) => r.tenantId === T_GONE));
    const rewrite = report.results.find((r) => r.tenantId === T_REWRITE)!;
    assert.equal(rewrite.broken, null);
    assert.ok(rewrite.head >= heads.get(T_REWRITE)!.chainSeq, "la cadena reescrita crecio mas alla del testigo");
    assert.deepEqual(kinds(T_REWRITE), ["TAIL_TRUNCATED_OR_REWRITTEN"], "mismo seq, otro hash");
    assert.deepEqual(kinds(T_OK), [], "tenants intactos sin anomalia");
    assert.deepEqual(kinds(A), []);

    // Persistencia: chain_run exit 2 sin raiz; checkpoints solo de tenants sin anomalia; los afectados conservan su ultimo checkpoint.
    const last = (await admin.query<{ run_id: string; exit_code: number; merkle_root: string | null; leaf_count: number }>("SELECT run_id::text, exit_code, merkle_root, leaf_count FROM integrity.chain_run ORDER BY finished_at DESC LIMIT 1")).rows[0]!;
    assert.deepEqual([last.exit_code, last.merkle_root, last.leaf_count], [2, null, 0]);
    const written = (await admin.query<{ tenant_id: string }>("SELECT tenant_id::text FROM integrity.chain_checkpoint WHERE run_id = $1", [last.run_id])).rows.map((r) => r.tenant_id);
    assert.ok(written.includes(T_OK), "el tenant intacto sigue checkpointeado");
    for (const t of [T_TRUNC, T_REWRITE, T_GONE]) assert.ok(!written.includes(t), `sin checkpoint nuevo para ${t}`);
    const latest = (await admin.query<{ head_chain_seq: string; head_event_hash: string }>("SELECT head_chain_seq::text, head_event_hash FROM integrity.chain_checkpoint WHERE tenant_id = $1 ORDER BY head_chain_seq DESC LIMIT 1", [T_TRUNC])).rows[0]!;
    assert.equal(latest.head_event_hash, heads.get(T_TRUNC)!.eventHash, "el testigo previo sigue intacto (append-only)");
    // La copia local de los afectados tampoco avanza (la comparacion sigue fallando en cada corrida).
    const doc = JSON.parse(await readFile(join(dir, "heads.json"), "utf8")) as { heads: Record<string, { chainSeq: number; eventHash: string }> };
    assert.equal(doc.heads[T_TRUNC]!.chainSeq, heads.get(T_TRUNC)!.chainSeq);
    assert.equal(doc.heads[T_GONE]!.chainSeq, heads.get(T_GONE)!.chainSeq);

    // Entrypoint real: exit 2, log por stderr con kind y tenant (uuid), sin hashes, sin ruta, una sola linea de resumen.
    const main = runMain(ctx, env);
    assert.equal(main.status, 2, main.stderr);
    assert.equal(main.stdout, "");
    const lines = main.stderr.split("\n").filter((l) => l !== "");
    assert.match(lines[0]!, /^chain_verify_run ok=false tenants=\d+ events=\d+ broken=0 unchained=0 anomalies=3 kinds=TAIL_TRUNCATED_OR_REWRITTEN=2,TENANT_MISSING=1$/);
    assert.ok(lines.includes(`chain_verify_anomaly kind=TAIL_TRUNCATED_OR_REWRITTEN tenant=${T_TRUNC}`));
    assert.ok(lines.includes(`chain_verify_anomaly kind=TENANT_MISSING tenant=${T_GONE}`));
    assert.equal(lines.filter((l) => l.startsWith("chain_verify_run ")).length, 1);
    assert.ok(!HEAD_LEAK(main.stderr) && !main.stderr.includes(dir));
    assert.ok(lines.some((l) => l.startsWith(`chain_verify_tenant tenant=${T_OK} `) && l.endsWith("status=ok")));
    assert.ok(lines.some((l) => l.startsWith(`chain_verify_tenant tenant=${T_TRUNC} `) && l.endsWith("status=bad")));
    assert.ok(!UUID_RE.test(main.stdout));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

pgTest("TEST-CNS-1779 pg: una divergencia real del ledger queda persistida como conteo por codigo (exit 2) sin ids de agregado ni tenant", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const T_R = fixtureUuid("t7b-rec");
  await driveInvitation(ctx, T_R, "1779-r");
  const reconcile = async () => {
    const proc = await startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_reconciler") } });
    try {
      return await proc.run();
    } finally {
      await proc.stop();
    }
  };
  await tamper(admin, async () => {
    assert.equal((await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = (SELECT max(chain_seq) FROM integrity.audit_event WHERE tenant_id = $1)", [T_R])).rowCount, 1);
  });
  const report = await reconcile();
  assert.equal(report.ok, false);
  assert.equal(exitCodeFor(report), RECONCILER_EXIT.DIVERGENCE);
  const last = (await admin.query<{ divergences: number; divergences_by_code: Record<string, number>; exit_code: number }>("SELECT divergences, divergences_by_code, exit_code FROM integrity.reconcile_run ORDER BY finished_at DESC LIMIT 1")).rows[0]!;
  assert.equal(last.exit_code, 2);
  assert.equal(last.divergences, report.divergences.length);
  assert.deepEqual(last.divergences_by_code, report.byKind);
  const asText = JSON.stringify(last);
  assert.ok(!UUID_RE.test(asText) && !asText.includes(T_R) && !/inv-|aggregate/i.test(asText), "sin ids");
  for (const k of Object.keys(last.divergences_by_code)) assert.match(k, /^[A-Z_]{1,40}$/);
});
