// Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`), §4.2.c (conciliacion: exit code != 0 y log sin PII), §10 fila 6e, G-9 (aprobado), F-PR6-29, P2(e), condicion de §15.3 / seguridad rev. c punto 7
// (integrity_reconciler NOBYPASSRLS con policies de SELECT explicitas y assert), INV-DBR-01/02/03/08; db/migrations/0056-0058; specs/db-roles.spec.yaml. SYNTHETIC ONLY.
// Seguridad PR #99 (P1-1): el reconciler NO lee payload, hashes ni refs de actor (7 columnas de integrity.audit_event) y NO recomputa la cadena (es del chain-verifier, F-PR6E-06).
// TEST-CNS-1610 (privilegios exactos del rol: atributos, sin membresias, columnas, 4 policies, sin EXECUTE; el verifier sigue sin SELECT de principal_identity),
// TEST-CNS-1611 (cross-tenant correcto: el reconciler ve todos los tenants sin GUC; app_rw solo el suyo; la conciliacion de datos coherentes da ok),
// TEST-CNS-1612 (reconciler sin escritura ni lectura de payload y demas columnas con PII/hashes, ni tablas ajenas, funciones, SET ROLE ni session_replication_role: 42501),
// TEST-CNS-1613 (arranque con rol equivocado rechazado: startup-checks y entrypoint; el rol correcto pasa),
// TEST-CNS-1614 (division de tareas: un payload mutado NO lo ve el reconciler (lo detecta el chain-verifier) y la salida no lo filtra), TEST-CNS-1615 (hueco: evento borrado -> chain_seq y sequence),
// TEST-CNS-1616 (par fuera de la particion con cadena valida), TEST-CNS-1617 (los pares del oraculo coinciden con las policies de la base; CANCELLED <-> INVITATION_CANCELLED y REVOKED <-> CONSENT_REVOKED).
// Los tests que corrompen el ledger usan tenants propios y van al final del archivo. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import type { Client } from "pg";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { computeEventHash, computePayloadHash, LEDGER_GENESIS_HASH } from "../../../src/server/modules/common/ledger-chain.ts";
import { ProcessRoleError } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { exitCodeFor, formatReport, RECONCILER_EXIT, startReconcilerProcess } from "../../../src/server/entrypoints/reconciler/reconciler-process.ts";
import { LEDGER_WRITER_PAIRS, TRANSITION_OWNER_PAIRS } from "../../../src/server/modules/integrity/ledger-reconciliation.ts";
import type { Divergence, ReconciliationReport } from "../../../src/server/modules/integrity/ledger-reconciliation.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import type { OtpVerificationRecord } from "../../../src/server/ports/otp-verification-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, seedRaw, type PgTestContext } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const DM = "dm-pr6e";
const PURPOSE = "STUDY_PARTICIPATION";
const GRANT = JSON.stringify([{ purpose: PURPOSE, choice: "GRANT" }]);

async function withApp<T>(ctx: PgTestContext, fn: (uow: PgUnitOfWork) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    return await fn(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

/** Invitacion legitima por el camino real (triggers de ledger_gen): DRAFT -> READY -> SENT -> OPENED [-> VERIFIED con OTP]. Devuelve las refs. */
async function driveInvitation(ctx: PgTestContext, T: string, key: string, upTo: "DRAFT" | "READY" | "SENT" | "VERIFIED"): Promise<{ inv: string; ver: string; subject: string }> {
  const inv = fixtureUuid(`inv-${key}`);
  const ver = fixtureUuid(`ver-${key}`);
  const subject = fixtureUuid(`sub-${key}`);
  const expires = new Date("2030-02-03T04:05:06.789Z");
  const base: InvitationRecord = { invitationRef: inv, tenantId: T, contextRef: "C", productRef: "P", subjectRef: subject, state: "DRAFT", enrollmentRef: fixtureUuid(`en-${key}`), participationRef: fixtureUuid(`pa-${key}`) };
  const ready: InvitationRecord = { ...base, state: "READY", consentVersion: "v1", expiresAt: expires, recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: "a@example.invalid" };
  const sent: InvitationRecord = { ...ready, state: "SENT", tokenHash: sha(`tok-${key}`), deliveryChannel: "CONSENT_APP_EMAIL" };
  const opened: InvitationRecord = { ...sent, state: "OPENED" };
  const verified: InvitationRecord = { ...opened, state: "VERIFIED", boundDecisionMakerRef: DM, verifiedByRef: ver, dmRefKeyVersion: 2 };
  const otp0: OtpVerificationRecord = { verificationRef: ver, tenantId: T, scope: "DECISION", parentRef: inv, channelRef: "a@example.invalid", codeHash: "a".repeat(64), attempts: 0, expiresAt: new Date(Date.now() + 3_600_000), state: "CODE_SENT", resendCount: 0 };
  const otp1: OtpVerificationRecord = { ...otp0, attempts: 1, state: "VERIFIED", consumedAt: new Date(), decisionMakerRef: DM, dmRefKeyVersion: 2 };
  await withApp(ctx, async (uow) => {
    const steps = upTo === "DRAFT" ? [base] : upTo === "READY" ? [base, ready] : upTo === "SENT" ? [base, ready, sent] : [base, ready, sent, opened];
    for (const s of steps) await uow.inTenant(T, (tx) => tx.invitationRepo.save(s));
    if (upTo === "VERIFIED") {
      await uow.inTenant(T, async (tx) => {
        await tx.otpRepo.save(otp0);
        await tx.otpRepo.save(otp1);
      });
      await uow.inTenant(T, (tx) => tx.invitationRepo.save(verified));
    }
  });
  return { inv, ver, subject };
}

const reconcilerEnv = (ctx: PgTestContext): Record<string, string> => ({ CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_reconciler") });

async function runReconciler(ctx: PgTestContext): Promise<ReconciliationReport> {
  const proc = await startReconcilerProcess({ env: reconcilerEnv(ctx) });
  try {
    return await proc.run();
  } finally {
    await proc.stop();
  }
}
const forTenant = (r: ReconciliationReport, t: string): Divergence[] => r.divergences.filter((d) => d.tenantId === t);
const tag = (d: Divergence): string => `${d.kind}${d.detail === undefined ? "" : `:${d.detail}`}`;

/** Corrompe el ledger de la base DESCARTABLE del archivo: deshabilita el trigger de inmutabilidad solo durante `work` y lo deja ENABLE ALWAYS. Solo tests (simula una manipulacion del ledger). */
async function tamper(admin: Client, work: () => Promise<void>): Promise<void> {
  await admin.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER audit_event_no_update_delete");
  try {
    await work();
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete");
  }
}

// Escenario compartido: A = invitacion COMPLETED + decision GRANTED; B = invitacion CANCELLED por I9 (y otra SENT).
const A = fixtureUuid("t1611-a");
const B = fixtureUuid("t1611-b");

pgTest("TEST-CNS-1610 pg: integrity_reconciler = LOGIN NOSUPERUSER NOBYPASSRLS sin membresias; SELECT solo de las columnas aprobadas; exactamente 4 policies de SELECT TO integrity_reconciler; sin EXECUTE; sin acceso a principal_identity (P2(e))", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const role = (await admin.query<{ rolcanlogin: boolean; rolsuper: boolean; rolbypassrls: boolean; rolcreatedb: boolean; rolcreaterole: boolean; rolreplication: boolean; rolconfig: string[] }>(
    "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolconfig FROM pg_roles WHERE rolname = 'integrity_reconciler'")).rows[0];
  assert.deepEqual([role?.rolcanlogin, role?.rolsuper, role?.rolbypassrls, role?.rolcreatedb, role?.rolcreaterole, role?.rolreplication], [true, false, false, false, false, false]);
  assert.ok(role?.rolconfig.includes("default_transaction_read_only=on"));
  const members = await admin.query("SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles x ON x.oid = m.member WHERE r.rolname = 'integrity_reconciler' OR x.rolname = 'integrity_reconciler'");
  assert.equal(members.rowCount, 0, "sin membresias en ningun sentido");
  // Columnas legibles: ledger completo (recomputo) y solo ref+estado en las tablas de estado.
  const cols = async (rel: string): Promise<string> =>
    (await admin.query<{ c: string }>(
      `SELECT string_agg(a.attname, ',' ORDER BY a.attname COLLATE "C") AS c FROM pg_attribute a WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege('integrity_reconciler', a.attrelid, a.attname, 'SELECT')`, [rel])).rows[0]?.c ?? "";
  assert.equal(await cols("app.invitation"), "invitation_ref,state,tenant_id");
  assert.equal(await cols("app.consent_decision"), "consent_id,state,tenant_id");
  assert.equal(await cols("case_state.revocation"), "revocation_ref,revoked_decision_ref,tenant_id");
  assert.equal(await cols("integrity.audit_event"), "aggregate_id,aggregate_type,chain_seq,event_type,occurred_at,sequence,tenant_id", "sin payload, hashes ni refs de actor (P1-1)");
  // Exactamente 3 policies (todas SELECT, TO integrity_reconciler, USING true), una por tabla.
  const pol = (await admin.query<{ rel: string; polname: string; polcmd: string; q: string }>(
    `SELECT p.polrelid::regclass::text AS rel, p.polname, p.polcmd, pg_get_expr(p.polqual, p.polrelid) AS q FROM pg_policy p
      WHERE (SELECT oid FROM pg_roles WHERE rolname = 'integrity_reconciler') = ANY (p.polroles) OR 0 = ANY (p.polroles) AND p.polrelid::regclass::text IN ('integrity.audit_event', 'app.invitation', 'app.consent_decision', 'case_state.revocation')
      ORDER BY 1`)).rows;
  assert.deepEqual(pol.map((p) => [p.rel, p.polname, p.polcmd, p.q]), [
    ["app.consent_decision", "consent_decision_reconciler_select", "r", "true"],
    ["app.invitation", "invitation_reconciler_select", "r", "true"],
    ["case_state.revocation", "revocation_reconciler_select", "r", "true"],
    ["integrity.audit_event", "audit_event_reconciler_select", "r", "true"],
  ]);
  // Sin privilegios de escritura ni EXECUTE en ningun esquema de dominio; ningun privilegio sobre otras tablas de app/ops/platform.
  const writes = await admin.query(
    `SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('app', 'ops', 'platform', 'integrity', 'case_state', 'ledger_gen', 'tenant_resolve') AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND (has_table_privilege('integrity_reconciler', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege('integrity_reconciler', c.oid, 'INSERT,UPDATE,REFERENCES'))`);
  assert.equal(writes.rowCount, 0);
  const reads = (await admin.query<{ t: string }>(
    `SELECT n.nspname || '.' || c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('app', 'ops', 'platform', 'integrity', 'case_state', 'ledger_gen', 'tenant_resolve') AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND has_any_column_privilege('integrity_reconciler', c.oid, 'SELECT') ORDER BY 1`)).rows.map((r) => r.t);
  assert.deepEqual(reads, ["app.consent_decision", "app.invitation", "case_state.revocation", "integrity.audit_event", "ops.db_catalog"]);
  const fns = await admin.query(
    `SELECT n.nspname || '.' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('app', 'ops', 'platform', 'integrity', 'case_state', 'ledger_gen', 'tenant_resolve') AND has_function_privilege('integrity_reconciler', p.oid, 'EXECUTE')`);
  assert.equal(fns.rowCount, 0, "sin EXECUTE de funciones de dominio");
  // P2(e): ni el reconciler ni el verifier leen la identidad del principal.
  for (const r of ["integrity_reconciler", "integrity_verifier"]) {
    const pi = await admin.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'platform' AND c.relname = 'principal_identity' AND has_any_column_privilege($1, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')", [r]);
    assert.equal(pi.rowCount, 0, `${r} sin privilegios sobre platform.principal_identity`);
  }
  // Otros roles no ganaron lectura del ledger por esta migracion.
  for (const r of ["integrity_verifier", "platform_rw"]) {
    assert.equal((await admin.query("SELECT has_any_column_privilege($1, 'integrity.audit_event', 'SELECT') AS s", [r])).rows[0]?.s, false, r);
  }
});

pgTest("TEST-CNS-1611 pg: cross-tenant correcto: el reconciler lee todos los tenants SIN GUC; app_rw solo el suyo (y nada sin contexto); la conciliacion de datos coherentes termina ok (exit 0)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  // A: invitacion legitima hasta VERIFIED y decision GRANTED + invitacion COMPLETED (triggers reales).
  const a = await driveInvitation(ctx, A, "1611-a", "VERIFIED");
  await seedRaw(admin, () => admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes,
       prior_steps_complete, steps_recorded, relationship_ref, consent_version, consent_text_hash, privacy_notice_version)
     VALUES ($1, $2, 'C', 'P', $3, $4, $5, $6, $7, 'PENDING', '[]', true, ARRAY['CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED'], 'SYNTHETIC_GUARDIAN', 'v1', $8, 'p1')`,
    [A, fixtureUuid("d1611"), a.subject, DM, a.inv, a.ver, fixtureUuid("ch1611"), sha("texto")]));
  await withApp(ctx, (uow) => uow.withTenantTx(A, async (tx) => {
    await tx.query("SELECT 1 FROM app.invitation WHERE invitation_ref = $1 FOR UPDATE", [a.inv]);
    await tx.query(
      `UPDATE app.consent_decision SET state = 'GRANTED', purposes = '${GRANT}'::jsonb, receipt_ref = $2, consent_version = 'v1', consent_text_hash = '${sha("texto")}', privacy_notice_version = 'p1' WHERE consent_id = $1`,
      [fixtureUuid("d1611"), fixtureUuid("r1611")]);
    await tx.query("UPDATE app.invitation SET state = 'COMPLETED', closed_by_consent_id = $1 WHERE invitation_ref = $2", [fixtureUuid("d1611"), a.inv]);
  }));
  // B: una invitacion VERIFIED cancelada por I9 y otra en SENT.
  const b = await driveInvitation(ctx, B, "1611-b", "VERIFIED");
  await withApp(ctx, (uow) => uow.withTenantTx(B, (tx) => tx.query("SELECT case_state.cancel_invitation_subject_mismatch($1, $2, 5)", [b.inv, DM])));
  await driveInvitation(ctx, B, "1611-b2", "SENT");

  // Lectura cross-tenant por policy explicita: el reconciler ve A y B sin fijar app.tenant_id.
  const rec = await ctx.connectAs("integrity_reconciler");
  const seen = (await rec.query<{ tenant_id: string }>("SELECT DISTINCT tenant_id FROM integrity.audit_event WHERE tenant_id IN ($1, $2) ORDER BY 1", [A, B])).rows.map((r) => r.tenant_id).sort();
  assert.deepEqual(seen, [A, B].sort());
  assert.equal((await rec.query<{ n: number }>("SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id IN ($1, $2)", [A, B])).rows[0]?.n, 3);
  assert.equal((await rec.query<{ n: number }>("SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1", [A])).rows[0]?.n, 1);
  assert.equal((await rec.query<{ t: string | null }>("SELECT current_setting('app.tenant_id', true) AS t")).rows[0]?.t ?? "", "", "sin GUC de tenant");
  // app_rw sigue aislado: con contexto A solo ve A; sin contexto no ve nada.
  await withApp(ctx, async (uow) => {
    const own = await uow.withTenantTx(A, (tx) => tx.query<{ tenant_id: string }>("SELECT DISTINCT tenant_id FROM integrity.audit_event"));
    assert.deepEqual(own.rows.map((r) => r.tenant_id), [A]);
  });
  const app = await ctx.connectAs("app_rw");
  assert.equal((await app.query("SELECT 1 FROM integrity.audit_event")).rowCount, 0, "app_rw sin contexto no ve el ledger");

  // Conciliacion de datos coherentes: ok, exit 0 y sin divergencias en A ni en B.
  const report = await runReconciler(ctx);
  assert.deepEqual(forTenant(report, A).map(tag), [], `A: ${JSON.stringify(forTenant(report, A))}`);
  assert.deepEqual(forTenant(report, B).map(tag), [], `B: ${JSON.stringify(forTenant(report, B))}`);
  assert.ok(report.tenants >= 2 && report.events >= 15);
  assert.equal(report.ok, true);
  assert.equal(exitCodeFor(report), RECONCILER_EXIT.OK);
  assert.match(formatReport(report)[0]!, /^reconciler_run ok=true tenants=\d+ events=\d+ divergences=0$/);
});

pgTest("TEST-CNS-1612 pg: el reconciler da 42501 al leer payload y demas columnas con PII/hashes del ledger y de las tablas de estado, y al escribir, leer tablas ajenas (rights_case, case_session, platform.*), ejecutar funciones, SET ROLE y session_replication_role", async (ctx) => {
  const rec = await ctx.connectAs("integrity_reconciler");
  // default_transaction_read_only = on (defensa en profundidad) daria 25006 antes del chequeo de privilegios: se levanta para probar que el CONTROL son los privilegios.
  await rec.query("SET default_transaction_read_only = off");
  const denied = async (sql: string, label: string): Promise<void> => {
    await assert.rejects(() => rec.query(sql), (e: unknown) => codeOf(e) === "42501", label);
  };
  const T0 = fixtureUuid("t1612");
  await denied(`INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES ('${T0}', 'Tenant', 'x', 1, 'TENANT_SEEDED', 'FIXTURE', '{}')`, "INSERT ledger");
  await denied("UPDATE integrity.audit_event SET payload = '{}'::jsonb", "UPDATE ledger");
  await denied("DELETE FROM integrity.audit_event", "DELETE ledger");
  await denied("TRUNCATE integrity.audit_event", "TRUNCATE ledger");
  await denied("UPDATE app.invitation SET state = 'CANCELLED'", "UPDATE invitation");
  await denied("DELETE FROM app.invitation", "DELETE invitation");
  await denied("UPDATE app.consent_decision SET state = 'REVOKED'", "UPDATE decision");
  await denied("INSERT INTO app.consent_decision (tenant_id, consent_id) VALUES (gen_random_uuid(), 'x')", "INSERT decision");
  // Ledger: payload (seudonimos del titular), refs de actor, hashes y claves de idempotencia NO son legibles (P1-1); SELECT * tampoco.
  await denied("SELECT * FROM integrity.audit_event", "SELECT * ledger");
  for (const col of ["payload", "recorded_by_ref", "cosigned_by_ref", "idempotency_key_hash", "payload_hash", "previous_event_hash", "event_hash", "actor_type", "actor_role", "event_id", "environment"]) {
    await denied(`SELECT ${col} FROM integrity.audit_event`, `audit_event.${col}`);
  }
  for (const col of ["payload", "event_hash"]) await denied(`SELECT count(*) FROM integrity.audit_event WHERE ${col} IS NOT NULL`, `audit_event.${col} en WHERE`);
  for (const col of ["status", "case_ref", "recorded_by_ref", "reason_code", "verification_ref"]) await denied(`SELECT ${col} FROM case_state.revocation`, `revocation.${col}`);
  // Columnas con PII o secretos: SELECT * y columnas concretas.
  await denied("SELECT * FROM app.invitation", "SELECT * invitation");
  for (const col of ["token_hash", "recipient_channel_ref", "subject_ref", "bound_decision_maker_ref"]) await denied(`SELECT ${col} FROM app.invitation`, `invitation.${col}`);
  for (const col of ["decision_maker_ref", "subject_ref", "receipt_ref"]) await denied(`SELECT ${col} FROM app.consent_decision`, `consent_decision.${col}`);
  // Tablas ajenas y esquema platform.
  for (const t of ["case_state.rights_case", "app.case_session", "app.outbox", "ops.security_event", "app.otp_verification", "app.enrollment", "tenant_resolve.handle"]) await denied(`SELECT 1 FROM ${t}`, t);
  await denied("SELECT 1 FROM platform.principal_identity", "principal_identity");
  await denied("SELECT 1 FROM platform.oidc_exchange", "oidc_exchange");
  await denied("SELECT 1 FROM platform.session_event", "session_event (fuera de 6e: 6c)");
  // Funciones: ni aserciones, ni transiciones, ni siembra, ni append.
  await denied("SELECT platform.record_assertion(NULL::text, NULL::text, NULL::text, NULL::text, NULL::text)", "record_assertion");
  await denied("SELECT case_state.apply_revocation('x', 0)", "apply_revocation");
  await denied("SELECT ledger_gen.seed_local_catalog_event('TENANT_SEEDED', 'x')", "seed_local_catalog_event");
  // Cambios de rol / de identidad / de replicacion.
  for (const r of ["ledger_writer", "transition_owner", "integrity_owner", "consent_owner", "app_rw", "integrity_verifier"]) {
    await assert.rejects(() => rec.query(`SET ROLE ${r}`), (e: unknown) => codeOf(e) === "42501", `SET ROLE ${r}`);
  }
  await denied("SET session_replication_role = replica", "session_replication_role");
  // Aunque levante la bandera de solo lectura (defensa en profundidad, no es el control), sigue sin poder escribir.
  await rec.query("SET default_transaction_read_only = off");
  await denied("UPDATE app.invitation SET state = 'CANCELLED'", "UPDATE tras SET read_only=off");
  // No puede crear nada.
  for (const s of ["app", "ops", "integrity", "public"]) await denied(`CREATE TABLE ${s}.x_1612 (a int)`, `CREATE en ${s}`);
});

pgTest("TEST-CNS-1613 pg: arranque con rol equivocado rechazado (startup-checks y entrypoint); el rol correcto pasa los chequeos de arranque", async (ctx) => {
  // El rol correcto pasa todos los chequeos (current_user = session_user = integrity_reconciler, sin superusuario, sin owners, catalogo LOCAL).
  const ok = await ctx.connectAs("integrity_reconciler");
  const good = await runStartupChecks(ok, { expectedRole: "integrity_reconciler", expectedEnvironment: "LOCAL" });
  assert.deepEqual(good.failures, []);
  assert.equal(good.ok, true);
  // Rol equivocado: otro rol de runtime, el migrador y el superusuario NO pasan con expectedRole = integrity_reconciler.
  for (const role of ["integrity_verifier", "app_rw", "worker", "platform_rw", "consent_migrator"] as const) {
    const c = await ctx.connectAs(role);
    const r = await runStartupChecks(c, { expectedRole: "integrity_reconciler", expectedEnvironment: "LOCAL" });
    assert.equal(r.ok, false, role);
    assert.ok(r.failures.some((f) => f.includes("integrity_reconciler")), `${role}: ${r.failures.join("|")}`);
  }
  const su = await ctx.connectAsSuperuser();
  const sr = await runStartupChecks(su, { expectedRole: "integrity_reconciler", expectedEnvironment: "LOCAL" });
  assert.equal(sr.ok, false);
  assert.ok(sr.failures.some((f) => f.includes("superusuario")));
  // session_user != current_user (un SET ROLE no disfraza la identidad): el superusuario asumiendo integrity_reconciler sigue rechazado por session_user.
  await su.query("SET ROLE integrity_reconciler");
  const disguised = await runStartupChecks(su, { expectedRole: "integrity_reconciler", expectedEnvironment: "LOCAL" });
  await su.query("RESET ROLE");
  assert.equal(disguised.ok, false);
  assert.ok(disguised.failures.some((f) => f.includes("session_user")), disguised.failures.join("|"));
  // Entrypoint: la URL con otro rol aborta con ProcessRoleError antes de conectar; la correcta arranca y concilia.
  for (const role of ["integrity_verifier", "app_rw", "worker", "platform_rw", "consent_migrator"] as const) {
    await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor(role) } }), ProcessRoleError, role);
  }
  const proc = await startReconcilerProcess({ env: reconcilerEnv(ctx) });
  await proc.stop();
  // Fuera de LOCAL/DEV declarado distinto del catalogo: no arranca (F-PR6-08).
  await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "DEV", CNS_DATABASE_URL: ctx.urlFor("integrity_reconciler") } }), /catálogo|catalogo|environment/);
});

pgTest("TEST-CNS-1614 pg: division de tareas (P1-1): un payload mutado en el ledger NO lo ve el reconciler (no lo lee; lo detecta el recomputo del chain-verifier) y la salida del reconciler no lo filtra", async (ctx) => {
  const C = fixtureUuid("t1614-c");
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, C, "1614-c", "READY");
  await tamper(admin, async () => {
    await admin.query("UPDATE integrity.audit_event SET occurred_at = now(), payload = payload || '{\"manipulado\":\"PII-SENTINELA\"}'::jsonb WHERE tenant_id = $1 AND event_type = 'INVITATION_READY'", [C]);
  });
  const report = await runReconciler(ctx);
  assert.deepEqual(forTenant(report, C).map(tag), [], "el reconciler no recomputa hashes: la mutacion del payload no es su deteccion");
  const log = formatReport(report).join("\n");
  for (const secret of ["PII-SENTINELA", "manipulado", "example.invalid", "dm-pr6e"]) assert.ok(!log.includes(secret), `la salida filtra ${secret}`);
});

pgTest("TEST-CNS-1615 pg: hueco: un evento borrado del ledger rompe chain_seq y la sequence del agregado y deja el estado de la fila adelantado respecto del ledger", async (ctx) => {
  const E = fixtureUuid("t1615-e");
  const admin = await ctx.fixtureAdmin();
  const { inv } = await driveInvitation(ctx, E, "1615-e", "SENT");
  await tamper(admin, async () => {
    const r = await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'INVITATION_READY'", [E, inv]);
    assert.equal(r.rowCount, 1);
  });
  const report = await runReconciler(ctx);
  const tags = forTenant(report, E).map(tag);
  assert.ok(tags.includes("CHAIN_SEQ_GAP"), tags.join(","));
  assert.ok(tags.includes("AGGREGATE_SEQUENCE_GAP"), tags.join(","));
  assert.ok(tags.includes("STATE_EVENT_MISMATCH:MISSING:INVITATION_READY"), tags.join(","));
  assert.equal(report.ok, false);
});

pgTest("TEST-CNS-1616 pg: un evento con cadena VALIDA pero con par Agregado:EVENTO fuera de la particion (ledger_writer 19 U transition_owner 14) es una divergencia", async (ctx) => {
  const F = fixtureUuid("t1616-f");
  const admin = await ctx.fixtureAdmin();
  // Inserta un eslabon bien formado (hashes reales) como superusuario (bypassa RLS y policies: simula un escritor que se salta la particion).
  await admin.query("BEGIN");
  try {
    const now = (await admin.query<{ t: string; env: string }>(`SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS t, ops.catalog_environment() AS env`)).rows[0]!;
    const payload = {};
    const link = {
      tenantId: F, chainSeq: 1, aggregateType: "Tenant", aggregateId: "tenant-1616", sequence: 1, eventType: "TENANT_STATUS_CHANGED", actorType: "HUMAN", actorRole: null, recordedByRef: null, cosignedByRef: null,
      idempotencyKeyHash: null, occurredAt: now.t, environment: now.env, payloadHash: computePayloadHash(payload), previousEventHash: LEDGER_GENESIS_HASH,
    };
    await admin.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash, occurred_at, environment)
       VALUES ($1, 'Tenant', 'tenant-1616', 1, 'TENANT_STATUS_CHANGED', 'HUMAN', '{}'::jsonb, 1, $2, $3, $4, now(), $5)`,
      [F, link.payloadHash, LEDGER_GENESIS_HASH, computeEventHash(link), now.env]);
    await admin.query("COMMIT");
  } catch (e) {
    await admin.query("ROLLBACK");
    throw e;
  }
  const report = await runReconciler(ctx);
  assert.deepEqual(forTenant(report, F).map(tag), ["PAIR_OUTSIDE_PARTITION:TENANT_STATUS_CHANGED"], "cadena valida: solo el par fuera de la particion");
  assert.equal(report.ok, false);
});

pgTest("TEST-CNS-1617 pg: los pares del oraculo (19 + 14) coinciden con las policies de INSERT de la base; REVOKED <-> CONSENT_REVOKED y CANCELLED <-> INVITATION_CANCELLED se concilian contra datos reales", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const pairsOf = async (policy: string): Promise<string[]> => {
    const q = (await admin.query<{ w: string }>("SELECT pg_get_expr(polwithcheck, polrelid) AS w FROM pg_policy WHERE polrelid = 'integrity.audit_event'::regclass AND polname = $1", [policy])).rows[0]?.w ?? "";
    return [...q.matchAll(/'([A-Za-z]+:[A-Z_]+)'::text/g)].map((m) => m[1]!).sort();
  };
  assert.deepEqual(await pairsOf("audit_event_ledger_insert"), [...LEDGER_WRITER_PAIRS].sort());
  assert.deepEqual(await pairsOf("audit_event_transition_insert"), [...TRANSITION_OWNER_PAIRS].sort());

  // REVOKED sin CONSENT_REVOKED (fila forzada con triggers de la base deshabilitados solo durante el fixture) -> divergencia; el estado CANCELLED forzado sin I9 tambien.
  const G = fixtureUuid("t1617-g");
  const v = await driveInvitation(ctx, G, "1617-g", "SENT");
  const subj = fixtureUuid("s1617");
  await seedRaw(admin, async () => {
    await admin.query(
      `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete, steps_recorded)
       VALUES ($1, 'd-1617', 'C', 'P', $2, $3, $4, 'v', $5, 'REVOKED', '[]', true, ARRAY[]::text[])`,
      [G, subj, DM, v.inv, fixtureUuid("ch1617")]);
    await admin.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE tenant_id = $1 AND invitation_ref = $2", [G, v.inv]);
  });
  const report = await runReconciler(ctx);
  const tags = forTenant(report, G).map(tag);
  assert.ok(tags.includes("STATE_EVENT_MISMATCH:MISSING:CONSENT_REVOKED"), tags.join(","));
  assert.ok(tags.includes("STATE_EVENT_MISMATCH:MISSING:INVITATION_CANCELLED"), tags.join(","));
  assert.ok(tags.includes("STATE_EVENT_MISMATCH:MISSING:PURPOSE_DECISION_RECORDED"), tags.join(","));
});
