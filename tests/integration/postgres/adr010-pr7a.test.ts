// Gobierna: ADR-010 rev. 6 PR-7 sub-PR 7a (F-6F-01, SEC-6F-02, SEC-6F-03, SEC-6F-07 b; T-1, T-15); db/migrations/0074; specs/db-roles.spec.yaml (integrity_chain_verifier); registers/findings-register-IT0.md. SYNTHETIC ONLY.
// TEST-CNS-1763 (0074: sin USAGE de app, ACL exacta, idempotente), 1764 (los procesos de integridad arrancan en un catalogo STAGING sin EXECUTE de retencion ni USAGE de app),
// 1765 (perfil NOT_APPLICABLE asierta que el rol NO ejecuta retencion; REQUIRED sigue exigiendo la configuracion), 1766 (chain_seq NULL fuera de LOCAL = exit 2; en LOCAL se conserva el legado previo a 0013).
// Cada archivo usa su propia base: el test 1766 cambia el catalogo de la base (LOCAL <-> STAGING) y lo restaura. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { Client } from "pg";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { openProcessPool } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { startChainVerifierProcess } from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";
import { CHAIN_VERIFIER_EXIT, exitCodeFor, formatChainReport } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { MIGRATIONS_DIR, pgTest, type PgRole, type PgTestContext } from "./harness.ts";

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const T = fixtureUuid("t7a-a");
const T_LEGACY = fixtureUuid("t7a-legacy"); // tenant propio de 1766: la fila legado debe ser anterior al eslabon 1 de SU cadena
const T_ONLY_NULL = fixtureUuid("t7a-null");

async function driveInvitation(ctx: PgTestContext, tenant: string, key: string): Promise<void> {
  const inv = fixtureUuid(`inv-${key}`);
  const base: InvitationRecord = { invitationRef: inv, tenantId: tenant, contextRef: "C", productRef: "P", subjectRef: fixtureUuid(`sub-${key}`), state: "DRAFT", enrollmentRef: fixtureUuid(`en-${key}`), participationRef: fixtureUuid(`pa-${key}`) };
  const ready: InvitationRecord = { ...base, state: "READY", consentVersion: "v1", expiresAt: new Date("2030-02-03T04:05:06.789Z"), recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: "a@example.invalid" };
  const sent: InvitationRecord = { ...ready, state: "SENT", tokenHash: sha(`tok-${key}`), deliveryChannel: "CONSENT_APP_EMAIL" };
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const s of [base, ready, sent]) await uow.inTenant(tenant, (tx) => tx.invitationRepo.save(s));
  } finally {
    await pool.end();
  }
}

async function setCatalog(admin: Client, environment: "LOCAL" | "STAGING"): Promise<void> {
  // Conserva el modo original de cada trigger (ENABLE ALWAYS): ENABLE TRIGGER USER los volveria ENABLE (origin).
  const triggers = (await admin.query<{ tgname: string; tgenabled: string }>("SELECT tgname::text AS tgname, tgenabled::text AS tgenabled FROM pg_trigger WHERE tgrelid = 'ops.db_catalog'::regclass AND NOT tgisinternal")).rows;
  await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER USER");
  await admin.query("UPDATE ops.db_catalog SET environment = $1", [environment]);
  for (const t of triggers) await admin.query(`ALTER TABLE ops.db_catalog ${t.tgenabled === "A" ? "ENABLE ALWAYS" : "ENABLE"} TRIGGER ${t.tgname}`);
}

pgTest("TEST-CNS-1763 pg: 0074 revoca USAGE de app al chain-verifier (ACL exacta: USAGE solo en integrity y ops, sin CREATE) y es idempotente; 0073 re-ejecutada + 0074 deja el mismo estado", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const state = async (): Promise<string[]> =>
    (await admin.query<{ s: string }>(
      `SELECT n.nspname || ':' || has_schema_privilege('integrity_chain_verifier', n.oid, 'USAGE') || ':' || has_schema_privilege('integrity_chain_verifier', n.oid, 'CREATE') AS s
         FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY 1`)).rows.map((r) => r.s);
  const before = await state();
  assert.ok(before.includes("app:false:false"), "sin USAGE ni CREATE sobre app");
  assert.ok(before.includes("integrity:true:false") && before.includes("ops:true:false"));
  assert.equal((await admin.query("SELECT 1 FROM pg_namespace n, aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a WHERE n.nspname = 'app' AND a.grantee = 'integrity_chain_verifier'::regrole")).rowCount, 0);
  const sql74 = readFileSync(join(MIGRATIONS_DIR, "0074_adr010_pr7a_chain_verifier_no_app_usage.sql"), "utf8");
  const sql73 = readFileSync(join(MIGRATIONS_DIR, "0073_adr010_pr6f_chain_verifier_ledger_select.sql"), "utf8");
  const migrator = await ctx.connectAs("consent_migrator");
  for (const sql of [sql74, sql73 + "\n" + sql74]) {
    await migrator.query("BEGIN");
    try {
      await migrator.query(sql);
      await migrator.query("COMMIT");
    } catch (e) {
      await migrator.query("ROLLBACK");
      throw e;
    }
    assert.deepEqual(await state(), before);
  }
  // Fail-closed: si alguien le devuelve USAGE de app, la aserción de 0074 aborta.
  await admin.query("GRANT USAGE ON SCHEMA app TO integrity_chain_verifier");
  try {
    await migrator.query("BEGIN");
    // 0074 revoca primero; para probar la aserción se concede PUBLIC-equivalente: se simula con USAGE a PUBLIC.
    await admin.query("GRANT USAGE ON SCHEMA app TO PUBLIC");
    await assert.rejects(() => migrator.query(sql74), /0074/);
  } finally {
    await migrator.query("ROLLBACK");
    await admin.query("REVOKE USAGE ON SCHEMA app FROM PUBLIC");
    await admin.query("REVOKE USAGE ON SCHEMA app FROM integrity_chain_verifier");
  }
  assert.deepEqual(await state(), before);
});

const ENV_STAGING = (ctx: PgTestContext, role: PgRole): Record<string, string> => ({ CNS_ENVIRONMENT: "STAGING", CNS_DB_ROLE_MODE: "IT0B_SYNTHETIC", CNS_DATABASE_URL: ctx.urlFor(role) });

pgTest("TEST-CNS-1764 pg: chain-verifier, reconciler y verifier arrancan con CNS_ENVIRONMENT=STAGING sin CNS_RETENTION_* (sin EXECUTE de retencion); el chain-verifier no tiene USAGE de app y su chequeo de arranque resuelve la vista del roster por catalogo", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await driveInvitation(ctx, T, "1764");
  await setCatalog(admin, "STAGING");
  try {
    for (const role of ["integrity_chain_verifier", "integrity_reconciler", "integrity_verifier", "platform_rw"] as const) {
      const process = role === "integrity_chain_verifier" ? "chain-verifier" : role === "integrity_reconciler" ? "reconciler" : role === "platform_rw" ? "platform" : "verifier";
      const pool = await openProcessPool({ process, environment: "STAGING", env: ENV_STAGING(ctx, role), max: 1 });
      await pool.end();
      const direct = await runStartupChecks(await ctx.connectAs(role), { expectedRole: role, expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC", retentionProfile: "NOT_APPLICABLE" });
      assert.deepEqual(direct.failures, [], role);
    }
    assert.equal((await admin.query("SELECT has_schema_privilege('integrity_chain_verifier', 'app', 'USAGE') AS u")).rows[0]?.u, false);
    // El proceso completo (arranque + corrida) en STAGING.
    const proc = await startChainVerifierProcess({ env: ENV_STAGING(ctx, "integrity_chain_verifier") });
    try {
      const report = await proc.run();
      assert.equal(report.ok, true);
    } finally {
      await proc.stop();
    }
  } finally {
    await setCatalog(admin, "LOCAL");
  }
});

pgTest("TEST-CNS-1765 pg: NOT_APPLICABLE falla si el rol puede ejecutar ops.retention_status/purge_p34 (app_rw, worker); REQUIRED (por defecto) sigue exigiendo CNS_RETENTION_* en STAGING (F-6F-01, T-1)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  await setCatalog(admin, "STAGING");
  try {
    for (const role of ["app_rw", "worker"] as const) {
      const r = await runStartupChecks(await ctx.connectAs(role), { expectedRole: role, expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC", retentionProfile: "NOT_APPLICABLE" });
      assert.ok(r.failures.some((f) => /ops\.retention_status/.test(f) && /NOT_APPLICABLE/.test(f)), `${role}: ${r.failures.join("|")}`);
    }
    // worker puede ejecutar ops.purge_p34: tambien se reporta.
    const w = await runStartupChecks(await ctx.connectAs("worker"), { expectedRole: "worker", expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC", retentionProfile: "NOT_APPLICABLE" });
    assert.ok(w.failures.some((f) => /ops\.purge_p34/.test(f)), w.failures.join("|"));
    // Perfil por defecto (REQUIRED): STAGING sin configuracion no arranca.
    const required = await runStartupChecks(await ctx.connectAs("app_rw"), { expectedRole: "app_rw", expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC" });
    assert.ok(required.failures.some((f) => /CNS_RETENTION_\*/.test(f)), required.failures.join("|"));
    // Un rol de integridad con perfil REQUIRED (el comportamiento previo a PR-7a) no puede arrancar en STAGING con retencion configurada: no ejecuta retention_status.
    const cv = await runStartupChecks(await ctx.connectAs("integrity_chain_verifier"), {
      expectedRole: "integrity_chain_verifier", expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC",
      retention: { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 30 },
    });
    assert.ok(cv.failures.some((f) => /no se pudo verificar ops\.retention_policy/.test(f)), cv.failures.join("|"));
  } finally {
    await setCatalog(admin, "LOCAL");
  }
});

pgTest("TEST-CNS-1766 pg: chain_seq NULL fuera de LOCAL = exit 2 (tambien en un tenant sin eslabon 1); en LOCAL el legado previo a 0013 se conserva (SEC-6F-07 b)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  // Filas sin eslabon: una ANTERIOR a la cadena del tenant T (legado; la cadena se crea despues) y un tenant que solo tiene filas sin eslabon. Se retira el CHECK solo para insertarlas.
  await admin.query("ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_chain_required");
  try {
    for (const [tenant, aggregate] of [[T_LEGACY, "legacy-t"], [T_ONLY_NULL, "legacy-null"]] as const) {
      await admin.query(
        `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload)
         VALUES ($1, 'Tenant', $2, 1, 'TENANT_STATUS_CHANGED', 'HUMAN', '{}'::jsonb)`,
        [tenant, aggregate],
      );
    }
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_chain_required CHECK (chain_seq IS NOT NULL) NOT VALID");
  }
  await driveInvitation(ctx, T_LEGACY, "1766"); // la cadena de T empieza DESPUES de la fila legado
  const run = async (environment: "LOCAL" | "STAGING") => {
    const env = environment === "LOCAL" ? { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_chain_verifier") } : ENV_STAGING(ctx, "integrity_chain_verifier");
    const proc = await startChainVerifierProcess({ env });
    try {
      return await proc.run();
    } finally {
      await proc.stop();
    }
  };
  // LOCAL: el legado anterior a la cadena no cuenta (y un tenant sin eslabon 1 tampoco): verde.
  const local = await run("LOCAL");
  assert.equal(local.ok, true, formatChainReport(local).join("|"));
  assert.equal(exitCodeFor(local), CHAIN_VERIFIER_EXIT.OK);
  // STAGING (catalogo): cualquier fila sin eslabon es exit 2, en T y en el tenant que solo tiene filas sin eslabon.
  await setCatalog(admin, "STAGING");
  try {
    const staging = await run("STAGING");
    assert.equal(staging.ok, false);
    assert.equal(exitCodeFor(staging), CHAIN_VERIFIER_EXIT.BROKEN);
    assert.equal(staging.unchained, 2);
    const lines = formatChainReport(staging);
    assert.ok(lines.some((l) => l.startsWith("chain_verify_unchained") && l.includes(T_ONLY_NULL)), lines.join("|"));
    assert.ok(lines.some((l) => l.startsWith("chain_verify_unchained") && l.includes(T_LEGACY)), lines.join("|"));
    for (const l of lines) assert.ok(!/legacy/.test(l), "el log no repite datos de las filas");
  } finally {
    await setCatalog(admin, "LOCAL");
  }
});
