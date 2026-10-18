// Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.3), P-34 (placeholder; LD-15 abierta), INV-21-10 y INV-21-19.
// TEST-CNS-1312: configuracion CNS_RETENTION_* (sin default; STAGING exige; LOCAL/DEV sin variables = DISABLED_LOCAL) y nucleo del CLI.
// TEST-CNS-1323: chequeos de arranque de retencion y senal retention_purge_stale (< 26 h por store). Sin Postgres: dobles.

import { CONSENT_OWNER_INVENTORY_ALLOWLIST } from "../../../src/infra/adapters/postgres/consent-owner-inventory.allowlist.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { PLACEHOLDER_P34_RETENTION_DAYS } from "../../../src/server/modules/common/approved-parameters.ts";
import { loadRetentionConfig, RETENTION_ENV_VARS } from "../../../src/server/modules/common/retention.config.ts";
import { executeRetentionPurge, formatPurgeLine, PURGE_ORDER } from "../../../src/infra/adapters/postgres/retention-purge.ts";
import { checkRetentionPurgeFreshness, MAX_PURGE_AGE_MS, RETENTION_PURGE_STALE_SIGNAL, runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { EXPECTED_MEMBERSHIPS, OWNER_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { FakeClient } from "./fakes.ts";

// ADR-010 PR-2: el modo de roles lo declara el deploy; fuera de LOCAL/DEV es obligatorio. Los dobles de abajo asumen el modo vigente (IT0B).
process.env.CNS_DB_ROLE_MODE ??= "IT0B_SYNTHETIC";

const ALL = {
  CNS_RETENTION_SECURITY_EVENT_DAYS: "30",
  CNS_RETENTION_OTP_BUDGET_DAYS: "30",
  CNS_RETENTION_OTP_VERIFICATION_DAYS: "30",
  CNS_RETENTION_PURGE_RUN_DAYS: "30",
};

test("TEST-CNS-1312 el placeholder P-34 es 30 y no se presenta como APPROVED (LD-15 abierta)", async () => {
  assert.equal(PLACEHOLDER_P34_RETENTION_DAYS, 30);
  const approved = await import("../../../src/server/modules/common/approved-parameters.ts");
  assert.ok(!Object.keys(approved).some((k) => /^APPROVED_P34/.test(k)), "no existe APPROVED_P34_*");
});

test("TEST-CNS-1312 STAGING/PRODUCTION/entorno desconocido sin CNS_RETENTION_* (o incompleto) lanzan; con las tres validas cargan", () => {
  for (const environment of ["STAGING", "PRODUCTION", undefined, "algo"]) {
    assert.throws(() => loadRetentionConfig({}, environment), /falta configurar/, String(environment));
    assert.throws(() => loadRetentionConfig({ CNS_RETENTION_SECURITY_EVENT_DAYS: "30" }, environment), /falta configurar CNS_RETENTION_OTP_BUDGET_DAYS, CNS_RETENTION_OTP_VERIFICATION_DAYS, CNS_RETENTION_PURGE_RUN_DAYS/, String(environment));
  }
  assert.deepEqual(loadRetentionConfig(ALL, "STAGING"), { status: "CONFIGURED", config: { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 30 } });
  assert.deepEqual(loadRetentionConfig({ ...ALL, CNS_RETENTION_PURGE_RUN_DAYS: "90" }, "STAGING"), { status: "CONFIGURED", config: { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 90 } });
});

test("TEST-CNS-1312 LOCAL/DEV sin variables = DISABLED_LOCAL; parcial o invalida lanza; el CLI no usa un default en codigo", () => {
  for (const environment of ["LOCAL", "DEV"]) {
    assert.deepEqual(loadRetentionConfig({}, environment), { status: "DISABLED_LOCAL" });
    assert.deepEqual(loadRetentionConfig({ CNS_RETENTION_SECURITY_EVENT_DAYS: "" }, environment), { status: "DISABLED_LOCAL" });
    assert.throws(() => loadRetentionConfig({ CNS_RETENTION_SECURITY_EVENT_DAYS: "30" }, environment), /falta configurar/);
    assert.equal(loadRetentionConfig(ALL, environment).status, "CONFIGURED");
    // CNS_RETENTION_OTP_BUDGET_DAYS no tiene default en codigo (spec 4.3): si falta habiendo otras, lanza.
    assert.throws(() => loadRetentionConfig({ ...ALL, CNS_RETENTION_OTP_BUDGET_DAYS: "" }, environment), /falta configurar CNS_RETENTION_OTP_BUDGET_DAYS/);
  }
  for (const bad of ["0", "-1", "1.5", "abc", "30d", "3651", "030", " "]) {
    for (const key of Object.values(RETENTION_ENV_VARS)) {
      assert.throws(() => loadRetentionConfig({ ...ALL, [key]: bad }, "LOCAL"), /entero de dias/, `${key}=${bad}`);
    }
  }
  assert.equal(loadRetentionConfig({ ...ALL, CNS_RETENTION_SECURITY_EVENT_DAYS: "3650" }, "STAGING").status, "CONFIGURED");
});

test("TEST-CNS-1312 el nucleo del CLI purga purge_run primero, llama ops.purge_p34 con los dias configurados e imprime solo run_id y conteos", async () => {
  const RUN = "11111111-1111-4111-8111-111111111111";
  const db = new FakeClient((text) => {
    if (text.includes("ops.purge_p34")) return { rows: [{ run_id: RUN }] };
    if (text.includes("ops.purge_run_summary")) return { rows: [{ tenants: "2", eligible_before: "5", deleted_count: "5", remaining_older_than_cutoff: "0" }] };
    return undefined;
  });
  const results = await executeRetentionPurge(db, { securityEventDays: 30, otpBudgetDays: 21, otpVerificationDays: 14, purgeRunDays: 60 });
  assert.deepEqual(results.map((r) => r.store), [...PURGE_ORDER]);
  assert.equal(PURGE_ORDER[0], "purge_run");
  const calls = db.queries.filter((q) => q.text.includes("ops.purge_p34")).map((q) => q.values);
  assert.deepEqual(calls, [["purge_run", 60], ["security_event", 30], ["otp_budget", 21], ["otp_verification", 14]]);
  assert.equal(formatPurgeLine(results[0]!), `store=purge_run run_id=${RUN} tenants=2 eligible=5 deleted=5 remaining=0`);
  // Post-condicion incumplida: falla cerrado.
  const bad = new FakeClient((text) => {
    if (text.includes("ops.purge_p34")) return { rows: [{ run_id: RUN }] };
    if (text.includes("ops.purge_run_summary")) return { rows: [{ tenants: "1", eligible_before: "5", deleted_count: "4", remaining_older_than_cutoff: "1" }] };
    return undefined;
  });
  await assert.rejects(() => executeRetentionPurge(bad, { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 30 }), /post-condicion/);
});

// --- TEST-CNS-1323 ---------------------------------------------------------------------------------------------------------------------------

function healthyDb(status: Array<{ store: string; retention_days: string; last_run_at: Date | null }> | "error", purgeExecRow?: { app_rw: boolean; platform_rw: boolean }): FakeClient {
  return new FakeClient((text) => {
    if (text.includes("V2|trigger|")) return { rows: CONSENT_OWNER_INVENTORY_ALLOWLIST.map((line) => ({ line })) }; // PR-7c (F-PR7-01): inventario de consent_owner = allowlist
    if (text.includes("pg_catalog.pg_settings")) return { rows: [] };
    if (text.includes("to_regprocedure")) return purgeExecRow === undefined ? { rows: [{ app_rw: false, platform_rw: false }] } : { rows: [purgeExecRow] };
    if (text.includes("ops.retention_status")) return status === "error" ? new Error("boom") : { rows: status };
    if (text.includes("u.rolname AS member")) return { rows: EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin })) }; // ADR-010 PR-2
    if (text.includes("FROM pg_catalog.pg_auth_members")) return { rows: [{ inherit_option: false, set_option: true }] };
    if (text.includes("has_table_privilege('staff_roster_reader', c.oid")) return { rows: [] };
    if (text.includes("reader_select")) return { rows: [{ reader_select: true, runtime_select: false, schema_create: false }] };
    if (text.includes("clock_timestamp")) return { rows: [{ db_ms: String(Date.now()) }] };
    if (text.includes("FROM pg_catalog.pg_roles WHERE rolname = current_user")) return { rows: [{ rolname: "app_rw", session_user_name: "app_rw", session_super: false, rolsuper: false, rolbypassrls: false }] };
    if (text.includes("pg_has_role")) return { rows: OWNER_ROLES.map((owner) => ({ owner, member: false })) };
    if (text.includes("has_schema_privilege")) return { rows: [] };
    if (text.includes("has_parameter_privilege")) return { rows: [{ can_set: false }] };
    if (text.includes("ops.db_catalog")) return { rows: [{ data_class: "SYNTHETIC", environment: "STAGING" }] };
    return undefined;
  });
}
const fresh = (hoursAgo: number): Date => new Date(Date.now() - hoursAgo * 3_600_000);
const cfg = { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 30 };
const policy = (last: Date | null) => ["otp_budget", "otp_verification", "purge_run", "security_event"].map((store) => ({ store, retention_days: "30", last_run_at: last }));

test("TEST-CNS-1323 arranque en STAGING: sin retencion configurada no arranca; con retencion que difiere de ops.retention_policy no arranca; coincidente arranca", async () => {
  const missing = await runStartupChecks(healthyDb(policy(null)), { expectedEnvironment: "STAGING", expectedRole: "app_rw" });
  assert.equal(missing.ok, false);
  assert.ok(missing.failures.some((f) => /CNS_RETENTION_\*.*STAGING/.test(f)));

  const differs = await runStartupChecks(healthyDb(policy(null)), { expectedEnvironment: "STAGING", expectedRole: "app_rw", retention: { ...cfg, securityEventDays: 7 } });
  assert.equal(differs.ok, false);
  assert.ok(differs.failures.some((f) => /security_event difiere de ops\.retention_policy/.test(f)));

  const unreadable = await runStartupChecks(healthyDb("error"), { expectedEnvironment: "STAGING", expectedRole: "app_rw", retention: cfg });
  assert.ok(unreadable.failures.some((f) => /no se pudo verificar ops\.retention_policy/.test(f)), "fail-closed");

  const noPolicy = await runStartupChecks(healthyDb([{ store: "security_event", retention_days: "30", last_run_at: null }]), { expectedEnvironment: "STAGING", expectedRole: "app_rw", retention: cfg });
  assert.ok(noPolicy.failures.some((f) => /sin politica|no tiene politica para (otp_budget|otp_verification|purge_run)/.test(f)));

  const ok = await runStartupChecks(healthyDb(policy(null)), { expectedEnvironment: "STAGING", expectedRole: "app_rw", retention: cfg });
  assert.deepEqual(ok, { ok: true, failures: [] });
});

test("TEST-CNS-1323 senal retention_purge_stale: sin corrida o con corrida de 26 h o mas por store; con corridas recientes de todos, ok", async () => {
  assert.equal(RETENTION_PURGE_STALE_SIGNAL, "retention_purge_stale");
  assert.equal(MAX_PURGE_AGE_MS, 26 * 3_600_000);
  assert.deepEqual(await checkRetentionPurgeFreshness(healthyDb(policy(fresh(1)))), { ok: true, stale: [] });
  assert.deepEqual(await checkRetentionPurgeFreshness(healthyDb(policy(fresh(25.9)))), { ok: true, stale: [] });
  assert.deepEqual(await checkRetentionPurgeFreshness(healthyDb(policy(null))), { ok: false, stale: ["otp_budget", "otp_verification", "purge_run", "security_event"] });
  assert.deepEqual(await checkRetentionPurgeFreshness(healthyDb(policy(fresh(26.5)))), { ok: false, stale: ["otp_budget", "otp_verification", "purge_run", "security_event"] });
  const mixed = await checkRetentionPurgeFreshness(healthyDb([
    { store: "otp_budget", retention_days: "30", last_run_at: fresh(2) },
    { store: "otp_verification", retention_days: "30", last_run_at: fresh(2) },
    { store: "purge_run", retention_days: "30", last_run_at: fresh(30) },
    { store: "security_event", retention_days: "30", last_run_at: fresh(3) },
  ]));
  assert.deepEqual(mixed, { ok: false, stale: ["purge_run"] });
  // Sin poder leer: falla cerrado (senal), nunca un falso ok. Sin filas: tampoco ok.
  assert.equal((await checkRetentionPurgeFreshness(healthyDb("error"))).ok, false);
  assert.equal((await checkRetentionPurgeFreshness(healthyDb([]))).ok, false);
  // La senal no lleva etiquetas de tenant: solo nombres de store.
  assert.ok(mixed.stale.every((s) => /^[a-z_]+$/.test(s)));
});

test("TEST-CNS-1323 el arranque falla si app_rw o platform_rw pueden ejecutar ops.purge_p34 (solo worker)", async () => {
  for (const row of [{ app_rw: true, platform_rw: false }, { app_rw: false, platform_rw: true }]) {
    const r = await runStartupChecks(healthyDb(policy(null), row), { expectedEnvironment: "STAGING", expectedRole: "app_rw", retention: cfg });
    assert.ok(r.failures.some((f) => /ejecutar ops\.purge_p34/.test(f)), r.failures.join("|"));
  }
});

test("TEST-CNS-1338 el nucleo del CLI reintenta UNA vez ante 23514 de purge_run_deleted_eq_eligible; si vuelve a fallar propaga; otros errores no se reintentan (P2-6)", async () => {
  const RUN = "22222222-2222-4222-8222-222222222222";
  const race = (): Error => Object.assign(new Error("check"), { code: "23514", constraint: "purge_run_deleted_eq_eligible" });
  const summaryRow = { rows: [{ tenants: "0", eligible_before: "0", deleted_count: "0", remaining_older_than_cutoff: "0" }] };
  const cfg1 = { securityEventDays: 30, otpBudgetDays: 30, otpVerificationDays: 30, purgeRunDays: 30 };

  let failuresLeft = 1;
  const once = new FakeClient((text, values) => {
    if (text.includes("ops.purge_p34")) {
      if (values?.[0] === "otp_budget" && failuresLeft-- > 0) return race();
      return { rows: [{ run_id: RUN }] };
    }
    if (text.includes("ops.purge_run_summary")) return summaryRow;
    return undefined;
  });
  const results = await executeRetentionPurge(once, cfg1);
  assert.equal(results.length, PURGE_ORDER.length);
  assert.equal(once.queries.filter((q) => q.text.includes("ops.purge_p34") && q.values?.[0] === "otp_budget").length, 2, "un reintento");

  const always = new FakeClient((text) => (text.includes("ops.purge_p34") ? race() : undefined));
  await assert.rejects(() => executeRetentionPurge(always, cfg1), /check/);
  assert.equal(always.queries.filter((q) => q.text.includes("ops.purge_p34")).length, 2, "solo un reintento, luego falla");

  const other = new FakeClient((text) => (text.includes("ops.purge_p34") ? Object.assign(new Error("otro"), { code: "23514", constraint: "otra" }) : undefined));
  await assert.rejects(() => executeRetentionPurge(other, cfg1), /otro/);
  assert.equal(other.queries.filter((q) => q.text.includes("ops.purge_p34")).length, 1, "otras constraints no se reintentan");
});
