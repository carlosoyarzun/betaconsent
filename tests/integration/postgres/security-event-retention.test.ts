// Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.2/§4.3, D5), CA-146, P-34 (placeholder de 30 dias; LD-15 abierta), INV-21-07/08/09/10/18,
// db/migrations/0031_retention_purge_p34.sql, INV-CM-01. Contra Postgres real (harness.ts; skip fuera de CI sin entorno): TEST-CNS-1308 (borrado/UPDATE/
// TRUNCATE directo falla para todos), 1309 (purga de security_event: solo lo vencido, conteos, una fila por tenant), 1310 (purga de purge_run y resumen),
// 1311 (purge_p34 aborta con politica distinta/ausente; retention_policy solo-agregar y sin grants), 1313 (CLI y chequeos de arranque), 1322 (purga de
// app.otp_verification). Usa SET ROLE security_event_owner (ruta en la allowlist del checker). Solo datos sinteticos; relojes sinteticos (occurred_at
// antiguo insertado por el superusuario del harness). Estos tests NO se corrieron localmente (sin Docker/Postgres): los corre el CI.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import type { Client } from "pg";

import { executeRetentionPurge } from "../../../src/infra/adapters/postgres/retention-purge.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { PLACEHOLDER_P34_RETENTION_DAYS } from "../../../src/server/modules/common/approved-parameters.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const DAYS = PLACEHOLDER_P34_RETENTION_DAYS;

/** Inserta un OTP_FAILED con occurred_at sintetico (el superusuario del harness fija el reloj; app_rw no puede). */
async function insertEvent(admin: Client, tenant: string, label: string, ageMinutes: number): Promise<void> {
  await admin.query(
    `INSERT INTO ops.security_event (tenant_id, event_type, verification_ref, otp_scope, occurred_at)
     VALUES ($1, 'OTP_FAILED', $2, 'DECISION', pg_catalog.now() - ($3::int * interval '1 minute'))`,
    [tenant, fixtureUuid(label), ageMinutes],
  );
}
const DAY_MIN = 24 * 60;
const OLD = DAYS * DAY_MIN + 60; // 1 h mas viejo que el limite
const EDGE_KEPT = DAYS * DAY_MIN - 60; // 1 h mas nuevo que el limite
const countAt = async (admin: Client, sql: string, values: unknown[] = []): Promise<number> => Number((await admin.query<{ n: string }>(sql, values)).rows[0]?.n);
const purge = async (worker: Client, store: string, days = DAYS): Promise<string> =>
  (await worker.query<{ run_id: string }>("SELECT ops.purge_p34($1, make_interval(days => $2)) AS run_id", [store, days])).rows[0]!.run_id;

pgTest("TEST-CNS-1308 pg: DELETE/UPDATE/TRUNCATE directos sobre ops.security_event fallan para superusuario, consent_owner, app_rw, worker y security_event_owner sin ops.purge_p34 (INV-21-07)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t-1308");
  await insertEvent(admin, t, "v-1308-old", OLD);
  const before = await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]);

  // Superusuario: el trigger ENABLE ALWAYS (current_user no es security_event_owner) incluso con la fila vencida.
  for (const sql of ["DELETE FROM ops.security_event WHERE tenant_id = '" + t + "'", "UPDATE ops.security_event SET otp_scope = 'MANAGE'", "TRUNCATE ops.security_event"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario: ${sql}`);
  }
  // Superusuario con una bandera falsa: sigue sin pasar porque current_user no es security_event_owner.
  await admin.query("BEGIN");
  try {
    await admin.query("SELECT set_config('ops.purge_active', 'on', true)");
    await assert.rejects(() => admin.query("DELETE FROM ops.security_event WHERE tenant_id = $1", [t]), (e: unknown) => codeOf(e) === "23000", "superusuario con bandera");
  } finally {
    await admin.query("ROLLBACK");
  }

  // Roles de runtime: sin privilegios (42501).
  for (const role of ["app_rw", "worker", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    for (const sql of ["DELETE FROM ops.security_event", "UPDATE ops.security_event SET otp_scope = 'MANAGE'", "TRUNCATE ops.security_event"]) {
      await assert.rejects(() => c.query(sql), (e: unknown) => codeOf(e) === "42501", `${role}: ${sql}`);
    }
  }

  // Migrador: consent_owner no tiene privilegios; security_event_owner (SET ROLE) ve la fila vencida pero el trigger exige ops.purge_p34.
  const migrator = await ctx.connectAs("consent_migrator");
  for (const asOwner of [false, true]) {
    for (const sql of ["DELETE FROM ops.security_event", "TRUNCATE ops.security_event"]) {
      await migrator.query("BEGIN");
      try {
        await migrator.query("SET LOCAL ROLE consent_owner");
        if (asOwner) await migrator.query("SET LOCAL ROLE security_event_owner");
        await assert.rejects(() => migrator.query(sql), (e: unknown) => codeOf(e) === (asOwner ? "23000" : "42501"), `${asOwner ? "security_event_owner" : "consent_owner"}: ${sql}`);
      } finally {
        await migrator.query("ROLLBACK");
      }
    }
  }
  // UPDATE como security_event_owner: no hay policy de UPDATE, no toca ninguna fila.
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("SET LOCAL ROLE security_event_owner");
    assert.equal((await migrator.query("UPDATE ops.security_event SET otp_scope = 'MANAGE'")).rowCount, 0);
  } finally {
    await migrator.query("ROLLBACK");
  }
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]), before, "nada se borro ni se modifico");
});

pgTest("TEST-CNS-1309 pg: ops.purge_p34('security_event') borra solo lo anterior al corte; la fila cercana al borde se conserva; deleted = eligible; remaining = 0; una fila purge_run por tenant mas el resumen (INV-21-08)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const A = fixtureUuid("t-1309-a");
  const B = fixtureUuid("t-1309-b");
  await insertEvent(admin, A, "a-old1", OLD);
  await insertEvent(admin, A, "a-old2", OLD + 10 * DAY_MIN);
  await insertEvent(admin, A, "a-edge", EDGE_KEPT);
  await insertEvent(admin, A, "a-new", 5);
  await insertEvent(admin, B, "b-old", OLD);
  await insertEvent(admin, B, "b-new", 5);
  const eligible = await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE occurred_at < now() - make_interval(days => $1)", [DAYS]);
  assert.ok(eligible >= 3);

  const worker = await ctx.connectAs("worker");
  const runId = await purge(worker, "security_event");

  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE occurred_at < now() - make_interval(days => $1)", [DAYS]), 0, "post-condicion: 0 vencidas");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [A]), 2, "A conserva la fila del borde y la nueva");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [B]), 1, "B conserva la nueva");

  const rows = (await admin.query<{ tenant_id: string | null; eligible_before: string; deleted_count: string; remaining_older_than_cutoff: string; retention: string; environment: string; store: string }>(
    "SELECT tenant_id, eligible_before, deleted_count, remaining_older_than_cutoff, retention::text, environment, store FROM ops.purge_run WHERE run_id = $1", [runId],
  )).rows;
  const summary = rows.find((r) => r.tenant_id === null)!;
  assert.equal(Number(summary.eligible_before), eligible);
  assert.equal(Number(summary.deleted_count), eligible);
  assert.equal(Number(summary.remaining_older_than_cutoff), 0);
  assert.equal(summary.store, "security_event");
  assert.equal(summary.environment, "LOCAL");
  assert.equal(rows.filter((r) => r.tenant_id !== null).reduce((n, r) => n + Number(r.deleted_count), 0), eligible, "los conteos por tenant suman el resumen");
  assert.equal(Number(rows.find((r) => r.tenant_id === A)!.deleted_count), 2);
  assert.equal(Number(rows.find((r) => r.tenant_id === B)!.deleted_count), 1);
  assert.equal(rows.filter((r) => r.tenant_id === A).length, 1, "una fila por tenant");
  const tenantRange = (await admin.query<{ ok: boolean }>(
    "SELECT bool_and(min_deleted_at <= max_deleted_at AND max_deleted_at < cutoff) AS ok FROM ops.purge_run WHERE run_id = $1 AND tenant_id IS NOT NULL", [runId],
  )).rows[0];
  assert.equal(tenantRange?.ok, true);

  // Una segunda corrida sin nada vencido: fila resumen con ceros (prueba de que la corrida ocurrio).
  const again = await purge(worker, "security_event");
  const second = (await admin.query<{ eligible_before: string; deleted_count: string; min_deleted_at: string | null; n: string }>(
    "SELECT eligible_before, deleted_count, min_deleted_at, (SELECT count(*) FROM ops.purge_run WHERE run_id = $1) AS n FROM ops.purge_run WHERE run_id = $1 AND tenant_id IS NULL", [again],
  )).rows[0];
  assert.deepEqual([Number(second?.eligible_before), Number(second?.deleted_count), second?.min_deleted_at, Number(second?.n)], [0, 0, null, 1]);
});

pgTest("TEST-CNS-1310 pg: la purga de purge_run no borra la corrida en curso; ops.purge_run es solo-agregar y sin acceso de runtime; ops.purge_run_summary solo devuelve conteos al worker (INV-21-07/08)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const worker = await ctx.connectAs("worker");
  // Fila de corrida vencida (31 dias) insertada con reloj sintetico.
  const oldRun = fixtureUuid("run-1310-old");
  await admin.query(
    `INSERT INTO ops.purge_run (run_id, store, tenant_id, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff, started_at, finished_at)
     VALUES ($1, 'security_event', NULL, now() - interval '61 days', interval '30 days', 0, 0, 0, now() - interval '31 days', now() - interval '31 days')`,
    [oldRun],
  );
  const baseline = await countAt(admin, "SELECT count(*) AS n FROM ops.purge_run WHERE finished_at < now() - make_interval(days => $1)", [DAYS]);
  assert.ok(baseline >= 1);

  const runId = await purge(worker, "purge_run");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.purge_run WHERE run_id = $1", [oldRun]), 0, "la corrida vencida se borro");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.purge_run WHERE finished_at < now() - make_interval(days => $1)", [DAYS]), 0);
  const own = (await admin.query<{ eligible_before: string; deleted_count: string; store: string }>("SELECT eligible_before, deleted_count, store FROM ops.purge_run WHERE run_id = $1", [runId])).rows;
  assert.equal(own.length, 1, "la corrida en curso quedo registrada y no se borro a si misma");
  assert.deepEqual([own[0]!.store, Number(own[0]!.eligible_before), Number(own[0]!.deleted_count)], ["purge_run", baseline, baseline]);

  // Resumen para el CLI: solo conteos, sin tenant_id; solo worker.
  const summary = (await worker.query<Record<string, string>>("SELECT * FROM ops.purge_run_summary($1)", [runId])).rows;
  assert.deepEqual(Object.keys(summary[0]!).sort(), ["deleted_count", "eligible_before", "remaining_older_than_cutoff", "store", "tenants"]);
  for (const role of ["app_rw", "platform_rw"] as const) {
    await assert.rejects(async () => (await ctx.connectAs(role)).query("SELECT * FROM ops.purge_run_summary($1)", [runId]), (e: unknown) => codeOf(e) === "42501", `${role} summary`);
  }

  // purge_run solo-agregar: UPDATE/DELETE/TRUNCATE fallan (superusuario: trigger; runtime: sin privilegios).
  for (const sql of ["UPDATE ops.purge_run SET deleted_count = deleted_count", "DELETE FROM ops.purge_run", "TRUNCATE ops.purge_run"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario: ${sql}`);
    for (const role of ["app_rw", "worker", "platform_rw"] as const) {
      await assert.rejects(async () => (await ctx.connectAs(role)).query(sql), (e: unknown) => codeOf(e) === "42501", `${role}: ${sql}`);
    }
  }
  for (const role of ["app_rw", "worker", "platform_rw"] as const) {
    await assert.rejects(async () => (await ctx.connectAs(role)).query("SELECT 1 FROM ops.purge_run"), (e: unknown) => codeOf(e) === "42501", `${role} SELECT`);
    await assert.rejects(async () => (await ctx.connectAs(role)).query("SELECT 1 FROM ops.retention_policy"), (e: unknown) => codeOf(e) === "42501", `${role} SELECT retention_policy`);
  }
  // CHECK de la post-condicion: una fila con restantes > 0 no se puede registrar.
  await assert.rejects(
    () => admin.query(
      `INSERT INTO ops.purge_run (run_id, store, cutoff, retention, eligible_before, deleted_count, remaining_older_than_cutoff, started_at)
       VALUES (gen_random_uuid(), 'security_event', now(), interval '30 days', 1, 1, 1, now() - interval '1 second')`,
    ),
    (e: unknown) => codeOf(e) === "23514",
  );
});

pgTest("TEST-CNS-1311 pg: ops.purge_p34 aborta (22023) si la retencion esperada difiere de la politica, el store no tiene politica o es nulo, sin borrar nada; retention_policy es solo-agregar con minimo 1 dia y sembrada con el placeholder P-34; EXECUTE solo worker (INV-21-09)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const worker = await ctx.connectAs("worker");
  const t = fixtureUuid("t-1311");
  await insertEvent(admin, t, "v-1311-old", OLD);
  const runsBefore = await countAt(admin, "SELECT count(*) AS n FROM ops.purge_run");

  for (const [store, expected] of [["security_event", "7 days"], ["security_event", "31 days"], ["otp_budget", "30 days"], ["no_existe", "30 days"], [null, "30 days"], ["security_event", null]] as const) {
    await assert.rejects(() => worker.query("SELECT ops.purge_p34($1::text, $2::interval)", [store, expected]), (e: unknown) => codeOf(e) === "22023", `${store}/${expected}`);
  }
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]), 1, "no se borro nada");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.purge_run"), runsBefore, "no se registro ninguna corrida");

  // Politica sembrada: tres stores a 30 dias, marcada como placeholder (LD-15 abierta), sin otp_budget (llega con PR-4).
  const policy = (await admin.query<{ store: string; retention: string; decision_ref: string }>("SELECT store, retention::text, decision_ref FROM ops.retention_policy ORDER BY store")).rows;
  assert.deepEqual(policy.map((p) => [p.store, p.retention]), [["otp_verification", `${DAYS} days`], ["purge_run", `${DAYS} days`], ["security_event", `${DAYS} days`]]);
  for (const p of policy) assert.match(p.decision_ref, /placeholder.*LD-15/);

  // Solo-agregar (superusuario: trigger) y minimo de 1 dia (CHECK; como security_event_owner via SET ROLE).
  for (const sql of ["UPDATE ops.retention_policy SET retention = interval '1 day'", "DELETE FROM ops.retention_policy", "TRUNCATE ops.retention_policy"]) {
    await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", sql);
  }
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("SET LOCAL ROLE security_event_owner");
    await assert.rejects(() => migrator.query("INSERT INTO ops.retention_policy (store, retention, decision_ref) VALUES ('otp_budget', interval '23 hours', 'x')"), (e: unknown) => codeOf(e) === "23514");
  } finally {
    await migrator.query("ROLLBACK");
  }

  // EXECUTE: purge_p34 y purge_run_summary solo worker; retention_status app_rw y worker; PUBLIC nada.
  const exec = async (role: string, fn: string): Promise<boolean> => (await admin.query<{ p: boolean }>("SELECT has_function_privilege($1, $2::regprocedure, 'EXECUTE') AS p", [role, fn])).rows[0]!.p;
  for (const role of ["app_rw", "worker", "platform_rw", "public"]) {
    assert.equal(await exec(role, "ops.purge_p34(text, interval)"), role === "worker", `purge_p34 ${role}`);
    assert.equal(await exec(role, "ops.purge_run_summary(uuid)"), role === "worker", `purge_run_summary ${role}`);
    assert.equal(await exec(role, "ops.retention_status()"), role === "worker" || role === "app_rw", `retention_status ${role}`);
    assert.equal(await exec(role, "ops.security_event_guard()"), false, `guard ${role}`);
  }
  // Cada funcion nueva es de security_event_owner con search_path fijo.
  const fns = (await admin.query<{ proname: string; owner: string; cfg: string[] }>(
    `SELECT proname, pg_get_userbyid(proowner) AS owner, proconfig AS cfg FROM pg_proc WHERE pronamespace = 'ops'::regnamespace
      AND proname IN ('purge_p34', 'purge_run_summary', 'retention_status', 'security_event_guard', 'append_only_guard') ORDER BY proname`,
  )).rows;
  assert.equal(fns.length, 5);
  for (const f of fns) {
    assert.equal(f.owner, "security_event_owner", f.proname);
    assert.ok(f.cfg.includes("search_path=pg_catalog, pg_temp"), f.proname);
  }
});

pgTest("TEST-CNS-1313 pg: el CLI retention-purge-cli purga como worker e imprime solo run_id y conteos; sin CNS_RETENTION_* en LOCAL sale 3 DISABLED_LOCAL; con una retencion distinta de la politica no purga; STAGING sin variables no arranca (INV-21-10)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t-1313");
  await insertEvent(admin, t, "v-1313-old", OLD);
  await insertEvent(admin, t, "v-1313-new", 5);
  const base = { PATH: process.env.PATH ?? "", CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("worker") };
  const cfg = { CNS_RETENTION_SECURITY_EVENT_DAYS: String(DAYS), CNS_RETENTION_OTP_VERIFICATION_DAYS: String(DAYS), CNS_RETENTION_PURGE_RUN_DAYS: String(DAYS) };
  const run = (env: Record<string, string>) => spawnSync(process.execPath, ["src/infra/adapters/postgres/retention-purge-cli.ts"], { env, encoding: "utf8" });

  const disabled = run(base);
  assert.equal(disabled.status, 3, disabled.stderr);
  assert.match(disabled.stdout, /DISABLED_LOCAL/);
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]), 2, "deshabilitada: no purga");

  // Retencion configurada distinta de la politica: no arranca, no borra.
  const mismatch = run({ ...base, ...cfg, CNS_RETENTION_SECURITY_EVENT_DAYS: "7" });
  assert.equal(mismatch.status, 1);
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]), 2);

  // Rol equivocado (app_rw) o STAGING sin variables: no corre.
  assert.equal(run({ ...base, ...cfg, CNS_DATABASE_URL: ctx.urlFor("app_rw") }).status, 1);
  assert.equal(run({ ...base, CNS_ENVIRONMENT: "STAGING" }).status, 1);

  const ok = run({ ...base, ...cfg });
  assert.equal(ok.status, 0, ok.stderr);
  const lines = ok.stdout.trim().split("\n");
  assert.equal(lines.length, 3, "una linea por store");
  for (const line of lines) assert.match(line, /^store=(purge_run|security_event|otp_verification) run_id=[0-9a-f-]{36} tenants=\d+ eligible=\d+ deleted=\d+ remaining=0$/);
  assert.ok(!ok.stdout.includes(t) && !ok.stdout.includes(fixtureUuid("v-1313-old")), "sin tenant_id ni refs en la salida");
  assert.equal(await countAt(admin, "SELECT count(*) AS n FROM ops.security_event WHERE tenant_id = $1", [t]), 1, "solo queda la fila nueva");

  // Nucleo reutilizable: otra corrida devuelve los tres stores con post-condicion 0.
  const results = await executeRetentionPurge(await ctx.connectAs("worker"), { securityEventDays: DAYS, otpVerificationDays: DAYS, purgeRunDays: DAYS });
  assert.deepEqual(results.map((r) => r.store), ["purge_run", "security_event", "otp_verification"]);
  assert.ok(results.every((r) => r.remaining === 0 && r.deleted === r.eligible));

  // Chequeo de arranque contra la base: coincide / difiere / STAGING sin configuracion.
  const app = await ctx.connectAs("app_rw");
  const same = { securityEventDays: DAYS, otpVerificationDays: DAYS, purgeRunDays: DAYS };
  assert.deepEqual(await runStartupChecks(app, { expectedEnvironment: "LOCAL", expectedRole: "app_rw", retention: same }), { ok: true, failures: [] });
  const differs = await runStartupChecks(app, { expectedEnvironment: "LOCAL", expectedRole: "app_rw", retention: { ...same, otpVerificationDays: 7 } });
  assert.ok(differs.failures.some((f) => /otp_verification difiere de ops\.retention_policy/.test(f)), differs.failures.join("|"));
  const noConfig = await runStartupChecks(app, { expectedRole: "app_rw" });
  assert.equal(noConfig.ok, true, "LOCAL sin configuracion: arranca (purga deshabilitada)");
});

pgTest("TEST-CNS-1322 pg: la purga de app.otp_verification borra solo filas con expires_at anterior al corte, nunca un challenge activo; security_event_owner no lee code_hash ni channel_ref (INV-21-18)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t-1322");
  const insertOtp = (ref: string, parent: string, state: string, expiresSql: string): Promise<unknown> =>
    admin.query(
      `INSERT INTO app.otp_verification (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, state)
       VALUES ($1, $2, 'DECISION', $3, 'titular-sintetico@example.com', repeat('a', 64), 0, ${expiresSql}, $4)`,
      [t, ref, parent, state],
    );
  await insertOtp("old", "p-old", "EXPIRED", `now() - interval '${DAYS + 1} days'`);
  await insertOtp("old-active-state", "p-old2", "CODE_SENT", `now() - interval '${DAYS + 2} days'`); // vencido hace mucho aunque su estado nunca se actualizo
  await insertOtp("recent", "p-recent", "EXPIRED", `now() - interval '${DAYS - 1} days'`);
  await insertOtp("active", "p-active", "CODE_SENT", `now() + interval '10 minutes'`);
  const eligible = await countAt(admin, "SELECT count(*) AS n FROM app.otp_verification WHERE expires_at < now() - make_interval(days => $1)", [DAYS]);
  assert.ok(eligible >= 2);

  const worker = await ctx.connectAs("worker");
  const runId = await purge(worker, "otp_verification");
  const left = (await admin.query<{ verification_ref: string }>("SELECT verification_ref FROM app.otp_verification WHERE tenant_id = $1 ORDER BY verification_ref", [t])).rows.map((r) => r.verification_ref);
  assert.deepEqual(left, ["active", "recent"], "el challenge activo y el reciente se conservan");
  const summary = (await admin.query<{ eligible_before: string; deleted_count: string; store: string }>("SELECT eligible_before, deleted_count, store FROM ops.purge_run WHERE run_id = $1 AND tenant_id IS NULL", [runId])).rows[0];
  assert.deepEqual([summary?.store, Number(summary?.eligible_before), Number(summary?.deleted_count)], ["otp_verification", eligible, eligible]);

  // El dueno de la purga no lee el correo ni el hash; no inserta ni actualiza.
  const migrator = await ctx.connectAs("consent_migrator");
  for (const sql of ["SELECT channel_ref FROM app.otp_verification", "SELECT code_hash FROM app.otp_verification", "UPDATE app.otp_verification SET attempts = 1", "INSERT INTO app.otp_verification (tenant_id) VALUES (gen_random_uuid())"]) {
    await migrator.query("BEGIN");
    try {
      await migrator.query("SET LOCAL ROLE consent_owner");
      await migrator.query("SET LOCAL ROLE security_event_owner");
      await assert.rejects(() => migrator.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
    } finally {
      await migrator.query("ROLLBACK");
    }
  }
  // Las columnas y policies de runtime no cambiaron: app_rw sigue sin DELETE.
  await assert.rejects(async () => (await ctx.connectAs("app_rw")).query("DELETE FROM app.otp_verification"), (e: unknown) => codeOf(e) === "42501");
});
