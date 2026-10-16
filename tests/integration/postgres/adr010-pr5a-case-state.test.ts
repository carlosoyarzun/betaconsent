// Gobierna: ADR-010 rev. 4 §4.2 (PR-5a), specs/state-machines/revocation.spec.yaml `dbEnforcement` (FN-RV-01..15, TRG-RV-01, INV-RV-12),
// specs/db-roles.spec.yaml (INV-DBR-04, INV-DBR-05, transition_owner), GRD-RV-05/26/29, F-A10-01 (app.revocation), F-A10-03..06,
// db/migrations/0037_adr010_case_state_revocation.sql. SYNTHETIC ONLY.
// TEST-CNS-1373 (app_rw no escribe app.revocation ni deja REVOKED; trigger por efecto), TEST-CNS-1374 (CHECKs GRD-RV-26/05/29),
// TEST-CNS-1375 (vectores dorados TS<->SQL: canonical_json y cadena del ledger escrita por las funciones), TEST-CNS-1376 (confirm_revocation
// rechaza HUMAN_ASSISTED; catalogo exacto de case_state).
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgTenantResolver } from "../../../src/infra/adapters/postgres/tenant-resolver.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { canonicalJson, verifyLedgerChain } from "../../../src/server/modules/common/ledger-chain.ts";
import type { RevocationPorts } from "../../../src/server/modules/revocation/revocation.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { revokeVia, type X6Env } from "../../contract/x6-revocation-scenarios.ts";
import { runFA1029Scenarios } from "../../contract/f-a10-29-scenarios.ts";
import { pgTest, seedFixture } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";
import { completeDownstreamAsWorker } from "./worker-env.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const constraintOf = (e: unknown): string | undefined => (e as { constraint?: string }).constraint;
const SEED = "SELECT set_config('case_state.effect', 'seed_local_revocation', false)";

pgTest("TEST-CNS-1373 pg: app_rw no escribe app.revocation ni deja una decision REVOKED; el trigger exige transition_owner y el efecto de la funcion (INV-RV-12, F-A10-01/06)", async (ctx) => {
  const T = fixtureUuid("t1373");
  const admin = await ctx.connectAsSuperuser();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    await admin.query(SEED);
    await admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status) VALUES ($1, 'r1373', 'c1373', 'd1373', 'REQUESTED')", [T]);
    await seedFixture(() => admin.query(
      `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
       VALUES ($1, 'd1373', 'x', 'x', 'x', 'x', 'x', 'x', 'c1373', 'GRANTED', '[]', true)`,
      [T],
    ));
    // app_rw: ni INSERT ni UPDATE de ninguna columna (incluidos attested_*), ni REVOKED en consent_decision (policy), ni EXECUTE de auxiliares.
    for (const sql of [
      "UPDATE app.revocation SET attested_revocation_ref = 'r1373', attested_case_ref = 'x' WHERE revocation_ref = 'r1373'",
      "UPDATE app.revocation SET status = 'VERIFIED', verified_auth_path = 'OTP' WHERE revocation_ref = 'r1373'",
      "UPDATE app.revocation SET verified_recovery_method = 'HUMAN_ASSISTED' WHERE revocation_ref = 'r1373'",
      "UPDATE app.revocation SET recorded_by_ref = 'x', cosigned_by_ref = 'y' WHERE revocation_ref = 'r1373'",
      "INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status) VALUES (current_setting('app.tenant_id')::uuid, 'x', 'c', 'd', 'REQUESTED')",
      "SELECT case_state.ledger_append('Revocation', 'r1373', 'REVOCATION_REQUESTED', 'HUMAN', NULL, NULL, NULL, '{}'::jsonb, NULL, 0)",
      "SELECT case_state.lock_revocation('r1373')",
      "SELECT set_config('case_state.effect', 'cosign_case_confirmation', true), (SELECT 1 FROM app.revocation FOR UPDATE)",
    ]) {
      await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
    }
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1373'")),
      (e: unknown) => codeOf(e) === "42501",
      "F-A10-06: app_rw no pone REVOKED",
    );
    // ADR-010 rev. 5 (6d parte 2, F-A10-26 cerrado por privilegio): app_rw ya no ejecuta cosign ni apply_revocation (42501), sea cual sea el estado.
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.cosign_case_confirmation('case')")),
      (e: unknown) => codeOf(e) === "42501",
    );
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.apply_revocation('r1373', 0)")),
      (e: unknown) => codeOf(e) === "42501",
    );
    // B1: des-revocar (REVOKED -> GRANTED) como app_rw no cambia nada (USING de la policy excluye REVOKED): 0 filas o 42501.
    await seedFixture(() => admin.query(
      `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
       VALUES ($1, 'd1373-rev', 'x', 'x', 'x', 'x', 'x', 'x', 'c1373b', 'GRANTED', '[]', true)`,
      [T],
    ));
    await seedFixture(() => admin.query("UPDATE app.consent_decision SET state = 'REVOKED' WHERE tenant_id = $1 AND consent_id = 'd1373-rev'", [T]));
    const unrevoke = await uow.withTenantTx(T, (tx) => tx.query("UPDATE app.consent_decision SET state = 'GRANTED' WHERE consent_id = 'd1373-rev' AND state = 'REVOKED'")).then((r) => r.rowCount, (e: unknown) => codeOf(e));
    assert.ok(unrevoke === 0 || unrevoke === "42501", `des-revocar: ${String(unrevoke)}`);
    assert.equal((await admin.query<{ state: string }>("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = 'd1373-rev'", [T])).rows[0]?.state, "REVOKED");
    // Triggers de DELETE y TRUNCATE (42501 incluso para el superusuario) y trigger: superusuario sin efecto, y transition_owner con el efecto de OTRA funcion, rechazados (42501); no cambia nada.
    await admin.query("RESET ALL");
    await assert.rejects(() => admin.query("DELETE FROM app.revocation WHERE revocation_ref = 'r1373'"), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => admin.query("TRUNCATE app.revocation"), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => admin.query("UPDATE app.revocation SET status = 'VERIFIED', verified_auth_path = 'OTP' WHERE revocation_ref = 'r1373'"), (e: unknown) => codeOf(e) === "42501");
    await admin.query("BEGIN");
    try {
      await admin.query("SET LOCAL ROLE transition_owner");
      await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
      for (const [effect, sql] of [
        ["confirm_revocation", "UPDATE app.revocation SET recorded_by_ref = 'x' WHERE revocation_ref = 'r1373'"],
        ["record_case_confirmation", "UPDATE app.revocation SET attested_revocation_ref = 'r1373', attested_case_ref = NULL WHERE revocation_ref = 'r1373'"],
        ["cosign_case_confirmation", "UPDATE app.revocation SET status = 'APPLIED', verified_auth_path = 'OTP' WHERE revocation_ref = 'r1373'"],
        ["propose_case_verification", "UPDATE app.revocation SET verified_recovery_method = 'HUMAN_ASSISTED' WHERE revocation_ref = 'r1373'"],
        ["", "UPDATE app.revocation SET recorded_by_ref = 'x' WHERE revocation_ref = 'r1373'"],
      ] as const) {
        await admin.query("SAVEPOINT s");
        await admin.query("SELECT set_config('case_state.effect', $1, true)", [effect]);
        await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "42501", `${effect}: ${sql}`);
        await admin.query("ROLLBACK TO s");
      }
    } finally {
      await admin.query("ROLLBACK");
    }
    assert.equal((await admin.query<{ status: string }>("SELECT status FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = 'r1373'", [T])).rows[0]?.status, "REQUESTED");
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1374 pg: CHECKs nuevos GRD-RV-26 (cosigned <> recorded), GRD-RV-05 (verification_ref UNIQUE por tenant) y GRD-RV-29 (verified_auth_path NOT NULL desde VERIFIED)", async (ctx) => {
  const A = fixtureUuid("t1374-a");
  const B = fixtureUuid("t1374-b");
  const admin = await ctx.connectAsSuperuser();
  await admin.query(SEED);
  const ins = (t: string, ref: string, cols: string, vals: string): Promise<unknown> =>
    admin.query(`INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, ${cols}) VALUES ($1, $2, 'c', $3, ${vals})`, [t, ref, `d-${ref}`]);
  const named = async (run: () => Promise<unknown>, constraint: string): Promise<void> => {
    await assert.rejects(run, (e: unknown) => constraintOf(e) === constraint, constraint);
  };
  const op = fixtureUuid("op-1374");
  // GRD-RV-26
  await named(() => ins(A, "r1", "verified_auth_path, recorded_by_ref, cosigned_by_ref", `'CONFIRMED', 'OTP', '${op}', '${op}'`), "revocation_cosigned_distinct_recorded");
  await named(() => ins(A, "r2", "verified_auth_path, cosigned_by_ref", `'CONFIRMED', 'OTP', '${op}'`), "revocation_cosigned_distinct_recorded");
  await ins(A, "r3", "verified_auth_path, recorded_by_ref, cosigned_by_ref", `'CONFIRMED', 'OTP', '${op}', '${fixtureUuid("op2-1374")}'`);
  // GRD-RV-29: cada estado desde VERIFIED exige authPath; REQUESTED y FAILED no.
  for (const status of ["VERIFIED", "CONFIRMED", "APPLIED", "DOWNSTREAM_PENDING", "DELIVERED", "COMPLETED"]) {
    await named(() => ins(A, `s-${status}`, "reason_code", `'${status}', NULL`), "revocation_verified_auth_path_required");
  }
  await ins(A, "q1", "reason_code", "'FAILED', 'WITHDRAWN_BY_REQUESTER'");
  // GRD-RV-05: UNIQUE por tenant (no global: otro tenant puede repetir la ref y no se filtra su existencia).
  await ins(A, "v1", "verified_auth_path, verification_ref", "'VERIFIED', 'OTP', 'ver-1374'");
  await named(() => ins(A, "v2", "verified_auth_path, verification_ref", "'VERIFIED', 'OTP', 'ver-1374'"), "revocation_verification_ref_uq");
  await ins(B, "v1", "verified_auth_path, verification_ref", "'VERIFIED', 'OTP', 'ver-1374'");
});

pgTest("TEST-CNS-1375 pg: vectores dorados TS<->SQL: case_state.canonical_json = canonicalJson de ledger-chain.ts y la cadena que escriben las funciones (hash en SQL) verifica en TS, sin huecos y con cada via", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const vectors: unknown[] = [
    { b: 1, a: "x" },
    { z: [1, 2, { y: null, x: true }], a: { c: "ñandú é ☃", b: "" } },
    { quote: "he said \"hi\"", back: "a\\b", ctl: "l1\nl2\tt\r\b\f", low: "\u0001\u001f", del: "\u007f", emoji: "😀" },
    { arr: [], obj: {}, n: -12, big: 9007199254740991, f: false },
    { "clave-ñ": 1, "ключ": "x", "鍵": { "é": [1], a: 2 }, zeta: 3, "\uE000": "bmp-alto", "\uFB01": "lig" },
    { revocationRef: fixtureUuid("v"), scope: "ALL", effectiveAt: "2026-10-12T10:00:00.123Z" },
  ];
  for (const v of vectors) {
    const r = await admin.query<{ c: string }>("SELECT case_state.canonical_json($1::jsonb) AS c", [JSON.stringify(v)]);
    assert.equal(r.rows[0]?.c, canonicalJson(v), `canonical_json: ${JSON.stringify(v)}`);
  }
  // Divergencia documentada: claves fuera del BMP ordenan distinto en JS (UTF-16) y SQL (punto de codigo); canonical_json las RECHAZA.
  await assert.rejects(() => admin.query("SELECT case_state.canonical_json($1::jsonb)", [JSON.stringify({ "\ud83d\ude00": 1, "\ue000": 2 })]), (e: unknown) => codeOf(e) === "22023");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(uow);
    const sink = createInMemoryRecoveryLinkChannelSink();
    const stub = createInMemoryDownstreamStub();
    const ports: RevocationPorts = { ...outside, recoveryLinkChannel: sink, recoveryTokenPolicy: { ttlMs: 60_000 }, uow, tenantResolver: createPgTenantResolver(pool), downstreamStub: stub };
    const env: X6Env = { ports, stub, sink };
    const T = fixtureUuid("t1375");
    for (const path of ["OTP", "LINK"] as const) // la via CASE (RH2/RH3) solo corre en platform: TEST-CNS-1711
    {
      const { revocationRef } = await revokeVia(env, T, `1375-${path}`, path);
      await completeDownstreamAsWorker(ctx, env, T, revocationRef, `1375-${path}`); // ADR-010 PR-6a: R5-R7 solo worker
    }
    const report = await verifyLedgerChain({ readChain: (t) => outside.ledger.readChain(t) }, T);
    assert.equal(report.ok, true, JSON.stringify(report));
    assert.ok(report.verified >= 18, `eslabones verificados: ${report.verified}`); // 9 por via (OTP, LINK); la via CASE (antes >= 20 con 3 vias) se cubre sobre platform en TEST-CNS-1711
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1376 pg: confirm_revocation rechaza una verificacion HUMAN_ASSISTED (solo RH3 con cuatro ojos) y case_state tiene exactamente las funciones declaradas, de transition_owner", async (ctx) => {
  const T = fixtureUuid("t1376");
  const admin = await ctx.connectAsSuperuser();
  await admin.query(SEED);
  await admin.query(
    `INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, case_ref, attested_revocation_ref, attested_case_ref, verified_auth_path, verified_recovery_method)
     VALUES ($1, 'r1376', 'c1376', 'd1376', 'VERIFIED', 'case1376', 'r1376', 'case1376', 'RECOVERY', 'HUMAN_ASSISTED')`,
    [T],
  );
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.confirm_revocation('r1376', 0)")),
      (e: unknown) => codeOf(e) === "RV002",
    );
    assert.equal((await admin.query<{ status: string }>("SELECT status FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = 'r1376'", [T])).rows[0]?.status, "VERIFIED");
  } finally {
    await pool.end();
  }
  const fns = (await admin.query<{ n: string; o: string; d: boolean }>(
    "SELECT p.proname AS n, pg_get_userbyid(p.proowner) AS o, p.prosecdef AS d FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' ORDER BY 1",
  )).rows;
  assert.deepEqual(fns.map((f) => f.n), [
    "alert_apply_exhausted", "apply_revocation", "approve_case_verification", "assert_decision_revocable", "assert_sequence", "cancel_invitation_subject_mismatch", "canonical_json", "close_case", "confirm_case_return", "confirm_revocation",
    "cosign_case_confirmation", "current_sequence", "express_revocation_intent_in_case", "ledger_append", "lock_revocation", "lock_rights_case", "mark_downstream_emitted", "open_rights_case_bearer",
    "propose_case_verification", "r4_apply", "read_case_apply_state", "record_case_confirmation", "record_downstream_ack", "record_erasure_attestation", "request_revocation", "revocation_transition_guard",
    "revoke_with_recovery_link", "rights_case_transition_guard", "seed_local_revocation", "seed_local_rights_case", "verify_revocation_otp",
    "withdraw_case_verification_proposal", "withdraw_revocation",
  ]); // ADR-010 PR-5b (0038) agrega las funciones de RightsCase
  assert.ok(fns.every((f) => f.o === "transition_owner"));
  assert.deepEqual(fns.filter((f) => !f.d).map((f) => f.n), ["canonical_json", "revocation_transition_guard", "rights_case_transition_guard"]);
  // GRD-CM-15 / PR-5a: EXECUTE exacto de las funciones de transicion para runtime (app_rw interino; worker solo SYSTEM); platform_rw e integrity_verifier ninguna.
  const ex = async (role: string, fn: string): Promise<boolean> =>
    (await admin.query<{ x: boolean }>("SELECT has_function_privilege($1, p.oid, 'EXECUTE') AS x FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = $2", [role, fn])).rows[0]?.x ?? false;
  for (const fn of ["apply_revocation", "mark_downstream_emitted", "record_downstream_ack", "record_erasure_attestation"]) assert.equal(await ex("worker", fn), true, fn);
  for (const fn of ["request_revocation", "verify_revocation_otp", "confirm_revocation", "revoke_with_recovery_link", "withdraw_revocation"]) {
    assert.equal(await ex("worker", fn), false, `worker ${fn}`);
    assert.equal(await ex("app_rw", fn), true, `app_rw ${fn}`);
  }
  // 6d parte 2: operador y R4 fuera de app_rw (el catalogo exacto lo fija el assert de 0070 y TEST-CNS-1701).
  for (const fn of ["cosign_case_confirmation", "apply_revocation", "approve_case_verification", "close_case", "r4_apply"]) assert.equal(await ex("app_rw", fn), false, `app_rw ${fn}`);
  for (const fn of ["ledger_append", "canonical_json", "lock_revocation", "revocation_transition_guard", "lock_rights_case", "rights_case_transition_guard"]) {
    for (const role of ["app_rw", "worker", "platform_rw", "integrity_verifier"]) assert.equal(await ex(role, fn), false, `${role} ${fn}`);
  }
  for (const role of ["platform_rw", "integrity_verifier"]) assert.equal(await ex(role, "apply_revocation"), false, role);
});

pgTest("TEST-CNS-1378 pg: aislamiento por tenant del camino de funciones: con el tenant B, withdraw/apply/revoke_with_recovery_link/propose sobre refs de A fallan (RV001/RV007) sin cambiar la fila, el token ni el ledger de A", async (ctx) => {
  const A = fixtureUuid("t1378-a");
  const B = fixtureUuid("t1378-b");
  const admin = await ctx.connectAsSuperuser();
  await admin.query(SEED);
  await admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, verified_auth_path) VALUES ($1, 'rA', 'cA', 'dA', 'CONFIRMED', 'OTP')", [A]);
  await admin.query("INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, case_ref) VALUES ($1, 'rA2', 'cA2', 'dA2', 'REQUESTED', 'caseA')", [A]);
  await seedFixture(() => admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
     VALUES ($1, 'dA', 'x', 'x', 'x', 'x', 'x', 'x', 'cA', 'GRANTED', '[]', true)`,
    [A],
  ));
  await admin.query("INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at) VALUES ($1, 'recA', $2, 'cA', 'dA', now() + interval '1 day')", [A, "a".repeat(64)]);
  const snapshot = async (): Promise<string> =>
    JSON.stringify([
      (await admin.query("SELECT revocation_ref, status, proposal_ref, verified_auth_path FROM app.revocation WHERE tenant_id = $1 ORDER BY 1", [A])).rows,
      (await admin.query("SELECT state FROM app.consent_decision WHERE tenant_id = $1", [A])).rows,
      (await admin.query("SELECT consumed_at FROM app.recovery_token WHERE tenant_id = $1", [A])).rows,
      (await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [A])).rows,
      (await admin.query("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1", [A])).rows,
    ]);
  const before = await snapshot();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const [sql, state] of [
      ["SELECT case_state.withdraw_revocation('rA', 0)", "RV001"],
      ["SELECT case_state.apply_revocation('rA', 0)", "42501"],
      ["SELECT case_state.confirm_revocation('rA', 0)", "RV001"],
      ["SELECT case_state.propose_case_verification('caseA', 'p', 'g', 5, 600)", "42501"],
      ["SELECT case_state.revoke_with_recovery_link('recA', 'nueva', 0)", "RV007"],
    ] as const) {
      await assert.rejects(() => uow.withTenantTx(B, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === state, sql);
    }
  } finally {
    await pool.end();
  }
  assert.equal(await snapshot(), before, "la fila, el token, la decision, el ledger y el outbox de A quedan intactos");
});

pgTest("TEST-CNS-1380 pg: R8 solo desde REQUESTED/VERIFIED/CONFIRMED, R3 no confirma HUMAN_ASSISTED y R1 exige decision GRANTED de la misma cadena (F-A10-29), igual que in-memory; la base tambien lo impone", async (ctx) => {
  const T = fixtureUuid("t1380");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const outside = pgOutsideTxPorts(uow);
    const ports: RevocationPorts = {
      ...outside,
      recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
      recoveryTokenPolicy: { ttlMs: 60_000 },
      uow,
      tenantResolver: createPgTenantResolver(pool),
      downstreamStub: createInMemoryDownstreamStub(),
    };
    await runFA1029Scenarios({ ports, seedDecision: (d) => seedFixture(() => uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(d))) }, T, "pg");
    // La base lo impone aunque el dominio se saltara: request_revocation con decision ausente o de otra cadena (RV003).
    await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.request_revocation('x1380', 'c1380', 'no-existe')")), (e: unknown) => codeOf(e) === "RV003");
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.request_revocation('x1380', 'otra-cadena', $1)", [fixtureUuid("d-r1-pg-ok")])),
      (e: unknown) => codeOf(e) === "RV003",
    );
  } finally {
    await pool.end();
  }
});
