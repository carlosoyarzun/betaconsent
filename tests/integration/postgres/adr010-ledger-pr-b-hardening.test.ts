// Gobierna: ADR-010 rev. 5 §4.2.b (capa 1), revision de seguridad de PR #98 (2026-10-15, 6 P2), F-PR6-22 (I9), LG-10, db/migrations/0049_adr010_ledger_gen_decision_seed_close_insert.sql. SYNTHETIC ONLY.
// TEST-CNS-1467 (tras I9 la decision queda congelada: C2/C3/C5 dan 42501 y no emiten),
// TEST-CNS-1468 (purpose ~ ^[A-Z_]{1,64}$ en GRANTED/DECLINED; el catalogo LG-10 sigue pendiente antes de datos reales),
// TEST-CNS-1469 (cross-tenant: con GUC tenant=A, INSERT en integrity.audit_event con tenant_id=B como ledger_writer y como transition_owner -> 42501),
// TEST-CNS-1470 (chequeo permanente: las unicas funciones que mencionan ledger_append / integrity.audit_event son las declaradas y solo dos hacen INSERT directo; todo uso de tenant_resolve.handle
// desde ledger_gen filtra por NEW.tenant_id). Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, seedRaw, type PgTestContext } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const DM = "dm-pr-b-hardening";
const GRANT = (purpose: string): string => JSON.stringify([{ purpose, choice: "GRANT" }]);

async function withApp<T>(ctx: PgTestContext, fn: (uow: PgUnitOfWork) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    return await fn(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

async function seedPair(admin: import("pg").Client, T: string, inv: string, id: string): Promise<void> {
  await seedRaw(admin, async () => {
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref, bound_decision_maker_ref, verified_by_ref, dm_ref_key_version)
       VALUES ($1, $2, 'C', 'P', $3, 'VERIFIED', 'e', 'p', $4, 'v', 2)`, [T, inv, `s-${inv}`, DM]);
    await admin.query(
      `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes,
         prior_steps_complete, steps_recorded, relationship_ref, consent_version, consent_text_hash, privacy_notice_version)
       VALUES ($1, $2, 'C', 'P', $3, $4, $5, 'v', $6, 'PENDING', '[]', true,
         ARRAY['CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED'], 'SYNTHETIC_GUARDIAN', 'v1', $7, 'p1')`,
      [T, id, `s-${inv}`, DM, inv, `ch-${id}`, sha("texto")]);
  });
}

const decide = (state: "GRANTED" | "DECLINED", purposes: string): string =>
  `UPDATE app.consent_decision SET state = '${state}', purposes = '${purposes}'::jsonb, receipt_ref = 'r', consent_version = 'v1', consent_text_hash = '${sha("texto")}', privacy_notice_version = 'p1' WHERE consent_id = $1`;

pgTest("TEST-CNS-1467 pg: tras I9 (invitacion CANCELLED) la decision PENDING queda congelada: C2, C3 y C5 dan 42501 y no emiten eventos", async (ctx) => {
  const T = fixtureUuid("t1467");
  const admin = await ctx.connectAsSuperuser();
  await seedPair(admin, T, "i1467", "d1467");
  await withApp(ctx, async (uow) => {
    const run = (sql: string, v: unknown[] = []) => uow.withTenantTx(T, (tx) => tx.query(sql, v));
    // Con la invitacion VERIFIED, un paso nuevo (C2) avanza.
    await run("UPDATE app.consent_decision SET steps_recorded = steps_recorded || ARRAY['CONTEXT_INFORMATION_VIEWED'] WHERE consent_id = 'd1467'");
    await run("SELECT case_state.cancel_invitation_subject_mismatch('i1467', $1, $2)", [DM, 0]);
    const before = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [T])).rows[0]?.n;
    await seedRaw(admin, () => admin.query("UPDATE app.consent_decision SET steps_recorded = ARRAY['CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED'] WHERE consent_id = 'd1467'"));
    const frozen: Array<[string, string]> = [
      ["C2", "UPDATE app.consent_decision SET steps_recorded = steps_recorded || ARRAY['CONTEXT_INFORMATION_VIEWED'] WHERE consent_id = 'd1467'"],
      ["C3", decide("GRANTED", GRANT("STUDY_PARTICIPATION")).replace("$1", "'d1467'")],
      ["C5", decide("DECLINED", JSON.stringify([{ purpose: "STUDY_PARTICIPATION", choice: "DECLINE" }])).replace("$1", "'d1467'")],
    ];
    for (const [label, sql] of frozen) {
      await assert.rejects(() => run(sql), (e: unknown) => codeOf(e) === "42501", label);
    }
    const after = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [T])).rows[0]?.n;
    assert.equal(after, before, "ningun evento nuevo");
  });
  assert.equal((await admin.query<{ s: string }>("SELECT state AS s FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = 'd1467'", [T])).rows[0]?.s, "PENDING");
});

pgTest("TEST-CNS-1468 pg: GRANTED/DECLINED exigen purpose ~ ^[A-Z_]{1,64}$ (el catalogo LG-10 sigue pendiente antes de datos reales)", async (ctx) => {
  const T = fixtureUuid("t1468");
  const admin = await ctx.connectAsSuperuser();
  const bad = ["study participation", "lower_case", "CON-GUION", "", "A".repeat(65), "<script>", "X1"];
  for (let i = 0; i < bad.length; i += 1) await seedPair(admin, T, `i1468-${i}`, `d1468-${i}`);
  await seedPair(admin, T, "i1468-ok", "d1468-ok");
  await withApp(ctx, async (uow) => {
    for (let i = 0; i < bad.length; i += 1) {
      await assert.rejects(
        () => uow.withTenantTx(T, (tx) => tx.query(decide("GRANTED", GRANT(bad[i]!)), [`d1468-${i}`])),
        (e: unknown) => codeOf(e) === "42501",
        `purpose ${JSON.stringify(bad[i])}`,
      );
    }
    await uow.withTenantTx(T, (tx) => tx.query(decide("GRANTED", GRANT("STUDY_PARTICIPATION")), ["d1468-ok"]));
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query(decide("GRANTED", JSON.stringify([{ purpose: 5, choice: "GRANT" }])), ["d1468-0"])),
      (e: unknown) => codeOf(e) === "42501",
      "purpose no string",
    );
  });
  const granted = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND state = 'GRANTED'", [T])).rows[0]?.n;
  assert.equal(granted, 1);
});

pgTest("TEST-CNS-1469 pg: con GUC tenant=A, un INSERT en integrity.audit_event con tenant_id=B (par permitido del rol) da 42501 para ledger_writer y para transition_owner; con tenant_id=A procede", async (ctx) => {
  const A = fixtureUuid("t1469-a");
  const B = fixtureUuid("t1469-b");
  const admin = await ctx.connectAsSuperuser();
  const H = "a".repeat(64);
  const row = (tenant: string, agg: string, type: string, chainSeq: number): string =>
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES ('${tenant}'::uuid, '${agg}', 'x-1469-${chainSeq}', 1, '${type}', 'HUMAN', '{}'::jsonb, ${chainSeq}, '${H}', '${String(chainSeq).padStart(64, "d")}', '${String(chainSeq).padStart(64, "c")}')`;
  const asRole = async (role: "ledger_writer" | "transition_owner", sql: string): Promise<string> => {
    await admin.query("BEGIN");
    try {
      await admin.query(role === "ledger_writer" ? "SET LOCAL ROLE ledger_writer" : "SET LOCAL ROLE transition_owner");
      await admin.query("SELECT set_config('app.tenant_id', $1, true)", [A]);
      await admin.query(sql);
      return "ok";
    } catch (e) {
      return codeOf(e) ?? "?";
    } finally {
      await admin.query("ROLLBACK");
    }
  };
  assert.equal(await asRole("ledger_writer", row(A, "Invitation", "INVITATION_OPENED", 1)), "ok");
  assert.equal(await asRole("ledger_writer", row(B, "Invitation", "INVITATION_OPENED", 2)), "42501");
  assert.equal(await asRole("transition_owner", row(A, "Revocation", "REVOCATION_REQUESTED", 3)), "ok");
  assert.equal(await asRole("transition_owner", row(B, "Revocation", "REVOCATION_REQUESTED", 4)), "42501");
});

pgTest("TEST-CNS-1470 pg (permanente): las unicas funciones que mencionan ledger_append o integrity.audit_event son las declaradas; solo case_state.ledger_append y ledger_gen.ledger_append hacen INSERT directo; todo uso de tenant_resolve.handle desde ledger_gen filtra por NEW.tenant_id", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const declared = [
    "case_state.approve_case_verification", "case_state.assert_sequence", "case_state.cancel_invitation_subject_mismatch", "case_state.close_case",
    "case_state.confirm_case_return", "case_state.confirm_revocation", "case_state.cosign_case_confirmation", "case_state.express_revocation_intent_in_case", "case_state.ledger_append",
    "case_state.mark_downstream_emitted", "case_state.open_rights_case_bearer", "case_state.r4_apply", "case_state.record_downstream_ack", "case_state.record_erasure_attestation", "case_state.request_revocation",
    "case_state.revoke_with_recovery_link", "case_state.verify_revocation_otp", "case_state.withdraw_case_verification_proposal", "case_state.withdraw_revocation",
    "integrity.audit_event_immutable", "integrity.audit_event_single_aggregate_type",
    "ledger_gen.emit_consent_decision", "ledger_gen.emit_enrollment", "ledger_gen.emit_invitation", "ledger_gen.emit_otp", "ledger_gen.ledger_append", "ledger_gen.seed_local_catalog_event",
  ];
  const mention = (await admin.query<{ f: string }>(
    `SELECT n.nspname || '.' || p.proname AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND (p.prosrc ~ 'ledger_append' OR p.prosrc ~ 'audit_event') ORDER BY 1`)).rows.map((r) => r.f);
  assert.deepEqual(mention, declared, "una funcion nueva que llama a un append o toca integrity.audit_event requiere revision (INV-DBR-07)");
  const inserters = (await admin.query<{ f: string }>(
    `SELECT n.nspname || '.' || p.proname AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prosrc ~* 'insert\\s+into\\s+integrity\\.audit_event' ORDER BY 1`)).rows.map((r) => r.f);
  assert.deepEqual(inserters, ["case_state.ledger_append", "ledger_gen.ledger_append"]);
  const handleUsers = (await admin.query<{ f: string; src: string }>(
    `SELECT p.proname AS f, p.prosrc AS src FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'ledger_gen' AND p.prosrc ~ 'tenant_resolve\\.handle'`)).rows;
  assert.ok(handleUsers.length >= 1, "emit_consent_decision usa tenant_resolve.handle");
  for (const u of handleUsers) {
    assert.match(u.src, /FROM tenant_resolve\.handle h WHERE h\.tenant_id = NEW\.tenant_id AND /, `${u.f}: tenant_resolve.handle sin filtro por NEW.tenant_id`);
    assert.equal((u.src.match(/tenant_resolve\.handle/g) ?? []).length, (u.src.match(/h\.tenant_id = NEW\.tenant_id/g) ?? []).length, `${u.f}: cada uso filtra por tenant`);
  }
});
