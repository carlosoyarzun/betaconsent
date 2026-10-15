// Gobierna: ADR-010 rev. 5 §4.2.b (capa 1; LG-1..LG-10; aceptada por Carlos el 2026-10-15), §4.2.b(14) (I9 / Q-18-I9 con ledger_writer, F-PR6-22), F-PR6-23 (bound_decision_maker_ref),
// specs/ledger-derivation.spec.yaml, db/migrations/0048_adr010_ledger_gen_invitation.sql. SYNTHETIC ONLY.
// TEST-CNS-1455 (vectores dorados TS<->SQL: la base y ledger-derivation.ts emiten los mismos eventos, claves, actores y payloads para Invitation y DMV),
// TEST-CNS-1456 (bound_decision_maker_ref solo se escribe en I5 y es inmutable desde VERIFIED: app_rw -> 42501),
// TEST-CNS-1457 (aristas fuera de la tabla, estado inicial fijo y CANCELLED terminal: 42501 uniforme sin valores; app_rw -> CANCELLED = 42501),
// TEST-CNS-1458 (fijar case_state.effect no altera la emision; el AFTER no emite en ->CANCELLED: I9 deja exactamente un INVITATION_CANCELLED).
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { deriveInvitationEvents, deriveOtpEvents } from "../../../src/server/modules/common/ledger-derivation.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import type { OtpVerificationRecord } from "../../../src/server/ports/otp-verification-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, seedRaw, type PgTestContext } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const DM = "dm-pr-b";

interface Row { event_type: string; aggregate_id: string; actor_type: string; actor_role: string | null; payload: unknown; idempotency_key_hash: string; sequence: number }

async function withApp<T>(ctx: PgTestContext, fn: (uow: PgUnitOfWork) => Promise<T>): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    return await fn(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

pgTest("TEST-CNS-1455 pg: vectores dorados TS<->SQL de Invitation y DecisionMakerVerification: la base emite los mismos eventos, claves, actores y payloads que ledger-derivation.ts", async (ctx) => {
  const T = fixtureUuid("t1455");
  const admin = await ctx.connectAsSuperuser();
  const inv = fixtureUuid("inv-1455");
  const ver = fixtureUuid("ver-1455");
  const expires = new Date("2030-02-03T04:05:06.789Z");
  const base: InvitationRecord = { invitationRef: inv, tenantId: T, contextRef: "C", productRef: "P", subjectRef: fixtureUuid("s1455"), state: "DRAFT", enrollmentRef: fixtureUuid("e1455"), participationRef: fixtureUuid("p1455") };
  const ready: InvitationRecord = { ...base, state: "READY", consentVersion: "v1", expiresAt: expires, recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: "a@example.invalid" };
  const sent: InvitationRecord = { ...ready, state: "SENT", tokenHash: sha("tok-1455"), deliveryChannel: "CONSENT_APP_EMAIL" };
  const opened: InvitationRecord = { ...sent, state: "OPENED" };
  const verified: InvitationRecord = { ...opened, state: "VERIFIED", boundDecisionMakerRef: DM, verifiedByRef: ver, dmRefKeyVersion: 2 };
  const otp0: OtpVerificationRecord = { verificationRef: ver, tenantId: T, scope: "DECISION", parentRef: inv, channelRef: "a@example.invalid", codeHash: "a".repeat(64), attempts: 0, expiresAt: new Date(Date.now() + 3_600_000), state: "CODE_SENT", resendCount: 0 };
  const otp1: OtpVerificationRecord = { ...otp0, attempts: 1, state: "VERIFIED", consumedAt: new Date(), decisionMakerRef: DM, dmRefKeyVersion: 2 };
  const chain: Array<readonly [InvitationRecord | null, InvitationRecord]> = [[null, base], [base, ready], [ready, sent], [sent, opened]];
  await withApp(ctx, async (uow) => {
    for (const [, next] of chain) await uow.inTenant(T, (tx) => tx.invitationRepo.save(next));
    await uow.inTenant(T, async (tx) => {
      await tx.otpRepo.save(otp0);
      await tx.otpRepo.save(otp1);
    });
    await uow.inTenant(T, (tx) => tx.invitationRepo.save(verified));
  });
  const rows = async (agg: string): Promise<Row[]> =>
    (await admin.query<Row>("SELECT event_type, aggregate_id, actor_type, actor_role, payload, idempotency_key_hash, sequence FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [T, agg])).rows;
  const expected = [...chain.map(([p, n]) => deriveInvitationEvents(p, n)), deriveInvitationEvents(opened, verified)].flat();
  const got = await rows(inv);
  assert.equal(got.length, expected.length);
  expected.forEach((e, i) => {
    const g = got[i]!;
    assert.deepEqual([g.event_type, g.actor_type, g.actor_role, g.payload, g.idempotency_key_hash, g.sequence], [e.eventType, e.actorType, e.actorRole ?? null, e.payload, sha(e.idempotencyKey), i + 1], `${e.eventType}`);
  });
  const dmv = deriveOtpEvents(otp0, otp1);
  const gotDmv = await rows(ver);
  assert.equal(gotDmv.length, 1);
  assert.deepEqual([gotDmv[0]?.event_type, gotDmv[0]?.actor_role, gotDmv[0]?.payload, gotDmv[0]?.idempotency_key_hash], [dmv[0]?.eventType, dmv[0]?.actorRole, dmv[0]?.payload, sha(dmv[0]!.idempotencyKey)]);
});

pgTest("TEST-CNS-1456 pg: bound_decision_maker_ref solo se escribe en la arista I5 y es inmutable desde VERIFIED (tambien para I9 y terminales): app_rw -> 42501 (F-PR6-23)", async (ctx) => {
  const T = fixtureUuid("t1456");
  const admin = await ctx.connectAsSuperuser();
  const inv = fixtureUuid("inv-1456");
  await seedRaw(admin, async () => {
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref, bound_decision_maker_ref, verified_by_ref, dm_ref_key_version)
       VALUES ($1, $2, 'C', 'P', 's1456', 'VERIFIED', 'e', 'p', $3, 'v', 2)`, [T, inv, DM]);
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref)
       VALUES ($1, 'inv-1456-o', 'C', 'P', 's1456-o', 'OPENED', 'e', 'p')`, [T]);
  });
  await withApp(ctx, async (uow) => {
    const run = (sql: string, v: unknown[] = []) => uow.withTenantTx(T, (tx) => tx.query(sql, v));
    // Inmutable desde VERIFIED.
    await assert.rejects(() => run("UPDATE app.invitation SET bound_decision_maker_ref = 'otro-dm' WHERE invitation_ref = $1", [inv]), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => run("UPDATE app.invitation SET bound_decision_maker_ref = NULL WHERE invitation_ref = $1", [inv]), (e: unknown) => codeOf(e) === "42501");
    // Fuera de I5 (OPENED, sin cambio de estado): no se escribe.
    await assert.rejects(() => run("UPDATE app.invitation SET bound_decision_maker_ref = 'x' WHERE invitation_ref = 'inv-1456-o'"), (e: unknown) => codeOf(e) === "42501");
    // En el INSERT tampoco.
    await assert.rejects(
      () => run("INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref, bound_decision_maker_ref) VALUES ($1, 'inv-1456-n', 'C', 'P', 's', 'DRAFT', 'e', 'p', 'x')", [T]),
      (e: unknown) => codeOf(e) === "42501");
    // I5 sin OTP VERIFIED de esa invitacion con el mismo seudonimo: rechazada (consistencia entre filas).
    await assert.rejects(
      () => run("UPDATE app.invitation SET state = 'VERIFIED', bound_decision_maker_ref = 'x', verified_by_ref = 'no-existe', dm_ref_key_version = 2 WHERE invitation_ref = 'inv-1456-o'"),
      (e: unknown) => codeOf(e) === "42501");
  });
  assert.equal((await admin.query<{ b: string }>("SELECT bound_decision_maker_ref AS b FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2", [T, inv])).rows[0]?.b, DM);
});

pgTest("TEST-CNS-1457 pg: estado inicial fijo, aristas fuera de la tabla y CANCELLED terminal dan 42501 uniforme sin valores; app_rw no deja CANCELLED ni inserta INVITATION_CANCELLED", async (ctx) => {
  const T = fixtureUuid("t1457");
  const admin = await ctx.connectAsSuperuser();
  await seedRaw(admin, async () => {
    for (const [ref, state] of [["i-draft", "DRAFT"], ["i-ready", "READY"], ["i-sent", "SENT"]] as const) {
      await admin.query(
        `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref)
         VALUES ($1, $2, 'C', 'P', 's-' || $2::text, $3, 'e', 'p')`, [T, ref, state]);
    }
  });
  await withApp(ctx, async (uow) => {
    const run = (sql: string, v: unknown[] = []) => uow.withTenantTx(T, (tx) => tx.query(sql, v));
    const denied = async (label: string, sql: string, v: unknown[] = []): Promise<void> => {
      await assert.rejects(() => run(sql, v), (e: unknown) => {
        const err = e as { code?: string; message?: string };
        return err.code === "42501" && !/i-draft|i-ready|i-sent|otro|SENT|READY/.test(err.message ?? "");
      }, label);
    };
    await denied("INSERT READY", "INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref) VALUES ($1, 'n1', 'C', 'P', 's-n1', 'READY', 'e', 'p')", [T]);
    await denied("INSERT sin enrollment", "INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, 'n2', 'C', 'P', 's-n2', 'DRAFT')", [T]);
    await denied("DRAFT->SENT", "UPDATE app.invitation SET state = 'SENT', token_hash = $1, delivery_channel = 'SCHOOL_CHANNEL', expires_at = now() WHERE invitation_ref = 'i-draft'", [sha("t")]);
    await denied("SENT->READY", "UPDATE app.invitation SET state = 'READY' WHERE invitation_ref = 'i-sent'");
    await denied("SENT->COMPLETED", "UPDATE app.invitation SET state = 'COMPLETED', closed_by_consent_id = 'c' WHERE invitation_ref = 'i-sent'");
    await denied("token_hash tras SENT", "UPDATE app.invitation SET token_hash = $1 WHERE invitation_ref = 'i-sent'", [sha("otro")]);
    await denied("canal tras SENT", "UPDATE app.invitation SET recipient_channel_ref = 'x@example.invalid' WHERE invitation_ref = 'i-sent'");
    await denied("app_rw -> CANCELLED", "UPDATE app.invitation SET state = 'CANCELLED' WHERE invitation_ref = 'i-sent'");
    await denied("READY sin version", "UPDATE app.invitation SET state = 'READY', expires_at = now(), recipient_binding = 'UNBOUND' WHERE invitation_ref = 'i-draft'");
    await denied("READY RECIPIENT_CHANNEL sin canal", "UPDATE app.invitation SET state = 'READY', consent_version = 'v', expires_at = now(), recipient_binding = 'RECIPIENT_CHANNEL' WHERE invitation_ref = 'i-draft'");
  });
  assert.deepEqual((await admin.query<{ s: string }>("SELECT state AS s FROM app.invitation WHERE tenant_id = $1 ORDER BY invitation_ref", [T])).rows.map((r) => r.s), ["DRAFT", "READY", "SENT"]);
  assert.equal((await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [T])).rows[0]?.n, 0, "ninguna arista rechazada escribio eventos");
});

pgTest("TEST-CNS-1458 pg: fijar case_state.effect no altera la emision; el AFTER no emite en ->CANCELLED y CANCELLED es terminal (I9 deja exactamente un INVITATION_CANCELLED de transition_owner)", async (ctx) => {
  const T = fixtureUuid("t1458");
  const admin = await ctx.connectAsSuperuser();
  await seedRaw(admin, async () => {
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref, bound_decision_maker_ref, verified_by_ref, dm_ref_key_version)
       VALUES ($1, 'i1458', 'C', 'P', 's1458', 'VERIFIED', 'e', 'p', $2, 'v', 2)`, [T, DM]);
  });
  await withApp(ctx, async (uow) => {
    await uow.withTenantTx(T, async (tx) => {
      await tx.query("SELECT set_config('case_state.effect', 'apply_revocation', true)");
      await tx.query("UPDATE app.invitation SET otp_exhausted = true WHERE invitation_ref = 'i1458'");
    });
    await uow.withTenantTx(T, async (tx) => {
      await tx.query("SELECT set_config('case_state.effect', 'cancel_invitation_subject_mismatch', true)");
      await tx.query("SELECT case_state.cancel_invitation_subject_mismatch('i1458', $1, 0)", [DM]);
    });
  });
  const ev = (await admin.query<{ event_type: string; actor_role: string }>("SELECT event_type, actor_role FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = 'i1458'", [T])).rows;
  assert.deepEqual(ev, [{ event_type: "INVITATION_CANCELLED", actor_role: "DECISION_MAKER" }], "un solo INVITATION_CANCELLED, sin duplicado del AFTER");
  await withApp(ctx, async (uow) => {
    const r = await uow.withTenantTx(T, (tx) => tx.query("UPDATE app.invitation SET state = 'VERIFIED' WHERE invitation_ref = 'i1458'"));
    assert.equal((r as { rowCount: number | null }).rowCount, 0);
  });
  await admin.query("BEGIN");
  try {
    await admin.query("SET LOCAL ROLE transition_owner");
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    await assert.rejects(() => admin.query("UPDATE app.invitation SET state = 'VERIFIED' WHERE invitation_ref = 'i1458'"), (e: unknown) => codeOf(e) === "42501");
  } finally {
    await admin.query("ROLLBACK");
  }
});
