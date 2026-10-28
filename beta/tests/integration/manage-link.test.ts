// Gobierna: DEC "Reconstrucción mínima" (2026-10-19), plan v2 H1-05/H1-07; SEC-CNS-024-V1 (verificación PR #121, V2 punto 5). Funciones de 0004: enlace de gestión con estado
// (issue_manage_link / open_manage_link), cancel_invitation y el cierre del P2 del outbox (consent_app ya no inserta; el reenvío con motivo es del operador por el pool mailer).
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { verifyLedger } from "../../src/ledger/read-chain.ts";
import { connect, connectAsOwner, createTestDb, failure, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let app: Client;
let mailer: Client;
let owner: Client;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const shaBuf = (s: string): Buffer => createHash("sha256").update(s).digest();
const uniq = (): string => randomBytes(5).toString("hex");
const DM = "dm-0123456789abcdef0123456789abcdef";

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  app = await connect(db.appUrl);
  mailer = await connect(db.mailerUrl);
  owner = await connectAsOwner(db);
});
after(async () => {
  await app.end();
  await mailer.end();
  await owner.end();
  await db.drop();
});

async function events(aggregate: string): Promise<Array<{ event_type: string; payload: Record<string, unknown> }>> {
  return (await owner.query<{ event_type: string; payload: Record<string, unknown> }>("SELECT event_type, payload FROM integrity.audit_event WHERE aggregate_id = $1 ORDER BY sequence", [aggregate])).rows;
}

/** Invitación OPENED (y VERIFIED si `verified`). */
async function opened(verified = false): Promise<{ inv: string; student: string; ver?: string }> {
  const student = `stu-${uniq()}`;
  const inv = (await app.query<{ invitation_ref: string }>("SELECT * FROM app.import_invitation($1, 'Ana', $2, 'batch-001')", [student, `g-${uniq()}@example.test`])).rows[0]!.invitation_ref;
  const token = sha(`token-${inv}`);
  await mailer.query("SELECT app.arm_invitation_token($1, $2, now() + interval '1 day', 'v-test')", [inv, token]);
  await app.query("SELECT * FROM app.open_invitation($1)", [token]);
  if (!verified) return { inv, student };
  const o = (await mailer.query<{ o_verification_ref: string; o_code: string }>("SELECT * FROM app.issue_otp($1, 'DECISION')", [inv])).rows[0]!;
  const v = (await app.query<{ outcome: string }>("SELECT * FROM app.verify_otp($1, $2, $3)", [o.o_verification_ref, o.o_code, DM])).rows[0]!;
  assert.equal(v.outcome, "VERIFIED");
  return { inv, student, ver: o.o_verification_ref };
}

async function granted(): Promise<{ inv: string; student: string; consentId: string }> {
  const o = await opened(true);
  const d = (await app.query<{ consent_id: string; state: string }>("SELECT * FROM app.record_decision($1, $2, 'GRANTED', 'v-test', $3, $4, $5::jsonb)", [o.inv, o.ver, sha("texto"), `idem-${uniq()}`, JSON.stringify(["STUDY_PARTICIPATION"])])).rows[0]!;
  return { inv: o.inv, student: o.student, consentId: d.consent_id };
}

test("record_decision encola recibo (payload completo) y enlace de gestión en la MISMA tx; sin token en el outbox", async () => {
  const g = await granted();
  const rows = (await owner.query<{ kind: string; dedupe_key: string; payload: Record<string, unknown> }>("SELECT kind, dedupe_key, payload FROM app.email_outbox WHERE invitation_ref = $1 ORDER BY kind", [g.inv])).rows;
  assert.deepEqual(rows.map((r) => r.kind), ["DECISION_RECEIPT", "RECOVERY_LINK"]);
  const receipt = rows[0]!.payload;
  assert.equal(receipt.decision, "GRANTED");
  assert.match(String(receipt.receiptRef), /^rcp-[0-9a-f]{24}$/);
  assert.deepEqual(receipt.purposes, [
    { purpose: "STUDY_PARTICIPATION", choice: "GRANT" }, { purpose: "AUDIO_RECORDING", choice: "DECLINE" },
    { purpose: "AUTOMATED_ANALYSIS", choice: "DECLINE" }, { purpose: "HUMAN_REVIEW", choice: "DECLINE" },
  ]);
  assert.deepEqual(rows[1]!.payload, { consentId: g.consentId, purpose: "MANAGE" });
  assert.ok(!JSON.stringify(rows).includes("@"));
});

test("issue_manage_link: token en claro una vez, solo el hash persiste, 7 días, MANAGE_LINK_ISSUED sin token; reemitir invalida el anterior", async () => {
  const g = await granted();
  const t1 = (await mailer.query<{ t: string }>("SELECT app.issue_manage_link($1) AS t", [g.consentId])).rows[0]!.t;
  assert.match(t1, /^[A-Za-z0-9_-]{43}$/);
  const row = (await owner.query<{ token_hash: Buffer; days: number }>("SELECT token_hash, extract(epoch FROM expires_at - created_at) / 86400 AS days FROM app.manage_link WHERE consent_decision_id = $1", [g.consentId])).rows;
  assert.equal(row.length, 1);
  assert.deepEqual(row[0]!.token_hash, shaBuf(t1));
  assert.equal(Math.round(Number(row[0]!.days)), 7);
  assert.ok(!JSON.stringify(await events(g.consentId)).includes(t1), "el ledger no lleva el token");
  const open1 = await app.query<{ consent_id: string; invitation_ref: string; state: string }>("SELECT * FROM app.open_manage_link($1)", [shaBuf(t1)]);
  assert.deepEqual(open1.rows, [{ consent_id: g.consentId, invitation_ref: g.inv, state: "GRANTED" }]);
  // abrir dos veces no consume (F-RB-02)
  assert.equal((await app.query("SELECT * FROM app.open_manage_link($1)", [shaBuf(t1)])).rows.length, 1);
  // reemitir
  const t2 = (await mailer.query<{ t: string }>("SELECT app.issue_manage_link($1) AS t", [g.consentId])).rows[0]!.t;
  assert.notEqual(t1, t2);
  assert.equal((await app.query("SELECT * FROM app.open_manage_link($1)", [shaBuf(t1)])).rows.length, 0, "el enlace anterior quedó invalidado");
  assert.equal((await app.query("SELECT * FROM app.open_manage_link($1)", [shaBuf(t2)])).rows.length, 1);
  assert.equal((await owner.query("SELECT 1 FROM app.manage_link WHERE consent_decision_id = $1 AND revoked_at IS NULL", [g.consentId])).rows.length, 1, "un solo enlace vigente");
  assert.deepEqual((await events(g.consentId)).filter((e) => e.event_type === "MANAGE_LINK_ISSUED").length, 2);
  assert.equal((await app.query("SELECT * FROM app.open_manage_link($1)", [shaBuf("desconocido")])).rows.length, 0);
  const rep = await verifyLedger(owner);
  assert.equal(rep.ok, true, JSON.stringify(rep));
});

test("vencido => sin fila; tras revoke_decision el enlace consumido solo informa REVOKED; issue_manage_link sobre decisión REVOKED/DECLINED/inexistente falla", async () => {
  const g = await granted();
  const t = (await mailer.query<{ t: string }>("SELECT app.issue_manage_link($1) AS t", [g.consentId])).rows[0]!.t;
  await owner.query("UPDATE app.manage_link SET expires_at = now() - interval '1 second', created_at = now() - interval '8 days' WHERE token_hash = $1", [shaBuf(t)]);
  assert.equal((await app.query("SELECT * FROM app.open_manage_link($1)", [shaBuf(t)])).rows.length, 0);
  const t2 = (await mailer.query<{ t: string }>("SELECT app.issue_manage_link($1) AS t", [g.consentId])).rows[0]!.t;
  const o = (await mailer.query<{ o_verification_ref: string; o_code: string }>("SELECT * FROM app.issue_otp($1, 'REVOCATION')", [g.consentId])).rows[0]!;
  await app.query("SELECT * FROM app.verify_otp($1, $2, $3)", [o.o_verification_ref, o.o_code, DM]);
  await app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-manage-1')", [g.consentId, o.o_verification_ref]);
  assert.notEqual((await owner.query<{ c: Date | null }>("SELECT consumed_at AS c FROM app.manage_link WHERE token_hash = $1", [shaBuf(t2)])).rows[0]!.c, null, "revoke_decision consume el enlace usado");
  const after = await app.query<{ state: string }>("SELECT * FROM app.open_manage_link($1)", [shaBuf(t2)]);
  assert.deepEqual(after.rows.map((r) => r.state), ["REVOKED"]);
  await assert.rejects(mailer.query("SELECT app.issue_manage_link($1)", [g.consentId]), /DECISION_NOT_GRANTED/);
  await assert.rejects(mailer.query("SELECT app.issue_manage_link('con-no-existe')"), /DECISION_NOT_FOUND/);
  // el recibo de revocación también lleva payload completo
  const rr = (await owner.query<{ payload: Record<string, unknown> }>("SELECT payload FROM app.email_outbox WHERE kind = 'REVOCATION_RECEIPT' AND invitation_ref = $1", [g.inv])).rows[0]!.payload;
  assert.equal(rr.decision, "REVOKED");
  assert.match(String(rr.receiptRef), /^rev-/);
});

test("cancel_invitation: OPENED|VERIFIED -> CANCELLED con reasonCode en el ledger, idempotente, libera la invitación viva y no toca decisiones", async () => {
  for (const verified of [false, true]) {
    const o = await opened(verified);
    await app.query("SELECT app.cancel_invitation($1, 'SUBJECT_MISMATCH_REPORTED')", [o.inv]);
    await app.query("SELECT app.cancel_invitation($1, 'SUBJECT_MISMATCH_REPORTED')", [o.inv]); // idempotente
    assert.equal((await app.query<{ state: string }>("SELECT state FROM app.invitation WHERE invitation_ref = $1", [o.inv])).rows[0]!.state, "CANCELLED");
    const cancelled = (await events(o.inv)).filter((e) => e.event_type === "INVITATION_CANCELLED");
    assert.equal(cancelled.length, 1, "un solo INVITATION_CANCELLED");
    assert.deepEqual(cancelled[0]!.payload, { invitationRef: o.inv, reasonCode: "SUBJECT_MISMATCH_REPORTED" });
    assert.equal((await app.query("SELECT * FROM app.open_invitation($1)", [sha(`token-${o.inv}`)])).rows.length, 0, "el enlace de invitación deja de resolver");
    // el índice parcial de "1 viva por estudiante" se libera: ahora puede existir otra invitación viva del mismo estudiante (vía propia de H2; aquí, el dueño).
    await owner.query("INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ($1, $2, 'Ana', 'otro@example.test')", [`inv-nueva-${uniq()}`, o.student]);
  }
  const g = await granted();
  await assert.rejects(app.query("SELECT app.cancel_invitation($1, 'SUBJECT_MISMATCH_REPORTED')", [g.inv]), /INVITATION_NOT_CANCELLABLE/);
  await assert.rejects(app.query("SELECT app.cancel_invitation('inv-no-existe', 'SUBJECT_MISMATCH_REPORTED')"), /INVITATION_NOT_FOUND/);
  const o = await opened();
  await assert.rejects(app.query("SELECT app.cancel_invitation($1, 'texto libre con espacios')", [o.inv]), /INVALID_REASON_CODE/);
  await assert.rejects(app.query("SELECT app.cancel_invitation($1, 'INVITER_WITHDRAWN')", [o.inv]), /INVALID_REASON_CODE/);
  assert.equal((await app.query<{ state: string }>("SELECT state FROM app.invitation WHERE invitation_ref = $1", [o.inv])).rows[0]!.state, "OPENED");
  const rep = await verifyLedger(owner);
  assert.equal(rep.ok, true, JSON.stringify(rep));
});

test("ABUSO (V2 punto 5): como consent_app, issue_manage_link / request_invitation_resend / issue_otp dan permission denied; no toca manage_link; no inserta en el outbox", async () => {
  const g = await granted();
  for (const sql of [
    "SELECT app.issue_manage_link($1)", "SELECT app.request_invitation_resend($1, 'OPERATOR_RESEND')", "SELECT * FROM app.issue_otp($1, 'MANAGE')",
  ]) assert.match((await failure(app, sql, [g.consentId])) ?? "", /permission denied/, sql);
  for (const sql of [
    "SELECT * FROM app.manage_link", "UPDATE app.manage_link SET revoked_at = now()", "INSERT INTO app.manage_link (consent_decision_id, token_hash, expires_at) VALUES ('x', '\\x00', now())", "DELETE FROM app.manage_link",
    "INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload) VALUES ('INVITATION', 'x', 'k', '{\"reissueReason\":\"OPERATOR_RESEND\"}')",
    "INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key) VALUES ('RECOVERY_LINK', 'x', 'k')",
    "UPDATE app.email_outbox SET payload = '{\"reissueReason\":\"X_FORCED\"}'::jsonb",
  ]) assert.match((await failure(app, sql)) ?? "", /permission denied/, sql);
  // y como consent_mailer: no abre enlaces, no cancela, no verifica ni decide
  for (const sql of ["SELECT * FROM app.open_manage_link('\\x00')", "SELECT app.cancel_invitation('x', 'SUBJECT_MISMATCH_REPORTED')", "SELECT app.enqueue_invitation_email('x', 'v1')", "SELECT * FROM app.manage_link",
    "INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key) VALUES ('INVITATION', 'x', 'k')"]) {
    assert.match((await failure(mailer, sql)) ?? "", /permission denied/, sql);
  }
});

test("enqueue_invitation_email: una fila por invitación, sin motivo; request_invitation_resend (mailer) agrega el reenvío con motivo validado", async () => {
  const o = await opened(); // OPENED: no armable para el CLI
  await assert.rejects(app.query("SELECT app.enqueue_invitation_email($1, 'v1')", [o.inv]), /INVITATION_NOT_ARMABLE/);
  const student = `stu-${uniq()}`;
  const inv = (await app.query<{ invitation_ref: string }>("SELECT * FROM app.import_invitation($1, 'Ana', $2, 'batch-001')", [student, `g-${uniq()}@example.test`])).rows[0]!.invitation_ref;
  await assert.rejects(app.query("SELECT app.enqueue_invitation_email($1, 'versión con espacios')", [inv]), /INVALID_CONSENT_VERSION/);
  await assert.rejects(app.query("SELECT app.enqueue_invitation_email('inv-no-existe', 'v1')"), /INVITATION_NOT_FOUND/);
  assert.equal((await app.query<{ r: boolean }>("SELECT app.enqueue_invitation_email($1, 'v1') AS r", [inv])).rows[0]!.r, true);
  assert.equal((await app.query<{ r: boolean }>("SELECT app.enqueue_invitation_email($1, 'v1') AS r", [inv])).rows[0]!.r, false, "idempotente");
  const rows = (await owner.query<{ payload: Record<string, unknown> }>("SELECT payload FROM app.email_outbox WHERE invitation_ref = $1", [inv])).rows;
  assert.deepEqual(rows.map((r) => r.payload), [{ consentVersion: "v1" }], "ningún motivo de reemisión sale de consent_app");
  // reenvío de operador: solo con la invitación SENT y un motivo válido
  await assert.rejects(mailer.query("SELECT app.request_invitation_resend($1, 'OPERATOR_RESEND')", [inv]), /INVITATION_NOT_ARMABLE/);
  await mailer.query("SELECT app.arm_invitation_token($1, $2, now() + interval '1 day', 'v1')", [inv, sha(`t-${inv}`)]);
  await assert.rejects(mailer.query("SELECT app.request_invitation_resend($1, 'mal motivo')", [inv]), /INVALID_REISSUE_REASON/);
  await mailer.query("SELECT app.request_invitation_resend($1, 'OPERATOR_RESEND')", [inv]);
  const after = (await owner.query<{ payload: Record<string, unknown> }>("SELECT payload FROM app.email_outbox WHERE invitation_ref = $1 ORDER BY created_at", [inv])).rows;
  assert.deepEqual(after[1]!.payload, { consentVersion: "v1", reissueReason: "OPERATOR_RESEND" });
});
