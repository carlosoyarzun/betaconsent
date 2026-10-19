// Gobierna: plan v2 H1-03 (funciones SECURITY DEFINER; criterios verificables de la tarea). Todo se ejecuta como consent_app, el rol del proceso web.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { readChain, verifyLedger } from "../../src/ledger/read-chain.ts";
import { connect, connectAsOwner, createTestDb, failure, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let app: Client;
let owner: Client;

const hex = (seed: string): string => createHash("sha256").update(seed).digest("hex");
const uniq = (): string => randomBytes(5).toString("hex");
const EXPIRES = "now() + interval '9 minutes'";

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  app = await connect(db.appUrl);
  owner = await connectAsOwner(db);
});
after(async () => {
  await app.end();
  await owner.end();
  await db.drop();
});

/** Invitación importada, con token armado y abierta. Devuelve sus refs y el hash del token. */
async function openedInvitation(c: Client = app): Promise<{ inv: string; student: string; token: string }> {
  const student = `stu-${uniq()}`;
  const imp = await c.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', $2, 'batch-1')", [student, `g-${uniq()}@example.test`]);
  const inv = imp.rows[0]!.invitation_ref;
  const token = hex(`token-${inv}`);
  await c.query(`SELECT app.arm_invitation_token($1, $2, ${EXPIRES}, 'v-test')`, [inv, token]);
  const opened = await c.query<{ invitation_ref: string; state: string }>("SELECT * FROM app.open_invitation($1)", [token]);
  assert.deepEqual(opened.rows.map((r) => [r.invitation_ref, r.state]), [[inv, "OPENED"]]);
  return { inv, student, token };
}

async function issue(parent: string, code: string, scope = "DECISION", c: Client = app): Promise<string> {
  return (await c.query<{ r: string }>(`SELECT app.issue_otp($1, $2, ${EXPIRES}, $3) AS r`, [parent, hex(code), scope])).rows[0]!.r;
}
async function verify(ver: string, code: string, c: Client = app): Promise<{ outcome: string; verification_ref: string | null; attempts_left: number }> {
  return (await c.query<{ outcome: string; verification_ref: string | null; attempts_left: number }>("SELECT * FROM app.verify_otp($1, $2, 'dm-test')", [ver, hex(code)])).rows[0]!;
}
async function events(aggregate: string): Promise<string[]> {
  return (await owner.query<{ event_type: string }>("SELECT event_type FROM integrity.audit_event WHERE aggregate_id = $1 ORDER BY sequence", [aggregate])).rows.map((r) => r.event_type);
}
async function status(student: string): Promise<{ status: string; decision_ref: string | null }> {
  return (await app.query<{ status: string; decision_ref: string | null }>("SELECT status, decision_ref FROM app.authorization_status($1)", [student])).rows[0]!;
}
async function decide(inv: string, ver: string, outcome: string, key: string, c: Client = app): Promise<{ consent_id: string; state: string; deduped: boolean }> {
  return (await c.query<{ consent_id: string; state: string; deduped: boolean }>("SELECT * FROM app.record_decision($1, $2, $3, 'v-test', $4, $5)", [inv, ver, outcome, hex("texto"), key])).rows[0]!;
}

test("import_invitation es idempotente y open_invitation no consume el token (2 aperturas, 1 solo evento OPENED)", async () => {
  const student = `stu-${uniq()}`;
  const a = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', 'b')", [student]);
  const b = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', 'b')", [student]);
  assert.equal(a.rows[0]?.created, true);
  assert.deepEqual(b.rows[0], { invitation_ref: a.rows[0]?.invitation_ref, created: false });
  const inv = a.rows[0]!.invitation_ref;
  const token = hex(`t-${inv}`);
  await app.query(`SELECT app.arm_invitation_token($1, $2, ${EXPIRES}, 'v-test')`, [inv, token]);
  for (let i = 0; i < 2; i++) assert.equal((await app.query("SELECT * FROM app.open_invitation($1)", [token])).rows.length, 1);
  assert.deepEqual(await events(inv), ["INVITATION_CREATED", "INVITATION_SENT", "INVITATION_OPENED"]);
  assert.equal((await owner.query("SELECT token_consumed_at FROM app.invitation WHERE invitation_ref = $1", [inv])).rows[0]?.token_consumed_at, null);
  // Token desconocido o vencido: respuesta uniforme (sin filas).
  assert.equal((await app.query("SELECT * FROM app.open_invitation($1)", [hex("no-existe")])).rows.length, 0);
  await owner.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE invitation_ref = $1", [inv]);
  assert.equal((await app.query("SELECT * FROM app.open_invitation($1)", [token])).rows.length, 0);
});

test("autorizar y revocar: decisión idempotente, ALREADY_DECIDED, y NOT_AUTHORIZED en la lectura siguiente a la revocación", async () => {
  const { inv, student } = await openedInvitation();
  assert.deepEqual(await status(student), { status: "NOT_AUTHORIZED", decision_ref: null });
  const ver = await issue(inv, "123456");
  assert.equal((await verify(ver, "000000")).outcome, "WRONG_CODE");
  const ok = await verify(ver, "123456");
  assert.deepEqual([ok.outcome, ok.verification_ref], ["VERIFIED", ver]);

  const d1 = await decide(inv, ver, "GRANTED", "idem-key-0001");
  assert.equal(d1.state, "GRANTED");
  assert.equal(d1.deduped, false);
  const d2 = await decide(inv, ver, "GRANTED", "idem-key-0001");
  assert.deepEqual([d2.consent_id, d2.deduped], [d1.consent_id, true]);
  await assert.rejects(decide(inv, ver, "GRANTED", "idem-key-0002"), /ALREADY_DECIDED/);
  assert.deepEqual(await events(d1.consent_id), ["CONSENT_GRANTED"]);
  assert.deepEqual(await events(inv), ["INVITATION_CREATED", "INVITATION_SENT", "INVITATION_OPENED", "INVITATION_VERIFIED", "INVITATION_COMPLETED"]);
  assert.deepEqual(await status(student), { status: "AUTHORIZED", decision_ref: d1.consent_id });
  const consumed = await owner.query<{ token_consumed_at: Date | null }>("SELECT token_consumed_at FROM app.invitation WHERE invitation_ref = $1", [inv]);
  assert.notEqual(consumed.rows[0]?.token_consumed_at, null);
  const outbox = await owner.query<{ kind: string; payload: Record<string, unknown> }>("SELECT kind, payload FROM app.email_outbox WHERE invitation_ref = $1", [inv]);
  assert.deepEqual(outbox.rows.map((r) => r.kind), ["DECISION_RECEIPT"]);
  assert.ok(!JSON.stringify(outbox.rows).includes("@"));

  // Revocación: OTP de gestión sobre la decisión; sin verificación no se puede.
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0001')", [d1.consent_id, ver]), /VERIFICATION_REQUIRED/); // OTP de otro scope
  const rver = await issue(d1.consent_id, "654321", "REVOCATION");
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0001')", [d1.consent_id, rver]), /VERIFICATION_REQUIRED/); // aún no verificado
  assert.equal((await verify(rver, "654321")).outcome, "VERIFIED");
  const rev = await app.query<{ revocation_ref: string; deduped: boolean }>("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0001')", [d1.consent_id, rver]);
  assert.equal(rev.rows[0]?.deduped, false);
  assert.deepEqual(await status(student), { status: "NOT_AUTHORIZED", decision_ref: null }); // lectura inmediatamente posterior al commit
  const again = await app.query<{ revocation_ref: string; deduped: boolean }>("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0001')", [d1.consent_id, rver]);
  assert.deepEqual(again.rows[0], { revocation_ref: rev.rows[0]?.revocation_ref, deduped: true });
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0002')", [d1.consent_id, rver]), /ALREADY_REVOKED/);
  assert.deepEqual(await events(d1.consent_id), ["CONSENT_GRANTED", "CONSENT_REVOKED"]);
  const kinds = await owner.query<{ kind: string }>("SELECT kind FROM app.email_outbox WHERE invitation_ref = $1 ORDER BY kind", [inv]);
  assert.deepEqual(kinds.rows.map((r) => r.kind), ["DECISION_RECEIPT", "REVOCATION_RECEIPT"]);
  const rep = await verifyLedger(owner);
  assert.equal(rep.ok, true, JSON.stringify(rep));
});

test("DECLINED: NOT_AUTHORIZED y no revocable; sin invitación: NOT_AUTHORIZED", async () => {
  const { inv, student } = await openedInvitation();
  const ver = await issue(inv, "111111");
  await verify(ver, "111111");
  const d = await decide(inv, ver, "DECLINED", "idem-decline-1");
  assert.equal(d.state, "DECLINED");
  assert.equal((await status(student)).status, "NOT_AUTHORIZED");
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0009')", [d.consent_id, ver]), /NOT_REVOCABLE_DECLINED/);
  assert.equal((await status(`nunca-visto-${uniq()}`)).status, "NOT_AUTHORIZED");
});

test("20 record_decision paralelos con la misma clave -> 1 decisión y 1 evento de decisión", async () => {
  const { inv } = await openedInvitation();
  const ver = await issue(inv, "222222");
  await verify(ver, "222222");
  const clients = await Promise.all(Array.from({ length: 20 }, () => connect(db.appUrl)));
  try {
    const res = await Promise.all(clients.map((c) => decide(inv, ver, "GRANTED", "idem-parallel-1", c)));
    assert.equal(new Set(res.map((r) => r.consent_id)).size, 1);
    assert.equal(res.filter((r) => !r.deduped).length, 1);
    const id = res[0]!.consent_id;
    assert.equal((await owner.query("SELECT 1 FROM app.consent_decision WHERE invitation_ref = $1", [inv])).rows.length, 1);
    assert.deepEqual(await events(id), ["CONSENT_GRANTED"]);
    assert.equal((await owner.query("SELECT 1 FROM app.email_outbox WHERE invitation_ref = $1", [inv])).rows.length, 1);
  } finally {
    await Promise.all(clients.map((c) => c.end()));
  }
});

test("2 verify_otp concurrentes con el código correcto -> 1 VERIFIED", async () => {
  const { inv } = await openedInvitation();
  const ver = await issue(inv, "333333");
  const clients = await Promise.all([connect(db.appUrl), connect(db.appUrl), connect(db.appUrl)]);
  try {
    const res = await Promise.all(clients.map((c) => verify(ver, "333333", c)));
    assert.deepEqual(res.map((r) => r.outcome).sort(), ["NOT_ACTIVE", "NOT_ACTIVE", "VERIFIED"]);
    assert.equal((await events(ver)).filter((e) => e === "DECISION_MAKER_CHANNEL_VERIFIED").length, 1);
  } finally {
    await Promise.all(clients.map((c) => c.end()));
  }
});

test("5 fallos -> LOCKED (y emite OTP_LOCKED); el código correcto después ya no sirve", async () => {
  const { inv } = await openedInvitation();
  const ver = await issue(inv, "444444");
  const outs: string[] = [];
  for (let i = 0; i < 5; i++) outs.push((await verify(ver, `mal-${i}`)).outcome);
  assert.deepEqual(outs, ["WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "LOCKED"]);
  assert.equal((await verify(ver, "444444")).outcome, "NOT_ACTIVE");
  assert.deepEqual(await events(ver), ["OTP_LOCKED"]);
  const row = await app.query<{ state: string; attempts: number }>("SELECT state, attempts FROM app.otp_challenge WHERE verification_ref = $1", [ver]);
  assert.deepEqual(row.rows[0], { state: "LOCKED", attempts: 5 });
});

test("OTP vencido -> rechazo (EXPIRED); reenvío antes de 60 s -> OTP_RESEND_TOO_SOON", async () => {
  const { inv } = await openedInvitation();
  const ver = (await app.query<{ r: string }>("SELECT app.issue_otp($1, $2, now() + interval '1 second') AS r", [inv, hex("555555")])).rows[0]!.r;
  await new Promise((r) => setTimeout(r, 1300));
  assert.equal((await verify(ver, "555555")).outcome, "EXPIRED");
  assert.equal((await verify(ver, "555555")).outcome, "NOT_ACTIVE");
  await assert.rejects(issue(inv, "666666"), /OTP_RESEND_TOO_SOON/);
});

test("presupuesto P-04: 10 fallos en la ventana agotan la invitación (issue_otp y verify_otp)", async () => {
  const { inv } = await openedInvitation();
  const key = hex(inv);
  await owner.query("INSERT INTO app.otp_budget (key_kind, key_hmac, window_start, expires_at, failures) VALUES ('INVITATION', $1, now(), now() + interval '1 day', 10)", [key]);
  await assert.rejects(issue(inv, "888888"), /OTP_BUDGET_EXHAUSTED/);
});

test("consent_app no puede escribir directo otp_challenge ni consent_decision ni revocation ni invitation", async () => {
  const { inv } = await openedInvitation();
  const ver = await issue(inv, "999999");
  assert.match((await failure(app, "UPDATE app.otp_challenge SET state = 'VERIFIED' WHERE verification_ref = $1", [ver])) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.otp_challenge SET attempts = 0")) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.consent_decision SET state = 'REVOKED'")) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.revocation (revocation_ref, consent_id, via, idempotency_key_hash) VALUES ('x','y','OTP_EMAIL', $1)", [hex("k")])) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('z','s','A','a@example.test')")) ?? "", /permission denied/);
  assert.match((await failure(app, "SELECT ledger_gen.ledger_append('Invitation','x','INVITATION_CREATED','HUMAN','OPERATOR','{}'::jsonb,NULL)")) ?? "", /permission denied/);
  const rows = await readChain(owner);
  assert.ok(rows.length > 0);
});
