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
  const imp = await c.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', $2, 'batch-001')", [student, `g-${uniq()}@example.test`]);
  const inv = imp.rows[0]!.invitation_ref;
  const token = hex(`token-${inv}`);
  await c.query(`SELECT app.arm_invitation_token($1, $2, ${EXPIRES}, 'v-test')`, [inv, token]);
  const opened = await c.query<{ invitation_ref: string; state: string }>("SELECT * FROM app.open_invitation($1)", [token]);
  assert.deepEqual(opened.rows.map((r) => [r.invitation_ref, r.state]), [[inv, "OPENED"]]);
  return { inv, student, token };
}

/** issue_otp genera el código en la base y lo devuelve en claro una sola vez. */
async function issue(parent: string, scope = "DECISION", c: Client = app): Promise<{ ver: string; code: string }> {
  const r = (await c.query<{ o_verification_ref: string; o_code: string }>("SELECT * FROM app.issue_otp($1, $2)", [parent, scope])).rows[0]!;
  assert.match(r.o_code, /^[0-9]{6}$/);
  return { ver: r.o_verification_ref, code: r.o_code };
}
const wrong = (code: string): string => (code === "000000" ? "111111" : "000000");
async function verify(ver: string, code: string, c: Client = app): Promise<{ outcome: string; verification_ref: string | null; attempts_left: number }> {
  return (await c.query<{ outcome: string; verification_ref: string | null; attempts_left: number }>("SELECT * FROM app.verify_otp($1, $2, 'dm-test-0001')", [ver, code])).rows[0]!;
}
/** Ejecuta `sql` como DUEÑO con el guard de OTP desactivado solo dentro de esta tx (simula el paso del tiempo sobre filas que el guard hace inmutables). */
async function unguardedOtp(sql: string, values: readonly unknown[] = []): Promise<void> {
  await owner.query("BEGIN");
  try {
    await owner.query("ALTER TABLE app.otp_challenge DISABLE TRIGGER otp_challenge_ledger_guard");
    await owner.query(sql, values as unknown[]);
    await owner.query("ALTER TABLE app.otp_challenge ENABLE ALWAYS TRIGGER otp_challenge_ledger_guard");
    await owner.query("COMMIT");
  } catch (e) {
    await owner.query("ROLLBACK");
    throw e;
  }
}
/** Fuerza el vencimiento de un OTP (la base fija expires_at = now()+10 min y el guard lo hace inmutable). */
async function expireOtp(ver: string): Promise<void> {
  await unguardedOtp("UPDATE app.otp_challenge SET expires_at = now() - interval '1 second', created_at = created_at - interval '2 hours' WHERE verification_ref = $1", [ver]);
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
  const a = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', 'batch-001')", [student]);
  const b = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', 'batch-001')", [student]);
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
  const { ver, code } = await issue(inv);
  assert.equal((await verify(ver, wrong(code))).outcome, "WRONG_CODE");
  const ok = await verify(ver, code);
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
  const { ver: rver, code: rcode } = await issue(d1.consent_id, "REVOCATION");
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0001')", [d1.consent_id, rver]), /VERIFICATION_REQUIRED/); // aún no verificado
  assert.equal((await verify(rver, rcode)).outcome, "VERIFIED");
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
  const { ver, code } = await issue(inv);
  await verify(ver, code);
  const d = await decide(inv, ver, "DECLINED", "idem-decline-1");
  assert.equal(d.state, "DECLINED");
  assert.equal((await status(student)).status, "NOT_AUTHORIZED");
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-key-0009')", [d.consent_id, ver]), /NOT_REVOCABLE_DECLINED/);
  assert.equal((await status(`nunca-visto-${uniq()}`)).status, "NOT_AUTHORIZED");
});

test("20 record_decision paralelos con la misma clave -> 1 decisión y 1 evento de decisión", async () => {
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  await verify(ver, code);
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
  const { ver, code } = await issue(inv);
  const clients = await Promise.all([connect(db.appUrl), connect(db.appUrl), connect(db.appUrl)]);
  try {
    const res = await Promise.all(clients.map((c) => verify(ver, code, c)));
    assert.deepEqual(res.map((r) => r.outcome).sort(), ["NOT_ACTIVE", "NOT_ACTIVE", "VERIFIED"]);
    assert.equal((await events(ver)).filter((e) => e === "DECISION_MAKER_CHANNEL_VERIFIED").length, 1);
  } finally {
    await Promise.all(clients.map((c) => c.end()));
  }
});

test("5 fallos -> LOCKED (y emite OTP_LOCKED); el código correcto después ya no sirve", async () => {
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  const outs: string[] = [];
  for (let i = 0; i < 5; i++) outs.push((await verify(ver, wrong(code))).outcome);
  assert.deepEqual(outs, ["WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "LOCKED"]);
  assert.equal((await verify(ver, code)).outcome, "NOT_ACTIVE");
  assert.deepEqual(await events(ver), ["OTP_LOCKED"]);
  const row = await app.query<{ state: string; attempts: number }>("SELECT state, attempts FROM app.otp_challenge WHERE verification_ref = $1", [ver]);
  assert.deepEqual(row.rows[0], { state: "LOCKED", attempts: 5 });
});

test("OTP vencido -> rechazo (EXPIRED); reenvío antes de 60 s -> OTP_RESEND_TOO_SOON", async () => {
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  await assert.rejects(issue(inv), /OTP_RESEND_TOO_SOON/);
  const exp = (await owner.query<{ s: number }>("SELECT extract(epoch FROM (expires_at - created_at)) AS s FROM app.otp_challenge WHERE verification_ref = $1", [ver])).rows[0]!.s;
  assert.ok(Math.abs(exp - 600) < 1, `la base fija P-02 = 10 min (fue ${exp} s)`);
  await expireOtp(ver);
  assert.equal((await verify(ver, code)).outcome, "EXPIRED");
  assert.equal((await verify(ver, code)).outcome, "NOT_ACTIVE");
});

test("presupuesto P-04: 10 fallos en la ventana agotan la invitación (issue_otp y verify_otp)", async () => {
  const { inv } = await openedInvitation();
  const key = hex(inv);
  await owner.query("INSERT INTO app.otp_budget (key_kind, key_hmac, window_start, expires_at, failures) VALUES ('INVITATION', $1, now(), now() + interval '1 day', 10)", [key]);
  await assert.rejects(issue(inv), /OTP_BUDGET_EXHAUSTED/);
});

test("consent_app no puede escribir directo otp_challenge ni consent_decision ni revocation ni invitation", async () => {
  const { inv } = await openedInvitation();
  const { ver } = await issue(inv);
  assert.match((await failure(app, "UPDATE app.otp_challenge SET state = 'VERIFIED' WHERE verification_ref = $1", [ver])) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.otp_challenge SET attempts = 0")) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.consent_decision SET state = 'REVOKED'")) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.revocation (revocation_ref, consent_id, via, idempotency_key_hash) VALUES ('x','y','OTP_EMAIL', $1)", [hex("k")])) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('z','s','A','a@example.test')")) ?? "", /permission denied/);
  assert.match((await failure(app, "SELECT ledger_gen.ledger_append('Invitation','x','INVITATION_CREATED','HUMAN','OPERATOR','{}'::jsonb,NULL)")) ?? "", /permission denied/);
  const rows = await readChain(owner);
  assert.ok(rows.length > 0);
});

// ---- SEC-CNS-024 ---------------------------------------------------------------------------------------------------------------------------------------------

test("F-SB-01: como consent_app, sin conocer el código, ninguna combinación de funciones consigue VERIFIED ni GRANTED", async () => {
  const { inv, student } = await openedInvitation();
  // El ataque anterior ya no tiene superficie: no hay firma que acepte un verificador del llamador.
  await assert.rejects(app.query(`SELECT app.issue_otp($1, $2, ${EXPIRES}, 'DECISION')`, [inv, "a".repeat(64)]), /does not exist/);
  assert.match((await failure(app, "SELECT code_hash FROM app.otp_challenge")) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.otp_challenge (verification_ref, scope, parent_ref, code_hash, expires_at) VALUES ('ver-forged', 'DECISION', $1, $2, now() + interval '9 minutes')", [inv, "a".repeat(64)])) ?? "", /permission denied/);

  // issue + verify con un código inventado x5 -> LOCKED (y nunca VERIFIED); el verificador-estilo-HMAC tampoco sirve.
  const { ver, code } = await issue(inv);
  const outs: string[] = [(await verify(ver, "a".repeat(64))).outcome];
  for (let i = 0; i < 4; i++) outs.push((await verify(ver, wrong(code))).outcome);
  assert.deepEqual(outs, ["WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "LOCKED"]);

  // record_decision sin verificación: con el challenge bloqueado, con uno solo emitido y con refs inventadas.
  await assert.rejects(decide(inv, ver, "GRANTED", "idem-abuse-01"), /VERIFICATION_REQUIRED/);
  await assert.rejects(decide(inv, "ver-inventado", "GRANTED", "idem-abuse-02"), /VERIFICATION_REQUIRED/);
  assert.equal((await owner.query("SELECT state FROM app.invitation WHERE invitation_ref = $1", [inv])).rows[0]?.state, "OPENED");

  assert.deepEqual(await status(student), { status: "NOT_AUTHORIZED", decision_ref: null });
  assert.equal((await owner.query("SELECT 1 FROM app.consent_decision WHERE invitation_ref = $1", [inv])).rows.length, 0);
  assert.ok(!(await events(inv)).includes("INVITATION_VERIFIED"));
  const rep = await verifyLedger(owner);
  assert.equal(rep.ok, true, JSON.stringify(rep));
});

test("F-SB-01: la revocación tampoco se puede forzar sin el código del apoderado", async () => {
  const { inv, student } = await openedInvitation();
  const o = await issue(inv);
  await verify(o.ver, o.code);
  const d = await decide(inv, o.ver, "GRANTED", "idem-abuse-rv1");
  const r = await issue(d.consent_id, "REVOCATION");
  for (let i = 0; i < 5; i++) await verify(r.ver, wrong(r.code));
  await assert.rejects(app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-abuse-001')", [d.consent_id, r.ver]), /VERIFICATION_REQUIRED/);
  assert.equal((await status(student)).status, "AUTHORIZED");
});

test("el código OTP es de 6 dígitos y solo existe su hash en la tabla", async () => {
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  const row = (await owner.query<{ code_hash: string }>("SELECT code_hash FROM app.otp_challenge WHERE verification_ref = $1", [ver])).rows[0]!;
  assert.equal(row.code_hash, createHash("sha256").update(`${ver}:${code}`).digest("hex"));
  const leak = await owner.query("SELECT 1 FROM app.otp_challenge o WHERE o::text LIKE $1", [`%${code}%`]);
  assert.equal(leak.rows.length, 0);
});

test("F-SB-03: reimportar tras GRANTED y tras REVOKED devuelve la existente (0 nuevas) y no cambia el correo", async () => {
  const { inv, student } = await openedInvitation();
  const { ver, code } = await issue(inv);
  await verify(ver, code);
  const d = await decide(inv, ver, "GRANTED", "idem-reimp-01");
  const count = async (): Promise<number> => (await owner.query<{ n: number }>("SELECT count(*)::int AS n FROM app.invitation WHERE student_ref = $1", [student])).rows[0]!.n;
  const email = async (): Promise<string> => (await owner.query<{ guardian_email: string }>("SELECT guardian_email FROM app.invitation WHERE invitation_ref = $1", [inv])).rows[0]!.guardian_email;
  const before = await email();
  const again = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'attacker@example.test', 'batch-002')", [student]);
  assert.deepEqual(again.rows[0], { invitation_ref: inv, created: false });
  assert.equal(await count(), 1);
  const r = await issue(d.consent_id, "REVOCATION");
  await verify(r.ver, r.code);
  await app.query("SELECT * FROM app.revoke_decision($1, $2, 'rev-reimp-001')", [d.consent_id, r.ver]);
  assert.equal((await status(student)).status, "NOT_AUTHORIZED");
  const again2 = await app.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, 'Ana', 'attacker@example.test', 'batch-003')", [student]);
  assert.deepEqual(again2.rows[0], { invitation_ref: inv, created: false });
  assert.equal(await count(), 1);
  assert.equal(await email(), before);
});

test("F-SB-04 + ventana de 10 min: con la verificación vencida hay que reemitir; con 9 min aún se puede decidir", async () => {
  const { inv } = await openedInvitation();
  const a = await issue(inv);
  await verify(a.ver, a.code);
  assert.equal((await owner.query("SELECT state FROM app.invitation WHERE invitation_ref = $1", [inv])).rows[0]?.state, "VERIFIED");
  // 9 min después de verificar: dentro de la ventana (se comprueba sin consumirla: otra invitación abajo).
  await unguardedOtp("UPDATE app.otp_challenge SET consumed_at = now() - interval '11 minutes', created_at = created_at - interval '2 hours' WHERE verification_ref = $1", [a.ver]);
  await assert.rejects(decide(inv, a.ver, "GRANTED", "idem-win-0001"), /VERIFICATION_REQUIRED/); // ventana de 10 min vencida
  // Antes de F-SB-04 la invitación quedaba bloqueada para siempre (issue_otp exigía OPENED).
  const b = await issue(inv);
  assert.equal((await verify(b.ver, b.code)).outcome, "VERIFIED");
  const d = await decide(inv, b.ver, "GRANTED", "idem-win-0001");
  assert.equal(d.state, "GRANTED");

  const { inv: inv2 } = await openedInvitation();
  const c = await issue(inv2);
  await verify(c.ver, c.code);
  await unguardedOtp("UPDATE app.otp_challenge SET consumed_at = now() - interval '9 minutes' WHERE verification_ref = $1", [c.ver]);
  assert.equal((await decide(inv2, c.ver, "GRANTED", "idem-win-0002")).state, "GRANTED");
});

test("P-07: el 3.er challenge LOCKED agota la invitación (OTP_EXHAUSTED)", async () => {
  const { inv } = await openedInvitation();
  for (let i = 0; i < 3; i++) {
    const { ver, code } = await issue(inv);
    for (let k = 0; k < 5; k++) await verify(ver, wrong(code));
    assert.equal((await owner.query("SELECT state FROM app.otp_challenge WHERE verification_ref = $1", [ver])).rows[0]?.state, "LOCKED");
    await unguardedOtp("UPDATE app.otp_challenge SET created_at = created_at - interval '2 hours' WHERE verification_ref = $1", [ver]);
    await owner.query("DELETE FROM app.otp_budget WHERE true");
  }
  await assert.rejects(issue(inv), /OTP_EXHAUSTED/);
});

test("F-SB-05: purposes solo admite códigos de la lista cerrada; un número o un objeto se rechaza y verify-ledger sigue OK", async () => {
  const { inv, student } = await openedInvitation();
  const { ver, code } = await issue(inv);
  await verify(ver, code);
  const rec = (purposes: string, key: string): Promise<unknown> =>
    app.query("SELECT * FROM app.record_decision($1, $2, 'GRANTED', 'v-test', $3, $4, $5::jsonb)", [inv, ver, hex("texto"), key, purposes]);
  await assert.rejects(rec("[1.5]", "idem-purp-001"), /INVALID_PURPOSES/);
  await assert.rejects(rec("[1]", "idem-purp-002"), /INVALID_PURPOSES/);
  await assert.rejects(rec('[{"purpose":"STUDY_PARTICIPATION"}]', "idem-purp-003"), /INVALID_PURPOSES/);
  await assert.rejects(rec('["OTRO_FIN"]', "idem-purp-004"), /INVALID_PURPOSES/);
  await assert.rejects(rec('["STUDY_PARTICIPATION","STUDY_PARTICIPATION"]', "idem-purp-005"), /INVALID_PURPOSES/);
  await assert.rejects(rec('"STUDY_PARTICIPATION"', "idem-purp-006"), /INVALID_PURPOSES/);
  await assert.rejects(rec("null", "idem-purp-007"), /INVALID_PURPOSES/);
  assert.equal((await status(student)).status, "NOT_AUTHORIZED");
  await rec('["STUDY_PARTICIPATION","AUDIO_RECORDING"]', "idem-purp-008");
  assert.equal((await status(student)).status, "AUTHORIZED");
  const rep = await verifyLedger(owner);
  assert.equal(rep.ok, true, JSON.stringify(rep));
});

test("F-SB-05: forma de las refs que entran al ledger (student_ref, import_batch_ref, versión): sin RUT, sin espacios ni arrobas", async () => {
  const imp = (student: string, batch: string): Promise<unknown> => app.query("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', $2)", [student, batch]);
  for (const bad of ["12.345.678-9", "12345678-9", "juan perez", "a@b.cl", "corto", "x".repeat(65)]) {
    await assert.rejects(imp(bad, "batch-001"), /invitation_student_ref_shape/, bad);
  }
  await assert.rejects(imp(`stu-${uniq()}`, "lote con texto libre"), /invitation_batch_ref_shape/);
  await imp(`stu-${uniq()}`, "batch-001");
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  await verify(ver, code);
  await assert.rejects(app.query("SELECT * FROM app.record_decision($1, $2, 'GRANTED', 'versión con espacios', $3, 'idem-ver-0001', '[]'::jsonb)", [inv, ver, hex("t")]), /INVALID_CONSENT_VERSION/);
});

test("el verify_otp confirmado no se revierte con un fallo posterior (WRONG_CODE cuenta aunque record_decision falle)", async () => {
  const { inv } = await openedInvitation();
  const { ver, code } = await issue(inv);
  const c = await connect(db.appUrl);
  try {
    assert.equal((await verify(ver, wrong(code), c)).outcome, "WRONG_CODE"); // tx propia, confirmada
    await assert.rejects(decide(inv, ver, "GRANTED", "idem-keep-0001", c), /VERIFICATION_REQUIRED/); // fallo posterior
  } finally {
    await c.end();
  }
  assert.equal((await owner.query("SELECT attempts FROM app.otp_challenge WHERE verification_ref = $1", [ver])).rows[0]?.attempts, 1);
});
