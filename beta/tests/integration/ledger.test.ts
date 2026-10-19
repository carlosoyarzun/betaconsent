// Gobierna: plan v2 H1-02. Ledger append-only + cadena SHA-256 + triggers guard/emit, roles y privilegios, índices parciales.
// Vectores dorados TS<->SQL: reutilizan los de TEST-CNS-912 / TEST-CNS-1456 del repo anterior (tests/unit/common/ledger-chain.test.ts@9345b78).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { canonicalJson, computePayloadHash } from "../../src/ledger/ledger-chain.ts";
import { readChain, verifyLedger } from "../../src/ledger/read-chain.ts";
import { connect, connectAsOwner, createTestDb, failure, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let owner: Client;
let app: Client;
let sup: Client;

const HASH = (c: string): string => c.repeat(64);

async function eventCount(): Promise<number> {
  return Number((await owner.query<{ n: string }>("SELECT count(*)::text AS n FROM integrity.audit_event")).rows[0]?.n);
}

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  owner = await connectAsOwner(db);
  app = await connect(db.appUrl);
  sup = await connect(db.superDbUrl);
});
after(async () => {
  await owner.end();
  await app.end();
  await sup.end();
  await db.drop();
});

test("consent_app no es miembro de consent_owner; el migrador solo tiene SET (sin INHERIT)", async () => {
  const members = await sup.query<{ member: string; inherit_option: boolean; set_option: boolean }>(
    `SELECT m.rolname AS member, am.inherit_option, am.set_option FROM pg_auth_members am
       JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member WHERE r.rolname = 'consent_owner'`,
  );
  assert.deepEqual(members.rows, [{ member: "consent_migrator", inherit_option: false, set_option: true }]);
  assert.equal((await sup.query<{ x: boolean }>("SELECT pg_has_role('consent_app', 'consent_owner', 'MEMBER') AS x")).rows[0]?.x, false);
  const attrs = await sup.query<{ rolname: string; rolcanlogin: boolean; rolinherit: boolean; rolbypassrls: boolean; rolcreatedb: boolean; rolcreaterole: boolean; rolsuper: boolean }>(
    "SELECT rolname, rolcanlogin, rolinherit, rolbypassrls, rolcreatedb, rolcreaterole, rolsuper FROM pg_roles WHERE rolname LIKE 'consent\\_%' ORDER BY rolname",
  );
  const by = Object.fromEntries(attrs.rows.map((r) => [r.rolname, r]));
  assert.equal(by.consent_owner?.rolcanlogin, false);
  assert.equal(by.consent_migrator?.rolcanlogin, true);
  assert.equal(by.consent_migrator?.rolinherit, false);
  assert.equal(by.consent_app?.rolcanlogin, true);
  for (const r of attrs.rows) assert.equal(r.rolbypassrls || r.rolcreatedb || r.rolcreaterole || r.rolsuper, false, r.rolname);
});

test("UPDATE/DELETE/TRUNCATE del ledger fallan como consent_app Y como consent_owner (privilegio) y el trigger los frena incluso al superusuario", async () => {
  // Sembrar una fila para que UPDATE/DELETE tengan objetivo.
  await app.query("INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('inv-seed', 'stu-seed', 'Ana', 'a@example.test')");
  for (const [who, c] of [["consent_app", app], ["consent_owner", owner]] as const) {
    for (const sql of ["UPDATE integrity.audit_event SET payload = '{}'::jsonb", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event"]) {
      const err = await failure(c, sql);
      assert.match(err ?? "", /permission denied|append-only/, `${who}: ${sql}`);
    }
  }
  // Superusuario (ignora los privilegios): lo frena el trigger ENABLE ALWAYS, también con session_replication_role = replica.
  await sup.query("SET session_replication_role = replica");
  try {
    for (const sql of ["UPDATE integrity.audit_event SET payload = '{}'::jsonb", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event"]) {
      assert.match((await failure(sup, sql)) ?? "", /append-only/, sql);
    }
  } finally {
    await sup.query("RESET session_replication_role");
  }
  assert.match((await failure(app, "INSERT INTO integrity.audit_event (aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash) VALUES ('X','y',1,'INVITATION_CREATED','HUMAN','{}',99,$1,$1,$1)", [HASH("a")])) ?? "", /permission denied/);
});

test("consent_app no puede escribir otp_challenge ni consent_decision ni leer code_hmac", async () => {
  assert.match((await failure(app, "UPDATE app.consent_decision SET state = 'REVOKED'")) ?? "", /permission denied/);
  assert.match((await failure(app, "INSERT INTO app.consent_decision (consent_id) VALUES ('x')")) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.otp_challenge SET state = 'VERIFIED'")) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.otp_challenge SET code_hmac = $1", [HASH("b")])) ?? "", /permission denied/);
  assert.match((await failure(app, "SELECT code_hmac FROM app.otp_challenge")) ?? "", /permission denied/);
  assert.match((await failure(app, "UPDATE app.invitation SET state = 'CANCELLED'")) ?? "", /permission denied/);
  assert.equal(await failure(app, "SELECT state, attempts FROM app.otp_challenge"), null);
});

test("los índices parciales rechazan 2 invitaciones vivas por student_ref (y permiten otra tras cancelar)", async () => {
  await app.query("INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('inv-a', 'stu-dup', 'Ana', 'a@example.test')");
  const err = await failure(app, "INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('inv-b', 'stu-dup', 'Ana', 'a@example.test')");
  assert.match(err ?? "", /invitation_single_live_per_student_uq/);
  await owner.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE invitation_ref = 'inv-a'");
  await app.query("INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ('inv-b', 'stu-dup', 'Ana', 'a@example.test')");
});

test("formas inválidas: correo sin minúsculas/forma, nombre vacío", async () => {
  const base = "INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email) VALUES ";
  assert.match((await failure(app, base + "('x1', 's-x1', 'Ana', 'A@Example.test')")) ?? "", /invitation_email_shape/);
  assert.match((await failure(app, base + "('x2', 's-x2', 'Ana', 'sin-arroba')")) ?? "", /invitation_email_shape/);
  assert.match((await failure(app, base + "('x3', 's-x3', '', 'a@example.test')")) ?? "", /invitation_first_name_len/);
});

test("flujo completo: cada INSERT/transición emite exactamente 1 evento encadenado y el verificador TS recalcula la misma cabeza", async () => {
  const emits = async (sql: string, values: readonly unknown[] = []): Promise<number> => {
    const before = await eventCount();
    await owner.query(sql, values);
    return (await eventCount()) - before;
  };
  const future = "now() + interval '1 hour'";
  assert.equal(await emits("INSERT INTO app.invitation (invitation_ref, student_ref, student_first_name, guardian_email, import_batch_ref) VALUES ('inv-1', 'stu-1', 'Ana', 'g@example.test', 'batch-1')"), 1);
  assert.equal(await emits(`UPDATE app.invitation SET state = 'SENT', token_hash = $1, token_expires_at = ${future}, consent_version = 'v-test' WHERE invitation_ref = 'inv-1'`, [HASH("1")]), 1);
  assert.equal(await emits(`UPDATE app.invitation SET token_hash = $1, token_expires_at = ${future} WHERE invitation_ref = 'inv-1'`, [HASH("2")]), 1); // rotación
  assert.equal(await emits("UPDATE app.invitation SET state = 'OPENED' WHERE invitation_ref = 'inv-1'"), 1);
  assert.equal(await emits(`INSERT INTO app.otp_challenge (verification_ref, scope, parent_ref, code_hmac, expires_at) VALUES ('ver-1', 'DECISION', 'inv-1', $1, ${future})`, [HASH("c")]), 0);
  assert.equal(await emits("UPDATE app.otp_challenge SET attempts = 1, state = 'VERIFIED', consumed_at = now(), decision_maker_ref = 'dm-1' WHERE verification_ref = 'ver-1'"), 1);
  assert.equal(await emits("UPDATE app.invitation SET state = 'VERIFIED' WHERE invitation_ref = 'inv-1'"), 1);
  const insertDecision = `INSERT INTO app.consent_decision (consent_id, invitation_ref, student_ref, decision_maker_ref, verification_ref, state, purposes, consent_version, consent_text_sha256, idempotency_key_hash)
     VALUES ('con-1', 'inv-1', 'stu-1', 'dm-1', 'ver-1', 'GRANTED', '[{"purpose":"LECTURA","choice":"GRANT"}]'::jsonb, 'v-test', $1, $2)`;
  assert.equal(await emits(insertDecision, [HASH("d"), HASH("e")]), 1);
  // Un segundo INSERT por la misma invitación (o con la misma clave) lo rechaza la base.
  assert.match((await failure(owner, insertDecision.replace("'con-1'", "'con-2'"), [HASH("d"), HASH("f")])) ?? "", /consent_decision_one_per_invitation/);
  assert.equal(await emits("UPDATE app.invitation SET state = 'COMPLETED', token_consumed_at = now() WHERE invitation_ref = 'inv-1'"), 1);

  const last = (await owner.query<{ event_type: string; payload: Record<string, unknown> }>("SELECT event_type, payload FROM integrity.audit_event WHERE aggregate_id = 'con-1'")).rows;
  assert.deepEqual(last.map((r) => r.event_type), ["CONSENT_GRANTED"]);
  assert.ok(!JSON.stringify(last).includes("@"), "el payload no lleva correos");

  const report = await verifyLedger(owner);
  assert.equal(report.ok, true, JSON.stringify(report));
  const rows = await readChain(owner);
  assert.equal(report.ok && report.verified, rows.length);
  assert.ok(rows.length >= 9);
  // El verificador TS ve la misma cabeza que SQL.
  const head = (await owner.query<{ chain_seq: string; event_hash: string }>("SELECT chain_seq::text AS chain_seq, event_hash FROM integrity.audit_event ORDER BY integrity.audit_event.chain_seq DESC LIMIT 1")).rows[0];
  assert.equal(rows[rows.length - 1]?.eventHash, head?.event_hash);
  assert.equal(String(rows[rows.length - 1]?.chainSeq), head?.chain_seq);
  // Cadena sin bifurcaciones ni huecos.
  assert.deepEqual(rows.map((r) => r.chainSeq), rows.map((_, i) => i + 1));
});

test("las transiciones inválidas las rechaza el guard (42501)", async () => {
  assert.match((await failure(owner, "UPDATE app.invitation SET state = 'COMPLETED' WHERE invitation_ref = 'inv-b'")) ?? "", /derivacion del ledger/); // READY>COMPLETED
  assert.match((await failure(owner, "UPDATE app.invitation SET guardian_email = 'otro@example.test' WHERE invitation_ref = 'inv-b'")) ?? "", /derivacion del ledger/); // inmutable
  assert.match((await failure(owner, "UPDATE app.otp_challenge SET state = 'EXPIRED', attempts = 5 WHERE verification_ref = 'ver-1'")) ?? "", /derivacion del ledger/); // VERIFIED es terminal
  assert.match((await failure(owner, "UPDATE app.consent_decision SET state = 'REVOKED', revoked_at = now() WHERE consent_id = 'con-1'")) ?? "", /derivacion del ledger/); // sin revocación PENDING
  // INSERT de decisión sin invitación VERIFIED (inv-b está READY) -> rechazado.
  assert.match((await failure(owner, `INSERT INTO app.consent_decision (consent_id, invitation_ref, student_ref, decision_maker_ref, verification_ref, state, purposes, consent_version, consent_text_sha256, idempotency_key_hash)
     VALUES ('con-9', 'inv-b', 'stu-dup', 'dm-1', 'ver-1', 'GRANTED', '[]'::jsonb, 'v', $1, $2)`, [HASH("d"), HASH("9")])) ?? "", /derivacion del ledger/);
});

test("vectores dorados TS<->SQL: canonical_json y hash del payload coinciden", async () => {
  const vectors: unknown[] = [
    {},
    { a: 1 },
    { b: 1, a: { d: [3, { y: 1, x: 2 }], c: null } },
    { B: 1, a: 2, _: 3, Z: [true, false, null], "ñ": "acción", é: 1 },
    { s: 'comillas "dobles" y \\ barra', u: "línea\nnueva", n: -42, e: [] },
    { arr: [[1, [2, [3]]], { k: { j: {} } }] },
  ];
  for (const v of vectors) {
    const r = await owner.query<{ c: string; h: string }>(
      "SELECT ledger_gen.canonical_json($1::jsonb) AS c, encode(sha256(convert_to(ledger_gen.canonical_json($1::jsonb), 'UTF8')), 'hex') AS h",
      [JSON.stringify(v)],
    );
    assert.equal(r.rows[0]?.c, canonicalJson(v), JSON.stringify(v));
    assert.equal(r.rows[0]?.h, computePayloadHash(v), JSON.stringify(v));
  }
});

test("la idempotencia estricta de ledger_append: misma clave y mismo evento = dedupe; distinto payload = RV002", async () => {
  const call = (payload: string): Promise<{ rows: Array<{ o_sequence: number; o_deduped: boolean }> }> =>
    owner.query("SELECT * FROM ledger_gen.ledger_append('Invitation', 'inv-idem', 'INVITATION_CREATED', 'HUMAN', 'OPERATOR', $1::jsonb, 'k-1')", [payload]);
  assert.deepEqual((await call('{"a":1}')).rows[0], { o_sequence: 1, o_deduped: false });
  assert.deepEqual((await call('{"a":1}')).rows[0], { o_sequence: 1, o_deduped: true });
  await assert.rejects(call('{"a":2}'), /clave de idempotencia reutilizada/);
});
