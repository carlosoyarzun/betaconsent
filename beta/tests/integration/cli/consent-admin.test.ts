// Gobierna: plan v2 H1-09. CLI consent-admin contra Postgres real con los dos pools (consent_app y consent_mailer).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createPools, assertPoolRoles, type RuntimePools } from "../../../src/db/pool.ts";
import { migrate } from "../../../src/db/migrate.ts";
import { runCli, type CliDeps } from "../../../src/cli/cli.ts";
import { MemoryMailer } from "../../../src/mail/memory-mailer.ts";
import { connect, createTestDb, MIGRATIONS_DIR, type TestDb } from "../pg-harness.ts";

let db: TestDb;
let pools: RuntimePools;
const mailer = new MemoryMailer();
const files = new Map<string, string>();
const BATCH = "lote-cli-0001";
const H = "student_ref,student_first_name,guardian_email";

function deps(): CliDeps {
  return {
    app: pools.app,
    mailer: pools.mailer,
    makeWorker: async () => ({ mailer, policy: { dataClass: "SYNTHETIC", allowlist: ["@example.test"] } }),
    readFile: (p) => {
      const c = files.get(p);
      if (c === undefined) throw new Error("ENOENT");
      return c;
    },
  };
}
const cli = (...argv: string[]) => runCli(argv, deps());
async function count(sql: string): Promise<number> {
  return Number((await pools.app.query<{ n: string }>(sql)).rows[0]?.n);
}

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  pools = createPools({ appUrl: db.appUrl, mailerUrl: db.mailerUrl });
  await assertPoolRoles(pools);
  files.set("ok.csv", `${H}\nstu-cli-0001,Ana,uno@example.test\nstu-cli-0002,Beto,dos@example.test\nstu-cli-0003,Cami,tres@example.test\n`);
  files.set("bad.csv", `${H}\nstu-cli-0010,Ana,diez@example.test\nstu-cli-0011,,once@example.test\n`);
});
after(async () => {
  await pools.app.end();
  await pools.mailer.end();
  await db.drop();
});

test("import dry-run (por defecto) no escribe y cuenta nuevas", async () => {
  const r = await cli("import-csv", "ok.csv", "--batch", BATCH, "--json");
  assert.equal(r.exitCode, 0);
  const o = JSON.parse(r.stdout);
  assert.deepEqual([o.mode, o.total, o.new, o.existing, o.invalid], ["dry-run", 3, 3, 0, 0]);
  assert.equal(await count("SELECT count(*) AS n FROM app.invitation"), 0);
});

test("fila inválida en el lote: 0 escritas, exit 1, correo enmascarado y sin PII", async () => {
  files.set("bad-mail.csv", `${H}\nstu-cli-0020,Ana,ok20@example.test\nstu-cli-0021,Eva,secreto-sin-arroba\n`);
  for (const f of ["bad.csv", "bad-mail.csv"]) {
    const r = await cli("import-csv", f, "--batch", BATCH, "--apply");
    assert.equal(r.exitCode, 1);
    assert.ok(!r.stdout.includes("@example.test") && !r.stdout.includes("secreto-sin-arroba"));
    assert.match(r.stdout, /fila 2/);
  }
  assert.equal(await count("SELECT count(*) AS n FROM app.invitation"), 0);
});

test("cabecera errónea: exit 1 y nada escrito", async () => {
  files.set("hdr.csv", "ref,name,mail\nx,y,z\n");
  const r = await cli("import-csv", "hdr.csv", "--batch", BATCH, "--apply");
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /CSV_BAD_HEADER/);
});

test("--batch inválido o --dry-run con --apply: uso incorrecto (exit 2)", async () => {
  assert.equal((await cli("import-csv", "ok.csv", "--batch", "x")).exitCode, 2);
  assert.equal((await cli("import-csv", "ok.csv", "--batch", BATCH, "--dry-run", "--apply")).exitCode, 2);
});

test("apply crea 3; reimportar -> 0 nuevas; el dry-run posterior ve 3 existentes", async () => {
  const a = JSON.parse((await cli("import-csv", "ok.csv", "--batch", BATCH, "--apply", "--json")).stdout);
  assert.deepEqual([a.mode, a.total, a.new, a.existing], ["apply", 3, 3, 0]);
  assert.equal(await count("SELECT count(*) AS n FROM app.invitation WHERE import_batch_ref = 'lote-cli-0001'"), 3);
  const b = JSON.parse((await cli("import-csv", "ok.csv", "--batch", BATCH, "--apply", "--json")).stdout);
  assert.deepEqual([b.new, b.existing], [0, 3]);
  const c = JSON.parse((await cli("import-csv", "ok.csv", "--batch", BATCH, "--json")).stdout);
  assert.deepEqual([c.new, c.existing], [0, 3]);
  assert.equal(await count("SELECT count(*) AS n FROM app.invitation"), 3);
});

test("send-invitations encola una fila por invitación (idempotente) y --run-worker-once envía con MemoryMailer", async () => {
  const s = JSON.parse((await cli("send-invitations", "--batch", BATCH, "--limit", "2", "--json")).stdout);
  assert.deepEqual([s.ready, s.enqueued, s.worker], [2, 2, null]);
  const plain = await cli("send-invitations", "--batch", BATCH);
  assert.match(plain.stdout, /worker del proceso web/);
  const s2 = JSON.parse((await cli("send-invitations", "--batch", BATCH, "--run-worker-once", "--json")).stdout);
  assert.equal(s2.enqueued, 0); // la corrida sin --limit anterior ya encoló la tercera
  assert.equal(s2.already_queued, 3);
  assert.equal(s2.worker.sent, 3);
  assert.equal(await count("SELECT count(*) AS n FROM app.email_outbox WHERE kind = 'INVITATION'"), 3);
  assert.equal(mailer.sent.length, 3);
  assert.equal(await count("SELECT count(*) AS n FROM app.invitation WHERE state = 'SENT'"), 3);
  // Segunda corrida: nada READY.
  const s3 = JSON.parse((await cli("send-invitations", "--batch", BATCH, "--json")).stdout);
  assert.equal(s3.ready, 0);
});

test("resend exige motivo válido y usa el pool mailer; el pool app no puede (permission denied)", async () => {
  const ref = (await pools.app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.invitation WHERE student_ref = 'stu-cli-0001'")).rows[0]?.invitation_ref as string;
  assert.equal((await cli("resend", ref)).exitCode, 2);
  assert.equal((await cli("resend", ref, "--reason", "malo")).exitCode, 2);
  const ok = await cli("resend", ref, "--reason", "OPERATOR_RESEND", "--run-worker-once", "--json");
  assert.equal(ok.exitCode, 0);
  assert.equal(JSON.parse(ok.stdout).worker.sent, 1);
  assert.equal(mailer.sent.length, 4);
  await assert.rejects(pools.app.query("SELECT app.request_invitation_resend($1, $2)", [ref, "OPERATOR_RESEND"]), /permission denied/);
  const bad = await runCli(["resend", "inv-no-existe", "--reason", "OPERATOR_RESEND"], deps());
  assert.equal(bad.exitCode, 1);
  assert.match(bad.stderr, /INVITATION_NOT_FOUND/);
});

test("status: conteos sin PII y authorization_status del estudiante", async () => {
  const r = JSON.parse((await cli("status", "--batch", BATCH, "--student", "stu-cli-0002", "--json")).stdout);
  assert.equal(r.invitations.SENT, 3);
  assert.equal(r.student.authorization_status, "NOT_AUTHORIZED");
  assert.equal(r.student.invitation_state, "SENT");
  const text = (await cli("status")).stdout;
  assert.match(text, /SENT/);
  assert.ok(!text.includes("@"));
});

test("cancel no está disponible hasta H2 (exit 3)", async () => {
  const r = await cli("cancel", "inv-x", "--reason", "OPERATOR_CANCELLED");
  assert.equal(r.exitCode, 3);
  assert.match(r.stderr, /H2/);
});

test("verify-ledger OK con cabeza y conteo; FALLA (exit 1) si se altera un eslabón", async () => {
  const r = await cli("verify-ledger", "--json");
  assert.equal(r.exitCode, 0);
  const o = JSON.parse(r.stdout);
  assert.equal(o.status, "OK");
  assert.ok(o.count > 0 && o.head.chain_seq === o.count && /^[0-9a-f]{64}$/.test(o.head.event_hash));
  // Alteración como superusuario (el ledger es append-only para los roles de runtime).
  const sup = await connect(db.superDbUrl);
  try {
    await sup.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER USER");
    await sup.query(`UPDATE integrity.audit_event SET payload = payload || '{"tampered": true}'::jsonb, occurred_at = now() WHERE chain_seq = 1`);
    await sup.query("ALTER TABLE integrity.audit_event ENABLE TRIGGER USER");
  } finally {
    await sup.end();
  }
  const bad = await cli("verify-ledger");
  assert.equal(bad.exitCode, 1);
  assert.match(bad.stdout, /LEDGER FALLA/);
});
