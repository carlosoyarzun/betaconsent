// Gobierna: plan v2 H1-06 + SEC-CNS-024-V1. Outbox en proceso contra Postgres real: el worker corre con el rol consent_mailer (mdb), el encolado/lectura de dominio con consent_app (app); valida los grants de ambos,
// allowlist sintética, reintentos, concurrencia y OTP sin rastro. La parte Mailpit corre solo si MAILPIT_SMTP_URL y MAILPIT_API_URL
// están definidas (CI: servicio axllent/mailpit del job beta-integration; local: docker run -p 1025:1025 -p 8025:8025 axllent/mailpit).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { MemoryMailer } from "../../src/mail/memory-mailer.ts";
import { MAX_ATTEMPTS, runOutboxTick, SUPPRESSED_STATUS, type MailLogger, type OutboxDeps } from "../../src/mail/outbox-worker.ts";
import { hashInvitationToken } from "../../src/domain/crypto.ts";
import { readGuardianEmail, sendOtpNow } from "../../src/mail/otp.ts";
import { readDataClass, type RecipientPolicy } from "../../src/mail/recipient-policy.ts";
import { SmtpMailer } from "../../src/mail/smtp-mailer.ts";
import { connect, connectAsOwner, createTestDb, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let app: Client;
let mdb: Client; // consent_mailer
let mdb2: Client;
let owner: Client;
let sup: Client;
let seq = 0;

const POLICY: RecipientPolicy = { dataClass: "SYNTHETIC", allowlist: ["@pruebas.example.invalid", "qa@example.invalid"] };
const logs: string[] = [];
const logger: MailLogger = {
  info: (m, f) => void logs.push(`${m} ${JSON.stringify(f ?? {})}`),
  warn: (m, f) => void logs.push(`${m} ${JSON.stringify(f ?? {})}`),
};
const RECEIPT_PAYLOAD = {
  decision: "GRANTED",
  consentVersion: "v1-borrador",
  decidedAt: "2026-10-19T15:00:00Z",
  receiptRef: "rcpt-1",
  purposes: [{ purpose: "STUDY_PARTICIPATION", choice: "GRANT" }],
};

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  app = await connect(db.appUrl);
  mdb = await connect(db.mailerUrl);
  mdb2 = await connect(db.mailerUrl);
  owner = await connectAsOwner(db);
  sup = await connect(db.superDbUrl);
});
after(async () => {
  for (const c of [app, mdb, mdb2, owner, sup]) await c.end();
  await db.drop();
});

function deps(mailer: MemoryMailer, over: Partial<OutboxDeps> = {}): OutboxDeps {
  return { db: mdb, mailer, policy: POLICY, logger, backoffMs: [0, 0], ...over };
}

/** consent_app ya no inserta en el outbox (0004): las filas de prueba con payload arbitrario las siembra el dueño. */
async function enqueueRaw(input: { kind: string; invitationRef: string; dedupeKey: string; payload: Record<string, unknown> }): Promise<boolean> {
  const r = await owner.query(
    "INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (tenant_id, dedupe_key) DO NOTHING RETURNING email_id",
    [input.kind, input.invitationRef, input.dedupeKey, JSON.stringify(input.payload)],
  );
  return r.rows.length === 1;
}

/** Crea invitación (READY) vía los grants de consent_app y encola un correo. Devuelve email_id. */
async function seed(email: string, kind: "INVITATION" | "DECISION_RECEIPT" = "INVITATION"): Promise<string> {
  const n = ++seq;
  // consent_app ya no inserta en app.invitation (0003): la invitación nace por import_invitation().
  const imp = await app.query<{ invitation_ref: string }>("SELECT * FROM app.import_invitation($1, 'Valentina', $2, 'batch-mail')", [`stu-${n}-${randomBytes(3).toString("hex")}`, email]);
  const ref = imp.rows[0]!.invitation_ref;
  const payload = kind === "INVITATION" ? { consentVersion: "v1-borrador" } : RECEIPT_PAYLOAD; // el outbox NO guarda el token: lo genera el worker al enviar
  assert.equal(await enqueueRaw({ kind, invitationRef: ref, dedupeKey: `${kind}:${ref}`, payload }), true);
  return (await app.query<{ email_id: string }>("SELECT email_id FROM app.email_outbox WHERE invitation_ref = $1", [ref])).rows[0]!.email_id;
}

async function row(id: string): Promise<{ status: string; attempts: number; last_error_code: string | null; provider_message_id: string | null }> {
  return (await app.query<{ status: string; attempts: number; last_error_code: string | null; provider_message_id: string | null }>(
    "SELECT status, attempts, last_error_code, provider_message_id FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!;
}

test("data_class se lee de ops.db_catalog con el rol consent_app", async () => {
  assert.equal(await readDataClass(app), "SYNTHETIC");
});

test("allowlist: destinatario fuera -> SUPPRESSED (FAILED + motivo), dentro -> SENT", async () => {
  const mailer = new MemoryMailer();
  const inside = await seed("madre@pruebas.example.invalid");
  const outside = await seed("alguien@real.example.invalid");
  const r = await runOutboxTick(deps(mailer));
  assert.deepEqual(r, { sent: 1, retry: 0, failed: 0, suppressed: 1 });
  assert.deepEqual(mailer.sent.map((m) => m.to), ["madre@pruebas.example.invalid"]);
  const a = await row(inside);
  assert.equal(a.status, "SENT");
  assert.match(a.provider_message_id ?? "", /^<memory-/);
  const b = await row(outside);
  assert.equal(b.status, "SUPPRESSED");
  assert.equal(SUPPRESSED_STATUS, "SUPPRESSED");
  assert.equal((await app.query("SELECT 1 FROM app.invitation WHERE invitation_ref = (SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1) AND state = 'READY'", [outside])).rows.length, 1, "una invitación suprimida no arma token");
  assert.equal(b.last_error_code, "SUPPRESSED_ALLOWLIST");
});

test("REAL ignora la allowlist", async () => {
  const mailer = new MemoryMailer();
  const id = await seed("cualquiera@real.example.invalid");
  await runOutboxTick(deps(mailer, { policy: { dataClass: "REAL", allowlist: [] } }));
  assert.equal((await row(id)).status, "SENT");
});

test("recibo de decisión se renderiza con los datos del payload y de la invitación", async () => {
  const mailer = new MemoryMailer();
  await seed("qa@example.invalid", "DECISION_RECEIPT");
  await runOutboxTick(deps(mailer));
  assert.equal(mailer.sent[0]?.template, "receipt_granted");
  assert.ok(mailer.sent[0]?.text.includes("Valentina"));
});

test("3 fallos -> FAILED, sin envíos, y no vuelve a reclamarse", async () => {
  const mailer = new MemoryMailer();
  mailer.failWith = Object.assign(new Error("boom: destinatario madre@pruebas.example.invalid"), { code: "ECONNECTION" });
  const id = await seed("qa@example.invalid");
  const r1 = await runOutboxTick(deps(mailer));
  assert.equal(r1.retry, 1);
  assert.deepEqual([(await row(id)).status, (await row(id)).attempts], ["PENDING", 1]);
  await runOutboxTick(deps(mailer));
  const r3 = await runOutboxTick(deps(mailer));
  assert.equal(r3.failed, 1);
  const f = await row(id);
  assert.deepEqual([f.status, f.attempts, f.last_error_code], ["FAILED", MAX_ATTEMPTS, "ECONNECTION"]);
  const r4 = await runOutboxTick(deps(mailer));
  assert.deepEqual(r4, { sent: 0, retry: 0, failed: 0, suppressed: 0 });
  assert.equal(mailer.sent.length, 0);
  assert.ok(!logs.join("\n").includes("madre@pruebas"), "el log no debe contener correos");
});

test("fallo transitorio y luego éxito: un solo envío", async () => {
  const mailer = new MemoryMailer();
  mailer.failWith = new Error("down");
  const id = await seed("qa@example.invalid");
  await runOutboxTick(deps(mailer));
  mailer.failWith = undefined;
  await runOutboxTick(deps(mailer));
  assert.equal((await row(id)).status, "SENT");
  assert.equal(mailer.sent.length, 1);
});

test("SEC-CNS-024-V1: el reintento rota el token con motivo OUTBOX_RETRY (ledger); un reenvío con token vigente sin motivo falla; con reissueReason rota", async () => {
  const mailer = new MemoryMailer();
  await runOutboxTick(deps(new MemoryMailer(), { batchSize: 100 })); // drena filas de tests anteriores
  mailer.failWith = new Error("down");
  const id = await seed("qa@example.invalid");
  const ref = (await app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!.invitation_ref;
  await runOutboxTick(deps(mailer)); // intento 1: arma el token (READY>SENT) y el SMTP falla
  mailer.failWith = undefined;
  await runOutboxTick(deps(mailer)); // intento 2: token vigente -> rota con OUTBOX_RETRY
  assert.equal((await row(id)).status, "SENT");
  const reasons = (await owner.query<{ payload: { reason: string } }>("SELECT payload FROM integrity.audit_event WHERE aggregate_id = $1 AND event_type = 'INVITATION_LINK_REISSUED'", [ref])).rows.map((r) => r.payload.reason);
  assert.deepEqual(reasons, ["OUTBOX_RETRY"]);
  // Segundo correo de invitación (otra dedupe_key) en el primer intento, sin motivo, sobre un token vigente: no se rota ni se envía.
  assert.equal(await enqueueRaw({ kind: "INVITATION", invitationRef: ref, dedupeKey: `INVITATION-AGAIN:${ref}`, payload: { consentVersion: "v1-borrador" } }), true);
  const before = (await owner.query<{ token_hash: string }>("SELECT token_hash FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]!.token_hash;
  const sentBefore = mailer.sent.length;
  await runOutboxTick(deps(mailer));
  assert.equal(mailer.sent.length, sentBefore);
  const failed = (await app.query<{ status: string; last_error_code: string }>("SELECT status, last_error_code FROM app.email_outbox WHERE dedupe_key = $1", [`INVITATION-AGAIN:${ref}`])).rows[0]!;
  assert.deepEqual([failed.status, failed.last_error_code], ["FAILED", "TOKEN_STILL_VALID"]);
  assert.equal((await owner.query<{ token_hash: string }>("SELECT token_hash FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]!.token_hash, before);
  // Reenvío explícito del operador: el payload lleva el motivo.
  assert.equal(await enqueueRaw({ kind: "INVITATION", invitationRef: ref, dedupeKey: `INVITATION-RESEND:${ref}`, payload: { consentVersion: "v1-borrador", reissueReason: "OPERATOR_RESEND" } }), true);
  await runOutboxTick(deps(mailer));
  assert.equal(mailer.sent.length, sentBefore + 1);
  assert.notEqual((await owner.query<{ token_hash: string }>("SELECT token_hash FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]!.token_hash, before);
});

test("el pool de la app no puede ejecutar el outbox (UPDATE) ni emitir token; el del mailer lee el destinatario por columnas", async () => {
  const id = await seed("qa@example.invalid");
  const ref = (await app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!.invitation_ref;
  await assert.rejects(app.query("UPDATE app.email_outbox SET status = 'SENT' WHERE email_id = $1", [id]), /permission denied/);
  await assert.rejects(runOutboxTick(deps(new MemoryMailer(), { db: app })), /permission denied/);
  assert.equal(await readGuardianEmail(mdb, ref), "qa@example.invalid");
  assert.equal(await readGuardianEmail(mdb, "inv-no-existe"), null);
  await runOutboxTick(deps(new MemoryMailer(), { batchSize: 100 })); // drena la fila sembrada
});

test("dos workers concurrentes (SKIP LOCKED): cada correo se envía una sola vez", async () => {
  const mailer = new MemoryMailer();
  const ids: string[] = [];
  for (let i = 0; i < 12; i++) ids.push(await seed("qa@example.invalid"));
  await Promise.all([runOutboxTick(deps(mailer, { batchSize: 4 })), runOutboxTick(deps(mailer, { db: mdb2, batchSize: 4 })), runOutboxTick(deps(mailer, { batchSize: 4 })).catch(() => undefined)]);
  await runOutboxTick(deps(mailer, { batchSize: 20 }));
  await runOutboxTick(deps(mailer, { db: mdb2, batchSize: 20 }));
  assert.equal(mailer.sent.length, 12);
  assert.equal(new Set(mailer.sent.map((m) => m.text)).size, 12);
  for (const id of ids) assert.equal((await row(id)).status, "SENT");
});

test("encolado idempotente por dedupe_key", async () => {
  const id = await seed("qa@example.invalid");
  const ref = (await app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!.invitation_ref;
  assert.equal(await enqueueRaw({ kind: "INVITATION", invitationRef: ref, dedupeKey: `INVITATION:${ref}`, payload: { linkPath: "/i/otro" } }), false);
});

test("muerte entre envío y marca SENT: queda SENDING y, vencido el lease, se reenvía (duplicado aceptado y documentado)", async () => {
  const mailer = new MemoryMailer();
  await runOutboxTick(deps(new MemoryMailer())); // drena filas PENDING de tests anteriores
  const id = await seed("qa@example.invalid");
  // La BD "se cae" justo al marcar SENT.
  const flaky = { query: (async (sql: string, v?: readonly unknown[]) => (sql.includes("'SENDING'") && sql.includes("WHERE email_id") ? Promise.reject(new Error("db caída")) : mdb.query(sql, v as unknown[]))) as never };
  await runOutboxTick(deps(mailer, { db: flaky }));
  assert.equal(mailer.sent.length, 1);
  assert.equal((await row(id)).status, "SENDING");
  await runOutboxTick(deps(mailer)); // lease vigente: no se reclama
  assert.equal(mailer.sent.length, 1);
  await owner.query("UPDATE app.email_outbox SET next_attempt_at = now() - interval '1 second' WHERE email_id = $1", [id]);
  await runOutboxTick(deps(mailer));
  assert.equal(mailer.sent.length, 2, "reenvío esperado tras vencer el lease");
  assert.equal((await row(id)).status, "SENT");
});

test("camino completo con MemoryMailer: import -> encolar -> worker -> invitación SENT con enlace cuyo token coincide con el hash de la fila", async () => {
  const mailer = new MemoryMailer();
  const id = await seed("madre@pruebas.example.invalid");
  const ref = (await app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!.invitation_ref;
  // Antes de enviar no hay token en ninguna parte (ni outbox ni invitación).
  const pre = (await owner.query<{ state: string; token_hash: string | null }>("SELECT state, token_hash FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]!;
  assert.deepEqual([pre.state, pre.token_hash], ["READY", null]);
  assert.ok(!JSON.stringify((await owner.query("SELECT payload FROM app.email_outbox WHERE email_id = $1", [id])).rows).includes("/i/"));

  const r = await runOutboxTick(deps(mailer, { batchSize: 100 }));
  assert.ok(r.sent >= 1);
  const mail = mailer.sent.find((m) => m.to === "madre@pruebas.example.invalid")!;
  assert.equal(mail.template, "invitation");
  const token = /\/i\/([A-Za-z0-9_-]{43})/.exec(mail.text)?.[1];
  assert.ok(token, "el correo trae el enlace /i/<token>");
  const post = (await owner.query<{ state: string; token_hash: string; token_expires_at: Date; consent_version: string }>("SELECT state, token_hash, token_expires_at, consent_version FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]!;
  assert.equal(post.state, "SENT");
  assert.equal(post.token_hash, hashInvitationToken(token!));
  assert.equal(post.consent_version, "v1-borrador");
  const days = (post.token_expires_at.getTime() - Date.now()) / 86_400_000;
  assert.ok(days > 6.9 && days <= 7, `P-10: 7 días (fue ${days})`);
  assert.equal((await row(id)).status, "SENT");
  // El token abre la invitación (open_invitation recibe el hash) y no queda en el outbox ni en los logs.
  assert.equal((await app.query("SELECT * FROM app.open_invitation($1)", [hashInvitationToken(token!)])).rows.length, 1);
  assert.ok(!JSON.stringify((await owner.query("SELECT * FROM app.email_outbox WHERE email_id = $1", [id])).rows).includes(token!));
  assert.ok(!logs.join("\n").includes(token!));
});

test("invitación ya no armable (cancelada) -> la fila queda FAILED con INVITATION_NOT_ARMABLE y no se envía nada", async () => {
  const mailer = new MemoryMailer();
  const id = await seed("madre@pruebas.example.invalid");
  const ref = (await app.query<{ invitation_ref: string }>("SELECT invitation_ref FROM app.email_outbox WHERE email_id = $1", [id])).rows[0]!.invitation_ref;
  await owner.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE invitation_ref = $1", [ref]);
  const r = await runOutboxTick(deps(mailer, { batchSize: 100 }));
  assert.ok(r.failed >= 1);
  const f = await row(id);
  assert.deepEqual([f.status, f.last_error_code], ["FAILED", "INVITATION_NOT_ARMABLE"]);
  assert.equal(mailer.sent.filter((m) => m.to === "madre@pruebas.example.invalid").length, 0);
  assert.equal((await owner.query("SELECT token_hash FROM app.invitation WHERE invitation_ref = $1", [ref])).rows[0]?.token_hash, null);
});

test("OTP: no queda en la BD (ninguna tabla) ni en los logs", async () => {
  const CODE = "861204";
  const mailer = new MemoryMailer();
  await sendOtpNow(mailer, "qa@example.invalid", CODE);
  assert.equal(mailer.sent.length, 1);
  const tables = (await sup.query<{ s: string; t: string }>("SELECT table_schema AS s, table_name AS t FROM information_schema.tables WHERE table_schema IN ('app', 'ops', 'integrity', 'ledger_gen') AND table_type = 'BASE TABLE'")).rows;
  for (const { s, t } of tables) {
    const hit = await sup.query(`SELECT 1 FROM ${sup.escapeIdentifier(s)}.${sup.escapeIdentifier(t)} x WHERE x::text LIKE $1 LIMIT 1`, [`%${CODE}%`]);
    assert.equal(hit.rows.length, 0, `${s}.${t} contiene el OTP`);
  }
  assert.ok(!logs.join("\n").includes(CODE));
});

// ---- Mailpit (opcional local, obligatorio en CI) ------------------------------------------------------------------------------------
const MAILPIT_SMTP = process.env.MAILPIT_SMTP_URL;
const MAILPIT_API = process.env.MAILPIT_API_URL;

test("Mailpit: llegan invitación, OTP y recibo (vía SmtpMailer)", { skip: MAILPIT_SMTP && MAILPIT_API ? false : "MAILPIT_SMTP_URL/MAILPIT_API_URL no definidas: Mailpit no disponible en local; lo corre CI (servicio axllent/mailpit)" }, async () => {
  const api = MAILPIT_API!;
  await fetch(`${api}/api/v1/messages`, { method: "DELETE" });
  const smtp = new SmtpMailer({ smtpUrl: MAILPIT_SMTP!, from: "no-reply@consent.example.invalid", publicOrigin: "https://consent.example.invalid", allowPlaintextLoopback: true });
  try {
    const CODE = "246810";
    const outboxMailer = new MemoryMailer(); // no se usa: el worker usa el SmtpMailer real
    void outboxMailer;
    const rcpt = await seed("qa@example.invalid", "DECISION_RECEIPT");
    const inv = await seed("qa@example.invalid", "INVITATION");
    await runOutboxTick({ db: mdb, mailer: smtp, policy: POLICY, logger, backoffMs: [0, 0] });
    assert.equal((await row(rcpt)).status, "SENT");
    assert.equal((await row(inv)).status, "SENT");
    await sendOtpNow(smtp, "qa@example.invalid", CODE);

    const list = (await (await fetch(`${api}/api/v1/messages`)).json()) as { messages: { ID: string; Subject: string; To: { Address: string }[] }[] };
    const subjects = list.messages.map((m) => m.Subject);
    assert.equal(list.messages.length, 3, `mensajes: ${subjects.join(" | ")}`);
    assert.ok(subjects.some((s) => s.includes("Invitación")));
    assert.ok(subjects.some((s) => s.includes("código de verificación")));
    assert.ok(subjects.some((s) => s.includes("Comprobante de tu decisión")));
    assert.ok(list.messages.every((m) => m.To[0]?.Address === "qa@example.invalid"));
    const otpMsg = list.messages.find((m) => m.Subject.includes("código"))!;
    const full = (await (await fetch(`${api}/api/v1/message/${otpMsg.ID}`)).json()) as { Text: string; HTML: string };
    assert.ok(full.Text.includes(CODE) && full.HTML.includes(CODE));
  } finally {
    smtp.close();
  }
});
