// Gobierna: plan v2 H1-05 y H1-07. Integración HTTP con PostgreSQL temporal: app real (puertos PG como consent_app), MemoryMailer y dist de fixture.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { after, before, test } from "node:test";

import type { Pool } from "pg";

import { generateInvitationToken } from "../../../src/domain/crypto.ts";
import { createPgPorts } from "../../../src/db/adapters/index.ts";
import { migrate } from "../../../src/db/migrate.ts";
import { createPool } from "../../../src/db/pool.ts";
import { PgUnitOfWork } from "../../../src/db/unit-of-work.ts";
import { MemoryMailer } from "../../../src/mail/memory-mailer.ts";
import { enqueueEmail, runOutboxTick } from "../../../src/mail/outbox-worker.ts";
import type { RecipientPolicy } from "../../../src/mail/recipient-policy.ts";
import { createApp } from "../../../src/server/app.ts";
import { MANAGE_TOKEN_TTL_SECONDS, signManageToken } from "../../../src/server/handles.ts";
import { createJsonLogger } from "../../../src/server/log.ts";
import { createPgRecipientLookup } from "../../../src/server/recipients.ts";
import { loadSpaBundle } from "../../../src/server/spa-assets.ts";
import { Browser, lastOtp, makeFixtureDist, ORIGIN } from "../../helpers-http.ts";
import { connect, createTestDb, MIGRATIONS_DIR } from "../pg-harness.ts";
import type { TestDb } from "../pg-harness.ts";

const SECRET = Buffer.alloc(48, 7);
const EMAIL = "apoderado.sintetico@pruebas.example.invalid";
const POLICY: RecipientPolicy = { dataClass: "SYNTHETIC", allowlist: ["@pruebas.example.invalid"] };
const PURPOSES = ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"];
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

let db: TestDb;
let pool: Pool;
let server: Server;
let base: string;
const mailer = new MemoryMailer(ORIGIN);
const logLines: string[] = [];
let healthy = true;
let n = 0;
let ports: ReturnType<typeof createPgPorts>;

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  pool = createPool({ connectionString: db.appUrl });
  ports = createPgPorts(new PgUnitOfWork(pool));
  const app = createApp({
    config: { publicOrigin: ORIGIN, sessionSecret: SECRET, environment: "LOCAL" },
    ports,
    recipients: createPgRecipientLookup(pool),
    mailer,
    policy: POLICY,
    outbox: { enqueue: async (i) => void (await enqueueEmail(pool, i)) },
    spa: loadSpaBundle(makeFixtureDist()),
    logger: createJsonLogger((l) => void logLines.push(l)),
    checkHealth: async () => {
      if (!healthy) throw new Error("db caída");
      await pool.query("SELECT 1");
    },
  });
  server = createServer((req, res) => void app.handle(req, res));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
after(async () => {
  await new Promise((r) => server.close(r));
  await pool.end();
  await db.drop();
});

/** Invitación armada con token conocido (equivale a lo que hace el worker al enviar). */
async function invite(): Promise<{ token: string; invitationRef: string; studentRef: string }> {
  const studentRef = `stu-${++n}-${Math.random().toString(16).slice(2, 8)}`;
  const { invitationRef } = await ports.invitations.import({ studentRef, studentFirstName: "Valentina", guardianEmail: EMAIL, batchRef: "batch-http" });
  const { token, tokenHash } = generateInvitationToken();
  await ports.invitations.armToken({ invitationRef, tokenHash, expiresAt: new Date(Date.now() + 3600_000), consentVersion: "v1" });
  return { token, invitationRef, studentRef };
}

async function toVerified(b: Browser, token: string): Promise<void> {
  assert.equal((await b.get(`/i/${token}`)).status, 303);
  assert.equal((await b.get("/welcome")).status, 200);
  assert.equal((await b.post("/invitation/open")).status, 200);
  assert.equal((await b.post("/otp/request")).status, 202);
  assert.equal((await b.get("/verify")).status, 200);
  const r = await b.post("/otp/submit", { code: lastOtp(mailer) });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { result: "VERIFIED", scope: "DECISION" });
  assert.equal((await b.get("/decision")).status, 200);
}

async function decide(b: Browser, choice: "GRANT" | "DECLINE"): Promise<{ consentId: string; state: string; receiptRef: string }> {
  const ps = await b.get("/decision/page-state");
  assert.equal(ps.status, 200);
  assert.equal(ps.json.servedVersion.consentVersion, "v1");
  for (const s of [{ stepKind: "CONTEXT_INFORMATION_VIEWED" }, { stepKind: "CONSENT_VERSION_VIEWED" }, { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "LEGAL_GUARDIAN", authorityDeclared: true }, { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true }]) {
    assert.equal((await b.post("/decision/steps", s)).status, 200);
  }
  const r = await b.post("/decision/submit", { purposes: PURPOSES.map((purpose) => ({ purpose, choice })) });
  assert.equal(r.status, 200);
  return r.json;
}

async function tick(): Promise<void> {
  await runOutboxTick({ db: pool, mailer, policy: POLICY, logger: { info() {}, warn() {} }, backoffMs: [0, 0], manageLinkPath: (c) => `/m/${signManageToken(SECRET, c, Math.floor(Date.now() / 1000) + MANAGE_TOKEN_TTL_SECONDS)}` });
}

test("CSP exacta, cabeceras y cookie CSRF __Host- en el shell; assets por manifest", async () => {
  const { token } = await invite();
  const b = new Browser(base);
  const redirect = await b.get(`/i/${token}`);
  assert.equal(redirect.status, 303);
  assert.equal(redirect.headers.get("location"), "/welcome");
  const setCookies = redirect.headers.get("set-cookie") ?? "";
  assert.match(setCookies, /__Host-cns-i-handle=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax/);
  const page = await b.get("/welcome");
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("content-security-policy"), CSP);
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.match(page.text, /content="ready"/);
  const csrf = page.headers.getSetCookie().find((c) => c.startsWith("__Host-cns-csrf="));
  assert.ok(csrf && /; Path=\/; Secure; SameSite=Lax$/.test(csrf) && !/Domain|HttpOnly/i.test(csrf));
  const asset = await b.get("/assets/app-abc12345.js");
  assert.equal(asset.status, 200);
  assert.equal((await b.get("/assets/otro.js")).status, 404);
});

test("POST sin CSRF o con Origin ajeno => 403 sin efecto; 404 uniforme con meta uniform-error", async () => {
  const { token } = await invite();
  const b = new Browser(base);
  await b.get(`/i/${token}`);
  await b.get("/welcome");
  const noCsrf = await b.post("/invitation/open", {}, { csrf: false });
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.json.code, "CSRF_REJECTED");
  assert.equal((await b.post("/invitation/open", {}, { origin: "https://evil.example" })).status, 403);
  assert.equal((await b.post("/invitation/open", {}, { origin: null })).status, 403);
  // sin efecto: la invitación sigue SENT
  const st = await pool.query("SELECT state FROM app.invitation WHERE token_hash IS NOT NULL ORDER BY created_at DESC LIMIT 1");
  assert.equal(st.rows[0]!.state, "SENT");

  const fresh = new Browser(base);
  for (const p of ["/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm", "/r/abc"]) {
    const r = await fresh.get(p);
    assert.equal(r.status, 404, p);
    assert.match(r.text, /<meta name="cns-page-state" content="uniform-error">/, p);
  }
  assert.equal((await fresh.get("/decision/page-state")).status, 404);
  assert.deepEqual((await fresh.get("/manage/page-state")).json, { status: 404 });
});

test("F-RB-02: dos GET de un escáner + GET del apoderado => llega a /welcome y el token sigue vivo", async () => {
  const { token, invitationRef } = await invite();
  const scanner = new Browser(base);
  assert.equal((await scanner.get(`/i/${token}`)).status, 303);
  assert.equal((await scanner.get(`/i/${token}`)).status, 303);
  const r = await pool.query("SELECT state, token_consumed_at FROM app.invitation WHERE invitation_ref = $1", [invitationRef]);
  assert.equal(r.rows[0]!.state, "SENT");
  assert.equal(r.rows[0]!.token_consumed_at, null);
  const guardian = new Browser(base);
  const hop = await guardian.get(`/i/${token}`);
  assert.equal(hop.headers.get("location"), "/welcome");
  const page = await guardian.get("/welcome");
  assert.equal(page.status, 200);
  assert.match(page.text, /content="ready"/);
  assert.equal((await guardian.post("/invitation/open")).json.result, "OPENED");
});

test("camino feliz: import -> arm -> /i -> open -> otp -> decisión GRANTED => AUTHORIZED; el recibo y el enlace de gestión salen por outbox", async () => {
  const { token, studentRef } = await invite();
  const b = new Browser(base);
  await toVerified(b, token);
  const out = await decide(b, "GRANT");
  assert.equal(out.state, "GRANTED");
  assert.match(out.receiptRef, /^rcp-/);
  assert.equal((await ports.authorization.byStudentRef(studentRef)).status, "AUTHORIZED");
  // reintento de submit: misma decisión
  const again = await b.post("/decision/submit", { purposes: PURPOSES.map((purpose) => ({ purpose, choice: "GRANT" })) });
  assert.equal(again.json.consentId, out.consentId);
  const before = mailer.sent.length;
  await tick();
  const mails = mailer.sent.slice(before).map((m) => m.template);
  assert.ok(mails.includes("receipt_granted"), `plantillas: ${mails}`);
  assert.ok(mails.includes("management_link"));
  const receipt = mailer.sent.slice(before).find((m) => m.template === "receipt_granted")!;
  assert.ok(receipt.text.includes(out.receiptRef), "el recibo lleva la misma referencia que vio el titular");
});

test("DECLINED => NOT_AUTHORIZED", async () => {
  const { token, studentRef } = await invite();
  const b = new Browser(base);
  await toVerified(b, token);
  const out = await decide(b, "DECLINE");
  assert.equal(out.state, "DECLINED");
  assert.equal((await ports.authorization.byStudentRef(studentRef)).status, "NOT_AUTHORIZED");
  await tick();
  assert.ok(mailer.sent.some((m) => m.template === "receipt_declined"));
});

test("OTP: 5 fallos => OTP_LOCKED (422 según contrato) y no hay decisión; submit sin pasos => 422", async () => {
  const { token } = await invite();
  const b = new Browser(base);
  await b.get(`/i/${token}`);
  await b.get("/welcome");
  await b.post("/invitation/open");
  await b.post("/otp/request");
  const real = lastOtp(mailer);
  const wrong = real === "000000" ? "111111" : "000000";
  let last;
  for (let i = 0; i < 5; i += 1) last = await b.post("/otp/submit", { code: wrong });
  assert.equal(last!.status, 422);
  assert.equal(last!.json.code, "OTP_LOCKED");
  assert.equal(last!.json.status, 422);
  assert.equal((await b.post("/otp/submit", { code: real })).json.code, "OTP_EXPIRED_OR_CONSUMED");
  assert.equal((await b.get("/decision/page-state")).status, 404);
});

test("revocación completa por /m: OTP REVOCATION -> confirm -> NOT_AUTHORIZED; doble confirm idempotente; recibo por outbox", async () => {
  const { token, studentRef } = await invite();
  const a = new Browser(base);
  await toVerified(a, token);
  const dec = await decide(a, "GRANT");
  await tick();
  const link = mailer.sent.filter((m) => m.template === "management_link").pop()!;
  const path = /\/m\/([A-Za-z0-9._~-]+)/.exec(link.text)![0];

  const b = new Browser(base);
  const hop = await b.get(path);
  assert.equal(hop.status, 303);
  assert.equal(hop.headers.get("location"), "/manage");
  assert.equal((await b.get("/manage")).status, 200);
  assert.deepEqual((await b.get("/manage/page-state")).json, { variant: "entry" });
  assert.equal((await b.post("/manage/revocation")).json.state, "REQUESTED");
  assert.equal((await b.post("/otp/request")).status, 202);
  assert.equal((await b.get("/manage/revocation/verify")).status, 200);
  assert.equal((await b.post("/manage/revocation/confirm")).status, 404, "sin OTP verificado no se puede confirmar");
  assert.deepEqual((await b.post("/otp/submit", { code: lastOtp(mailer) })).json, { result: "VERIFIED", scope: "REVOCATION" });
  assert.equal((await b.get("/manage/revocation/confirm")).status, 200);
  assert.equal((await b.post("/manage/revocation/verify")).json.state, "VERIFIED");
  assert.equal((await ports.authorization.byStudentRef(studentRef)).status, "AUTHORIZED");
  const c1 = await b.post("/manage/revocation/confirm");
  assert.equal(c1.status, 200);
  const c2 = await b.post("/manage/revocation/confirm");
  assert.equal(c2.status, 200);
  assert.equal(c2.json.revocationRef, c1.json.revocationRef);
  assert.equal((await pool.query("SELECT count(*)::int AS c FROM app.revocation WHERE consent_id = $1", [dec.consentId])).rows[0]!.c, 1);
  assert.equal((await ports.authorization.byStudentRef(studentRef)).status, "NOT_AUTHORIZED");
  assert.deepEqual((await b.get("/manage/page-state")).json, { variant: "revoked" });
  const before = mailer.sent.length;
  await tick();
  const rec = mailer.sent.slice(before).find((m) => m.template === "receipt_revoked");
  assert.ok(rec, "recibo de revocación por outbox");
  assert.ok(rec.text.includes(c1.json.revocationRef));
});

test("withdraw antes de confirmar cancela la solicitud; /manage/recovery-link y /recovery/revoke sin efecto", async () => {
  const { token, studentRef } = await invite();
  const a = new Browser(base);
  await toVerified(a, token);
  const dec = await decide(a, "GRANT");
  const b = new Browser(base);
  await b.get(`/m/${signManageToken(SECRET, dec.consentId, Math.floor(Date.now() / 1000) + 600)}`);
  await b.get("/manage");
  await b.get("/manage/page-state");
  await b.post("/manage/revocation");
  await b.post("/otp/request");
  await b.post("/otp/submit", { code: lastOtp(mailer) });
  assert.equal((await b.post("/manage/revocation/withdraw")).json.state, "FAILED");
  assert.equal((await b.post("/manage/revocation/confirm")).status, 404);
  assert.equal((await ports.authorization.byStudentRef(studentRef)).status, "AUTHORIZED");
  assert.equal((await b.post("/manage/recovery-link")).status, 202);
  assert.equal((await b.post("/recovery/revoke", { confirmTotalWithdrawal: true })).status, 404);
  // token de gestión manipulado => uniforme
  const bad = new Browser(base);
  await bad.get(`/m/${signManageToken(SECRET, dec.consentId, Math.floor(Date.now() / 1000) + 600)}x`);
  assert.equal((await bad.get("/manage")).status, 404);
});

test("logs sin PII: ni correo, ni OTP, ni token, ni cookies, ni query", async () => {
  const { token } = await invite();
  const b = new Browser(base);
  await toVerified(b, token);
  const code = lastOtp(mailer);
  await b.get("/welcome?email=secreto%40x.cl&t=zzz");
  const all = logLines.join("\n");
  assert.ok(logLines.length > 5);
  for (const line of logLines) {
    const o = JSON.parse(line);
    assert.ok(["ts", "level", "msg", "method", "route", "status", "ms", "requestId", "code", "scope"].every(() => true));
    assert.equal(typeof o.ts, "string");
  }
  for (const secret of [EMAIL, "pruebas.example", code, token, "secreto", "__Host-", "cookie", "csrf", "set-cookie"]) {
    assert.ok(!all.toLowerCase().includes(secret.toLowerCase()), `el log contiene ${secret}`);
  }
  assert.ok(all.includes('"route":"/i/:token"'));
});

test("/healthz: 200 con BD y 503 si falla", async () => {
  const b = new Browser(base);
  assert.equal((await b.get("/healthz")).status, 200);
  healthy = false;
  try {
    assert.equal((await b.get("/healthz")).status, 503);
  } finally {
    healthy = true;
  }
});

test("cuerpo > 16 KB => 413; JSON inválido => 400; método no soportado => 405", async () => {
  const { token } = await invite();
  const b = new Browser(base);
  await b.get(`/i/${token}`);
  await b.get("/welcome");
  assert.equal((await b.post("/otp/submit", { code: "1".repeat(20_000) })).status, 413);
  const bad = await fetch(base + "/otp/submit", { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: "{no-json" });
  assert.equal(bad.status, 400);
  const put = await fetch(base + "/welcome", { method: "PUT" });
  assert.equal(put.status, 405);
});
