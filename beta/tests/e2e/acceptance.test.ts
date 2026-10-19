// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19), criterios de aceptación; plan v2 H1-11.
// E2E de API/proceso: arranca el proceso REAL src/server/main.ts (dos pools, SmtpMailer, worker de outbox) y la CLI REAL src/cli/main.ts contra
// PostgreSQL temporal y un buzón SMTP (Mailpit en CI; receptor SMTP mínimo en local). Recorre los 8 pasos en orden: cada test depende del anterior.
// Solo datos sintéticos (@example.test). La SPA se cubre en beta-frontend; aquí el shell es el dist de fixture.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { Browser, makeFixtureDist, ORIGIN } from "../helpers-http.ts";
import { createLectorProMock } from "../helpers/lectorpro-mock.ts";
import { BETA_ROOT, connect, createTestDb, MIGRATIONS_DIR } from "../integration/pg-harness.ts";
import type { TestDb } from "../integration/pg-harness.ts";
import { openMailbox } from "./mailbox.ts";
import type { Mail, Mailbox } from "./mailbox.ts";

const PURPOSES = ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"];
const API_SECRET = Buffer.alloc(32, 5);
const BATCH = "B-E2E-0001";
const BATCH2 = "B-E2E-0002";
const SUBJ = { invitation: "Invitación", otp: "código de verificación", receipt: "Comprobante de tu decisión", revoked: "Comprobante de retiro", manage: "Enlace para gestionar" };
const S1 = { ref: "stu-ejemplo-0001", email: "apoderado1@example.test" }; // camino feliz y revocación
const S2 = { ref: "stu-ejemplo-0002", email: "apoderado2@example.test" }; // DECLINED
const S3 = { ref: "stu-ejemplo-0003", email: "apoderado3@example.test" }; // concurrencia de submit
const S4 = { ref: "stu-e2e-extra-0004", email: "apoderado4@example.test" }; // subject-mismatch

let db: TestDb;
let box: Mailbox;
let sup: Client;
let tmp: string;
let port: number;
let server: ChildProcess | undefined;
let serverOut = "";
let serverErr = "";
let serverExit: Promise<number | null>;
let cliOut = "";
const t0 = Date.now();
const tokens = new Map<string, string>(); // email -> token de invitación (solo en memoria del test)
let s1Session: Browser | undefined; // sesión verificada del apoderado 1 (pasos 3 -> 4)
const decisions = new Map<string, string>(); // studentRef -> consentId

const base = (): string => `http://127.0.0.1:${port}`;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function envFor(d: TestDb, extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "",
    CNS_ENVIRONMENT: "LOCAL",
    CNS_DATABASE_URL: d.appUrl,
    CNS_MAILER_DATABASE_URL: d.mailerUrl,
    CNS_SESSION_SECRET: Buffer.alloc(48, 9).toString("base64"),
    CNS_PUBLIC_ORIGIN: ORIGIN,
    CNS_SMTP_URL: box.smtpUrl,
    CNS_SMTP_FROM: "no-reply@consent.example.invalid",
    CNS_MAIL_ALLOWLIST: "@example.test",
    CNS_API_KEYS: `k1:${API_SECRET.toString("base64")}`,
    PORT: String(port),
    BIND: "127.0.0.1",
    ...extra,
  };
}

function cli(args: string[], d: TestDb = db): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [join(BETA_ROOT, "src", "cli", "main.ts"), ...args], { cwd: BETA_ROOT, env: envFor(d) });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (b: Buffer) => (stdout += b.toString()));
    c.stderr.on("data", (b: Buffer) => (stderr += b.toString()));
    c.on("exit", (code) => {
      cliOut += stdout + stderr;
      resolve({ code, stdout, stderr });
    });
  });
}
const cliJson = async (args: string[]): Promise<any> => {
  const r = await cli([...args, "--json"]);
  assert.equal(r.code, 0, `CLI ${args.join(" ")} salió con ${r.code}: ${r.stderr}${r.stdout}`);
  return JSON.parse(r.stdout);
};

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

async function until<T>(what: string, fn: () => Promise<T | undefined | false> | T | undefined | false, ms = 20_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v !== undefined && v !== false) return v;
    if (Date.now() - start > ms) throw new Error(`timeout (${ms} ms) esperando: ${what}`);
    await sleep(100);
  }
}

const mailsTo = async (email: string, subjectPart: string): Promise<Mail[]> => (await box.list()).filter((m) => m.to === email && m.subject.includes(subjectPart));
async function waitMailCount(email: string, subjectPart: string, count: number): Promise<Mail[]> {
  return until(`${count} correo(s) "${subjectPart}" para ${email}`, async () => {
    const l = await mailsTo(email, subjectPart);
    return l.length >= count ? l : undefined;
  });
}
const pathOf = (m: Mail, prefix: "i" | "m"): string => {
  const p = new RegExp(`/${prefix}/[A-Za-z0-9_-]{43}`).exec(m.text)?.[0];
  assert.ok(p, `el correo "${m.subject}" lleva un enlace /${prefix}/<token>`);
  return p;
};
const q = async <T extends Record<string, any>>(sql: string, args: unknown[] = []): Promise<T[]> => (await sup.query<T>(sql, args)).rows;

function startServer(): void {
  const child = spawn(process.execPath, [join(BETA_ROOT, "src", "server", "main.ts")], { env: envFor(db, { CNS_SPA_DIST_DIR: makeFixtureDist() }) });
  server = child;
  child.stdout.on("data", (d: Buffer) => (serverOut += d.toString()));
  child.stderr.on("data", (d: Buffer) => (serverErr += d.toString()));
  serverExit = new Promise((r) => child.on("exit", (code) => r(code)));
}

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), "beta-e2e-"));
  box = await openMailbox();
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  sup = await connect(db.superDbUrl);
  port = await freePort();
  startServer();
  await until("servidor escuchando", () => serverOut.includes("servidor escuchando") || (serverErr !== "" ? Promise.reject(new Error(`servidor abortó: ${serverErr}`)) : undefined), 15_000);
  console.log(`# buzón: ${box.kind}`);
});

after(async () => {
  if (server && server.exitCode === null) {
    server.kill("SIGKILL");
    await serverExit;
  }
  await sup?.end().catch(() => undefined);
  await box?.close();
  await db?.drop();
  rmSync(tmp, { recursive: true, force: true });
  console.log(`# duración total E2E: ${((Date.now() - t0) / 1000).toFixed(1)} s`);
});

/** El apoderado abre el enlace, pide el OTP y lo verifica (paso 3). */
async function guardianVerify(who: { email: string }, scope: "DECISION"): Promise<Browser> {
  const b = new Browser(base());
  const path = `/i/${tokens.get(who.email)}`;
  assert.equal((await b.get(path)).status, 303, "GET /i/<token> redirige (303)");
  assert.equal((await b.get("/welcome")).status, 200, "shell /welcome");
  assert.equal((await b.post("/invitation/open")).json?.result, "OPENED", "invitación abierta");
  const before = (await mailsTo(who.email, SUBJ.otp)).length;
  assert.equal((await b.post("/otp/request")).status, 202, "OTP solicitado");
  const otps = await waitMailCount(who.email, SUBJ.otp, before + 1);
  const code = /\b(\d{6})\b/.exec(otps.at(-1)!.text)?.[1];
  assert.ok(code, "el correo trae un código de 6 dígitos");
  const r = await b.post("/otp/submit", { code });
  assert.equal(r.status, 200, `otp/submit: ${r.text}`);
  assert.deepEqual(r.json, { result: "VERIFIED", scope });
  return b;
}

async function decide(b: Browser, choice: "GRANT" | "DECLINE"): Promise<{ consentId: string; state: string; receiptRef: string; version: string; text: string }> {
  const ps = await b.get("/decision/page-state");
  assert.equal(ps.status, 200, "decision/page-state");
  const served = ps.json.servedVersion;
  assert.ok(served.consentVersion && typeof served.text === "string", "page-state trae la versión servida");
  for (const s of [{ stepKind: "CONTEXT_INFORMATION_VIEWED" }, { stepKind: "CONSENT_VERSION_VIEWED" }, { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "LEGAL_GUARDIAN", authorityDeclared: true }, { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true }]) {
    assert.equal((await b.post("/decision/steps", s)).status, 200, `paso ${s.stepKind}`);
  }
  const r = await b.post("/decision/submit", { purposes: PURPOSES.map((purpose) => ({ purpose, choice })) });
  assert.equal(r.status, 200, `decision/submit: ${r.text}`);
  return { ...r.json, version: served.consentVersion, text: served.text };
}

const lectorpro = (): ReturnType<typeof createLectorProMock> => createLectorProMock({ baseUrl: base(), keyId: "k1", secret: API_SECRET, timeoutMs: 2000 });

// ---------------------------------------------------------------------------------------------------------------------------------------
test("paso 1: importar invitaciones (CSV) -> N nuevas; reimportar -> 0 nuevas", async () => {
  const dry = await cliJson(["import-csv", "examples/invitations.example.csv", "--batch", BATCH]);
  assert.deepEqual([dry.mode, dry.new], ["dry-run", 3], "dry-run cuenta 3 y no escribe");
  assert.equal((await q("SELECT count(*)::int AS n FROM app.invitation"))[0]!.n, 0, "dry-run no escribe");
  const a = await cliJson(["import-csv", "examples/invitations.example.csv", "--batch", BATCH, "--apply"]);
  assert.deepEqual([a.total, a.new, a.existing], [3, 3, 0], "apply: 3 nuevas");
  const b = await cliJson(["import-csv", "examples/invitations.example.csv", "--batch", BATCH, "--apply"]);
  assert.deepEqual([b.new, b.existing], [0, 3], "reimport: 0 nuevas");
  const extra = join(tmp, "extra.csv");
  writeFileSync(extra, `student_ref,student_first_name,guardian_email\n${S4.ref},Dario,${S4.email}\n`);
  const c = await cliJson(["import-csv", extra, "--batch", BATCH2, "--apply"]);
  assert.equal(c.new, 1, "segundo lote (subject-mismatch): 1 nueva");
  assert.equal((await q("SELECT count(*)::int AS n FROM app.invitation"))[0]!.n, 4);
});

test("paso 2: send-invitations --run-worker-once -> el buzón recibe N correos; el token no queda en outbox ni en logs", async () => {
  for (const batch of [BATCH, BATCH2]) {
    const s = await cliJson(["send-invitations", "--batch", batch, "--run-worker-once"]);
    assert.ok(s.enqueued + s.already_queued >= 1, `lote ${batch} encolado`);
  }
  for (const who of [S1, S2, S3, S4]) {
    const [mail] = await waitMailCount(who.email, SUBJ.invitation, 1);
    tokens.set(who.email, pathOf(mail!, "i").slice("/i/".length));
  }
  const n = (await box.list()).filter((m) => m.subject.includes(SUBJ.invitation)).length;
  assert.equal(n, 4, "exactamente 4 correos de invitación (1 por apoderado, sin duplicados)");
  const sent = await q("SELECT count(*)::int AS n FROM app.email_outbox WHERE kind = 'INVITATION' AND status = 'SENT'");
  assert.equal(sent[0]!.n, 4, "las 4 filas del outbox quedaron SENT");
  const outbox = (await q("SELECT payload::text AS p, coalesce(last_error_code,'') AS e FROM app.email_outbox")).map((r) => r.p + r.e).join("\n");
  for (const [email, tok] of tokens) {
    assert.ok(!outbox.includes(tok), `el token (${email}) no está en email_outbox`);
    assert.ok(!(serverOut + serverErr).includes(tok), `el token (${email}) no está en los logs del servidor`);
    assert.ok(!cliOut.includes(tok), `el token (${email}) no está en la salida de la CLI`);
  }
  const ledger = (await q("SELECT payload::text AS p FROM integrity.audit_event")).map((r) => r.p).join("\n");
  for (const tok of tokens.values()) assert.ok(!ledger.includes(tok), "el token no está en el ledger");
});

test("paso 3: escáner (GET x2) + apoderado -> shell; open -> OTP del correo -> VERIFIED", async () => {
  const path = `/i/${tokens.get(S1.email)}`;
  const scanner = new Browser(base());
  assert.equal((await scanner.get(path)).status, 303, "escáner #1");
  assert.equal((await scanner.get(path)).status, 303, "escáner #2");
  const st = await q("SELECT state, token_consumed_at FROM app.invitation WHERE student_ref = $1", [S1.ref]);
  assert.equal(st[0]!.state, "SENT", "los GET del escáner no consumen la invitación");
  assert.equal(st[0]!.token_consumed_at, null);
  const guardian = new Browser(base());
  const hop = await guardian.get(path);
  assert.equal(hop.status, 303);
  assert.equal(hop.headers.get("location"), "/welcome");
  const shell = await guardian.get("/welcome");
  assert.equal(shell.status, 200);
  assert.match(shell.text, /content="ready"/, "shell servido");
  assert.equal((await guardian.post("/invitation/open")).json.result, "OPENED");
  const otpBefore = (await mailsTo(S1.email, SUBJ.otp)).length;
  assert.equal((await guardian.post("/otp/request")).status, 202);
  const otp = (await waitMailCount(S1.email, SUBJ.otp, otpBefore + 1)).at(-1)!;
  const code = /\b(\d{6})\b/.exec(otp.text)?.[1];
  assert.ok(code, "OTP de 6 dígitos en el correo");
  const bad = await guardian.post("/otp/submit", { code: code === "000000" ? "111111" : "000000" });
  assert.notEqual(bad.status, 200, "un código erróneo no verifica");
  const ok = await guardian.post("/otp/submit", { code });
  assert.deepEqual(ok.json, { result: "VERIFIED", scope: "DECISION" });
  // La sesión verificada se reutiliza en el paso 4.
  s1Session = guardian;
});

test("paso 4: decisión GRANTED con la versión servida -> recibo en el buzón; authorization_status = AUTHORIZED por CLI", async () => {
  const b = s1Session!;
  const out = await decide(b, "GRANT");
  assert.equal(out.state, "GRANTED");
  assert.match(out.receiptRef, /^rcp-/);
  decisions.set(S1.ref, out.consentId);
  const row = (await q("SELECT consent_version, consent_text_sha256, state FROM app.consent_decision WHERE consent_id = $1", [out.consentId]))[0]!;
  assert.equal(row.consent_version, out.version, "la decisión guarda la versión servida");
  assert.equal(row.consent_text_sha256, createHash("sha256").update(out.text).digest("hex"), "y el SHA-256 del texto exacto que se sirvió");
  const receipt = (await waitMailCount(S1.email, SUBJ.receipt, 1))[0]!;
  assert.ok(receipt.text.includes(out.receiptRef), "el recibo lleva la referencia que vio el titular");
  assert.ok(receipt.text.includes(out.version), "y la versión del consentimiento");
  await waitMailCount(S1.email, SUBJ.manage, 1);
  const st = await cliJson(["status", "--student", S1.ref]);
  assert.equal(st.student.authorization_status, "AUTHORIZED", "CLI status --student");
});

test("paso 5: mock de LectorPro (HMAC real) -> canStartReading true; replay del nonce -> 401 -> false", async () => {
  const lp = lectorpro();
  assert.equal(await lp.canStartReading(S1.ref), true, "AUTHORIZED => puede iniciar lectura");
  assert.equal(await lp.canStartReading(S2.ref), false, "sin decisión => no puede");
  // Replay: se captura una petición firmada y se reenvía idéntica.
  let captured: { url: string; headers: Record<string, string> } | undefined;
  const recording = createLectorProMock({
    baseUrl: base(), keyId: "k1", secret: API_SECRET,
    fetchImpl: (async (url: string, init: RequestInit) => {
      captured = { url, headers: init.headers as Record<string, string> };
      return fetch(url, init);
    }) as typeof fetch,
  });
  assert.equal(await recording.canStartReading(S1.ref), true);
  assert.ok(captured);
  const replay = await fetch(captured.url, { headers: captured.headers });
  assert.equal(replay.status, 401, "mismo nonce => 401");
  const replayer = createLectorProMock({ baseUrl: base(), keyId: "k1", secret: API_SECRET, fetchImpl: (async (url: string) => fetch(url, { headers: captured!.headers })) as typeof fetch });
  assert.equal(await replayer.canStartReading(S1.ref), false, "el cliente trata el 401 como fail-closed");
  assert.ok(replayer.events.some((e) => e.reason === "HTTP_401"));
});

test("paso 6: enlace de gestión del correo -> revocación con OTP -> recibo; confirm repetido y x10 en paralelo -> una sola revocación", async () => {
  const mpath = pathOf((await waitMailCount(S1.email, SUBJ.manage, 1)).at(-1)!, "m");
  const mToken = mpath.slice("/m/".length);
  const outbox = (await q("SELECT payload::text AS p FROM app.email_outbox")).map((r) => r.p).join("\n");
  assert.ok(!outbox.includes(mToken) && !(serverOut + serverErr).includes(mToken), "el token de gestión no está en outbox ni en logs");
  const b = new Browser(base());
  const hop = await b.get(mpath);
  assert.equal(hop.status, 303);
  assert.equal(hop.headers.get("location"), "/manage");
  assert.equal((await b.get("/manage")).status, 200);
  assert.deepEqual((await b.get("/manage/page-state")).json, { variant: "entry" });
  assert.equal((await b.post("/manage/revocation")).json.state, "REQUESTED");
  const before = (await mailsTo(S1.email, SUBJ.otp)).length;
  assert.equal((await b.post("/otp/request")).status, 202);
  const code = /\b(\d{6})\b/.exec((await waitMailCount(S1.email, SUBJ.otp, before + 1)).at(-1)!.text)?.[1];
  assert.ok(code);
  assert.equal((await b.post("/manage/revocation/confirm")).status, 404, "sin OTP verificado no se confirma");
  assert.deepEqual((await b.post("/otp/submit", { code })).json, { result: "VERIFIED", scope: "REVOCATION" });
  assert.equal((await b.post("/manage/revocation/verify")).json.state, "VERIFIED");
  assert.equal((await b.get("/manage/revocation/confirm")).status, 200);
  assert.equal((await lectorpro().canStartReading(S1.ref)), true, "antes del confirm sigue AUTORIZADO");

  const results = await Promise.all(Array.from({ length: 10 }, () => b.post("/manage/revocation/confirm")));
  for (const r of results) assert.equal(r.status, 200, `confirm paralelo: ${r.text}`);
  const refs = new Set(results.map((r) => r.json.revocationRef));
  assert.equal(refs.size, 1, "los 10 confirm devuelven la misma revocationRef");
  const again = await b.post("/manage/revocation/confirm");
  assert.equal(again.json.revocationRef, [...refs][0], "confirm repetido: mismo resultado");
  const consentId = decisions.get(S1.ref)!;
  assert.equal((await q("SELECT count(*)::int AS n FROM app.revocation WHERE consent_id = $1", [consentId]))[0]!.n, 1, "una sola fila en app.revocation");
  assert.equal((await q("SELECT count(*)::int AS n FROM integrity.audit_event WHERE aggregate_id = $1 AND event_type LIKE '%REVOKED%'", [consentId]))[0]!.n >= 1, true);
  const rec = (await waitMailCount(S1.email, SUBJ.revoked, 1))[0]!;
  assert.ok(rec.text.includes([...refs][0] as string), "recibo de revocación con la referencia");
  assert.equal((await mailsTo(S1.email, SUBJ.revoked)).length, 1, "un solo recibo de revocación");
});

test("paso 6b: en la PRIMERA consulta tras el commit LectorPro ya no permite lecturas nuevas", async () => {
  assert.equal(await lectorpro().canStartReading(S1.ref), false, "primera consulta tras revocar => false");
  const st = await cliJson(["status", "--student", S1.ref]);
  assert.equal(st.student.authorization_status, "NOT_AUTHORIZED");
});

test("extra: segundo apoderado DECLINED -> NOT_AUTHORIZED y canStartReading false", async () => {
  const b = await guardianVerify(S2, "DECISION");
  const out = await decide(b, "DECLINE");
  assert.equal(out.state, "DECLINED");
  assert.equal(await lectorpro().canStartReading(S2.ref), false);
  assert.equal((await cliJson(["status", "--student", S2.ref])).student.authorization_status, "NOT_AUTHORIZED");
  const rec = (await waitMailCount(S2.email, SUBJ.receipt, 1))[0]!;
  assert.ok(rec.text.includes(out.receiptRef));
});

test("extra: 20 POST /decision/submit paralelos con la misma sesión -> 1 decisión y 1 evento", async () => {
  const b = await guardianVerify(S3, "DECISION");
  const ps = await b.get("/decision/page-state");
  assert.equal(ps.status, 200);
  for (const s of [{ stepKind: "CONTEXT_INFORMATION_VIEWED" }, { stepKind: "CONSENT_VERSION_VIEWED" }, { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "LEGAL_GUARDIAN", authorityDeclared: true }, { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true }]) {
    assert.equal((await b.post("/decision/steps", s)).status, 200);
  }
  const body = { purposes: PURPOSES.map((purpose) => ({ purpose, choice: "GRANT" })) };
  const rs = await Promise.all(Array.from({ length: 20 }, () => b.post("/decision/submit", body)));
  for (const r of rs) assert.equal(r.status, 200, `submit paralelo: ${r.text}`);
  const ids = new Set(rs.map((r) => r.json.consentId));
  assert.equal(ids.size, 1, "los 20 submit devuelven el mismo consentId");
  const consentId = [...ids][0] as string;
  decisions.set(S3.ref, consentId);
  assert.equal((await q("SELECT count(*)::int AS n FROM app.consent_decision WHERE student_ref = $1", [S3.ref]))[0]!.n, 1, "1 decisión");
  assert.equal((await q("SELECT count(*)::int AS n FROM integrity.audit_event WHERE aggregate_id = $1 AND event_type = 'CONSENT_GRANTED'", [consentId]))[0]!.n, 1, "1 evento CONSENT_GRANTED");
  assert.equal(await lectorpro().canStartReading(S3.ref), true);
  assert.equal((await waitMailCount(S3.email, SUBJ.receipt, 1)).length, 1, "un solo recibo");
});

test("extra: subject-mismatch cancela la invitación y no queda autorización", async () => {
  const b = await guardianVerify(S4, "DECISION");
  const r = await b.post("/decision/subject-mismatch");
  assert.deepEqual(r.json, { result: "INVITATION_CANCELLED" });
  assert.equal((await q("SELECT state FROM app.invitation WHERE student_ref = $1", [S4.ref]))[0]!.state, "CANCELLED");
  const submit = await b.post("/decision/submit", { purposes: PURPOSES.map((purpose) => ({ purpose, choice: "GRANT" })) });
  assert.equal(submit.status, 404, "la sesión se descartó");
  assert.equal((await q("SELECT count(*)::int AS n FROM app.consent_decision WHERE student_ref = $1", [S4.ref]))[0]!.n, 0);
  assert.equal(await lectorpro().canStartReading(S4.ref), false);
});

test("paso 7: con el servidor apagado LectorPro no permite lecturas (fail-closed)", async () => {
  const lp = lectorpro();
  assert.equal(await lp.canStartReading(S3.ref), true, "antes de apagar, S3 autorizado");
  server!.kill("SIGTERM");
  assert.equal(await serverExit, 0, "cierre ordenado");
  assert.equal(await lp.canStartReading(S3.ref), false, "servidor apagado => false");
  assert.ok(lp.events.some((e) => e.event === "authorization_denied_fail_closed" && e.reason === "NETWORK_ERROR"), "el cliente registra NETWORK_ERROR");
  const all = serverOut + serverErr;
  for (const secret of [S1.email, S2.email, "__Host-", ...tokens.values()]) assert.ok(!all.includes(secret), "logs del servidor sin PII ni tokens");
});

test("paso 8: verify-ledger OK; pg_dump + pg_restore en base nueva -> misma cabeza; fila alterada -> exit 1", async () => {
  const v = await cli(["verify-ledger", "--json"]);
  assert.equal(v.code, 0, `verify-ledger: ${v.stdout}${v.stderr}`);
  const head = JSON.parse(v.stdout);
  assert.equal(head.ok, true);
  assert.ok(head.count >= 20, `el ledger tiene eventos (${head.count})`);

  const file = join(tmp, "consent.dump");
  const dump = spawnSync(process.env.PG_DUMP ?? "pg_dump", ["-Fc", "-f", file, db.superDbUrl], { encoding: "utf8" });
  assert.equal(dump.status, 0, `pg_dump: ${dump.stderr || dump.error?.message}`);
  const dst = await createTestDb(); // nota: bootstrap-roles.sql rota las contraseñas de los roles del clúster; la base origen ya no se usa
  try {
    const restore = spawnSync(process.env.PG_RESTORE ?? "pg_restore", ["--exit-on-error", "-d", dst.superDbUrl, file], { encoding: "utf8" });
    assert.equal(restore.status, 0, `pg_restore: ${restore.stderr || restore.error?.message}`);
    const v2 = await cli(["verify-ledger", "--json"], dst);
    assert.equal(v2.code, 0, `verify-ledger en la copia: ${v2.stdout}${v2.stderr}`);
    const head2 = JSON.parse(v2.stdout);
    assert.deepEqual(head2.head, head.head, "misma cabeza (chain_seq y event_hash) tras restaurar");
    assert.equal(head2.count, head.count);

    // Alteración en la copia (superusuario; trigger de inmutabilidad y CHECK de occurred_at retirados solo en la copia).
    const c = await connect(dst.superDbUrl);
    try {
      await c.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER audit_event_no_update_delete");
      await c.query("ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_occurred_at_is_now"); // solo en la copia: el CHECK impide reescribir la fila
      const hit = await c.query("UPDATE integrity.audit_event SET payload = jsonb_set(payload, '{tampered}', 'true') WHERE chain_seq = (SELECT min(chain_seq) + 3 FROM integrity.audit_event)");
      assert.equal(hit.rowCount, 1, "se alteró exactamente una fila de la copia");
    } finally {
      await c.end();
    }
    const v3 = await cli(["verify-ledger", "--json"], dst);
    assert.equal(v3.code, 1, "ledger alterado => exit 1");
    assert.equal(JSON.parse(v3.stdout).ok, false);
  } finally {
    await dst.drop();
  }
});
