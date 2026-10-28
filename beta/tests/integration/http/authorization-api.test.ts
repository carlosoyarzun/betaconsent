// Gobierna: plan v2 H1-08; API-CNS-001; DEC-BR-022 rev. 2 (a)(b)(c)(e). Integración HTTP con PostgreSQL temporal: app real, cliente de referencia y mock de LectorPro.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { createPgPorts } from "../../../src/db/adapters/index.ts";
import { migrate } from "../../../src/db/migrate.ts";
import { createPools } from "../../../src/db/pool.ts";
import type { Queryable, RuntimePools } from "../../../src/db/pool.ts";
import { PgUnitOfWork } from "../../../src/db/unit-of-work.ts";
import { MemoryMailer } from "../../../src/mail/memory-mailer.ts";
import { canonicalString, signRequest } from "../../../src/server/api/authorization.ts";
import { createApp } from "../../../src/server/app.ts";
import { createJsonLogger } from "../../../src/server/log.ts";
import { createPgRecipientLookup } from "../../../src/server/recipients.ts";
import { loadSpaBundle } from "../../../src/server/spa-assets.ts";
import { createLectorProMock } from "../../helpers/lectorpro-mock.ts";
import { makeFixtureDist, ORIGIN } from "../../helpers-http.ts";
import { connect, connectAsOwner, createTestDb, MIGRATIONS_DIR } from "../pg-harness.ts";
import type { TestDb } from "../pg-harness.ts";

const K1 = { keyId: "k-old", secret: randomBytes(32) };
const K2 = { keyId: "k-new", secret: randomBytes(32) };
const PREFIX = "/api/v1/authorization-status/";
const hex = (s: string): string => createHash("sha256").update(s).digest("hex");

let db: TestDb;
let pools: RuntimePools;
let owner: Client;
const logLines: string[] = [];
const servers: Server[] = [];

async function start(keys: Array<{ keyId: string; secret: Buffer }>, opts: { apiDb?: Queryable; limit?: number } = {}): Promise<string> {
  const app = createApp({
    config: { publicOrigin: ORIGIN, sessionSecret: Buffer.alloc(48, 7), environment: "LOCAL", apiKeys: keys },
    ports: createPgPorts(new PgUnitOfWork(pools.app), { mailerUow: new PgUnitOfWork(pools.mailer) }),
    recipients: createPgRecipientLookup(pools.app),
    readGuardianEmail: async () => null,
    mailer: new MemoryMailer(ORIGIN),
    policy: { dataClass: "SYNTHETIC", allowlist: ["@pruebas.example.invalid"] },
    spa: loadSpaBundle(makeFixtureDist()),
    logger: createJsonLogger((l) => void logLines.push(l)),
    checkHealth: async () => undefined,
    apiDb: opts.apiDb ?? pools.app,
    apiRateLimitPerMinute: opts.limit,
  });
  const server = createServer((req, res) => void app.handle(req, res));
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

let base: string;
before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  pools = createPools({ appUrl: db.appUrl, mailerUrl: db.mailerUrl });
  owner = await connectAsOwner(db);
  base = await start([K1, K2]);
});
after(async () => {
  for (const s of servers) await new Promise((r) => (s.closeAllConnections(), s.close(r)));
  await owner.end();
  await pools.app.end();
  await pools.mailer.end();
  await db.drop();
});

/** GET firmado a mano (para forzar nonce repetido, timestamp o clave). */
async function call(url: string, studentRef: string, o: { key?: { keyId: string; secret: Buffer }; ts?: number; nonce?: string } = {}): Promise<{ status: number; json: any; headers: Headers }> {
  const key = o.key ?? K1;
  const path = PREFIX + encodeURIComponent(studentRef);
  const ts = String(o.ts ?? Math.floor(Date.now() / 1000));
  const nonce = o.nonce ?? randomBytes(16).toString("base64url");
  const res = await fetch(url + path, { headers: { "x-cns-key-id": key.keyId, "x-cns-timestamp": ts, "x-cns-nonce": nonce, "x-cns-signature": signRequest(key.secret, canonicalString("GET", path, ts, nonce, "")) } });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : undefined, headers: res.headers };
}

/** Invitación -> OTP -> decisión; devuelve estudiante y consentId. */
async function decided(outcome: "GRANTED" | "DECLINED"): Promise<{ student: string; consentId: string }> {
  const n = randomBytes(5).toString("hex");
  const student = `stu-${n}`;
  const inv = (await pools.app.query("SELECT * FROM app.import_invitation($1, 'Ana', $2, 'batch-001')", [student, `g-${n}@pruebas.example.invalid`])).rows[0]!.invitation_ref as string;
  const token = hex(`t-${inv}`);
  await pools.mailer.query("SELECT app.arm_invitation_token($1, $2, now() + interval '9 minutes', 'v-test')", [inv, token]);
  await pools.app.query("SELECT * FROM app.open_invitation($1)", [token]);
  const o = (await pools.mailer.query("SELECT * FROM app.issue_otp($1, 'DECISION')", [inv])).rows[0]!;
  await pools.app.query("SELECT * FROM app.verify_otp($1, $2, 'dm-test-0001')", [o.o_verification_ref, o.o_code]);
  const d = (await pools.app.query("SELECT * FROM app.record_decision($1, $2, $3, 'v-test', $4, $5)", [inv, o.o_verification_ref, outcome, hex("texto"), `idem-${n}-0001`])).rows[0]!;
  return { student, consentId: d.consent_id as string };
}
async function revoke(consentId: string): Promise<void> {
  const o = (await pools.mailer.query("SELECT * FROM app.issue_otp($1, 'REVOCATION')", [consentId])).rows[0]!;
  await pools.app.query("SELECT * FROM app.verify_otp($1, $2, 'dm-test-0001')", [o.o_verification_ref, o.o_code]);
  await pools.app.query("SELECT * FROM app.revoke_decision($1, $2, $3)", [consentId, o.o_verification_ref, `rev-${randomBytes(4).toString("hex")}-001`]);
}

test("AUTHORIZED tras GRANTED; NOT_AUTHORIZED en la lectura inmediatamente posterior a REVOKED; Cache-Control no-store", async () => {
  const { student, consentId } = await decided("GRANTED");
  const a = await call(base, student);
  assert.equal(a.status, 200);
  assert.equal(a.headers.get("cache-control"), "no-store");
  assert.equal(a.json.status, "AUTHORIZED");
  assert.equal(a.json.decisionRef, consentId);
  assert.ok(!Number.isNaN(Date.parse(a.json.asOf)));
  await revoke(consentId);
  const b = await call(base, student); // sin esperar: la siguiente lectura ya ve la revocación
  assert.deepEqual([b.status, b.json.status, b.json.decisionRef], [200, "NOT_AUTHORIZED", undefined]);
});

test("NOT_AUTHORIZED tras DECLINED, para studentRef inexistente y para referencia mal formada (misma forma, sin 404)", async () => {
  const { student } = await decided("DECLINED");
  for (const ref of [student, "stu-no-existe", "con espacios/raros"]) {
    const r = await call(base, ref);
    assert.equal(r.status, 200, ref);
    assert.equal(r.json.status, "NOT_AUTHORIZED", ref);
  }
});

test("replay del mismo nonce => 401; skew de 120 s => 401; firma de otra clave => 401; clave desconocida => 401", async () => {
  const nonce = randomBytes(16).toString("base64url");
  assert.equal((await call(base, "stu-x", { nonce })).status, 200);
  assert.equal((await call(base, "stu-x", { nonce })).status, 401);
  assert.equal((await call(base, "stu-x", { ts: Math.floor(Date.now() / 1000) - 120 })).status, 401);
  assert.equal((await call(base, "stu-x", { ts: Math.floor(Date.now() / 1000) + 120 })).status, 401);
  assert.equal((await call(base, "stu-x", { key: { keyId: K1.keyId, secret: K2.secret } })).status, 401);
  assert.equal((await call(base, "stu-x", { key: { keyId: "k-nope", secret: K1.secret } })).status, 401);
  const noHeaders = await fetch(base + PREFIX + "stu-x");
  assert.equal(noHeaders.status, 401);
  assert.equal(noHeaders.headers.get("cache-control"), "no-store");
});

test("rotación: la clave vieja sigue válida mientras esté activa y da 401 al retirarla", async () => {
  assert.equal((await call(base, "stu-x", { key: K1 })).status, 200);
  assert.equal((await call(base, "stu-x", { key: K2 })).status, 200);
  const retired = await start([K2]);
  assert.equal((await call(retired, "stu-x", { key: K1 })).status, 401);
  assert.equal((await call(retired, "stu-x", { key: K2 })).status, 200);
});

test("429 al exceder el límite por keyId; las no autenticadas no consumen cuota", async () => {
  const limited = await start([K1, K2], { limit: 3 });
  for (let i = 0; i < 5; i++) await call(limited, "stu-x", { key: { keyId: K1.keyId, secret: K2.secret } }); // firmas malas: no cuentan
  const codes: number[] = [];
  for (let i = 0; i < 5; i++) codes.push((await call(limited, "stu-x", { key: K1 })).status);
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
  assert.equal((await call(limited, "stu-x", { key: K2 })).status, 200); // otra clave, otra cuota
});

test("BD caída => 503 y el cliente (mock de LectorPro) devuelve false; con BD sana el mock refleja el estado", async () => {
  const dead: Queryable = { query: async () => { throw new Error("db caída"); } };
  const down = await start([K1], { apiDb: dead });
  assert.equal((await call(down, "stu-x")).status, 503);
  const lpDown = createLectorProMock({ baseUrl: down, keyId: K1.keyId, secret: K1.secret });
  assert.equal(await lpDown.canStartReading("stu-x"), false);
  assert.deepEqual(lpDown.events.map((e) => e.reason), ["HTTP_503"]);

  const { student, consentId } = await decided("GRANTED");
  const lp = createLectorProMock({ baseUrl: base, keyId: K2.keyId, secret: K2.secret });
  assert.equal(await lp.canStartReading(student), true);
  await revoke(consentId);
  assert.equal(await lp.canStartReading(student), false); // DEC-BR-022 (a)/(b): consulta fresca antes de cada lectura
});

test("api_access_log registra cada llamada sin PII y los logs no contienen secretos ni firmas", async () => {
  const { student } = await decided("GRANTED");
  logLines.length = 0;
  const nonce = randomBytes(16).toString("base64url");
  await call(base, student, { nonce });
  await call(base, student, { nonce }); // replay
  await call(base, "stu-desconocido-9");
  const rows = (await owner.query("SELECT key_id, student_ref, result, status_code FROM app.api_access_log ORDER BY access_id")).rows;
  const last = rows.slice(-3) as Array<{ key_id: string; student_ref: string; result: string; status_code: number }>;
  assert.deepEqual(last.map((r) => [r.key_id, r.result, r.status_code]), [[K1.keyId, "AUTHORIZED", 200], [K1.keyId, "UNAUTHENTICATED", 401], [K1.keyId, "NOT_AUTHORIZED", 200]]);
  assert.equal(last[0]!.student_ref, student);
  const cols = (await owner.query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'api_access_log'")).rows.map((r) => String(r.column_name));
  assert.ok(!cols.some((c) => /email|name|ip|rut/.test(c.replace("student_ref", "")))); // sin columnas de PII
  const logs = logLines.join("\n");
  for (const secret of [K1.secret, K2.secret]) assert.ok(!logs.includes(secret.toString("base64")) && !logs.includes(secret.toString("base64url")));
  assert.ok(!logs.includes(nonce));
  assert.ok(!logs.includes(student), "el studentRef no aparece en los logs de aplicación");
  assert.ok(logs.includes("/api/v1/authorization-status/:studentRef"));
});

test("record_api_nonce purga vencidos y consent_app no puede borrar api_nonce directamente", async () => {
  await owner.query("INSERT INTO app.api_nonce (key_id, nonce, seen_at) VALUES ('k-old', 'nonce-viejo-0001', now() - interval '1 hour')");
  assert.equal((await pools.app.query("SELECT app.record_api_nonce('k-old', 'nonce-nuevo-0001') AS f")).rows[0]!.f, true);
  assert.equal((await owner.query("SELECT 1 FROM app.api_nonce WHERE nonce = 'nonce-viejo-0001'")).rowCount, 0);
  await assert.rejects(pools.app.query("DELETE FROM app.api_nonce"), /permission denied/);
});
