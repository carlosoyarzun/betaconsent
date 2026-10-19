// Gobierna: SEC-CNS-024 F-SB-06. Un backup del ledger debe poder restaurarse: pg_dump -Fc + pg_restore en una base nueva devuelve TODAS las filas y verifyLedger OK.
// Los CHECK con now()/catálogo van NOT VALID (como 0013:87 del repo anterior); si fueran VALID, pg_restore rechazaría las filas históricas.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { migrate } from "../../src/db/migrate.ts";
import { readChain, verifyLedger } from "../../src/ledger/read-chain.ts";
import { connect, createTestDb, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let src: TestDb;
let dst: TestDb;
let srcSuper: Client;
let dstSuper: Client;
let app: Client;
let mailer: Client;
let dir: string;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "beta-dump-"));
  src = await createTestDb();
  const m = await connect(src.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  srcSuper = await connect(src.superDbUrl);
  app = await connect(src.appUrl);
  mailer = await connect(src.mailerUrl);
});
after(async () => {
  for (const c of [srcSuper, dstSuper, app, mailer]) if (c) await c.end();
  await src.drop();
  if (dst) await dst.drop();
  rmSync(dir, { recursive: true, force: true });
});

test("pg_dump -Fc + pg_restore en una base nueva restaura todas las filas del ledger y verifyLedger OK", async () => {
  // Historia real: invitación -> OTP -> decisión GRANTED (varios eventos, varios agregados).
  const student = `stu-${randomBytes(4).toString("hex")}`;
  const inv = (await app.query<{ invitation_ref: string }>("SELECT * FROM app.import_invitation($1, 'Ana', 'g@example.test', 'batch-001')", [student])).rows[0]!.invitation_ref;
  const tok = createHash("sha256").update(inv).digest("hex");
  await mailer.query("SELECT app.arm_invitation_token($1, $2, now() + interval '1 day', 'v-test')", [inv, tok]);
  await app.query("SELECT * FROM app.open_invitation($1)", [tok]);
  const o = (await mailer.query<{ o_verification_ref: string; o_code: string }>("SELECT * FROM app.issue_otp($1, 'DECISION')", [inv])).rows[0]!;
  await app.query("SELECT * FROM app.verify_otp($1, $2, 'dm-backup-0001')", [o.o_verification_ref, o.o_code]);
  await app.query("SELECT * FROM app.record_decision($1, $2, 'GRANTED', 'v-test', $3, 'idem-backup-01', '[\"STUDY_PARTICIPATION\"]'::jsonb)", [inv, o.o_verification_ref, "a".repeat(64)]);

  const before = await readChain(srcSuper);
  assert.ok(before.length >= 6, `esperaba una historia con varios eventos (hay ${before.length})`);
  assert.equal((await verifyLedger(srcSuper)).ok, true);

  const file = join(dir, "consent.dump");
  const dump = spawnSync(process.env.PG_DUMP ?? "pg_dump", ["-Fc", "-f", file, src.superDbUrl], { encoding: "utf8" });
  assert.equal(dump.status, 0, dump.stderr || dump.error?.message);

  dst = await createTestDb(); // base nueva y vacía (mismos roles del clúster)
  const restore = spawnSync(process.env.PG_RESTORE ?? "pg_restore", ["--exit-on-error", "-d", dst.superDbUrl, file], { encoding: "utf8" });
  assert.equal(restore.status, 0, restore.stderr || restore.error?.message);

  dstSuper = await connect(dst.superDbUrl);
  const after_ = await readChain(dstSuper);
  assert.equal(after_.length, before.length, "el restore debe devolver TODAS las filas del ledger");
  const rep = await verifyLedger(dstSuper);
  assert.equal(rep.ok, true, JSON.stringify(rep));
  assert.equal(after_.at(-1)?.eventHash, before.at(-1)?.eventHash);
  // Los dos CHECK siguen controlando cada INSERT nuevo, aunque no estén validados sobre lo histórico.
  const cons = await dstSuper.query<{ conname: string; convalidated: boolean }>(
    "SELECT conname, convalidated FROM pg_constraint WHERE conname IN ('audit_event_occurred_at_is_now', 'audit_event_environment_is_catalog') ORDER BY conname",
  );
  assert.deepEqual(cons.rows, [
    { conname: "audit_event_environment_is_catalog", convalidated: false },
    { conname: "audit_event_occurred_at_is_now", convalidated: false },
  ]);
});
