// Gobierna: plan v2 H1-05. Arranque real de src/server/main.ts como proceso: gates fail-closed (F-SB-02), /healthz, cierre ordenado con SIGTERM.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { migrate } from "../../../src/db/migrate.ts";
import { makeFixtureDist } from "../../helpers-http.ts";
import { BETA_ROOT, connect, createTestDb, MIGRATIONS_DIR } from "../pg-harness.ts";
import type { TestDb } from "../pg-harness.ts";

let db: TestDb;
before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
});
after(async () => db.drop());

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function run(databaseUrl: string, port: number, mailerUrl: string = db.mailerUrl) {
  const child = spawn(process.execPath, [join(BETA_ROOT, "src", "server", "main.ts")], {
    env: {
      PATH: process.env.PATH ?? "",
      CNS_ENVIRONMENT: "LOCAL",
      CNS_DATABASE_URL: databaseUrl,
      CNS_MAILER_DATABASE_URL: mailerUrl,
      CNS_SESSION_SECRET: Buffer.alloc(48, 3).toString("base64"),
      CNS_PUBLIC_ORIGIN: "http://localhost:8080",
      CNS_SMTP_URL: "smtp://127.0.0.1:1",
      CNS_SMTP_FROM: "no-reply@consent.example.invalid",
      CNS_MAIL_ALLOWLIST: "@pruebas.example.invalid",
      CNS_API_KEYS: `k1:${Buffer.alloc(32, 5).toString("base64")}`,
      PORT: String(port),
      BIND: "127.0.0.1",
      CNS_SPA_DIST_DIR: makeFixtureDist(),
    },
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (d: Buffer) => (out += d.toString()));
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
  return { child, exited, output: () => out, errors: () => err };
}

async function waitFor(cond: () => boolean, ms = 8000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timeout esperando al proceso");
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("main arranca como consent_app, responde /healthz y SIGTERM cierra con código 0", async () => {
  const port = await freePort();
  const p = run(db.appUrl, port);
  await waitFor(() => p.output().includes("servidor escuchando"));
  const r = await fetch(`http://127.0.0.1:${port}/healthz`);
  assert.equal(r.status, 200);
  p.child.kill("SIGTERM");
  assert.equal(await p.exited, 0);
  assert.ok(p.output().includes("cierre ordenado"));
});

test("F-SB-02: con el rol superusuario/migrador el proceso ABORTA antes de escuchar", async () => {
  for (const url of [db.superDbUrl, db.migratorUrl]) {
    const port = await freePort();
    const p = run(url, port);
    assert.equal(await p.exited, 1);
    assert.match(p.errors(), /ARRANQUE ABORTADO/);
    assert.ok(!p.output().includes("servidor escuchando"));
  }
});

test("falta de variables obligatorias aborta con código 1 sin imprimir valores", async () => {
  const child = spawn(process.execPath, [join(BETA_ROOT, "src", "server", "main.ts")], { env: { PATH: process.env.PATH ?? "" } });
  let err = "";
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  const code = await new Promise((r) => child.on("exit", r));
  assert.equal(code, 1);
  assert.match(err, /CNS_SESSION_SECRET/);
});
