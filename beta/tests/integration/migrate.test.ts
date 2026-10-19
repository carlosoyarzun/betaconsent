// Gobierna: plan v2 H1-02. Runner de migraciones: en limpio, reaplicar = no-op, checksum alterado = error; gate de entorno contra el catálogo real.
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { assertEnvironment, EnvironmentMismatchError } from "../../src/db/assert-environment.ts";
import { migrate, MigrationChecksumError, sha256File } from "../../src/db/migrate.ts";
import { connect, connectAsOwner, createTestDb, failure, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let migrator: Client;

before(async () => {
  db = await createTestDb();
  migrator = await connect(db.migratorUrl);
});
after(async () => {
  await migrator.end();
  await db.drop();
});

test("migra en limpio (2 archivos) y registra checksum en ops.schema_migrations", async () => {
  const r = await migrate(migrator, MIGRATIONS_DIR);
  assert.deepEqual(r.applied, ["0001_catalog_school_ledger.sql", "0002_domain.sql"]);
  const owner = await connectAsOwner(db);
  try {
    const { rows } = await owner.query<{ filename: string; sha256: string }>("SELECT filename, sha256 FROM ops.schema_migrations ORDER BY filename");
    assert.equal(rows.length, 2);
    for (const row of rows) assert.equal(row.sha256.trim(), sha256File(readFileSync(join(MIGRATIONS_DIR, row.filename), "utf8")));
    const cat = await owner.query<{ environment: string; data_class: string }>("SELECT environment, data_class FROM ops.db_catalog");
    assert.deepEqual(cat.rows, [{ environment: "LOCAL", data_class: "SYNTHETIC" }]);
    // Todos los objetos pertenecen a consent_owner (SET ROLE en la migración).
    const foreign = await owner.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('app','integrity','ops','ledger_gen') AND pg_get_userbyid(c.relowner) <> 'consent_owner'");
    assert.equal(foreign.rows.length, 0);
  } finally {
    await owner.end();
  }
});

test("reaplicar es no-op", async () => {
  const r = await migrate(migrator, MIGRATIONS_DIR);
  assert.deepEqual(r.applied, []);
  assert.equal(r.skipped.length, 2);
});

test("checksum alterado -> MigrationChecksumError (sin aplicar nada)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "beta-mig-"));
  try {
    cpSync(MIGRATIONS_DIR, dir, { recursive: true });
    const f = join(dir, "0001_catalog_school_ledger.sql");
    writeFileSync(f, readFileSync(f, "utf8") + "\n-- editada\n");
    await assert.rejects(migrate(migrator, dir), MigrationChecksumError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("una migración que falla hace rollback completo y no se registra", async () => {
  const dir = mkdtempSync(join(tmpdir(), "beta-mig-"));
  try {
    cpSync(MIGRATIONS_DIR, dir, { recursive: true });
    writeFileSync(join(dir, "0003_rota.sql"), "CREATE TABLE app.parcial (x int);\nSELECT 1/0;\n");
    await assert.rejects(migrate(migrator, dir), /division by zero/);
    const owner = await connectAsOwner(db);
    try {
      assert.equal((await owner.query("SELECT 1 FROM pg_tables WHERE tablename = 'parcial'")).rows.length, 0);
      assert.equal((await owner.query("SELECT 1 FROM ops.schema_migrations WHERE filename = '0003_rota.sql'")).rows.length, 0);
    } finally {
      await owner.end();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("assertEnvironment contra el catálogo real: LOCAL pasa, REAL aborta", async () => {
  const app = await connect(db.appUrl);
  try {
    await assertEnvironment(app, { environment: "LOCAL" });
    await assert.rejects(assertEnvironment(app, { environment: "REAL" }), EnvironmentMismatchError);
  } finally {
    await app.end();
  }
});

test("el catálogo es inmutable: UPDATE/DELETE/TRUNCATE fallan incluso como dueño", async () => {
  const owner = await connectAsOwner(db);
  try {
    assert.match((await failure(owner, "UPDATE ops.db_catalog SET environment = 'REAL', data_class = 'REAL'")) ?? "", /inmutable|permission denied/);
    assert.match((await failure(owner, "DELETE FROM ops.db_catalog")) ?? "", /inmutable|permission denied/);
    assert.match((await failure(owner, "TRUNCATE ops.db_catalog")) ?? "", /inmutable|permission denied/);
  } finally {
    await owner.end();
  }
});
