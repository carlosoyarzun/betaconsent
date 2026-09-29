// Gobierna: CA-124 (H09), decisión D2 de Carlos (2026-09-29), diseño de CA-124 §2 (runner).
// TEST-CNS-749 (sin ID en el diseño). Requiere Postgres real (harness.ts): skip fuera de CI sin entorno.

import assert from "node:assert/strict";
import {
  applyDatabaseScope,
  loadMigrations,
  MigrationError,
  parseMigration,
} from "../../../src/infra/adapters/postgres/migrate.ts";
import { MIGRATIONS_DIR, pgTest } from "./harness.ts";

pgTest("TEST-CNS-749 pg: re-aplicar es idempotente y ops.schema_migration registra versión y sha256", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  const migrations = loadMigrations(MIGRATIONS_DIR);
  assert.deepEqual(await applyDatabaseScope(migrator, migrations), []);

  const rows = (await migrator.query<{ version: string; sha256: string }>("SELECT version, sha256 FROM ops.schema_migration ORDER BY version")).rows;
  assert.deepEqual(
    rows,
    migrations.filter((m) => m.scope === "database").map((m) => ({ version: m.version, sha256: m.sha256 })),
  );

  // Los roles de runtime no ven ni escriben el registro de migraciones.
  const app = await ctx.connectAs("app_rw");
  await assert.rejects(() => app.query("SELECT 1 FROM ops.schema_migration"), (e: unknown) => (e as { code?: string }).code === "42501");
});

pgTest("TEST-CNS-749 pg: un checksum distinto en una migración ya aplicada falla", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  const migrations = loadMigrations(MIGRATIONS_DIR).map((m) =>
    m.version === "0001" ? parseMigration("0001_schemas_catalog.sql", `${m.sql}\n-- editada después de aplicarse\n`) : m,
  );
  await assert.rejects(() => applyDatabaseScope(migrator, migrations), MigrationError);
});

pgTest("TEST-CNS-749 pg: una migración que falla no deja cambios parciales ni se registra; la siguiente sí se aplica", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  const base = loadMigrations(MIGRATIONS_DIR);
  const bad = parseMigration("9001_bad.sql", "-- scope: database\nCREATE TABLE ops.parcial (i int);\nSELECT 1/0;\n");
  await assert.rejects(() => applyDatabaseScope(migrator, [...base, bad]), (e: unknown) => (e as { code?: string }).code === "22012");

  const admin = await ctx.connectAsSuperuser();
  assert.equal((await admin.query("SELECT 1 FROM pg_tables WHERE tablename = 'parcial'")).rows.length, 0);
  assert.equal((await admin.query("SELECT 1 FROM ops.schema_migration WHERE version = '9001'")).rows.length, 0);

  const ok = parseMigration("9002_ok.sql", "-- scope: database\nCREATE TABLE ops.probe (i int);\n");
  assert.deepEqual(await applyDatabaseScope(migrator, [...base, ok]), ["9002"]);
  assert.deepEqual(await applyDatabaseScope(migrator, [...base, ok]), []);
  // El objeto quedó a nombre de consent_owner, no del migrador ni de un superusuario.
  const owner = (await admin.query<{ o: string }>("SELECT tableowner AS o FROM pg_tables WHERE tablename = 'probe'")).rows[0];
  assert.equal(owner?.o, "consent_owner");
});

pgTest("TEST-CNS-749 pg: el alcance cluster no se ejecuta en el paso database", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  const cluster = parseMigration("9003_cluster.sql", "-- scope: cluster\nCREATE TABLE ops.no_debe_existir (i int);\n");
  assert.deepEqual(await applyDatabaseScope(migrator, [...loadMigrations(MIGRATIONS_DIR), cluster]), []);
  const admin = await ctx.connectAsSuperuser();
  assert.equal((await admin.query("SELECT 1 FROM pg_tables WHERE tablename = 'no_debe_existir'")).rows.length, 0);
});
