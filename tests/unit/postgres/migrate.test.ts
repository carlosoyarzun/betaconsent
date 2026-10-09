// Gobierna: CA-124 (H09), decisión D2 de Carlos (2026-09-29), diseño de CA-124 §2 (runner).
// TEST-CNS-749 (sin ID en el diseño: el runner no tenía test asignado). Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadMigrations,
  migrationSetDigest,
  MigrationError,
  parseMigration,
  setRolePasswords,
} from "../../../src/infra/adapters/postgres/migrate.ts";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "db", "migrations");

test("TEST-CNS-749 parseMigration valida nombre, alcance y calcula sha256", () => {
  const m = parseMigration("0007_algo_bueno.sql", "-- scope: database\nSELECT 1;\n");
  assert.deepEqual([m.version, m.name, m.scope], ["0007", "algo_bueno", "database"]);
  assert.match(m.sha256, /^[0-9a-f]{64}$/);
  assert.notEqual(m.sha256, parseMigration("0007_algo_bueno.sql", "-- scope: database\nSELECT 2;\n").sha256);
  for (const bad of ["7_x.sql", "0007-x.sql", "0007_X.sql", "0007_x.txt"]) {
    assert.throws(() => parseMigration(bad, "-- scope: database\n"), MigrationError, bad);
  }
  assert.throws(() => parseMigration("0008_x.sql", "SELECT 1;\n"), /scope/);
  assert.throws(() => parseMigration("0008_x.sql", "-- scope: superuser\n"), /scope/);
});

test("TEST-CNS-749 las migraciones del repo: 0000, 0004, 0018, 0026 y 0028 son cluster, el resto database, versiones únicas y ordenadas", () => {
  const migrations = loadMigrations(MIGRATIONS_DIR);
  assert.equal(migrations[0]?.version, "0000");
  assert.equal(migrations[0]?.scope, "cluster");
  // Solo 0000 (roles), 0004 (outbox_claimer), 0018 (roles del roster, API-CNS-116), 0026 (integrity_owner, X8) y 0028 (security_event_owner, SEC-CNS-021) son de alcance cluster; el resto, database.
  assert.deepEqual(migrations.filter((m) => m.scope === "cluster").map((m) => m.version), ["0000", "0004", "0018", "0026", "0028"]);
  const versions = migrations.map((m) => m.version);
  assert.deepEqual(versions, [...versions].sort());
  assert.equal(new Set(versions).size, versions.length);
  assert.match(migrationSetDigest(migrations), /^[0-9a-f]{64}$/);
});

test("TEST-CNS-749 ninguna migración contiene contraseñas ni credenciales (cero secretos en el repo)", () => {
  for (const m of loadMigrations(MIGRATIONS_DIR)) {
    const sql = m.sql.replace(/--[^\n]*/g, "");
    assert.doesNotMatch(sql, /\bPASSWORD\b/i, `${m.version} fija una contraseña`);
    assert.doesNotMatch(sql, /\bSUPERUSER\b(?<!NOSUPERUSER)/, `${m.version} concede SUPERUSER`);
  }
});

test("TEST-CNS-749 setRolePasswords escapa la contraseña como literal y rechaza contraseñas cortas", async () => {
  const issued: string[] = [];
  const superuser = {
    query: async (text: string) => {
      issued.push(text);
      return { rows: [], rowCount: 0 };
    },
    escapeLiteral: (v: string) => `'${v.replace(/'/g, "''")}'`,
  };
  await setRolePasswords(superuser, { app_rw: "pa'ss-word-1", consent_migrator: "otra-clave-9" });
  assert.deepEqual(issued, ["ALTER ROLE consent_migrator PASSWORD 'otra-clave-9'", "ALTER ROLE app_rw PASSWORD 'pa''ss-word-1'"]);
  await assert.rejects(() => setRolePasswords(superuser, { worker: "corta" }), MigrationError);
});
