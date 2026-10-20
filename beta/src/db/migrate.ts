// Gobierna: plan v2 H1-02 (runner simple de migraciones: tabla ops.schema_migrations, orden lexicográfico,
// SET ROLE consent_owner, checksum SHA-256, reaplicar = no-op). Regla de Carlos: una migración aplicada nunca se edita.
// Se conecta como consent_migrator (LOGIN NOINHERIT, miembro de consent_owner con SET); cada archivo corre en UNA tx
// con SET LOCAL ROLE consent_owner, de modo que todos los objetos quedan con un único dueño NOLOGIN.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { Queryable } from "./assert-environment.ts";

export class MigrationChecksumError extends Error {
  constructor(filename: string) {
    super(`La migración ${filename} ya fue aplicada con otro contenido (checksum distinto). Las migraciones aplicadas no se editan: crear una nueva.`);
    this.name = "MigrationChecksumError";
  }
}

export interface MigrateResult {
  readonly applied: readonly string[];
  readonly skipped: readonly string[];
}

const FILE_RE = /^\d{4}_[a-z0-9_]+\.sql$/;
/** Clave del advisory lock de sesión que serializa dos runners concurrentes. */
const LOCK_KEY = "consent-beta:migrate";

export function sha256File(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export async function migrate(client: Queryable, migrationsDir: string): Promise<MigrateResult> {
  const files = readdirSync(migrationsDir).filter((f) => FILE_RE.test(f)).sort();
  await client.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [LOCK_KEY]);
  try {
    let rows: Array<{ filename: string; sha256: string }>;
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL ROLE consent_owner");
      await client.query("CREATE SCHEMA IF NOT EXISTS ops AUTHORIZATION consent_owner");
      await client.query(
        `CREATE TABLE IF NOT EXISTS ops.schema_migrations (
           filename   text        PRIMARY KEY,
           sha256     char(64)    NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
           applied_at timestamptz NOT NULL DEFAULT now()
         )`,
      );
      rows = (await client.query<{ filename: string; sha256: string }>("SELECT filename, sha256 FROM ops.schema_migrations")).rows;
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    }

    const done = new Map(rows.map((r) => [r.filename, r.sha256.trim()]));
    for (const name of done.keys()) {
      if (!files.includes(name)) throw new Error(`La migración aplicada ${name} no existe en ${migrationsDir}.`);
    }

    const applied: string[] = [];
    const skipped: string[] = [];
    for (const filename of files) {
      const sql = readFileSync(join(migrationsDir, filename), "utf8");
      const sha = sha256File(sql);
      const prev = done.get(filename);
      if (prev !== undefined) {
        if (prev !== sha) throw new MigrationChecksumError(filename);
        skipped.push(filename);
        continue;
      }
      await client.query("BEGIN");
      try {
        await client.query("SET LOCAL ROLE consent_owner");
        await client.query(sql);
        await client.query("INSERT INTO ops.schema_migrations (filename, sha256) VALUES ($1, $2)", [filename, sha]);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      }
      applied.push(filename);
    }
    return { applied, skipped };
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [LOCK_KEY]);
  }
}
