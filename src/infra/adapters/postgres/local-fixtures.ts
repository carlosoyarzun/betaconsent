// Gobierna: CA-124 (H09), SEC-CNS-017 finding (c), DEC-BR-014 §4 (solo datos sinteticos), ADR-002 §8.
//
// Paso LOCAL-ONLY separado de las migraciones versionadas: aplica `db/fixtures/local/*.sql` (catalogo
// del tenant de dev: app.subject / app.school_participation, SELECT-only para app_rw) como
// consent_migrator -> consent_owner. Nunca corre desde el proceso web, nunca como superusuario, y se
// niega si CNS_ENVIRONMENT != LOCAL o si ops.db_catalog no es LOCAL/SYNTHETIC (el propio SQL tambien aborta).
// No registra en ops.schema_migration (idempotente por ON CONFLICT). No esta en el CLI de migraciones.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Queryable } from "./pool.ts";

export class LocalFixtureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalFixtureError";
  }
}

const FIXTURE_FILE_RE = /^\d{4}_[a-z0-9_]+\.sql$/;
const FIXTURE_SCOPE_LINE = "-- scope: local-fixture";

export function loadLocalFixtures(dir: string): { name: string; sql: string }[] {
  return readdirSync(dir)
    .filter((f) => FIXTURE_FILE_RE.test(f))
    .sort()
    .map((name) => {
      const sql = readFileSync(join(dir, name), "utf-8");
      if ((sql.split("\n", 1)[0] ?? "").trim() !== FIXTURE_SCOPE_LINE) {
        throw new LocalFixtureError(`"${name}" debe comenzar con "${FIXTURE_SCOPE_LINE}".`);
      }
      return { name, sql };
    });
}

/**
 * `migrator` es la conexion de consent_migrator. Fail-closed: entorno distinto de LOCAL, sesion
 * superusuario, o catalogo que no es LOCAL/SYNTHETIC -> LocalFixtureError y no se ejecuta nada.
 * Devuelve los nombres aplicados.
 */
export async function applyLocalFixtures(
  migrator: Queryable,
  fixtures: readonly { name: string; sql: string }[],
  options: { environment: string },
): Promise<string[]> {
  if (options.environment !== "LOCAL") {
    throw new LocalFixtureError("Las fixtures locales solo corren con CNS_ENVIRONMENT=LOCAL. Abortando (fail-closed).");
  }
  const who = await migrator.query<{ session_user: string; rolsuper: boolean }>(
    "SELECT session_user::text AS session_user, r.rolsuper FROM pg_roles r WHERE r.rolname = session_user",
  );
  const me = who.rows[0];
  if (!me || me.rolsuper || me.session_user !== "consent_migrator") {
    throw new LocalFixtureError("Las fixtures locales exigen la sesion de consent_migrator (no superusuario). Abortando.");
  }
  const applied: string[] = [];
  for (const f of fixtures) {
    await migrator.query("BEGIN");
    try {
      await migrator.query("SET LOCAL ROLE consent_owner");
      await migrator.query(f.sql);
      await migrator.query("COMMIT");
    } catch (error) {
      await migrator.query("ROLLBACK");
      throw error;
    }
    applied.push(f.name);
  }
  return applied;
}
