// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03),
// ADR-002 (PostgreSQL), DEC-BR-014 §4 (solo datos sintéticos).
//
// Smoke test de la capa "integration": se conecta al service container de PostgreSQL
// (CI) o a una instancia local (docker compose de desarrollo) y verifica UNA sola
// cosa: que el servidor responde una consulta trivial. No es un test de esquema, RLS
// ni ledger (eso llega con el código de dominio en src/ y sus propios tests de
// integración, gobernados por ADR-002/ADR-006). Cero datos: SELECT 1, sin tablas, sin
// fixtures. Credenciales solo por variables de entorno efímeras (POSTGRES_* / TEST_*),
// nunca hardcodeadas; el job de CI las genera (ver .github/workflows/tests.yml).
//
// Si no hay Postgres disponible fuera de CI (TEST_DATABASE_URL ausente, sin docker
// local), el test se omite en vez de fallar — H03 no exige Postgres en todo entorno
// local (ver tests/README.md).
//
// Fail-closed en CI (SEC-CNS-011 P1-01): si CI o GITHUB_ACTIONS es "true" y
// TEST_DATABASE_URL falta, el test FALLA (no se omite). Un skip vacuo dejaría el check
// requerido "integration" verde sin haber probado nada (p. ej. si el step pierde la
// variable o el service container no llega a levantarse); eso contradice H03. Fuera de
// CI, el skip se mantiene para no exigir Docker en todo clon local.

import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

const DATABASE_URL = process.env.TEST_DATABASE_URL;
const IN_CI = process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true";
const TEST_NAME = "TEST-CNS-901 integración: el service container de PostgreSQL responde SELECT 1";

if (!DATABASE_URL && IN_CI) {
  test(TEST_NAME, () => {
    throw new Error(
      "TEST_DATABASE_URL no está definida en CI (CI o GITHUB_ACTIONS = \"true\"). El job " +
        "\"integration\" (.github/workflows/tests.yml) debe exponer la credencial efímera " +
        "del service container de PostgreSQL; no se permite un skip vacuo en CI " +
        "(fail-closed, SEC-CNS-011 P1-01).",
    );
  });
} else {
  test(
    TEST_NAME,
    { skip: !DATABASE_URL && "TEST_DATABASE_URL no está definida (sin Postgres disponible; ver tests/README.md)" },
    async () => {
      const client = new pg.Client({ connectionString: DATABASE_URL });
      await client.connect();
      try {
        const result = await client.query("SELECT 1 AS ok");
        assert.equal(result.rows[0]?.ok, 1);
      } finally {
        await client.end();
      }
    },
  );
}
