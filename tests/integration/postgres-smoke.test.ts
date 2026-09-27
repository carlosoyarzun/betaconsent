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
// Si no hay Postgres disponible (TEST_DATABASE_URL ausente: ni CI ni docker local), el
// test se omite en vez de fallar — H03 deja el job "preparado", no exige Postgres en
// todo entorno local (ver tests/README.md).

import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

const DATABASE_URL = process.env.TEST_DATABASE_URL;

test(
  "TEST-CNS-901 integración: el service container de PostgreSQL responde SELECT 1",
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
