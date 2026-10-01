// Gobierna: DEC-BR-014 rev. 8 §4 y X3 (D8 (a)): la allowlist de destinatarios de los sinks de IT0
// (src/server/modules/common/synthetic-recipient.ts, isReservedEmail) debe ser la MISMA regla que la
// funcion SQL app.is_reserved_email (db/migrations/0005_tenant_catalog.sql). Compara ambas sobre un
// corpus de casos limite; cualquier divergencia falla. TEST-CNS-955. Requiere Postgres real (harness.ts).

import assert from "node:assert/strict";

import { isReservedEmail } from "../../../src/server/modules/common/synthetic-recipient.ts";
import { pgTest } from "./harness.ts";

const CORPUS = [
  "a@example.invalid", "a@x.test", "a+b@x.y.test", "a@sub.dom.invalid", "A@EXAMPLE.COM", "a@example.org", "a@example.net",
  "a@example.com.evil.cl", "a@evil-example.com", "a@b.test.cl", "a@test", "a@invalid", "@example.invalid", "a b@example.com",
  "alguien@gmail.com", "padre@colegio.cl", "a@b", "", "a@@example.com", "a@example.invalid ", " a@example.invalid", "a@x_y.test",
  "a@-x.test", "a@example.co", "a@sub.example.com", "a@EXAMPLE.INVALID", "ñ@example.com", "a@x.TEST",
];

pgTest("TEST-CNS-955 pg: isReservedEmail (TS) coincide con app.is_reserved_email (SQL) en todo el corpus de casos limite", async (ctx) => {
  const client = await ctx.connectAs("app_rw");
  let trues = 0;
  for (const value of CORPUS) {
    const { rows } = await client.query<{ ok: boolean }>("SELECT app.is_reserved_email($1) AS ok", [value]);
    const sql = rows[0]?.ok === true;
    if (sql) trues++;
    assert.equal(isReservedEmail(value), sql, `divergencia para un caso del corpus (indice ${CORPUS.indexOf(value)})`);
  }
  assert.ok(trues >= 6 && trues < CORPUS.length, "el corpus debe tener positivos y negativos");
});
