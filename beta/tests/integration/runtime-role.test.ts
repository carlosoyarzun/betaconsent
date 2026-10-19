// Gobierna: SEC-CNS-024 F-SB-02. Gate de arranque del rol de runtime: rechaza superusuario, BYPASSRLS, session_user != current_user y membresías.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import type { Client } from "pg";

import { assertRuntimeRole, RuntimeRoleError } from "../../src/db/assert-runtime-role.ts";
import { migrate } from "../../src/db/migrate.ts";
import { connect, createTestDb, MIGRATIONS_DIR, type TestDb } from "./pg-harness.ts";

let db: TestDb;
let sup: Client;

before(async () => {
  db = await createTestDb();
  const m = await connect(db.migratorUrl);
  try {
    await migrate(m, MIGRATIONS_DIR);
  } finally {
    await m.end();
  }
  sup = await connect(db.superDbUrl);
});
after(async () => {
  await sup.end();
  await db.drop();
});

async function violations(c: Client): Promise<string> {
  try {
    await assertRuntimeRole(c);
    return "";
  } catch (e) {
    assert.ok(e instanceof RuntimeRoleError, String(e));
    return e.message;
  }
}

test("consent_app limpio pasa el gate", async () => {
  const c = await connect(db.appUrl);
  try {
    await assertRuntimeRole(c);
  } finally {
    await c.end();
  }
});

test("superusuario, migrador y dueño (SET ROLE) son rechazados", async () => {
  assert.match(await violations(sup), /superusuario/);
  const m = await connect(db.migratorUrl);
  try {
    assert.match(await violations(m), /miembro de consent_owner o consent_migrator|no es consent_app/);
    await m.query("SET ROLE consent_owner");
    const msg = await violations(m);
    assert.match(msg, /session_user distinto de current_user/);
    assert.match(msg, /no es consent_app/);
  } finally {
    await m.end();
  }
});

test("SET ROLE activo dentro de una sesión de consent_app no pasa (session_user != current_user)", async () => {
  await sup.query("GRANT consent_migrator TO consent_app");
  const c = await connect(db.appUrl);
  try {
    assert.match(await violations(c), /miembro/);
  } finally {
    await c.end();
    await sup.query("REVOKE consent_migrator FROM consent_app");
  }
});

test("BYPASSRLS, membresía en consent_owner y roles predefinidos (pg_write_all_data) son rechazados", async () => {
  try {
    await sup.query("ALTER ROLE consent_app BYPASSRLS");
    let c = await connect(db.appUrl);
    try {
      assert.match(await violations(c), /BYPASSRLS/);
    } finally {
      await c.end();
    }
    await sup.query("ALTER ROLE consent_app NOBYPASSRLS");

    await sup.query("GRANT consent_owner TO consent_app");
    c = await connect(db.appUrl);
    try {
      assert.match(await violations(c), /consent_owner o consent_migrator/);
    } finally {
      await c.end();
    }
    await sup.query("REVOKE consent_owner FROM consent_app");

    await sup.query("GRANT pg_write_all_data TO consent_app");
    c = await connect(db.appUrl);
    try {
      assert.match(await violations(c), /otro rol/);
    } finally {
      await c.end();
    }
  } finally {
    await sup.query("ALTER ROLE consent_app NOBYPASSRLS");
    await sup.query("REVOKE pg_write_all_data FROM consent_app");
    await sup.query("REVOKE consent_owner FROM consent_app");
  }
  const ok = await connect(db.appUrl);
  try {
    await assertRuntimeRole(ok);
  } finally {
    await ok.end();
  }
});
