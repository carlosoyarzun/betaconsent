// Gobierna: X8 decision 3 (Carlos, 2026-10-06), F-X8-11, DEC-BR-014 §6, db/migrations/0026 y 0027, ADR-002 §2.
// TEST-CNS-1230: el migrador asumiendo consent_owner NO puede alterar ni escribir el ledger (42501). ADR-010 rev. 6 PR-7d (C-1, Carlos 2026-10-16): la membresia de integrity_owner es SOLO
// {ddl_breakglass: INHERIT false, SET true} en AMBOS modos (consent_owner y consent_migrator ya no pueden hacer SET ROLE integrity_owner: 42501); invierte la version de X8/PR-2.
// TEST-CNS-1231: ownership del ledger y la cadena/append/idempotencia de app_rw siguen funcionando.
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { checkRoleMemberships, EXPECTED_MEMBERSHIPS } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { enableLedgerMechanicsAppend, pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;

pgTest("TEST-CNS-1230 pg: consent_owner (migrador) no puede alterar ni escribir el ledger NI asumir integrity_owner (42501); la unica membresia de integrity_owner es ddl_breakglass (ambos modos)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const members = (await admin.query<{ member: string; inherit_option: boolean; set_option: boolean }>(
    `SELECT m.rolname AS member, a.inherit_option, a.set_option
       FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member
      WHERE r.rolname = 'integrity_owner'`,
  )).rows;
  // ADR-010 PR-2 (INV-DBR-03): la membresia se afirma contra la lista exacta del modo (role-membership.ts), no contra una constante local.
  // PR-7d: integrity_owner solo lo asume ddl_breakglass (ceremonia), en los dos modos; consent_owner ya no (REVOKE en 0086).
  for (const mode of ["IT0B_SYNTHETIC", "REAL_DATA"] as const) {
    const expectedMembers = EXPECTED_MEMBERSHIPS[mode].filter((e) => e.role === "integrity_owner")
      .map((e) => ({ member: e.member, inherit_option: e.inherit, set_option: e.set }));
    assert.deepEqual(expectedMembers, [{ member: "ddl_breakglass", inherit_option: false, set_option: true }], mode);
  }
  assert.deepEqual(members, [{ member: "ddl_breakglass", inherit_option: false, set_option: true }]);
  // El migrador no puede asumir integrity_owner, ni directo ni via consent_owner (la membresia ya no existe: 42501).
  for (const via of [null, "consent_owner"]) {
    const mig = await ctx.connectAs("consent_migrator");
    if (via !== null) await mig.query(`SET ROLE ${via}`);
    await assert.rejects(() => mig.query("SET ROLE integrity_owner"), (e: unknown) => codeOf(e) === "42501", `SET ROLE integrity_owner (via=${via ?? "migrador"})`);
  }
  assert.deepEqual(await checkRoleMemberships(admin, "IT0B_SYNTHETIC"), [], "la membresia de todos los roles gobernados coincide con el modo");

  const migrator = await ctx.connectAs("consent_migrator");
  const statements = [
    "DROP TABLE integrity.audit_event",
    "ALTER TABLE integrity.audit_event DISABLE TRIGGER audit_event_no_update_delete",
    "ALTER TABLE integrity.audit_event DISABLE TRIGGER ALL",
    "ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_pkey",
    "ALTER TABLE integrity.audit_event NO FORCE ROW LEVEL SECURITY",
    "DROP FUNCTION integrity.audit_event_immutable() CASCADE",
    "ALTER TABLE integrity.audit_event OWNER TO consent_owner",
    "CREATE TABLE integrity.intruder (x int)",
    "SELECT count(*) FROM integrity.audit_event",
    "INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload) VALUES (gen_random_uuid(), 'A', 'a', 1, 'E', 'HUMAN', '{}'::jsonb)",
  ];
  for (const sql of statements) {
    await migrator.query("BEGIN");
    await migrator.query("SET LOCAL ROLE consent_owner");
    await assert.rejects(() => migrator.query(sql), (e: unknown) => codeOf(e) === "42501", sql);
    await migrator.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1231 pg: el ledger pertenece a integrity_owner, sin CREATE temporal y con append de app_rw, cadena e idempotencia intactos", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const owners = (await admin.query<{ what: string; owner: string }>(
    `SELECT 'schema' AS what, pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = 'integrity'
      UNION ALL SELECT 'table', pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'integrity.audit_event'::regclass
      UNION ALL SELECT 'function', pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'integrity.audit_event_immutable()'::regprocedure`,
  )).rows;
  assert.equal(owners.length, 3);
  for (const o of owners) assert.equal(o.owner, "integrity_owner", o.what);
  // Supuesto de 0027: consent_owner es dueno de la base (si no, el GRANT CREATE ON DATABASE aborta la migracion).
  const dba = (await admin.query<{ owner: string }>("SELECT pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname = current_database()")).rows[0];
  assert.equal(dba?.owner, "consent_owner");
  // La revocacion del CREATE temporal en la base la afirma 0027 dentro de su tx (la base de prueba nace con
  // CREATE DATABASE ... TEMPLATE, que no copia datacl, asi que verificarlo aqui no probaria nada).
  const wrong = (await admin.query<{ n: number }>(
    `SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'integrity' AND pg_get_userbyid(c.relowner) <> 'integrity_owner')
          + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'integrity' AND pg_get_userbyid(p.proowner) <> 'integrity_owner') AS n`,
  )).rows[0];
  assert.equal(Number(wrong?.n), 0, "todo objeto de integrity pertenece a integrity_owner");
  const triggers = (await admin.query<{ tgenabled: string }>(
    "SELECT tgenabled FROM pg_trigger WHERE tgrelid = 'integrity.audit_event'::regclass AND tgname LIKE 'audit_event_no_%'",
  )).rows;
  assert.deepEqual(triggers.map((t) => t.tgenabled), ["A", "A"]);

  // Append de app_rw (grants por columnas heredados) y UNIQUE de idempotencia.
  const tenant = "11111111-1111-4111-8111-111111111111";
  await enableLedgerMechanicsAppend(ctx); // ADR-010 rev. 5 PR-b: app_rw ya no inserta en produccion; aqui se ejercita la cadena/idempotencia del ledger
  const app = await ctx.connectAs("app_rw");
  await app.query("BEGIN");
  await app.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
  const insert = `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, idempotency_key_hash,
                                                       chain_seq, payload_hash, previous_event_hash, event_hash)
                  VALUES ($1, 'Invitation', 'agg-1', $2::int, 'INVITATION_OPENED', 'HUMAN', '{}'::jsonb, $3, $2::int::bigint,
                          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $4, $5)`;
  const zero = "0".repeat(64);
  await app.query(insert, [tenant, 1, "b".repeat(64), zero, "c".repeat(64)]);
  await app.query("SAVEPOINT s");
  await assert.rejects(() => app.query(insert, [tenant, 2, "b".repeat(64), "c".repeat(64), "d".repeat(64)]), (e: unknown) => codeOf(e) === "23505", "idempotencia");
  await app.query("ROLLBACK TO s");
  await assert.rejects(() => app.query("UPDATE integrity.audit_event SET event_type = 'X'"), (e: unknown) => codeOf(e) === "42501");
  await app.query("ROLLBACK");
});
