// Gobierna: CA-124 (PR-C), db/migrations/0005..0008, ADR-002 §8, ADR-006 §4-§6, common.spec.yaml
// INV-CM-02/INV-3 (X5), DEC-BR-014 §4 (solo sinteticos), SEC-CNS-012 (P1-2, P1-5, P1-6),
// SEC-CNS-013 (P2-8). TEST-CNS-807..814: esquema, RLS, grants, CHECK, tenant_resolve, email
// reservado y endurecimiento del outbox. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { claimOutbox, createPgOutboxAdapter } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const RUNTIME = ["app_rw", "worker", "platform_rw"] as const;
const AGGREGATES = ["consent_decision", "revocation", "recovery_token"] as const;
const READ_ONLY = ["subject", "school_participation"] as const;
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);

async function columnsWith(admin: Client, table: string, role: string, privilege: "INSERT" | "UPDATE" | "SELECT"): Promise<string[]> {
  const r = await admin.query<{ attname: string }>(
    `SELECT a.attname FROM pg_attribute a
      WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
        AND has_column_privilege($2, a.attrelid, a.attnum, $3)
      ORDER BY a.attname`,
    [table, role, privilege],
  );
  return r.rows.map((row) => row.attname);
}

pgTest("TEST-CNS-807 pg: tablas de PR-C con FORCE RLS, policies por app.current_tenant_id() solo para app_rw, sin DELETE/TRUNCATE y grants minimos por columna", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const table of [...AGGREGATES, ...READ_ONLY]) {
    const qname = `app.${table}`;
    const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
      "SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = $1::regclass",
      [qname],
    )).rows[0];
    assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" }, qname);

    const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
      "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'app' AND tablename = $1",
      [table],
    )).rows;
    const expectedCmds = READ_ONLY.includes(table as (typeof READ_ONLY)[number]) ? ["SELECT"] : ["INSERT", "SELECT", "UPDATE"];
    assert.deepEqual(policies.map((p) => p.cmd).sort(), expectedCmds, `${qname}: policies`);
    for (const p of policies) {
      assert.deepEqual(p.roles, ["app_rw"], `${qname}: policy solo TO app_rw`);
      assert.match(`${p.qual ?? ""}${p.with_check ?? ""}`, /app\.current_tenant_id\(\)/);
      if (p.cmd === "UPDATE") {
        assert.match(p.qual ?? "", /current_tenant_id/);
        assert.match(p.with_check ?? "", /current_tenant_id/);
      }
    }

    for (const role of RUNTIME) {
      for (const privilege of ["DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, $2, $3) AS p", [role, qname, privilege])).rows[0];
        assert.equal(r?.p, false, `${role} ${privilege} ${qname}`);
      }
    }
    for (const role of ["worker", "platform_rw"]) {
      for (const privilege of ["SELECT", "INSERT", "UPDATE"]) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, $2, $3) AS p", [role, qname, privilege])).rows[0];
        assert.equal(r?.p, false, `${role} ${privilege} ${qname}`);
      }
    }
    // data_class y created_at los fija la base: nunca insertables ni actualizables por runtime.
    for (const column of ["data_class", "created_at"]) {
      for (const privilege of ["INSERT", "UPDATE"] as const) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', $1, $2, $3) AS p", [qname, column, privilege])).rows[0];
        assert.equal(r?.p, false, `app_rw ${privilege} ${qname}.${column}`);
      }
    }
  }

  for (const table of READ_ONLY) {
    assert.deepEqual(await columnsWith(admin, `app.${table}`, "app_rw", "INSERT"), [], `${table}: sin INSERT para runtime`);
    assert.deepEqual(await columnsWith(admin, `app.${table}`, "app_rw", "UPDATE"), [], `${table}: sin UPDATE para runtime`);
  }
  assert.deepEqual(await columnsWith(admin, "app.subject", "app_rw", "SELECT"), ["subject_ref", "tenant_id"]);

  assert.deepEqual(await columnsWith(admin, "app.consent_decision", "app_rw", "UPDATE"), ["prior_steps_complete", "purposes", "receipt_ref", "state", "steps_recorded"]);
  assert.deepEqual(await columnsWith(admin, "app.revocation", "app_rw", "UPDATE"), [
    "attested_case_ref", "attested_revocation_ref", "case_ref", "cosigned_by_ref", "proposal_ref", "proposed_by_ref", "reason_code",
    "recorded_by_ref", "second_approver_ref", "status", "verification_script_version", "verified_auth_path", "verified_recovery_method",
  ]);
  assert.deepEqual(await columnsWith(admin, "app.recovery_token", "app_rw", "UPDATE"), ["consumed_at"]);
  assert.deepEqual(await columnsWith(admin, "app.recovery_token", "app_rw", "INSERT"), [
    "chain_ref", "consumed_at", "expires_at", "recovery_ref", "revoked_decision_ref", "tenant_id", "token_hash",
  ]);

  // Ningun rol de runtime es BYPASSRLS ni miembro de un owner (cubierto por TEST-CNS-744/746; aqui sobre las tablas nuevas).
  const bypass = (await admin.query("SELECT 1 FROM pg_roles WHERE rolbypassrls AND rolname = ANY($1)", [[...RUNTIME]])).rows;
  assert.deepEqual(bypass, []);
});

pgTest("TEST-CNS-808 pg: CHECK de las tablas nuevas (data_class SYNTHETIC, enums, forma del hash, longitudes, par de atestacion)", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t808");
  const expectFail = async (sql: string, values: unknown[], constraint: string): Promise<void> => {
    await admin.query("SAVEPOINT s");
    await assert.rejects(
      () => admin.query(sql, values),
      (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === constraint,
      constraint,
    );
    await admin.query("ROLLBACK TO s");
  };
  await admin.query("BEGIN");
  try {
    // data_class distinto de SYNTHETIC en cada tabla (incluidas las de catalogo y tenant_resolve).
    await expectFail("INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete, data_class) VALUES ($1, 'c', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'GRANTED', '[]', true, 'REAL')", [t], "consent_decision_data_class_synthetic");
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, data_class) VALUES ('dec', $1, 'r', 'ch', 'REQUESTED', 'REAL')", [t], "revocation_data_class_synthetic");
    await expectFail("INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at, data_class) VALUES ($1, 'r', $2, 'ch', 'd', now(), 'REAL')", [t, hex("h808")], "recovery_token_data_class_synthetic");
    await expectFail("INSERT INTO app.subject (tenant_id, subject_ref, data_class) VALUES ($1, 's', 'REAL')", [t], "subject_data_class_synthetic");
    await expectFail("INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status, data_class) VALUES ($1, 'p', 'c', 'p', 'ACTIVE', 'REAL')", [t], "school_participation_data_class_synthetic");
    await expectFail("INSERT INTO tenant_resolve.recovery_token (token_hash, tenant_id, recovery_ref, data_class) VALUES ($1, $2, 'r', 'REAL')", [hex("h808b"), t], "recovery_token_data_class_synthetic");

    // Enums, formas y pares.
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'r', 'ch', 'EXPIRED')", [t], "revocation_status_enum");
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, verified_auth_path) VALUES ('dec', $1, 'r', 'ch', 'VERIFIED', 'SMS')", [t], "revocation_auth_path_enum");
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, reason_code) VALUES ('dec', $1, 'r', 'ch', 'FAILED', 'OTHER')", [t], "revocation_reason_code_enum");
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, attested_case_ref) VALUES ('dec', $1, 'r', 'ch', 'VERIFIED', 'case')", [t], "revocation_attestation_pair");
    await expectFail("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, '', 'ch', 'REQUESTED')", [t], "revocation_ref_len");
    await expectFail("INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete) VALUES ($1, 'c', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'MAYBE', '[]', true)", [t], "consent_decision_state_enum");
    await expectFail("INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete) VALUES ($1, 'c', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'GRANTED', '{}', true)", [t], "consent_decision_purposes_array");
    await expectFail("INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at) VALUES ($1, 'r', 'no-es-sha256', 'ch', 'd', now())", [t], "recovery_token_hash_shape");
    await expectFail("INSERT INTO tenant_resolve.recovery_token (token_hash, tenant_id, recovery_ref) VALUES ('NO', $1, 'r')", [t], "recovery_token_hash_shape");
    await expectFail("INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, 'p', 'c', 'p', 'ARCHIVED')", [t], "school_participation_status_enum");

    // Y una fila valida SI entra (los CHECK no son vacuos): data_class queda SYNTHETIC por defecto.
    await admin.query("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'ok', 'ch', 'REQUESTED')", [t]);
    const row = (await admin.query<{ data_class: string }>("SELECT data_class FROM app.revocation WHERE tenant_id = $1", [t])).rows[0];
    assert.equal(row?.data_class, "SYNTHETIC");
  } finally {
    await admin.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-809 pg: sin tenant 0 filas y escritura rechazada; tenant_id falso rechazado; conexion reusada A->B (max=1) no ve lo de A, sobre las tablas nuevas", async (ctx) => {
  const ta = fixtureUuid("t809-a");
  const tb = fixtureUuid("t809-b");
  const admin = await ctx.connectAsSuperuser();
  await admin.query("INSERT INTO app.subject (tenant_id, subject_ref) VALUES ($1, 's809')", [ta]);
  await admin.query("INSERT INTO app.school_participation (tenant_id, participation_ref, context_ref, product_ref, status) VALUES ($1, 'p809', 'c', 'p', 'ACTIVE')", [ta]);
  await admin.query("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'r809', 'ch', 'REQUESTED')", [ta]);
  await admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
     VALUES ($1, 'c809', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'GRANTED', '[]', true)`,
    [ta],
  );
  await admin.query("INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at) VALUES ($1, 'rec809', $2, 'ch', 'd', now())", [ta, hex("h809")]);

  const tables = ["subject", "school_participation", "revocation", "consent_decision", "recovery_token"];
  // Sin set_config: 0 filas (la conexion es app_rw, FORCE RLS).
  const app = await ctx.connectAs("app_rw");
  for (const table of tables) {
    assert.equal((await app.query(`SELECT 1 FROM app.${table}`)).rows.length, 0, `${table}: sin tenant debe dar 0 filas`);
  }
  await assert.rejects(
    () => app.query("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'x', 'ch', 'REQUESTED')", [ta]),
    (e: unknown) => codeOf(e) === "42501",
    "INSERT sin tenant rechazado por RLS",
  );

  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool);
    const counts = async (tenant: string): Promise<{ pid: number; n: Record<string, number> }> =>
      uow.withTenantTx(tenant, async (tx) => {
        const pid = (await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]?.pid ?? -1;
        const n: Record<string, number> = {};
        for (const table of tables) n[table] = (await tx.query<{ c: number }>(`SELECT count(*)::int AS c FROM app.${table}`)).rows[0]?.c ?? -1;
        return { pid, n };
      });
    const a = await counts(ta);
    const b = await counts(tb);
    assert.equal(a.pid, b.pid, "misma conexion (pool max=1)");
    assert.deepEqual(a.n, { subject: 1, school_participation: 1, revocation: 1, consent_decision: 1, recovery_token: 1 });
    assert.deepEqual(b.n, { subject: 0, school_participation: 0, revocation: 0, consent_decision: 0, recovery_token: 0 }, "B no ve lo de A");

    // tenant_id falso (WITH CHECK): B no puede insertar ni "mover" filas hacia A. Una unidad por intento.
    for (const sql of [
      "INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'falso', 'ch', 'REQUESTED')",
      "INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at) VALUES ($1, 'falso', $2, 'ch', 'd', now())",
    ]) {
      await assert.rejects(
        () => uow.withTenantTx(tb, (tx) => tx.query(sql, sql.includes("recovery_token") ? [ta, hex("falso809")] : [ta])),
        (e: unknown) => codeOf(e) === "42501",
        sql,
      );
    }
    // UPDATE de filas ajenas: 0 filas afectadas bajo RLS (y no cambia nada).
    const upd = await uow.withTenantTx(tb, (tx) => tx.query("UPDATE app.revocation SET status = 'FAILED' WHERE revocation_ref = 'r809'"));
    assert.equal(upd.rowCount, 0);
    // Mover una fila propia a otro tenant tambien falla (WITH CHECK del UPDATE): tenant_id ni siquiera es actualizable.
    await assert.rejects(
      () => uow.withTenantTx(ta, (tx) => tx.query("UPDATE app.revocation SET tenant_id = $1 WHERE revocation_ref = 'r809'", [tb])),
      (e: unknown) => codeOf(e) === "42501",
    );
  } finally {
    await pool.end();
  }
  assert.equal((await admin.query("SELECT 1 FROM app.revocation WHERE tenant_id = $1", [tb])).rows.length, 0);
  assert.equal((await admin.query<{ status: string }>("SELECT status FROM app.revocation WHERE revocation_ref = 'r809'")).rows[0]?.status, "REQUESTED");
});

pgTest("TEST-CNS-810 pg: tenant_resolve cerrado para runtime; funciones SECURITY DEFINER de tenant_resolve_owner con search_path fijo y EXECUTE solo para app_rw", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const rel = (await admin.query<{ owner: string; rls: boolean }>(
    "SELECT pg_get_userbyid(relowner) AS owner, relrowsecurity AS rls FROM pg_class WHERE oid = 'tenant_resolve.recovery_token'::regclass",
  )).rows[0];
  assert.equal(rel?.owner, "tenant_resolve_owner");
  assert.equal(rel?.rls, false, "sin RLS por diseno (excepcion ADR-006 §4): se protege por funciones, no por policies");
  for (const role of [...RUNTIME, "consent_migrator"]) {
    for (const privilege of ["SELECT", "INSERT", "UPDATE", "REFERENCES"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, 'tenant_resolve.recovery_token', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege} tenant_resolve.recovery_token`);
    }
    for (const privilege of ["DELETE", "TRUNCATE", "TRIGGER"]) {
      const r = (await admin.query<{ p: boolean }>("SELECT has_table_privilege($1, 'tenant_resolve.recovery_token', $2) AS p", [role, privilege])).rows[0];
      assert.equal(r?.p, false, `${role} ${privilege} tenant_resolve.recovery_token`);
    }
  }
  for (const role of RUNTIME) {
    const c = await ctx.connectAs(role as "app_rw" | "worker" | "platform_rw");
    await assert.rejects(() => c.query("SELECT * FROM tenant_resolve.recovery_token"), (e: unknown) => codeOf(e) === "42501", `${role}: SELECT directo`);
    await assert.rejects(() => c.query("INSERT INTO tenant_resolve.recovery_token (token_hash, tenant_id, recovery_ref) VALUES ($1, $2, 'r')", [hex("h810"), fixtureUuid("t810")]), (e: unknown) => codeOf(e) === "42501");
  }

  const fns = (await admin.query<{ name: string; owner: string; secdef: boolean; config: string[] | null; args: string }>(
    `SELECT p.proname AS name, pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS config,
            pg_get_function_arguments(p.oid) AS args
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'tenant_resolve' ORDER BY p.proname`,
  )).rows;
  // 0007 (recovery) + 0011 (invitacion y handle, PR-D): todas cumplen las mismas invariantes.
  assert.deepEqual(fns.map((f) => f.name), [
    "by_handle_hash", "by_invitation_token_hash", "by_recovery_token_hash",
    "register_handle", "register_invitation_token", "register_recovery_token", "rotate_handle",
  ]);
  for (const f of fns) {
    assert.equal(f.owner, "tenant_resolve_owner", f.name);
    assert.equal(f.secdef, true, `${f.name} SECURITY DEFINER`);
    assert.deepEqual(f.config, ["search_path=pg_catalog, pg_temp"], `${f.name} search_path`);
    assert.doesNotMatch(f.args, /uuid/i, `${f.name}: el tenant nunca es un parametro`);
    for (const role of RUNTIME) {
      const r = (await admin.query<{ p: boolean }>(
        "SELECT has_function_privilege($1, (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'tenant_resolve' AND p.proname = $2), 'EXECUTE') AS p",
        [role, f.name],
      )).rows[0];
      assert.equal(r?.p, role === "app_rw", `${role} EXECUTE ${f.name}`);
    }
    const pub = (await admin.query<{ p: boolean }>(
      `SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                       WHERE p.proname = $1 AND p.pronamespace = 'tenant_resolve'::regnamespace AND a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS p`,
      [f.name],
    )).rows[0];
    assert.equal(pub?.p, false, `PUBLIC EXECUTE ${f.name}`);
  }
  // worker y platform_rw no pueden ni siquiera invocar el lookup.
  for (const role of ["worker", "platform_rw"] as const) {
    const c = await ctx.connectAs(role);
    await assert.rejects(() => c.query("SELECT * FROM tenant_resolve.by_recovery_token_hash($1)", [hex("h810")]), (e: unknown) => codeOf(e) === "42501", role);
  }
  // PUBLIC tampoco: el esquema ni siquiera es utilizable para quien no sea app_rw.
  const usage = (await admin.query<{ p: boolean }>("SELECT has_schema_privilege('worker', 'tenant_resolve', 'USAGE') AS p")).rows[0];
  assert.equal(usage?.p, false);
});

pgTest("TEST-CNS-811 pg: register_recovery_token toma el tenant de app.current_tenant_id() (sin tenant falla), es idempotente y un hash ya registrado por otro tenant falla sin revelarlo", async (ctx) => {
  const ta = fixtureUuid("t811-a");
  const tb = fixtureUuid("t811-b");
  const h = hex("h811");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    // Sin tenant en la transaccion: falla (no hay forma de registrar "a nombre de" otro).
    const raw = await ctx.connectAs("app_rw");
    await assert.rejects(() => raw.query("SELECT tenant_resolve.register_recovery_token($1, 'r811')", [h]), (e: unknown) => codeOf(e) === "42501");
    assert.equal((await raw.query("SELECT * FROM tenant_resolve.by_recovery_token_hash($1)", [h])).rows.length, 0);

    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_recovery_token($1, 'r811')", [h]));
    const found = (await raw.query<{ tenant_id: string; recovery_ref: string }>("SELECT * FROM tenant_resolve.by_recovery_token_hash($1)", [h])).rows;
    assert.deepEqual(found, [{ tenant_id: ta, recovery_ref: "r811" }], "el tenant registrado es el de la transaccion");
    // Idempotente para el mismo (hash, tenant, ref).
    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_recovery_token($1, 'r811')", [h]));
    // Mismo hash desde otro tenant o con otra ref: falla (unique_violation) sin nombrar al otro tenant.
    for (const [tenant, ref] of [[tb, "r811"], [ta, "otra-ref"]] as const) {
      await assert.rejects(
        () => uow.withTenantTx(tenant, (tx) => tx.query("SELECT tenant_resolve.register_recovery_token($1, $2)", [h, ref])),
        (e: unknown) => codeOf(e) === "23505" && !String((e as Error).message).includes(ta),
        `${tenant}/${ref}`,
      );
    }
    assert.deepEqual((await raw.query("SELECT tenant_id FROM tenant_resolve.by_recovery_token_hash($1)", [h])).rows, [{ tenant_id: ta }]);
    // La fila quedo SYNTHETIC por defecto (P1-5).
    const admin = await ctx.connectAsSuperuser();
    assert.equal((await admin.query<{ data_class: string }>("SELECT data_class FROM tenant_resolve.recovery_token WHERE token_hash = $1", [h])).rows[0]?.data_class, "SYNTHETIC");
  } finally {
    await pool.end();
  }
});

/** Columnas de email, contacto o destino (por nombre: email/correo/channel/recipient/destin/contact/phone/
 * telefono; recipient_binding es un enum, no un contacto; SEC-CNS-015 P2-B: no basta el nombre "email") de los esquemas del producto SIN un CHECK que use
 * app.is_reserved_email. PR-D las usa en app.invitation.recipient_channel_ref y app.otp_verification.channel_ref. */
async function unguardedEmailColumns(db: Client): Promise<string[]> {
  const r = await db.query<{ col: string }>(
    `SELECT n.nspname || '.' || c.relname || '.' || a.attname AS col
       FROM pg_attribute a
       JOIN pg_class c ON c.oid = a.attrelid AND c.relkind IN ('r', 'p')
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('app', 'integrity', 'ops', 'tenant_resolve')
        AND a.attnum > 0 AND NOT a.attisdropped
        AND a.attname ~* '(e_?mail|correo|channel|recipient(?!_binding)|destin|contact|phone|tel[eé]fono)'
        AND NOT EXISTS (
          SELECT 1 FROM pg_constraint k
           WHERE k.conrelid = c.oid AND k.contype = 'c' AND a.attnum = ANY (k.conkey)
             AND pg_get_constraintdef(k.oid) ~ 'is_reserved_email')
      ORDER BY 1`,
  );
  return r.rows.map((row) => row.col);
}

pgTest("TEST-CNS-812 pg: email solo de dominios reservados (P1-5): funcion app.is_reserved_email, toda columna de email del esquema la usa y ninguna columna rut/run", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const check = async (email: string | null): Promise<boolean | null> =>
    (await admin.query<{ ok: boolean | null }>("SELECT app.is_reserved_email($1) AS ok", [email])).rows[0]?.ok ?? null;
  for (const ok of ["padre@colegio.test", "a.b+c@sub.dominio.invalid", "x@example.com", "x@example.org", "x@EXAMPLE.NET", "x@t.TEST"]) {
    assert.equal(await check(ok), true, ok);
  }
  for (const bad of [
    "persona@gmail.com", "persona@example.cl", "persona@miexample.com", "persona@example.com.evil.io", "persona@test.cl",
    "persona@colegio.testing", "sin-arroba.test", "dos@@x.test", "a b@x.test", "", "@x.test", "persona@invalid.com",
  ]) {
    assert.equal(await check(bad), false, `${bad} no es dominio reservado`);
  }
  assert.equal(await check(null), null, "NULL pasa el CHECK (columna opcional)");

  // El esquema real no tiene columnas de email sin guarda ni columnas rut/run (test de catalogo).
  assert.deepEqual(await unguardedEmailColumns(admin), []);
  const rut = await admin.query<{ col: string }>(
    `SELECT n.nspname || '.' || c.relname || '.' || a.attname AS col
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid AND c.relkind IN ('r', 'p')
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('app', 'integrity', 'ops', 'tenant_resolve') AND a.attnum > 0 AND NOT a.attisdropped
        AND (a.attname ~* '^(rut|run|rol_unico)$' OR a.attname ~* '(^|_)(rut|run)(_|$)')`,
  );
  assert.deepEqual(rut.rows, []);

  // Meta-prueba: el escaneo detecta una columna de email sin guarda y la guarda real rechaza dominios no reservados.
  const migrator = await ctx.connectAs("consent_migrator");
  await migrator.query("BEGIN");
  try {
    await migrator.query("SET LOCAL ROLE consent_owner");
    await migrator.query("CREATE TABLE app.probe_contact (contact_email text)");
    assert.deepEqual(await unguardedEmailColumns(migrator), ["app.probe_contact.contact_email"]);
    await migrator.query("ALTER TABLE app.probe_contact ADD CONSTRAINT probe_email_reserved CHECK (app.is_reserved_email(contact_email))");
    assert.deepEqual(await unguardedEmailColumns(migrator), []);
    await migrator.query("INSERT INTO app.probe_contact VALUES ('x@colegio.test'), (NULL)");
    await migrator.query("SAVEPOINT s");
    await assert.rejects(
      () => migrator.query("INSERT INTO app.probe_contact VALUES ('persona@gmail.com')"),
      (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === "probe_email_reserved",
    );
    await migrator.query("ROLLBACK TO s");
  } finally {
    await migrator.query("ROLLBACK");
  }
  // Los roles de runtime pueden evaluar la funcion (la usaran los CHECK en sus INSERT) y PUBLIC no.
  for (const role of RUNTIME) {
    const c = await ctx.connectAs(role);
    assert.equal((await c.query<{ ok: boolean }>("SELECT app.is_reserved_email('a@b.test') AS ok")).rows[0]?.ok, true, role);
  }
});

pgTest("TEST-CNS-813 pg: el worker solo lee el sobre del outbox de eventos CLAIMED (P2-8); PENDING y DELIVERED no son visibles", async (ctx) => {
  const t = fixtureUuid("t813");
  const admin = await ctx.connectAsSuperuser();
  const policy = (await admin.query<{ qual: string }>("SELECT qual FROM pg_policies WHERE schemaname = 'app' AND tablename = 'outbox' AND policyname = 'outbox_worker_select'")).rows[0];
  assert.match(policy?.qual ?? "", /current_tenant_id\(\)/);
  assert.match(policy?.qual ?? "", /status = 'CLAIMED'/);

  const appPool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const workerPool = createPool({ connectionString: ctx.urlFor("worker"), max: 2 });
  try {
    const appUow = new PgUnitOfWork(appPool);
    const workerUow = new PgUnitOfWork(workerPool);
    const ref = fixtureUuid("rev813");
    await appUow.withTenantTx(t, (tx) =>
      createPgOutboxAdapter(tx).enqueue({
        tenantId: t,
        eventType: "consent.revoked",
        contextRef: "BETA_2026_01",
        subjectRef: fixtureUuid("subj813"),
        occurredAt: "2026-10-01T12:00:00.000Z",
        payload: { revocationRef: ref, scope: "ALL", effectiveAt: "2026-10-01T12:00:00.000Z" },
        dedupeKey: `${ref}:consent.revoked`,
      }),
    );
    const visible = (): Promise<number> =>
      workerUow.withTenantTx(t, async (tx) => (await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox")).rows[0]?.n ?? -1);
    assert.equal(await visible(), 0, "PENDING: el worker no ve el sobre antes del claim");

    const client = await workerPool.connect();
    let claimed;
    try {
      claimed = await claimOutbox(client, 100);
    } finally {
      client.release();
    }
    assert.ok(claimed.some((c) => c.tenantId === t));
    assert.equal(await visible(), 1, "CLAIMED: visible dentro de inTenant");

    await admin.query("UPDATE app.outbox SET status = 'DELIVERED' WHERE tenant_id = $1", [t]);
    assert.equal(await visible(), 0, "DELIVERED: ya no es visible para el worker");
  } finally {
    await appPool.end();
    await workerPool.end();
  }
});

pgTest("TEST-CNS-814 pg: las columnas de identidad no son actualizables y el runtime no puede borrar ni escribir columnas fijadas por la base", async (ctx) => {
  const t = fixtureUuid("t814");
  const admin = await ctx.connectAsSuperuser();
  await admin.query("INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status) VALUES ('dec', $1, 'r814', 'ch', 'REQUESTED')", [t]);
  await admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
     VALUES ($1, 'c814', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'GRANTED', '[]', true)`,
    [t],
  );
  await admin.query("INSERT INTO app.recovery_token (tenant_id, recovery_ref, token_hash, chain_ref, revoked_decision_ref, expires_at) VALUES ($1, 'rec814', $2, 'ch', 'd', now() + interval '1 day')", [t, hex("h814")]);

  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool);
    const denied = [
      "UPDATE app.revocation SET chain_ref = 'otra' WHERE revocation_ref = 'r814'",
      "UPDATE app.revocation SET revoked_decision_ref = 'otra' WHERE revocation_ref = 'r814'",
      "UPDATE app.revocation SET data_class = 'REAL' WHERE revocation_ref = 'r814'",
      "UPDATE app.consent_decision SET chain_ref = 'otra' WHERE consent_id = 'c814'",
      "UPDATE app.consent_decision SET subject_ref = 'otro' WHERE consent_id = 'c814'",
      "UPDATE app.recovery_token SET expires_at = now() + interval '100 years' WHERE recovery_ref = 'rec814'",
      "UPDATE app.recovery_token SET token_hash = repeat('a', 64) WHERE recovery_ref = 'rec814'",
      "DELETE FROM app.revocation WHERE revocation_ref = 'r814'",
      "DELETE FROM app.consent_decision WHERE consent_id = 'c814'",
      "DELETE FROM app.recovery_token WHERE recovery_ref = 'rec814'",
      "TRUNCATE app.recovery_token",
      "INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, data_class) VALUES ('dec', current_setting('app.tenant_id')::uuid, 'x', 'ch', 'REQUESTED', 'SYNTHETIC')",
      "UPDATE tenant_resolve.recovery_token SET tenant_id = tenant_id",
    ];
    for (const sql of denied) {
      await assert.rejects(() => uow.withTenantTx(t, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
    }
    // Lo permitido si funciona: el estado y el consumo.
    await uow.withTenantTx(t, (tx) => tx.query("UPDATE app.revocation SET status = 'VERIFIED' WHERE revocation_ref = 'r814'"));
    await uow.withTenantTx(t, (tx) => tx.query("UPDATE app.recovery_token SET consumed_at = now() WHERE recovery_ref = 'rec814'"));
  } finally {
    await pool.end();
  }
  const row = (await admin.query<{ status: string; chain_ref: string }>("SELECT status, chain_ref FROM app.revocation WHERE revocation_ref = 'r814'")).rows[0];
  assert.deepEqual(row, { status: "VERIFIED", chain_ref: "ch" });
});
