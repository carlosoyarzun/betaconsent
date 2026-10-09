// Gobierna: CA-124 (PR-D), db/migrations/0010_invitation_otp_rights_case_enrollment.sql y
// 0011_tenant_resolve_invitation_handle.sql, ADR-002 §8, ADR-006 §4-§6, common.spec.yaml INV-CM-02/INV-3
// (X5), DEC-BR-014 §4 (solo sinteticos), SEC-CNS-012 (P1-2, P1-5), SEC-CNS-015 P2-B (columnas de contacto o
// destino con app.is_reserved_email). TEST-CNS-838..841: esquema, RLS, grants, CHECK, email reservado,
// tenant_resolve de invitacion/handle y unicos parciales. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;
const RUNTIME = ["app_rw", "worker", "platform_rw"] as const;
const TABLES = ["invitation", "otp_verification", "rights_case", "enrollment"] as const;
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

pgTest("TEST-CNS-838 pg: invitation, otp_verification, rights_case y enrollment con FORCE RLS, policies por app.current_tenant_id() solo para app_rw, sin DELETE/TRUNCATE, identidad inmutable y grants minimos por columna", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const table of TABLES) {
    const qname = `app.${table}`;
    const rel = (await admin.query<{ rls: boolean; force: boolean; owner: string }>(
      "SELECT relrowsecurity AS rls, relforcerowsecurity AS force, pg_get_userbyid(relowner) AS owner FROM pg_class WHERE oid = $1::regclass",
      [qname],
    )).rows[0];
    assert.deepEqual(rel, { rls: true, force: true, owner: "consent_owner" }, qname);

    const policies = (await admin.query<{ cmd: string; roles: string[]; qual: string | null; with_check: string | null }>(
      "SELECT cmd, roles::text[] AS roles, qual, with_check FROM pg_policies WHERE schemaname = 'app' AND tablename = $1 AND policyname !~ '_roster_owner_select$'",
      [table],
    )).rows;
    // 0031 (SEC-CNS-021 PR-3): app.otp_verification suma SELECT y DELETE acotados por vencimiento TO security_event_owner; app_rw queda exactamente INSERT/SELECT/UPDATE.
    const ownerPolicies = policies.filter((p) => p.roles.includes("security_event_owner"));
    assert.deepEqual(ownerPolicies.map((p) => `${p.cmd}:${p.roles.join(",")}`).sort(), table === "otp_verification" ? ["DELETE:security_event_owner", "SELECT:security_event_owner"] : [], `${qname}: policies del dueno de la purga`);
    policies.splice(0, policies.length, ...policies.filter((p) => !p.roles.includes("security_event_owner")));
    assert.deepEqual(policies.map((p) => p.cmd).sort(), ["INSERT", "SELECT", "UPDATE"], `${qname}: policies`);
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
    // data_class y created_at los fija la base; tenant_id y la PK nunca son actualizables (identidad inmutable).
    for (const column of ["data_class", "created_at"]) {
      for (const privilege of ["INSERT", "UPDATE"] as const) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', $1, $2, $3) AS p", [qname, column, privilege])).rows[0];
        assert.equal(r?.p, false, `app_rw ${privilege} ${qname}.${column}`);
      }
    }
    const update = await columnsWith(admin, qname, "app_rw", "UPDATE");
    assert.ok(!update.includes("tenant_id"), `${qname}: tenant_id inmutable`);
  }
  // Solo cambian de estado las columnas de estado; la identidad se fija al crear.
  assert.deepEqual(await columnsWith(admin, "app.invitation", "app_rw", "UPDATE"), [
    "bound_decision_maker_ref", "consent_version", "expires_at", "recipient_binding", "recipient_channel_ref", "state", "token_hash",
  ]);
  assert.deepEqual(await columnsWith(admin, "app.otp_verification", "app_rw", "UPDATE"), ["attempts", "code_hash", "consumed_at", "expires_at", "resend_count", "state"]);
  assert.deepEqual(await columnsWith(admin, "app.rights_case", "app_rw", "UPDATE"), ["origin", "revocation_ref", "status"]);
  assert.deepEqual(await columnsWith(admin, "app.enrollment", "app_rw", "UPDATE"), ["state"]);
  assert.deepEqual(await columnsWith(admin, "app.invitation", "app_rw", "INSERT"), [
    "bound_decision_maker_ref", "consent_version", "context_ref", "enrollment_ref", "expires_at", "invitation_ref", "participation_ref",
    "product_ref", "recipient_binding", "recipient_channel_ref", "reissue_of_ref", "state", "subject_ref", "tenant_id", "token_hash",
  ]);
  const bypass = (await admin.query("SELECT 1 FROM pg_roles WHERE rolbypassrls AND rolname = ANY($1)", [[...RUNTIME]])).rows;
  assert.deepEqual(bypass, []);
});

pgTest("TEST-CNS-839 pg: CHECK de las tablas de PR-D (data_class SYNTHETIC, enums, formas, longitudes) y SEC-CNS-015 P2-B: toda columna de contacto o destino solo admite email de dominio reservado", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t839");
  const expectFail = async (sql: string, values: unknown[], constraint: string): Promise<void> => {
    await admin.query("SAVEPOINT s");
    await assert.rejects(
      () => admin.query(sql, values),
      (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === constraint,
      constraint,
    );
    await admin.query("ROLLBACK TO s");
  };
  const inv = (extraCols: string, extraVals: string): string =>
    `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state${extraCols}) VALUES ($1, 'i', 'c', 'p', 's', 'DRAFT'${extraVals})`;
  const otpIns = (scope: string, channel: string, extraCols = "", extraVals = ""): string =>
    `INSERT INTO app.otp_verification (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, state${extraCols})
     VALUES ($1, 'v', '${scope}', 'p', '${channel}', '${hex("c839")}', 0, now(), 'CODE_SENT'${extraVals})`;
  await admin.query("BEGIN");
  try {
    // data_class distinto de SYNTHETIC en cada tabla.
    await expectFail(inv(", data_class", ", 'REAL'"), [t], "invitation_data_class_synthetic");
    await expectFail(otpIns("DECISION", "a@x.test", ", data_class", ", 'REAL'"), [t], "otp_data_class_synthetic");
    await expectFail("INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, data_class) VALUES ($1, 'c', 'ch', 'd', 'OPEN', 'REAL')", [t], "rights_case_data_class_synthetic");
    await expectFail("INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state, data_class) VALUES ($1, 'e', 's', 'p', 'ACTIVE', 'REAL')", [t], "enrollment_data_class_synthetic");
    await expectFail("INSERT INTO tenant_resolve.invitation_token (token_hash, tenant_id, invitation_ref, data_class) VALUES ($1, $2, 'i', 'REAL')", [hex("h839"), t], "invitation_token_data_class_synthetic");
    await expectFail("INSERT INTO tenant_resolve.handle (handle_hash, tenant_id, chain_ref, revoked_decision_ref, data_class) VALUES ($1, $2, 'c', 'd', 'REAL')", [hex("h839b"), t], "handle_data_class_synthetic");

    // Enums, formas y longitudes.
    await expectFail("INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, 'i', 'c', 'p', 's', 'CANCELLED')", [t], "invitation_state_enum");
    await expectFail(inv(", recipient_binding", ", 'EMAIL'"), [t], "invitation_binding_enum");
    await expectFail(inv(", token_hash", ", 'no-es-sha256'"), [t], "invitation_token_hash_shape");
    await expectFail("INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, '', 'c', 'p', 's', 'DRAFT')", [t], "invitation_ref_len");
    await expectFail(otpIns("SMS", "a@x.test"), [t], "otp_scope_enum");
    await expectFail(otpIns("DECISION", "a@x.test").replace("'CODE_SENT'", "'PENDING'"), [t], "otp_state_enum");
    await expectFail(otpIns("DECISION", "a@x.test").replace(`'${hex("c839")}'`, "'123456'"), [t], "otp_code_hash_shape");
    await expectFail(otpIns("DECISION", "a@x.test").replace(", 0, now()", ", -1, now()"), [t], "otp_attempts_nonneg");
    await expectFail("INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status) VALUES ($1, 'c', 'ch', 'd', 'REOPENED')", [t], "rights_case_status_enum");
    await expectFail("INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c', 'ch', 'd', 'OPEN', 'OTHER')", [t], "rights_case_origin_enum");
    await expectFail("INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state) VALUES ($1, 'e', 's', 'p', 'PAUSED')", [t], "enrollment_state_enum");
    await expectFail("INSERT INTO tenant_resolve.invitation_token (token_hash, tenant_id, invitation_ref) VALUES ('NO', $1, 'i')", [t], "invitation_token_hash_shape");
    await expectFail("INSERT INTO tenant_resolve.handle (handle_hash, tenant_id, chain_ref, revoked_decision_ref) VALUES ('NO', $1, 'c', 'd')", [t], "handle_hash_shape");

    // SEC-CNS-015 P2-B: columnas de contacto/destino (invitation.recipient_channel_ref, otp_verification.channel_ref).
    for (const bad of ["persona@gmail.com", "persona@example.cl", "sin-arroba", "dos@@x.test", "", "persona@colegio.testing"]) {
      await expectFail(inv(", recipient_channel_ref", `, '${bad}'`), [t], "invitation_recipient_channel_reserved");
      await expectFail(otpIns("DECISION", bad), [t], "otp_channel_reserved");
    }
    // En scope de derechos el canal puede ser una ref opaca 'mgmt:', pero NO en DECISION ni otro valor libre.
    await expectFail(otpIns("DECISION", "mgmt:chain-1"), [t], "otp_channel_reserved");
    await expectFail(otpIns("REVOCATION", fixtureUuid("chain-1")), [t], "otp_channel_reserved");
    await expectFail(otpIns("MANAGE", "persona@gmail.com"), [t], "otp_channel_reserved");
    // SEC-CNS-016 C1: un email real no entra disfrazado de ref opaca 'mgmt:'.
    await expectFail(otpIns("MANAGE", "mgmt:persona@gmail.com"), [t], "otp_channel_reserved");
    await expectFail(otpIns("REVOCATION", "mgmt:chain:x@y.cl"), [t], "otp_channel_reserved");

    // Filas validas SI entran (los CHECK no son vacuos): data_class queda SYNTHETIC por defecto.
    await admin.query(inv(", recipient_channel_ref", ", 'padre@colegio.test'"), [t]);
    await admin.query(otpIns("DECISION", "padre@example.org"), [t]);
    await admin.query(otpIns("REVOCATION", "mgmt:chain-ok").replace("'v'", "'v2'"), [t]);
    for (const table of ["invitation", "otp_verification"]) {
      assert.equal((await admin.query<{ data_class: string }>(`SELECT data_class FROM app.${table} WHERE tenant_id = $1 LIMIT 1`, [t])).rows[0]?.data_class, "SYNTHETIC");
    }
  } finally {
    await admin.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-840 pg: tenant_resolve.invitation_token y handle cerrados para runtime; by_*/register_*/rotate_handle SECURITY DEFINER con search_path fijo, tenant desde la tx (sin tenant falla), idempotentes y sin revelar al otro tenant", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const table of ["invitation_token", "handle"]) {
    const q = `tenant_resolve.${table}`;
    const rel = (await admin.query<{ owner: string; rls: boolean }>("SELECT pg_get_userbyid(relowner) AS owner, relrowsecurity AS rls FROM pg_class WHERE oid = $1::regclass", [q])).rows[0];
    assert.equal(rel?.owner, "tenant_resolve_owner", q);
    assert.equal(rel?.rls, false, `${q}: sin RLS por diseno (ADR-006 §4)`);
    for (const role of [...RUNTIME, "consent_migrator"]) {
      for (const privilege of ["SELECT", "INSERT", "UPDATE", "REFERENCES"]) {
        const r = (await admin.query<{ p: boolean }>("SELECT has_any_column_privilege($1, $2, $3) AS p", [role, q, privilege])).rows[0];
        assert.equal(r?.p, false, `${role} ${privilege} ${q}`);
      }
    }
    for (const role of RUNTIME) {
      const c = await ctx.connectAs(role);
      await assert.rejects(() => c.query(`SELECT * FROM ${q}`), (e: unknown) => codeOf(e) === "42501", `${role}: SELECT directo ${q}`);
    }
  }
  const fns = ["by_invitation_token_hash", "register_invitation_token", "by_handle_hash", "register_handle", "rotate_handle"];
  const rows = (await admin.query<{ name: string; owner: string; secdef: boolean; config: string[] | null; args: string }>(
    `SELECT p.proname AS name, pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS config, pg_get_function_arguments(p.oid) AS args
       FROM pg_proc p WHERE p.pronamespace = 'tenant_resolve'::regnamespace AND p.proname = ANY($1) ORDER BY p.proname`,
    [fns],
  )).rows;
  assert.deepEqual(rows.map((f) => f.name), [...fns].sort());
  for (const f of rows) {
    assert.equal(f.owner, "tenant_resolve_owner", f.name);
    assert.equal(f.secdef, true, `${f.name} SECURITY DEFINER`);
    assert.deepEqual(f.config, ["search_path=pg_catalog, pg_temp"], `${f.name} search_path`);
    assert.doesNotMatch(f.args, /uuid/i, `${f.name}: el tenant nunca es un parametro`);
    for (const role of RUNTIME) {
      const r = (await admin.query<{ p: boolean }>(
        "SELECT has_function_privilege($1, (SELECT p.oid FROM pg_proc p WHERE p.pronamespace = 'tenant_resolve'::regnamespace AND p.proname = $2), 'EXECUTE') AS p",
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

  const ta = fixtureUuid("t840-a");
  const tb = fixtureUuid("t840-b");
  const hInv = hex("h840-inv");
  const hHandle = hex("h840-handle");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    const raw = await ctx.connectAs("app_rw");
    // Sin tenant en la tx: register_* y rotate_handle fallan (no hay forma de registrar "a nombre de" otro).
    for (const sql of [
      "SELECT tenant_resolve.register_invitation_token($1, 'i840')",
      "SELECT tenant_resolve.register_handle($1, 'c840', 'd840')",
      "SELECT tenant_resolve.rotate_handle($1)",
    ]) {
      await assert.rejects(() => raw.query(sql, [hInv]), (e: unknown) => codeOf(e) === "42501", sql);
    }
    assert.equal((await raw.query("SELECT * FROM tenant_resolve.by_invitation_token_hash($1)", [hInv])).rows.length, 0);

    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_invitation_token($1, 'i840')", [hInv]));
    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_handle($1, 'c840', 'd840')", [hHandle]));
    assert.deepEqual((await raw.query("SELECT * FROM tenant_resolve.by_invitation_token_hash($1)", [hInv])).rows, [{ tenant_id: ta, invitation_ref: "i840" }], "el tenant registrado es el de la tx");
    assert.deepEqual((await raw.query("SELECT * FROM tenant_resolve.by_handle_hash($1)", [hHandle])).rows, [{ tenant_id: ta, chain_ref: "c840", revoked_decision_ref: "d840" }]);
    // Idempotente para la misma tupla.
    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_invitation_token($1, 'i840')", [hInv]));
    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.register_handle($1, 'c840', 'd840')", [hHandle]));
    // Mismo hash desde otro tenant o con otra tupla: unique_violation sin nombrar al otro tenant.
    const attempts: Array<[string, string, unknown[]]> = [
      [tb, "SELECT tenant_resolve.register_invitation_token($1, 'i840')", [hInv]],
      [ta, "SELECT tenant_resolve.register_invitation_token($1, 'otra')", [hInv]],
      [tb, "SELECT tenant_resolve.register_handle($1, 'c840', 'd840')", [hHandle]],
      [ta, "SELECT tenant_resolve.register_handle($1, 'otra', 'd840')", [hHandle]],
    ];
    for (const [tenant, sql, values] of attempts) {
      await assert.rejects(
        () => uow.withTenantTx(tenant, (tx) => tx.query(sql, values)),
        (e: unknown) => codeOf(e) === "23505" && !String((e as Error).message).includes(ta),
        `${tenant} ${sql}`,
      );
    }
    // rotate_handle: otro tenant no cambia nada; el dueño si, y el handle rotado deja de resolver.
    await uow.withTenantTx(tb, (tx) => tx.query("SELECT tenant_resolve.rotate_handle($1)", [hHandle]));
    assert.equal((await raw.query("SELECT * FROM tenant_resolve.by_handle_hash($1)", [hHandle])).rows.length, 1);
    await uow.withTenantTx(ta, (tx) => tx.query("SELECT tenant_resolve.rotate_handle($1)", [hHandle]));
    assert.equal((await raw.query("SELECT * FROM tenant_resolve.by_handle_hash($1)", [hHandle])).rows.length, 0);
    for (const [table, key, h] of [["invitation_token", "token_hash", hInv], ["handle", "handle_hash", hHandle]] as const) {
      assert.equal((await admin.query<{ data_class: string }>(`SELECT data_class FROM tenant_resolve.${table} WHERE ${key} = $1`, [h])).rows[0]?.data_class, "SYNTHETIC");
    }
    // worker y platform_rw no pueden ni invocar los lookups.
    for (const role of ["worker", "platform_rw"] as const) {
      const c = await ctx.connectAs(role);
      await assert.rejects(() => c.query("SELECT * FROM tenant_resolve.by_invitation_token_hash($1)", [hInv]), (e: unknown) => codeOf(e) === "42501", role);
      await assert.rejects(() => c.query("SELECT * FROM tenant_resolve.by_handle_hash($1)", [hHandle]), (e: unknown) => codeOf(e) === "42501", role);
    }
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-841 pg: unicos parciales GRD-IV-01, GRD-OT-08, GRD-RC-02 y GRD-TC-03 (23505 por constraint) y PgUnitOfWork reintenta al perdedor hasta ver al ganador o rendirse con el error de dominio del guard", async (ctx) => {
  const t = fixtureUuid("t841");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool);
    const inv = (ref: string, state = "DRAFT"): { invitationRef: string; tenantId: string; contextRef: string; productRef: string; subjectRef: string; state: "DRAFT" } =>
      ({ invitationRef: ref, tenantId: t, contextRef: "BETA_2026_01", productRef: "P", subjectRef: "subject-841", state: state as "DRAFT" });
    // GRD-IV-01: una invitacion no terminal por (contexto, sujeto).
    await uow.withTenantTx(t, (tx) => tx.query("INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, 'i841-a', 'BETA_2026_01', 'P', 'subject-841', 'DRAFT')", [t]));
    await assert.rejects(
      () => uow.withTenantTx(t, (tx) => tx.query("INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state) VALUES ($1, 'i841-b', 'BETA_2026_01', 'P', 'subject-841', 'READY')", [t])),
      (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "invitation_single_non_terminal_uq",
    );
    // Mapeado por inTenant al error de dominio del guard tras agotar los reintentos (la ganadora sigue ahi).
    await assert.rejects(
      () => uow.inTenant(t, (tx) => tx.invitationRepo.save(inv("i841-c"))),
      (e: unknown) => e instanceof DomainError && e.code === "ERR-IV-02",
    );
    // Una terminal libera el (contexto, sujeto).
    await uow.withTenantTx(t, (tx) => tx.query("UPDATE app.invitation SET state = 'COMPLETED' WHERE invitation_ref = 'i841-a'"));
    await uow.inTenant(t, (tx) => tx.invitationRepo.save(inv("i841-d")));

    // GRD-OT-08: un challenge activo por (padre, scope).
    const otpSql = (ref: string, state: string): string =>
      `INSERT INTO app.otp_verification (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, state)
       VALUES ($1, '${ref}', 'DECISION', 'parent-841', 'a@x.test', '${hex("c841")}', 0, now(), '${state}')`;
    await uow.withTenantTx(t, (tx) => tx.query(otpSql("v841-a", "CODE_SENT"), [t]));
    await assert.rejects(
      () => uow.withTenantTx(t, (tx) => tx.query(otpSql("v841-b", "NOT_STARTED"), [t])),
      (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "otp_single_active_uq",
    );
    await uow.withTenantTx(t, (tx) => tx.query("UPDATE app.otp_verification SET state = 'VERIFIED' WHERE verification_ref = 'v841-a'"));
    await uow.withTenantTx(t, (tx) => tx.query(otpSql("v841-b", "CODE_SENT"), [t]));

    // GRD-RC-02: un caso no terminal por (cadena, decision).
    const caseSql = (ref: string, status: string): string =>
      `INSERT INTO app.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status) VALUES ($1, '${ref}', 'chain-841', 'dec-841', '${status}')`;
    await uow.withTenantTx(t, (tx) => tx.query(caseSql("c841-a", "OPEN"), [t]));
    await assert.rejects(
      () => uow.withTenantTx(t, (tx) => tx.query(caseSql("c841-b", "CONTACTING"), [t])),
      (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "rights_case_single_open_uq",
    );
    await uow.withTenantTx(t, (tx) => tx.query("UPDATE app.rights_case SET status = 'RESOLVED' WHERE case_ref = 'c841-a'"));
    await uow.withTenantTx(t, (tx) => tx.query(caseSql("c841-b", "OPEN"), [t]));

    // GRD-TC-03: un Enrollment ACTIVE por (sujeto, participacion).
    const enrSql = (ref: string, state: string): string =>
      `INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state) VALUES ($1, '${ref}', 'subject-841', 'part-841', '${state}')`;
    await uow.withTenantTx(t, (tx) => tx.query(enrSql("e841-a", "ACTIVE"), [t]));
    await assert.rejects(
      () => uow.withTenantTx(t, (tx) => tx.query(enrSql("e841-b", "ACTIVE"), [t])),
      (e: unknown) => codeOf(e) === "23505" && constraintOf(e) === "enrollment_single_active_uq",
    );
    await assert.rejects(
      () => uow.inTenant(t, (tx) => tx.enrollmentRepo.save({ enrollmentRef: "e841-c", tenantId: t, subjectRef: "subject-841", participationRef: "part-841", state: "ACTIVE" })),
      (e: unknown) => e instanceof DomainError && e.code === "ERR-TC-03",
    );
    await uow.withTenantTx(t, (tx) => tx.query(enrSql("e841-b", "CLOSED"), [t]));
  } finally {
    await pool.end();
  }
});
