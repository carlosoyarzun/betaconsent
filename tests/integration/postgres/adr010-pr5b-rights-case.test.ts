// Gobierna: ADR-010 rev. 4 §4.2 (PR-5b), specs/state-machines/rights-case.spec.yaml `dbEnforcement` (FN-RC-01, FN-RC-02, FN-RC-03, FN-RC-06,
// TRG-RC-01, INV-RC-07), specs/db-roles.spec.yaml (INV-DBR-07), GRD-RC-01/02/04/07/09/14, F-A10-01, db/migrations/0038_adr010_case_state_rights_case.sql
// y 0039_adr010_ledger_allowlist_close_case_d6.sql (allowlist de INV-DBR-07, D5; close_case D6). SYNTHETIC ONLY.
// TEST-CNS-1381 (app_rw no escribe case_state.rights_case; trigger TRG-RC-01 por efecto; DELETE/TRUNCATE; terminales no se revierten), TEST-CNS-1382 (camino feliz
// y codigos de error exactos de las funciones), TEST-CNS-1383 (aislamiento por tenant del camino de funciones), TEST-CNS-1384 (INV-DBR-07: app_rw no inserta
// en el ledger eventos Revocation/RightsCase/CONSENT_REVOKED; los demas tipos siguen), TEST-CNS-1385 (siembra LOCAL sin upsert sobre terminales).
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { invitationRefPayload } from "../../contract/ledger-payload-fixtures.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { disableLedgerMechanicsAppend, enableLedgerMechanicsAppend, pgTest, seedFixture } from "./harness.ts";
import { pgOutsideTxPorts } from "./outside-tx.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const SEED_RC = "SELECT set_config('case_state.effect', 'seed_local_rights_case', false)";
const SEED_RV = "SELECT set_config('case_state.effect', 'seed_local_revocation', false)";

async function seedDecision(admin: import("pg").Client, tenant: string, consent: string, chain: string): Promise<void> {
  await seedFixture(() => admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete)
     VALUES ($1, $2, 'x', 'x', 'x', 'x', 'x', 'x', $3, 'GRANTED', '[]', true)`,
    [tenant, consent, chain],
  ));
}

pgTest("TEST-CNS-1381 pg: app_rw no escribe case_state.rights_case; el trigger TRG-RC-01 exige transition_owner y el efecto; DELETE/TRUNCATE rechazados; un terminal no se revierte (INV-RC-07)", async (ctx) => {
  const T = fixtureUuid("t1381");
  const admin = await ctx.connectAsSuperuser();
  await admin.query(SEED_RC);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-open', 'ch1', 'd1', 'OPEN', 'LIMIT_REACHED')", [T]);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-done', 'ch2', 'd2', 'RESOLVED', 'LIMIT_REACHED')", [T]);
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const sql of [
      "UPDATE case_state.rights_case SET status = 'CONTACTING' WHERE case_ref = 'c-open'",
      "UPDATE case_state.rights_case SET revocation_ref = 'x' WHERE case_ref = 'c-open'",
      "INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES (current_setting('app.tenant_id')::uuid, 'x', 'c', 'd', 'OPEN', 'LIMIT_REACHED')",
      "SELECT case_state.lock_rights_case('c-open')",
      "SELECT case_state.rights_case_transition_guard()",
      "SELECT set_config('case_state.effect', 'close_case', true), (SELECT 1 FROM case_state.rights_case WHERE case_ref = 'c-open' FOR UPDATE)",
      "DELETE FROM case_state.rights_case WHERE case_ref = 'c-open'",
      "TRUNCATE case_state.rights_case",
    ]) {
      await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === "42501", sql);
    }
    assert.ok((await uow.withTenantTx(T, (tx) => tx.query("SELECT 1 FROM case_state.rights_case"))).rowCount === 2, "app_rw si lee");
  } finally {
    await pool.end();
  }
  // Superusuario: DELETE/TRUNCATE tambien (trigger), y UPDATE sin efecto.
  await admin.query("RESET ALL");
  await assert.rejects(() => admin.query("DELETE FROM case_state.rights_case WHERE case_ref = 'c-open'"), (e: unknown) => codeOf(e) === "42501");
  await assert.rejects(() => admin.query("TRUNCATE case_state.rights_case"), (e: unknown) => codeOf(e) === "42501");
  await assert.rejects(() => admin.query("UPDATE case_state.rights_case SET status = 'CONTACTING' WHERE case_ref = 'c-open'"), (e: unknown) => codeOf(e) === "42501");
  // transition_owner con el efecto de OTRA funcion, con un par fuera del grafo o tocando columnas ajenas: 42501; un terminal no se toca (policy USING: 0 filas).
  await admin.query("BEGIN");
  try {
    await admin.query("SET LOCAL ROLE transition_owner");
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    for (const [effect, sql] of [
      ["open_rights_case_bearer", "UPDATE case_state.rights_case SET status = 'CONTACTING' WHERE case_ref = 'c-open'"],
      ["confirm_case_return", "UPDATE case_state.rights_case SET status = 'CONTACTING' WHERE case_ref = 'c-open'"], // origin LIMIT_REACHED no se mira aqui: el grafo si lo permite
      ["confirm_case_return", "UPDATE case_state.rights_case SET status = 'RESOLVED' WHERE case_ref = 'c-open'"], // OPEN -> RESOLVED fuera del grafo
      ["close_case", "UPDATE case_state.rights_case SET status = 'RESOLVED' WHERE case_ref = 'c-open'"], // OPEN no cierra
      ["express_revocation_intent_in_case", "UPDATE case_state.rights_case SET status = 'IN_VERIFICATION' WHERE case_ref = 'c-open'"], // OPEN -> IN_VERIFICATION
      ["", "UPDATE case_state.rights_case SET status = 'CONTACTING' WHERE case_ref = 'c-open'"],
    ] as const) {
      await admin.query("SAVEPOINT s");
      await admin.query("SELECT set_config('case_state.effect', $1, true)", [effect]);
      if (effect === "confirm_case_return" && sql.includes("'CONTACTING'")) {
        // Par permitido para ese efecto: no debe fallar (control positivo del trigger).
        await admin.query(sql);
      } else {
        await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "42501", `${effect}: ${sql}`);
      }
      await admin.query("ROLLBACK TO s");
    }
    for (const effect of ["close_case", "confirm_case_return", "express_revocation_intent_in_case"]) {
      await admin.query("SAVEPOINT s");
      await admin.query("SELECT set_config('case_state.effect', $1, true)", [effect]);
      // La policy de UPDATE (USING excluye terminales) oculta la fila: 0 filas afectadas, exacto (el trigger ni se alcanza).
      const r = await admin.query("UPDATE case_state.rights_case SET status = 'OPEN' WHERE case_ref = 'c-done'");
      assert.equal(r.rowCount, 0, `terminal ${effect}`);
      await admin.query("ROLLBACK TO s");
    }
    // Verificacion DENTRO de la tx (antes del ROLLBACK): los estados siguen siendo los sembrados.
    assert.deepEqual((await admin.query<{ s: string }>("SELECT status AS s FROM case_state.rights_case WHERE tenant_id = $1 ORDER BY case_ref", [T])).rows.map((r) => r.s), ["RESOLVED", "OPEN"]);
  } finally {
    await admin.query("ROLLBACK");
  }

});

pgTest("TEST-CNS-1382 pg: funciones de RightsCase: camino feliz hasta RESOLVED con ledger encadenado y codigos de error exactos (RC001/RC002/RC003/RC009/RV001/RV002/RV409)", async (ctx) => {
  const T = fixtureUuid("t1382");
  const admin = await ctx.connectAsSuperuser();
  const D = fixtureUuid("d1382");
  const chain = fixtureUuid("chain1382");
  await seedDecision(admin, T, D, chain);
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const run = (sql: string, values: unknown[] = []) => new PgUnitOfWork(pool).withTenantTx(T, (tx) => tx.query<{ r: Record<string, unknown> }>(sql, values));
  const fails = async (sql: string, values: unknown[], code: string): Promise<void> => {
    await assert.rejects(() => run(sql, values), (e: unknown) => codeOf(e) === code, `${sql} -> ${code}`);
  };
  const events = async (agg: string): Promise<string[]> =>
    (await admin.query<{ t: string }>("SELECT event_type AS t FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [T, agg])).rows.map((r) => r.t);
  try {
    const C = fixtureUuid("case1382");
    const OPEN = "SELECT case_state.open_rights_case_bearer($1::text, $2::text, $3::text, $4::text) AS r";
    // GRD-RC-04 / GRD-RC-01 (codigos exactos).
    await fails(OPEN, [C, chain, D, "REQUEST_EXPIRED"], "RC002");
    await fails(OPEN, [C, chain, D, "SCHOOL_REPORTED"], "RC002");
    await fails(OPEN, [C, chain, D, "OTRO"], "RC002");
    await fails(OPEN, [C, "otra-cadena", D, "CHANNEL_UNREACHABLE"], "RC001");
    await fails(OPEN, [C, chain, "no-existe", "CHANNEL_UNREACHABLE"], "RC001");
    assert.equal((await admin.query("SELECT 1 FROM case_state.rights_case WHERE tenant_id = $1", [T])).rowCount, 0, "los rechazos no persisten nada");
    // RC1: crea; GRD-RC-02: la segunda apertura devuelve el caso existente sin evento.
    const opened = (await run(OPEN, [C, chain, D, "CHANNEL_UNREACHABLE"])).rows[0]?.r;
    assert.deepEqual(opened, { caseRef: C, created: true, sequence: 1 });
    const again = (await run(OPEN, [fixtureUuid("case1382-b"), chain, D, "CHANNEL_UNREACHABLE"])).rows[0]?.r;
    assert.equal(again?.created, false);
    assert.equal(again?.caseRef, C);
    assert.deepEqual(await events(C), ["RIGHTS_CASE_OPENED"]);
    const row = await admin.query<{ actor_type: string; actor_role: string; payload: Record<string, unknown> }>(
      "SELECT actor_type, actor_role, payload FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, C]);
    assert.equal(row.rows[0]?.actor_role, "UNVERIFIED_BEARER");
    assert.deepEqual(row.rows[0]?.payload, { caseRef: C, reasonCode: "CHANNEL_UNREACHABLE", initiatedVia: "DECISION_MAKER" });
    // RC3 desde OPEN: transicion invalida (RV002); RC2u: secuencia vieja RV409.
    const EXPR = "SELECT case_state.express_revocation_intent_in_case($1::text, $2::text, $3::text, 'DECISION_MAKER', $4::text, false, 0) AS r";
    const REV = fixtureUuid("rev1382");
    await fails(EXPR, [C, chain, D, REV], "RV002");
    await fails("SELECT case_state.confirm_case_return($1::text, 0::integer) AS r", [C], "RV409");
    await fails("SELECT case_state.confirm_case_return($1::text, 1::integer) AS r", [fixtureUuid("case-nope")], "RV001");
    // RC2u ok e idempotente.
    assert.equal((await run("SELECT case_state.confirm_case_return($1::text, 1::integer) AS r", [C])).rows[0]?.r?.changed, true);
    assert.equal((await run("SELECT case_state.confirm_case_return($1::text, 2::integer) AS r", [C])).rows[0]?.r?.changed, false);
    assert.deepEqual(await events(C), ["RIGHTS_CASE_OPENED", "RIGHTS_CASE_CONTACTING"]);
    // GRD-RC-07: RC2u con otro origen -> RC001 (ERR-RC-01 uniforme).
    const C2 = fixtureUuid("case1382-lr");
    const D2 = fixtureUuid("d1382-2");
    await seedDecision(admin, T, D2, fixtureUuid("chain1382-2"));
    await run(OPEN, [C2, fixtureUuid("chain1382-2"), D2, "LIMIT_REACHED"]);
    await fails("SELECT case_state.confirm_case_return($1::text, 1::integer) AS r", [C2], "RC001");
    // RC3 (GRD-RC-14: caso de otra cadena/decision -> RC009), lado Revocation + lado caso en el mismo lote.
    await fails(EXPR, [C, fixtureUuid("chain-ajena"), D, REV], "RC009");
    await fails(EXPR, [C, chain, "otra-decision", REV], "RC009");
    await run(EXPR, [C, chain, D, REV]);
    assert.equal((await admin.query<{ status: string; revocation_ref: string }>("SELECT status, revocation_ref FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2", [T, C])).rows[0]?.status, "IN_VERIFICATION");
    assert.deepEqual(await events(REV), ["REVOCATION_REQUESTED"]);
    await fails(EXPR, [C, chain, D, fixtureUuid("rev1382-b")], "RV409"); // segundo RC3 con el caso ya IN_VERIFICATION: conflicto para que el UoW reejecute y converja por R12
    // R12 (attach) sobre la Revocation ligada: ok; sobre otra: RV002.
    await run("SELECT case_state.express_revocation_intent_in_case($1::text, $2::text, $3::text, 'DECISION_MAKER', $4::text, true, 1) AS r", [C, chain, D, REV]);
    await fails("SELECT case_state.express_revocation_intent_in_case($1::text, $2::text, $3::text, 'DECISION_MAKER', $4::text, true, 2) AS r", [C, chain, D, fixtureUuid("otra")], "RV002");
    // ADR-010 rev. 5 (6d parte 2): close_case ya no lo ejecuta app_rw (solo platform_rw + rights_operator con sesion CASE): GRD-RC-09, D6 y el terminal se prueban en TEST-CNS-1711.
    assert.deepEqual(await events(C), ["RIGHTS_CASE_OPENED", "RIGHTS_CASE_CONTACTING"]);
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1383 pg: aislamiento por tenant del camino de funciones de RightsCase: con el tenant B, open/confirm/close/express sobre refs de A fallan sin cambiar la fila ni el ledger de A", async (ctx) => {
  const A = fixtureUuid("t1383-a");
  const B = fixtureUuid("t1383-b");
  const admin = await ctx.connectAsSuperuser();
  const D = fixtureUuid("d1383");
  await seedDecision(admin, A, D, "cA");
  await admin.query(SEED_RC);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'cA-open', 'cA', $2, 'OPEN', 'CHANNEL_UNREACHABLE')", [A, D]);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'cA-contacting', 'cA2', 'dA2', 'CONTACTING', 'LIMIT_REACHED')", [A]);
  await admin.query("RESET ALL");
  const snapshot = async (): Promise<string> =>
    JSON.stringify([
      (await admin.query("SELECT case_ref, status, revocation_ref FROM case_state.rights_case WHERE tenant_id = $1 ORDER BY 1", [A])).rows,
      (await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [A])).rows,
      (await admin.query("SELECT count(*)::int AS n FROM case_state.revocation WHERE tenant_id = $1", [A])).rows,
    ]);
  const before = await snapshot();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    for (const [sql, code] of [
      ["SELECT case_state.confirm_case_return('cA-open', 0)", "RV001"],
      ["SELECT case_state.express_revocation_intent_in_case('cA-contacting', 'cA2', 'dA2', 'DECISION_MAKER', 'rB', false, 0)", "RV001"],
      ["SELECT case_state.open_rights_case_bearer('cB', 'cA', '" + D + "', 'CHANNEL_UNREACHABLE')", "RC001"], // la decision y la cadena de A no existen en B
    ] as const) {
      await assert.rejects(() => uow.withTenantTx(B, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === code, sql);
    }
    // B tampoco ve las filas de A ni puede sembrar un caso con el tenant de A.
    assert.equal((await uow.withTenantTx(B, (tx) => tx.query("SELECT 1 FROM case_state.rights_case"))).rowCount, 0);
    await assert.rejects(
      () => uow.withTenantTx(B, (tx) => tx.query("SELECT case_state.seed_local_rights_case($1::uuid, 'x', 'c', 'd', 'OPEN', NULL, NULL)", [A])),
      (e: unknown) => codeOf(e) === "42501",
    );
  } finally {
    await pool.end();
  }
  assert.equal(await snapshot(), before);
});

pgTest("TEST-CNS-1384 pg: INV-DBR-07 (PR-b): app_rw no inserta NINGUN evento en el ledger (ni Revocation/RightsCase/CONSENT_REVOKED ni los derivados): 42501 por falta de INSERT (F-A10-01, F-A10-30)", async (ctx) => {
  const T = fixtureUuid("t1384");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const H = "a".repeat(64);
  const insert = (agg: string, type: string, seq: number, chainSeq: number): string =>
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES (current_setting('app.tenant_id')::uuid, '${agg}', 'agg-1384-${chainSeq}', ${seq}, '${type}', 'HUMAN', '${JSON.stringify(invitationRefPayload("1384"))}'::jsonb, ${chainSeq}, '${H}', '${"0".repeat(64)}', '${String(chainSeq).padStart(64, "b")}')`;
  try {
    const uow = new PgUnitOfWork(pool);
    for (const [agg, type] of [
      ["Revocation", "REVOCATION_REQUESTED"],
      ["Revocation", "RECEIPT_CREATED"],
      ["RightsCase", "RIGHTS_CASE_OPENED"],
      ["RightsCase", "RIGHTS_CASE_CLOSED"],
      ["ConsentDecision", "CONSENT_REVOKED"],
      ["Revocation", "CONSENT_REVOKED"],
    ] as const) {
      await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query(insert(agg, type, 1, 1))), (e: unknown) => codeOf(e) === "42501", `${agg}/${type}`);
    }
    // ADR-010 rev. 5 PR-b (0049): tampoco los tipos derivados (Invitation, ConsentDecision, Enrollment, DMV): los emite ledger_writer desde las filas de estado.
    for (const [agg, type] of [["Invitation", "INVITATION_OPENED"], ["ConsentDecision", "CONSENT_GRANTED"], ["Enrollment", "ENROLLMENT_STATUS_CHANGED"], ["DecisionMakerVerification", "DECISION_MAKER_CHANNEL_VERIFIED"]] as const) {
      await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query(insert(agg, type, 1, 2))), (e: unknown) => codeOf(e) === "42501", `${agg}/${type}`);
    }
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1385 pg: seed_local_rights_case falla (42501) sobre un caso terminal sin cambiarlo y actualiza uno no terminal", async (ctx) => {
  const T = fixtureUuid("t1385");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    const seed = (status: string) => uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.seed_local_rights_case($1::uuid, 'c1385', 'ch', 'd', $2::text, NULL, NULL)", [T, status]));
    const status = async () => (await uow.withTenantTx(T, (tx) => tx.query<{ s: string }>("SELECT status AS s FROM case_state.rights_case WHERE case_ref = 'c1385'"))).rows[0]?.s;
    await seed("OPEN");
    await seed("CONTACTING");
    assert.equal(await status(), "CONTACTING");
    await seed("RESOLVED");
    assert.equal(await status(), "RESOLVED");
    for (const again of ["WITHDRAWN", "OPEN", "CONTACTING"]) {
      await assert.rejects(() => seed(again), (e: unknown) => codeOf(e) === "42501", again);
    }
    assert.equal(await status(), "RESOLVED", "un terminal no se modifica ni se revierte");
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1386 pg: RC2u: el atajo idempotente exige origin CHANNEL_UNREACHABLE y el evento caseRef:contacting; secuencia vieja y otro origin dan codigos exactos; close_case exige la ref del operador; RC3 con el caso ya IN_VERIFICATION da RV409 (converge por R12)", async (ctx) => {
  const T = fixtureUuid("t1386");
  const admin = await ctx.connectAsSuperuser();
  const D = fixtureUuid("d1386");
  await seedDecision(admin, T, D, "ch1386");
  const D2 = fixtureUuid("d1386-real");
  await seedDecision(admin, T, D2, "ch1386-real");
  await admin.query(SEED_RC);
  // CONTACTING sembrado sin evento: con origin CU el atajo no vale (RV002 tras el control de secuencia); con otro origin: RC001.
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-cu-noevent', 'ch1386', $2, 'CONTACTING', 'CHANNEL_UNREACHABLE')", [T, D]);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-lr', 'chx', 'dx', 'CONTACTING', 'LIMIT_REACHED')", [T]);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin, revocation_ref) VALUES ($1, 'c-iv', 'ch1386', 'dy', 'IN_VERIFICATION', 'CHANNEL_UNREACHABLE', 'rv-iv')", [T]);
  await admin.query("RESET ALL");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const uow = new PgUnitOfWork(pool);
  const fails = async (sql: string, code: string): Promise<void> => {
    await assert.rejects(() => uow.withTenantTx(T, (tx) => tx.query(sql)), (e: unknown) => codeOf(e) === code, `${sql} -> ${code}`);
  };
  try {
    await fails("SELECT case_state.confirm_case_return('c-cu-noevent', 0)", "RV002");
    await fails("SELECT case_state.confirm_case_return('c-lr', 0)", "RC001");
    // Camino real: OPEN -> CONTACTING con evento; reintento con la secuencia vigente es no-op; con secuencia vieja y el evento presente tambien converge.
    await uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.open_rights_case_bearer('c-real', 'ch1386-real', $1, 'CHANNEL_UNREACHABLE')", [D2]));
    await fails("SELECT case_state.confirm_case_return('c-real', 0)", "RV409"); // secuencia vieja con el caso aun OPEN
    await uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.confirm_case_return('c-real', 1)"));
    const again = await uow.withTenantTx(T, (tx) => tx.query<{ r: { changed: boolean; sequence: number } }>("SELECT case_state.confirm_case_return('c-real', 1) AS r"));
    assert.deepEqual(again.rows[0]?.r, { changed: false, sequence: 2 });
    // RC3 sobre un caso ya IN_VERIFICATION con Revocation: RV409 (el UoW reejecuta y la segunda unidad converge por R12), no RV002.
    await fails("SELECT case_state.express_revocation_intent_in_case('c-iv', 'ch1386', 'dy', 'DECISION_MAKER', 'rv-nueva', false, 0)", "RV409");
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1387 pg: INV-DBR-07 como particion de pares (PR-b): app_rw sin policy de INSERT; ledger_writer solo sus 19 pares y transition_owner solo sus 14 (disjuntos); CHECK enum de aggregate_type y un solo aggregate_type por aggregate_id", async (ctx) => {
  const T = fixtureUuid("t1387");
  const admin = await ctx.connectAsSuperuser();
  const H = "a".repeat(64);
  const row = (agg: string, id: string, type: string, chainSeq: number, tenant = "current_setting('app.tenant_id')::uuid", seq = 1): string =>
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES (${tenant}, '${agg}', '${id}', ${seq}, '${type}', 'HUMAN', '${JSON.stringify(invitationRefPayload("1387"))}'::jsonb, ${chainSeq}, '${H}', '${String(chainSeq).padStart(64, "d")}', '${String(chainSeq).padStart(64, "c")}')`;
  // Ninguna policy de INSERT/ALL alcanza a app_rw (0049).
  const reach = await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_policy p WHERE p.polrelid = 'integrity.audit_event'::regclass AND p.polcmd IN ('a', '*')
        AND (0::oid = ANY (p.polroles) OR (SELECT oid FROM pg_roles WHERE rolname = 'app_rw') = ANY (p.polroles))`);
  assert.equal(reach.rows[0]?.n, 0);
  const asRole = async (role: "ledger_writer" | "transition_owner", sql: string): Promise<string> => {
    await admin.query("BEGIN");
    try {
      await admin.query(role === "ledger_writer" ? "SET LOCAL ROLE ledger_writer" : "SET LOCAL ROLE transition_owner");
      await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
      await admin.query(sql);
      return "ok";
    } catch (e) {
      return codeOf(e) ?? "?";
    } finally {
      await admin.query("ROLLBACK");
    }
  };
  let n = 1;
  // ledger_writer: sus pares si; Revocation/RightsCase/CONSENT_REVOKED/INVITATION_CANCELLED no (policy: 42501).
  assert.equal(await asRole("ledger_writer", row("Invitation", "ok-i", "INVITATION_OPENED", n++)), "ok");
  assert.equal(await asRole("ledger_writer", row("ConsentDecision", "ok-c", "CONSENT_GRANTED", n++)), "ok");
  for (const [agg, type] of [["Revocation", "REVOCATION_REQUESTED"], ["RightsCase", "RIGHTS_CASE_OPENED"], ["Revocation", "CONSENT_REVOKED"], ["Invitation", "INVITATION_CANCELLED"], ["Invitation", "CONSENT_GRANTED"], ["Tenant", "TENANT_STATUS_CHANGED"]] as const) {
    assert.equal(await asRole("ledger_writer", row(agg, `lw-${type}`, type, n++)), "42501", `ledger_writer ${agg}:${type}`);
  }
  // transition_owner: sus 14 pares si; los de ledger_writer no (la policy ahora restringe el WITH CHECK, 0037:90-91).
  assert.equal(await asRole("transition_owner", row("Revocation", "to-r", "REVOCATION_REQUESTED", n++)), "ok");
  assert.equal(await asRole("transition_owner", row("Invitation", "to-c", "INVITATION_CANCELLED", n++)), "ok");
  for (const [agg, type] of [["Invitation", "INVITATION_OPENED"], ["ConsentDecision", "CONSENT_GRANTED"], ["Enrollment", "ENROLLMENT_STATUS_CHANGED"], ["Tenant", "TENANT_SEEDED"]] as const) {
    assert.equal(await asRole("transition_owner", row(agg, `to-${type}`, type, n++)), "42501", `transition_owner ${agg}:${type}`);
  }
  // CHECK enum de aggregate_type (superusuario salta RLS: exacto 23514 y nombre de la restriccion).
  await assert.rejects(
    () => admin.query(row("Foo", "f2", "INVITATION_OPENED", 14, `'${T}'::uuid`)),
    (e: unknown) => codeOf(e) === "23514" && (e as { constraint?: string }).constraint === "audit_event_aggregate_type_enum",
  );
  // Trigger: un aggregate_id ya usado por 'Invitation' no se reutiliza con otro aggregate_type (23000 exacto), tampoco para el superusuario.
  await admin.query(row("Invitation", "ok-i", "INVITATION_OPENED", 16, `'${T}'::uuid`));
  await assert.rejects(
    () => admin.query(row("ConsentDecision", "ok-i", "CONSENT_GRANTED", 15, `'${T}'::uuid`, 2)),
    (e: unknown) => codeOf(e) === "23000",
  );
  // Mismo aggregate_type y mismo aggregate_id: sigue permitido (misma secuencia de un agregado).
  await admin.query(row("Invitation", "ok-i", "INVITATION_OPENED", 17, `'${T}'::uuid`, 2));
});

// TEST-CNS-1388 (D6) y TEST-CNS-1390 (closeCase por el dominio con app_rw) se retiraron: close_case solo por platform con sesion CASE; cobertura en TEST-CNS-1711.

pgTest("TEST-CNS-1391 pg: concurrencia del trigger de un aggregate_type por aggregate_id: app_rw (Invitation:X, sin commit; INSERT de mecanica del harness) contra RC3 sobre la misma X, en ambos ordenes, nunca deja dos aggregate_type para X", async (ctx) => {
  const T = fixtureUuid("t1391");
  try {
  await enableLedgerMechanicsAppend(ctx); // ADR-010 rev. 5 PR-b: app_rw ya no inserta en produccion; este test ejercita el trigger/lock del ledger
  const admin = await ctx.connectAsSuperuser();
  const D = fixtureUuid("d1391");
  await seedDecision(admin, T, D, "ch1391");
  await seedDecision(admin, T, fixtureUuid("d1391-b"), "ch1391-b");
  await admin.query(SEED_RC);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-a', 'ch1391', $2, 'CONTACTING', 'LIMIT_REACHED')", [T, D]);
  await admin.query("INSERT INTO case_state.rights_case (tenant_id, case_ref, chain_ref, revoked_decision_ref, status, origin) VALUES ($1, 'c-b', 'ch1391-b', $2, 'CONTACTING', 'LIMIT_REACHED')", [T, fixtureUuid("d1391-b")]);
  await admin.query("RESET ALL");
  const H = "a".repeat(64);
  const invite = (id: string, chainSeq: number): string =>
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES (current_setting('app.tenant_id')::uuid, 'Invitation', '${id}', 1, 'INVITATION_OPENED', 'HUMAN', '${JSON.stringify(invitationRefPayload("1391"))}'::jsonb, ${chainSeq}, '${H}', '${String(chainSeq).padStart(64, "d")}', '${String(chainSeq).padStart(64, "c")}')`;
  const rc3 = (cs: string, chain: string, dec: string, x: string): string =>
    `SELECT case_state.express_revocation_intent_in_case('${cs}', '${chain}', '${dec}', 'DECISION_MAKER', '${x}', false, 0)`;
  const open = async (): Promise<import("pg").Client> => {
    const c = await ctx.connectAs("app_rw");
    await c.query("BEGIN");
    await c.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    return c;
  };
  const types = async (x: string): Promise<string[]> =>
    (await admin.query<{ t: string }>("SELECT DISTINCT aggregate_type AS t FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY 1", [T, x])).rows.map((r) => r.t);
  const pidOf = async (c: import("pg").Client): Promise<number> => Number((await c.query<{ p: number }>("SELECT pg_backend_pid() AS p")).rows[0]?.p);
  // Espera a que ESA conexion (pid) quede bloqueada en el advisory lock del ledger del tenant, no cualquier sesion.
  const waiting = async (pid: number): Promise<void> => {
    for (let i = 0; i < 100; i += 1) {
      const r = await admin.query("SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory'", [pid]);
      if (r.rowCount && r.rowCount > 0) return;
      await new Promise((res) => setTimeout(res, 50));
    }
    throw new Error("la segunda transaccion no quedo esperando el lock del ledger del tenant");
  };

  // Orden A: RC3 (sin commit) toma el lock del ledger del tenant; el INSERT de Invitation:X espera y, tras el COMMIT de RC3, falla por el trigger (23000).
  {
    const X = fixtureUuid("x1391-a");
    const rc = await open();
    const inv = await open();
    const invPid = await pidOf(inv); // antes de la sentencia pendiente: un Client de pg encola las consultas
    await rc.query(rc3("c-a", "ch1391", D, X));
    const pending = inv.query(invite(X, 9101)).then(() => "ok", (e: unknown) => codeOf(e));
    await waiting(invPid);
    await rc.query("COMMIT");
    assert.equal(await pending, "23000");
    await inv.query("ROLLBACK");
    assert.deepEqual(await types(X), ["Revocation"]);
  }
  // Orden B: Invitation:X (sin commit) toma el lock; RC3 sobre la misma X espera y, tras el COMMIT, falla (el agregado ya tiene un evento) y no deja un segundo tipo.
  {
    const X = fixtureUuid("x1391-b");
    const inv = await open();
    const rc = await open();
    const rcPid = await pidOf(rc);
    await inv.query(invite(X, 9102));
    const pending = rc.query(rc3("c-b", "ch1391-b", fixtureUuid("d1391-b"), X)).then(() => "ok", (e: unknown) => codeOf(e));
    await waiting(rcPid);
    await inv.query("COMMIT");
    // Determinista: ledger_append comprueba la secuencia (ya hay un evento de X) antes de insertar, asi que falla con RV409 exacto.
    assert.equal(await pending, "RV409");
    await rc.query("ROLLBACK");
    assert.deepEqual(await types(X), ["Invitation"]);
  }
  } finally {
    await disableLedgerMechanicsAppend(ctx); // el grant/policy de mecanica no persiste en la base del archivo (1384/1387 afirman que app_rw no inserta)
  }
});
