// Gobierna: ADR-010 rev. 5 (LG-3/LG-5, F-A10-30), opcion A de Carlos (2026-10-14), invitation.spec.yaml I9/GRD-IV-10/ERR-IV-09,
// db/migrations/0044_invitation_cancel_subject_mismatch_fn.sql. La cancelacion por "No es mi estudiante" es UNA funcion SECURITY DEFINER
// (case_state.cancel_invitation_subject_mismatch); app_rw no puede insertar Invitation:INVITATION_CANCELLED ni dejar CANCELLED por su cuenta.
// TEST-CNS-1443 (comportamiento de la funcion bajo app_rw), TEST-CNS-1444 (privilegios y allowlist). SYNTHETIC ONLY.
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const DM = "dm-1443";

const SEED_INV = (ref: string, state: string, dm: string | null): string =>
  `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, bound_decision_maker_ref)
   VALUES ($1, '${ref}', 'c', 'p', 's-${ref}', '${state}', ${dm === null ? "NULL" : `'${dm}'`})`;

pgTest("TEST-CNS-1443 pg (app_rw): case_state.cancel_invitation_subject_mismatch: VERIFIED -> CANCELLED con exactamente un INVITATION_CANCELLED; idempotente; otro DM, estado no VERIFIED y tenant ajeno se rechazan sin escribir (GRD-IV-10, ERR-IV-09)", async (ctx) => {
  const A = fixtureUuid("t1443-a");
  const B = fixtureUuid("t1443-b");
  const admin = await ctx.connectAsSuperuser();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    await admin.query(SEED_INV("v1443", "VERIFIED", DM), [A]);
    await admin.query(SEED_INV("s1443", "SENT", null), [A]);
    await admin.query(SEED_INV("c1443", "COMPLETED", DM), [A]);
    const call = (tenant: string, ref: string, dm: string, seq = 0): Promise<unknown> =>
      uow.withTenantTx(tenant, (tx) => tx.query("SELECT case_state.cancel_invitation_subject_mismatch($1, $2, $3)", [ref, dm, seq]));
    const events = async (ref: string): Promise<number> =>
      (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'INVITATION_CANCELLED'", [A, ref])).rows[0]?.n ?? -1;
    const stateOf = async (ref: string): Promise<string | undefined> =>
      (await admin.query<{ state: string }>("SELECT state FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2", [A, ref])).rows[0]?.state;

    // Rechazos antes de escribir: otro DM (IV009), estado SENT y COMPLETED (IV009), tenant ajeno e inexistente (RV001).
    await assert.rejects(() => call(A, "v1443", "otro-dm"), (e: unknown) => codeOf(e) === "IV009");
    await assert.rejects(() => call(A, "s1443", DM), (e: unknown) => codeOf(e) === "IV009");
    await assert.rejects(() => call(A, "c1443", DM), (e: unknown) => codeOf(e) === "IV009");
    await assert.rejects(() => call(B, "v1443", DM), (e: unknown) => codeOf(e) === "RV001");
    await assert.rejects(() => call(A, "no-existe", DM), (e: unknown) => codeOf(e) === "RV001");
    assert.equal(await stateOf("v1443"), "VERIFIED");
    assert.equal(await events("v1443"), 0);
    // Secuencia desfasada -> RV409 antes de los guards de estado, sin escribir.
    await assert.rejects(() => call(A, "v1443", DM, 7), (e: unknown) => codeOf(e) === "RV409");
    assert.equal(await stateOf("v1443"), "VERIFIED");

    // Camino feliz: CANCELLED + un solo evento con el payload del contrato, escrito por transition_owner (actor DECISION_MAKER).
    await call(A, "v1443", DM);
    assert.equal(await stateOf("v1443"), "CANCELLED");
    assert.equal(await events("v1443"), 1);
    const ev = (await admin.query<{ payload: unknown; actor_type: string; actor_role: string; sequence: number }>(
      "SELECT payload, actor_type, actor_role, sequence FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = 'v1443' AND event_type = 'INVITATION_CANCELLED'", [A])).rows[0];
    assert.deepEqual(ev?.payload, { invitationRef: "v1443", reasonCode: "SUBJECT_MISMATCH_REPORTED" });
    assert.equal(ev?.actor_type, "HUMAN");
    assert.equal(ev?.actor_role, "DECISION_MAKER");
    assert.equal(ev?.sequence, 1);

    // Idempotente para el mismo DM (misma secuencia vigente = 1): no escribe de nuevo; otro DM sigue sin obtener el acuse.
    await call(A, "v1443", DM, 1);
    assert.equal(await events("v1443"), 1);
    await assert.rejects(() => call(A, "v1443", "otro-dm", 1), (e: unknown) => codeOf(e) === "IV009");
    assert.equal(await events("v1443"), 1);
  } finally {
    await pool.end();
  }
});

pgTest("TEST-CNS-1444 pg: app_rw sigue SIN poder insertar el par Invitation:INVITATION_CANCELLED en el ledger ni dejar una invitacion CANCELLED (ni des-cancelarla); la funcion es de transition_owner con EXECUTE solo app_rw (0041, 0044)", async (ctx) => {
  const T = fixtureUuid("t1444");
  const admin = await ctx.connectAsSuperuser();
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    await admin.query(SEED_INV("v1444", "VERIFIED", DM), [T]);
    await admin.query(SEED_INV("x1444", "VERIFIED", DM), [T]);
    await admin.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE tenant_id = $1 AND invitation_ref = 'x1444'", [T]);
    // Insert directo del par en el ledger: RLS (allowlist de 19 pares, 0041).
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query(
        `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, actor_role, payload)
         VALUES (app.current_tenant_id(), 'Invitation', 'v1444', 1, 'INVITATION_CANCELLED', 'HUMAN', 'DECISION_MAKER', '{"invitationRef":"v1444","reasonCode":"SUBJECT_MISMATCH_REPORTED"}'::jsonb)`)),
      (e: unknown) => codeOf(e) === "42501",
    );
    // UPDATE directo a CANCELLED (WITH CHECK) y des-cancelar (USING excluye CANCELLED: 0 filas).
    await assert.rejects(
      () => uow.withTenantTx(T, (tx) => tx.query("UPDATE app.invitation SET state = 'CANCELLED' WHERE invitation_ref = 'v1444'")),
      (e: unknown) => codeOf(e) === "42501",
    );
    const undo = await uow.withTenantTx(T, (tx) => tx.query("UPDATE app.invitation SET state = 'VERIFIED' WHERE invitation_ref = 'x1444'"));
    assert.equal((undo as { rowCount: number | null }).rowCount, 0);
    assert.equal((await admin.query<{ state: string }>("SELECT state FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = 'x1444'", [T])).rows[0]?.state, "CANCELLED");
    assert.equal((await admin.query<{ state: string }>("SELECT state FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = 'v1444'", [T])).rows[0]?.state, "VERIFIED");

    // Catalogo: funcion, dueno, EXECUTE exacto y allowlist de 19 pares sin el par.
    const f = (await admin.query<{ owner: string; secdef: boolean; cfg: string[] }>(
      "SELECT pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS secdef, p.proconfig AS cfg FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'cancel_invitation_subject_mismatch'")).rows[0];
    assert.equal(f?.owner, "transition_owner");
    assert.equal(f?.secdef, true);
    assert.deepEqual(f?.cfg, ["search_path=pg_catalog, pg_temp"]);
    const ex = async (role: string): Promise<boolean> =>
      (await admin.query<{ x: boolean }>("SELECT has_function_privilege($1, p.oid, 'EXECUTE') AS x FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace WHERE s.nspname = 'case_state' AND p.proname = 'cancel_invitation_subject_mismatch'", [role])).rows[0]?.x ?? false;
    assert.equal(await ex("app_rw"), true);
    for (const role of ["worker", "platform_rw", "integrity_verifier"]) assert.equal(await ex(role), false, role);
    const expr = (await admin.query<{ e: string }>("SELECT pg_get_expr(polwithcheck, polrelid) AS e FROM pg_policy WHERE polrelid = 'integrity.audit_event'::regclass AND polname = 'audit_event_tenant_insert'")).rows[0]?.e ?? "";
    assert.equal(expr.includes("Invitation:INVITATION_CANCELLED"), false);
    assert.equal([...expr.matchAll(/'([A-Za-z]+:[A-Z_]+)'/g)].length, 19);
  } finally {
    await pool.end();
  }
});
