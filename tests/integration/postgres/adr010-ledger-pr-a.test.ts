// Gobierna: ADR-010 rev. 5 (PR-a, cierre parcial de F-A10-30; LG-3 y LG-5 de Carlos, 2026-10-13), specs/db-roles.spec.yaml INV-DBR-07,
// db/migrations/0041_adr010_ledger_allowlist_19_dedupe_estricto.sql. SYNTHETIC ONLY.
// TEST-CNS-1440 (los 5 pares sin productor son rechazados para app_rw con 42501 y la allowlist es exactamente de 19 pares),
// TEST-CNS-1441 (dedupe estricto de case_state.ledger_append: payload, actor o tipo distintos abortan con RV002 sin escribir),
// TEST-CNS-1442 (dedupe identico sigue siendo idempotente: mismo evento, sin fila nueva).
// Cada test filtra por su tenant/aggregate_id propios. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { invitationRefPayload } from "../../contract/ledger-payload-fixtures.ts";
import { pgTest } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;

const REMOVED_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ["Tenant", "TENANT_STATUS_CHANGED"],
  ["SchoolParticipation", "SCHOOL_PARTICIPATION_STATUS_CHANGED"],
  ["Invitation", "INVITATION_TOKEN_ROTATED"],
  ["Invitation", "INVITATION_EXPIRED"],
  ["Invitation", "INVITATION_CANCELLED"],
];

pgTest("TEST-CNS-1440 pg: la allowlist de INSERT de app_rw son exactamente 19 pares y los 5 sin productor (TENANT_STATUS_CHANGED, SCHOOL_PARTICIPATION_STATUS_CHANGED, INVITATION_TOKEN_ROTATED, INVITATION_EXPIRED, INVITATION_CANCELLED) dan 42501", async (ctx) => {
  const T = fixtureUuid("t1440");
  const admin = await ctx.connectAsSuperuser();
  const H = "a".repeat(64);
  const row = (agg: string, id: string, type: string, chainSeq: number): string =>
    `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload, chain_seq, payload_hash, previous_event_hash, event_hash)
     VALUES (current_setting('app.tenant_id')::uuid, '${agg}', '${id}', 1, '${type}', 'HUMAN', '${JSON.stringify(invitationRefPayload("1440"))}'::jsonb, ${chainSeq}, '${H}', '${String(chainSeq).padStart(64, "d")}', '${String(chainSeq).padStart(64, "c")}')`;
  // Catalogo: la expresion WITH CHECK contiene exactamente 19 literales Agregado:Evento, ninguno de los 5 retirados.
  const pol = await admin.query<{ e: string }>(
    "SELECT pg_get_expr(p.polwithcheck, p.polrelid) AS e FROM pg_policy p WHERE p.polrelid = 'integrity.audit_event'::regclass AND p.polname = 'audit_event_tenant_insert'");
  const expr = pol.rows[0]?.e ?? "";
  const pairs = new Set([...expr.matchAll(/'([A-Za-z]+:[A-Z_]+)'/g)].map((m) => m[1]));
  assert.equal(pairs.size, 19);
  for (const [agg, ev] of REMOVED_PAIRS) assert.ok(!pairs.has(`${agg}:${ev}`), `${agg}:${ev} fuera de la allowlist`);
  const reach = await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_policy p WHERE p.polrelid = 'integrity.audit_event'::regclass AND p.polcmd IN ('a', '*')
        AND (0::oid = ANY (p.polroles) OR (SELECT oid FROM pg_roles WHERE rolname = 'app_rw') = ANY (p.polroles))`);
  assert.equal(reach.rows[0]?.n, 1, "una sola policy de INSERT alcanza a app_rw");
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    let seq = 1;
    for (const [agg, ev] of REMOVED_PAIRS) {
      await assert.rejects(
        () => uow.withTenantTx(T, (tx) => tx.query(row(agg, `agg1440-${ev}`, ev, seq++))),
        (e: unknown) => codeOf(e) === "42501",
        `${agg}:${ev}`,
      );
    }
    // Control positivo: un par que sigue en la allowlist se inserta.
    await uow.withTenantTx(T, (tx) => tx.query(row("Invitation", "agg1440-ok", "INVITATION_OPENED", seq++)));
  } finally {
    await pool.end();
  }
  const n = await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id LIKE 'agg1440-%'", [T]);
  assert.equal(n.rows[0]?.n, 1, "solo el control positivo quedo escrito");
});

/** Llama case_state.ledger_append como transition_owner en una tx del tenant; devuelve [sequence, deduped] o el SQLSTATE. */
async function append(admin: import("pg").Client, tenant: string, agg: string, over: { eventType?: string; actorType?: string; actorRole?: string | null; payload?: unknown } = {}): Promise<{ seq: number; deduped: boolean }> {
  const r = await admin.query<{ o_sequence: number; o_deduped: boolean }>(
    "SELECT o_sequence, o_deduped FROM case_state.ledger_append('Invitation', $1, $2, $3, $4, NULL, NULL, $5::jsonb, $6, 0)",
    [agg, over.eventType ?? "INVITATION_OPENED", over.actorType ?? "HUMAN", over.actorRole === undefined ? "DECISION_MAKER" : over.actorRole, JSON.stringify(over.payload ?? invitationRefPayload("1441")), `key-${agg}`],
  );
  void tenant;
  return { seq: r.rows[0]?.o_sequence ?? -1, deduped: r.rows[0]?.o_deduped ?? false };
}

async function inTransitionOwnerTx(admin: import("pg").Client, tenant: string, fn: () => Promise<void>): Promise<void> {
  await admin.query("BEGIN");
  try {
    await admin.query("SET LOCAL ROLE transition_owner");
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
    await fn();
  } finally {
    await admin.query("ROLLBACK");
  }
}

pgTest("TEST-CNS-1441 pg: dedupe estricto de case_state.ledger_append: la misma clave con payload, actor o tipo distintos aborta con RV002 y no escribe ni devuelve el evento previo", async (ctx) => {
  const T = fixtureUuid("t1441");
  const agg = "agg1441";
  const admin = await ctx.connectAsSuperuser();
  await inTransitionOwnerTx(admin, T, async () => {
    const first = await append(admin, T, agg);
    assert.deepEqual(first, { seq: 1, deduped: false });
    const variants: ReadonlyArray<[string, Parameters<typeof append>[3]]> = [
      ["payload distinto", { payload: { ...invitationRefPayload("1441"), invitationRef: fixtureUuid("otra") } }],
      ["actor_type distinto", { actorType: "SYSTEM_GUARD" }],
      ["actor_role distinto", { actorRole: "UNVERIFIED_BEARER" }],
      ["event_type distinto", { eventType: "INVITATION_VERIFIED" }],
    ];
    for (const [label, over] of variants) {
      await admin.query("SAVEPOINT v");
      await assert.rejects(() => append(admin, T, agg, over), (e: unknown) => codeOf(e) === "RV002", label);
      await admin.query("ROLLBACK TO v");
    }
    const n = await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, agg]);
    assert.equal(n.rows[0]?.n, 1, "ninguna variante escribio");
  });
});

pgTest("TEST-CNS-1442 pg: el dedupe identico sigue siendo idempotente (misma secuencia, deduped = true, sin fila nueva) y el orden de claves del payload no cuenta", async (ctx) => {
  const T = fixtureUuid("t1442");
  const agg = "agg1442";
  const admin = await ctx.connectAsSuperuser();
  await inTransitionOwnerTx(admin, T, async () => {
    const payload = invitationRefPayload("1442");
    assert.deepEqual(await append(admin, T, agg, { payload }), { seq: 1, deduped: false });
    assert.deepEqual(await append(admin, T, agg, { payload }), { seq: 1, deduped: true });
    const reordered = Object.fromEntries(Object.entries(payload).reverse());
    assert.deepEqual(await append(admin, T, agg, { payload: reordered }), { seq: 1, deduped: true });
    const n = await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, agg]);
    assert.equal(n.rows[0]?.n, 1);
  });
});
