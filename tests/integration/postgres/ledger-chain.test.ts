// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 (subconjunto IT0 de ADR-011 / S4-16: triggers de
// inmutabilidad incluidos TRUNCATE y migrator, recomputacion de la cadena SHA-256 por tenant y
// lista blanca; HMAC y ancla fuera), db/migrations/0013_ledger_chain.sql, common.spec.yaml
// ledgerEnvelope. TEST-CNS-913 (verificador contra mutaciones reales, CHECK/UNIQUE de la cadena y
// lista blanca = CHECK), 914 (concurrencia por tenant), 915 (inmutabilidad para migrator y
// superusuario). Requiere Postgres real (harness.ts); skip sin entorno. Solo datos sinteticos.

import { payloadFor, revocationRequestedPayload } from "../../contract/ledger-payload-fixtures.ts";
import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { verifyLedgerChain } from "../../../src/server/modules/common/ledger-chain.ts";
import { LEDGER_EVENT_TYPES } from "../../../src/server/modules/common/ledger-event-types.ts";
import type { LedgerEventInput } from "../../../src/server/ports/ledger.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, type PgTestContext } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const H = "a".repeat(64);
const Z = "0".repeat(64);

function ev(tenantId: string, aggregateId: string, extra: Partial<LedgerEventInput> = {}): LedgerEventInput {
  return {
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId,
    actorType: "HUMAN",
    expectedSequence: 0,
    ...extra,
    payload: extra.payload ?? payloadFor(extra.eventType ?? "REVOCATION_REQUESTED", `${aggregateId}:${extra.expectedSequence ?? 0}`),
  };
}

async function withUow<T>(ctx: PgTestContext, work: (uow: PgUnitOfWork) => Promise<T>, max = 4): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max });
  try {
    return await work(new PgUnitOfWork(pool));
  } finally {
    await pool.end();
  }
}

/**
 * Mutacion "como atacante con privilegios": triggers de inmutabilidad desactivados y, ademas, el CHECK
 * `occurred_at = now()` (que se reevalua en todo UPDATE) retirado. Restaura ambos (triggers ENABLE ALWAYS y
 * el CHECK como NOT VALID, igual que en 0013).
 */
async function withMutationsAllowed(admin: import("pg").Client, mutate: () => Promise<void>): Promise<void> {
  await admin.query("ALTER TABLE integrity.audit_event DISABLE TRIGGER USER");
  await admin.query("ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_occurred_at_is_now");
  try {
    await mutate();
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_occurred_at_is_now CHECK (occurred_at = pg_catalog.now()) NOT VALID");
    await admin.query("ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_update_delete");
    await admin.query("ALTER TABLE integrity.audit_event ENABLE ALWAYS TRIGGER audit_event_no_truncate");
  }
}

async function seedChain(uow: PgUnitOfWork, tenant: string, n: number): Promise<void> {
  const agg = fixtureUuid(`agg-${tenant}`);
  await uow.inTenant(tenant, async ({ ledger }) => {
    for (let i = 0; i < n; i++) {
      await ledger.append(ev(tenant, agg, { expectedSequence: i, eventType: i === 0 ? "REVOCATION_REQUESTED" : "REVOCATION_VERIFIED" }));
    }
  });
}

pgTest("TEST-CNS-913 pg: verifyLedgerChain detecta la mutacion de una fila hecha como superusuario con los triggers desactivados; CHECK/UNIQUE de la cadena y lista blanca igual al CHECK", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  await withUow(ctx, async (uow) => {
    const verify = (t: string) => uow.inTenant(t, ({ ledger }) => verifyLedgerChain(ledger, t));

    // Tres tenants con cadena de 4 eslabones, cada uno para una mutacion distinta.
    const [tPayload, tGap, tHash, tClean] = ["t913-payload", "t913-gap", "t913-hash", "t913-clean"].map(fixtureUuid) as [string, string, string, string];
    for (const t of [tPayload, tGap, tHash, tClean]) await seedChain(uow, t, 4);
    for (const t of [tPayload, tGap, tHash, tClean]) assert.deepEqual(await verify(t), { ok: true, verified: 4 });

    // Sin desactivar los triggers la mutacion es imposible incluso para el superusuario (INV-CM-01).
    await assert.rejects(() => admin.query("UPDATE integrity.audit_event SET payload = '{}'::jsonb WHERE tenant_id = $1", [tPayload]), (e: unknown) => codeOf(e) === "23000");

    await withMutationsAllowed(admin, async () => {
      await admin.query("UPDATE integrity.audit_event SET payload = '{\"step\": 99}'::jsonb WHERE tenant_id = $1 AND chain_seq = 2", [tPayload]);
      await admin.query("DELETE FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = 2", [tGap]);
      await admin.query("UPDATE integrity.audit_event SET event_hash = $2 WHERE tenant_id = $1 AND chain_seq = 3", [tHash, H]);
    });
    const triggers = (await admin.query<{ tgenabled: string }>("SELECT tgenabled FROM pg_trigger WHERE tgrelid = 'integrity.audit_event'::regclass AND NOT tgisinternal")).rows;
    assert.ok(triggers.length === 2 && triggers.every((t) => t.tgenabled === "A"), "triggers restaurados ENABLE ALWAYS");

    assert.deepEqual(await verify(tPayload), { ok: false, verified: 1, brokenAt: { chainSeq: 2, aggregateId: fixtureUuid(`agg-${tPayload}`), sequence: 2, reason: "PAYLOAD_HASH_MISMATCH" } });
    const gap = await verify(tGap);
    assert.ok(!gap.ok && gap.brokenAt.chainSeq === 3 && gap.brokenAt.reason === "CHAIN_SEQ_GAP" && gap.verified === 1, JSON.stringify(gap));
    const hash = await verify(tHash);
    assert.ok(!hash.ok && hash.brokenAt.chainSeq === 3 && hash.brokenAt.reason === "EVENT_HASH_MISMATCH" && hash.verified === 2, JSON.stringify(hash));
    assert.deepEqual(await verify(tClean), { ok: true, verified: 4 }, "la mutacion de otro tenant no afecta a este");
  });

  // CHECK/UNIQUE de la cadena (la base no recomputa el hash, pero fuerza forma, unicidad y presencia).
  const t = fixtureUuid("t913-checks");
  const insert = (over: Record<string, string>): Promise<unknown> => {
    const cols: Record<string, string> = {
      tenant_id: `'${t}'`, aggregate_type: "'A'", aggregate_id: `'agg-${Math.random().toString(16).slice(2)}'`, sequence: "1",
      event_type: "'CONSENT_GRANTED'", actor_type: "'HUMAN'", payload: "'{}'::jsonb",
      chain_seq: "1", payload_hash: `'${H}'`, previous_event_hash: `'${Z}'`, event_hash: `'${H}'`, ...over,
    };
    for (const k of Object.keys(cols)) if (cols[k] === "") delete cols[k];
    return admin.query(`INSERT INTO integrity.audit_event (${Object.keys(cols).join(",")}) VALUES (${Object.values(cols).join(",")})`);
  };
  await assert.rejects(() => insert({ chain_seq: "", payload_hash: "", previous_event_hash: "", event_hash: "" }), (e: unknown) => codeOf(e) === "23514", "INSERT sin eslabon (chain_required)");
  await assert.rejects(() => insert({ event_hash: "" }), (e: unknown) => codeOf(e) === "23514", "eslabon incompleto (all_or_none)");
  await assert.rejects(() => insert({ event_hash: "'XYZ'" }), (e: unknown) => codeOf(e) === "23514", "forma sha256");
  await assert.rejects(() => insert({ chain_seq: "0" }), (e: unknown) => codeOf(e) === "23514");
  await assert.rejects(() => insert({ event_type: "'NOT_IN_VOCABULARY'" }), (e: unknown) => codeOf(e) === "23514", "lista blanca");
  await insert({});
  await assert.rejects(() => insert({ event_hash: `'${"b".repeat(64)}'`, previous_event_hash: `'${"c".repeat(64)}'` }), (e: unknown) => codeOf(e) === "23505", "UNIQUE (tenant, chain_seq)");
  await assert.rejects(() => insert({ chain_seq: "2", event_hash: `'${"b".repeat(64)}'` }), (e: unknown) => codeOf(e) === "23505", "UNIQUE (tenant, previous_event_hash): sin bifurcaciones");
  await insert({ chain_seq: "2", previous_event_hash: `'${H}'`, event_hash: `'${"b".repeat(64)}'` });

  // La lista blanca del CHECK es exactamente la del codigo.
  const def = (await admin.query<{ d: string }>(
    "SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'integrity.audit_event'::regclass AND conname = 'audit_event_event_type_allowlist'",
  )).rows[0]?.d ?? "";
  const inDb = [...def.matchAll(/'([A-Z_]+)'::text/g)].map((m) => m[1] as string).sort();
  assert.deepEqual(inDb, [...LEDGER_EVENT_TYPES].sort());

  // El runtime no puede fijar eventId/environment pero si las 4 columnas de la cadena (grants por columna).
  for (const [column, expected] of [["chain_seq", true], ["payload_hash", true], ["previous_event_hash", true], ["event_hash", true], ["event_id", false], ["environment", true], ["occurred_at", true], ["data_class", false]] as const) {
    const r = (await admin.query<{ p: boolean }>("SELECT has_column_privilege('app_rw', 'integrity.audit_event', $1, 'INSERT') AS p", [column])).rows[0];
    assert.equal(r?.p, expected, `INSERT(${column})`);
  }
});

pgTest("TEST-CNS-914 pg: appends concurrentes del mismo tenant (conexiones distintas) no rompen la cadena: chainSeq 1..N sin huecos y verifyLedgerChain ok; tenants intercalados tienen cadenas independientes", async (ctx) => {
  await withUow(ctx, async (uow) => {
    const ta = fixtureUuid("t914-a");
    const tb = fixtureUuid("t914-b");
    const N = 12;
    const jobs: Array<Promise<unknown>> = [];
    for (let i = 0; i < N; i++) {
      for (const t of [ta, tb]) {
        jobs.push(uow.inTenant(t, ({ ledger }) => ledger.append(ev(t, fixtureUuid(`agg914-${t}-${i}`), { payload: revocationRequestedPayload(`i${i}`) }))));
      }
    }
    await Promise.all(jobs);
    for (const t of [ta, tb]) {
      const rows = await uow.inTenant(t, ({ ledger }) => ledger.readChain(t));
      assert.deepEqual(rows.map((r) => r.chainSeq), Array.from({ length: N }, (_, i) => i + 1), "sin huecos ni duplicados");
      assert.deepEqual(await uow.inTenant(t, ({ ledger }) => verifyLedgerChain(ledger, t)), { ok: true, verified: N });
    }
    // Varios appends del MISMO agregado dentro de una sola tx tambien encadenan.
    const t = fixtureUuid("t914-c");
    await seedChain(uow, t, 3);
    assert.deepEqual(await uow.inTenant(t, ({ ledger }) => verifyLedgerChain(ledger, t)), { ok: true, verified: 3 });
  }, 8);
});

pgTest("TEST-CNS-915 pg: los triggers de inmutabilidad bloquean UPDATE/DELETE/TRUNCATE tambien para consent_migrator (y SET ROLE consent_owner) y para superusuario con session_replication_role=replica", async (ctx) => {
  const tenant = fixtureUuid("t915");
  await withUow(ctx, (uow) => seedChain(uow, tenant, 2));
  const admin = await ctx.connectAsSuperuser();
  const count = async (): Promise<number> => (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [tenant])).rows[0]?.n ?? -1;
  const hashes = async (): Promise<string> => JSON.stringify((await admin.query("SELECT payload, event_hash FROM integrity.audit_event WHERE tenant_id = $1 ORDER BY chain_seq", [tenant])).rows);
  const before = await hashes();

  // El migrador es miembro del dueno: tiene los privilegios de UPDATE/DELETE/TRUNCATE. Bajo RLS FORCE
  // y sin policy para el dueno no ve filas (la mutacion no alcanza nada); si ademas quita FORCE RLS
  // (puede, es el dueno) la fila SI es visible y el trigger ENABLE ALWAYS la rechaza. TRUNCATE no pasa
  // por RLS: lo ataja el trigger de sentencia.
  const mutations = ["UPDATE integrity.audit_event SET payload = '{}'::jsonb", "DELETE FROM integrity.audit_event", "UPDATE integrity.audit_event SET event_hash = repeat('b', 64)"];
  for (const viaSetRole of [false, true]) {
    const mig = await ctx.connectAs("consent_migrator");
    if (viaSetRole) await mig.query("SET ROLE consent_owner");
    for (const sql of mutations) {
      const r = await mig.query(sql);
      assert.equal(r.rowCount, 0, `migrador (setRole=${viaSetRole}) bajo FORCE RLS no alcanza filas: ${sql}`);
    }
    for (const sql of mutations) {
      await mig.query("BEGIN");
      await mig.query("ALTER TABLE integrity.audit_event NO FORCE ROW LEVEL SECURITY");
      await assert.rejects(() => mig.query(sql), (e: unknown) => codeOf(e) === "23000", `migrador sin FORCE RLS (setRole=${viaSetRole}): ${sql}`);
      await mig.query("ROLLBACK");
    }
    await assert.rejects(() => mig.query("TRUNCATE integrity.audit_event"), (e: unknown) => codeOf(e) === "23000", `migrador (setRole=${viaSetRole}): TRUNCATE`);
  }
  const force = (await admin.query<{ f: boolean }>("SELECT relforcerowsecurity AS f FROM pg_class WHERE oid = 'integrity.audit_event'::regclass")).rows[0]?.f;
  assert.equal(force, true, "FORCE RLS restaurado (los ALTER fueron transaccionales)");

  for (const replica of [false, true]) {
    if (replica) await admin.query("SET session_replication_role = replica");
    for (const sql of ["UPDATE integrity.audit_event SET event_hash = repeat('b', 64)", "UPDATE integrity.audit_event SET chain_seq = chain_seq + 10", "DELETE FROM integrity.audit_event", "TRUNCATE integrity.audit_event"]) {
      await assert.rejects(() => admin.query(sql), (e: unknown) => codeOf(e) === "23000", `superusuario (replica=${replica}): ${sql}`);
    }
    if (replica) await admin.query("SET session_replication_role = origin");
  }
  assert.equal(await count(), 2, "las filas siguen");
  assert.equal(await hashes(), before, "y sin cambios");
});

pgTest("TEST-CNS-916 pg: el CLI ledger-verify-cli sale 0 con la cadena integra, 2 con un eslabon roto y 1 sin entorno LOCAL o con tenant invalido; sin PII en la salida", async (ctx) => {
  const { spawnSync } = await import("node:child_process");
  const t = fixtureUuid("t916");
  await withUow(ctx, (uow) => seedChain(uow, t, 3));
  const run = (args: string[], env: Record<string, string>) =>
    spawnSync(process.execPath, ["src/infra/adapters/postgres/ledger-verify-cli.ts", ...args], { env: { PATH: process.env.PATH ?? "", ...env }, encoding: "utf8" });
  const good = { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("app_rw") };

  const ok = run([t], good);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /3 eslabones integros/);
  // P2-2: la cola se imprime y las expectativas se hacen cumplir.
  const tailHash = /eventHash=([0-9a-f]{64})/.exec(ok.stdout)?.[1] ?? "";
  assert.match(ok.stdout, /cola: chainSeq=3 eventHash=[0-9a-f]{64}/);
  assert.equal(run([t, "--expect-min-seq=3", `--expect-tail=${tailHash}`], good).status, 0);
  const truncated = run([t, "--expect-min-seq=4"], good);
  assert.equal(truncated.status, 2);
  assert.match(truncated.stderr, /posible truncamiento/);
  assert.equal(run([t, `--expect-tail=${"b".repeat(64)}`], good).status, 2);
  assert.equal(run([t, "--bogus"], good).status, 1);
  assert.equal(run([t, "--expect-tail=zz"], good).status, 1);
  assert.equal(run([t], { ...good, CNS_ENVIRONMENT: "STAGING" }).status, 1);
  assert.equal(run(["no-es-uuid"], good).status, 1);

  const admin = await ctx.connectAsSuperuser();
  await withMutationsAllowed(admin, async () => {
    await admin.query("UPDATE integrity.audit_event SET payload = '{\"step\": 77}'::jsonb WHERE tenant_id = $1 AND chain_seq = 3", [t]);
  });
  const broken = run([t], good);
  assert.equal(broken.status, 2);
  assert.match(broken.stderr, /chainSeq=3.*PAYLOAD_HASH_MISMATCH.*2 eslabones previos/);
  assert.ok(!broken.stderr.includes(t) && !broken.stdout.includes(t), "la salida no repite el tenant ni payloads");
});

pgTest("TEST-CNS-920 pg: el CLI falla si hay una fila sin eslabon (chain_seq NULL) posterior al inicio de la cadena; las filas legado anteriores no cuentan", async (ctx) => {
  const { spawnSync } = await import("node:child_process");
  const t = fixtureUuid("t920");
  const admin = await ctx.connectAsSuperuser();
  // Legado: fila sin eslabon ANTERIOR a la cadena (como las previas a 0013): se inserta sin CHECK de cadena.
  await admin.query("ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_chain_required");
  try {
    await admin.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload)
       VALUES ($1, 'Legacy', 'legacy-1', 1, 'TENANT_STATUS_CHANGED', 'HUMAN', '{}'::jsonb)`,
      [t],
    );
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_chain_required CHECK (chain_seq IS NOT NULL) NOT VALID");
  }
  await withUow(ctx, (uow) => seedChain(uow, t, 2));
  const run = () =>
    spawnSync(process.execPath, ["src/infra/adapters/postgres/ledger-verify-cli.ts", t], {
      env: { PATH: process.env.PATH ?? "", CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("app_rw") },
      encoding: "utf8",
    });
  const legacyOnly = run();
  assert.equal(legacyOnly.status, 0, legacyOnly.stderr + legacyOnly.stdout);

  // Posterior: alguien evade el CHECK (lo retira) e inserta una fila sin eslabon despues del inicio de la cadena.
  await admin.query("ALTER TABLE integrity.audit_event DROP CONSTRAINT audit_event_chain_required");
  try {
    await admin.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload)
       VALUES ($1, 'Evasion', 'evasion-1', 1, 'TENANT_STATUS_CHANGED', 'HUMAN', '{}'::jsonb)`,
      [t],
    );
  } finally {
    await admin.query("ALTER TABLE integrity.audit_event ADD CONSTRAINT audit_event_chain_required CHECK (chain_seq IS NOT NULL) NOT VALID");
  }
  const evaded = run();
  assert.equal(evaded.status, 2);
  assert.match(evaded.stderr, /1 filas sin eslabon/);
});

pgTest("TEST-CNS-921 pg: app_rw no puede falsear occurred_at ni environment: la base los fuerza (occurred_at = now() de la tx, environment = catalogo); eventHash v2 los cubre", async (ctx) => {
  const t = fixtureUuid("t921");
  const app = await ctx.connectAs("app_rw");
  const insert = (over: string, params: unknown[]): Promise<unknown> =>
    app.query(
      `INSERT INTO integrity.audit_event (tenant_id, aggregate_type, aggregate_id, sequence, event_type, actor_type, payload,
                                          chain_seq, payload_hash, previous_event_hash, event_hash, ${over})
       VALUES ($1, 'A', 'b', 1, 'CONSENT_GRANTED', 'HUMAN', '{}'::jsonb, 1, repeat('a', 64), repeat('0', 64), repeat('a', 64), ${params.length > 1 ? "$2" : "$2"})`,
      [t, ...params],
    );
  for (const [col, value] of [["environment", "STAGING"], ["occurred_at", "2020-01-01T00:00:00Z"]] as const) {
    await app.query("BEGIN");
    await app.query("SELECT set_config('app.tenant_id', $1, true)", [t]);
    await assert.rejects(() => insert(col, [value]), (e: unknown) => codeOf(e) === "23514", `falsear ${col}`);
    await app.query("ROLLBACK");
  }
  // Y el adaptador (legitimo) si escribe: el eslabon queda verificable con v2.
  await withUow(ctx, async (uow) => {
    await seedChain(uow, t, 2);
    const rows = await uow.inTenant(t, ({ ledger }) => ledger.readChain(t));
    assert.match(rows[0]?.occurredAt ?? "", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    assert.equal(rows[0]?.environment, "LOCAL");
    assert.deepEqual(await uow.inTenant(t, ({ ledger }) => verifyLedgerChain(ledger, t)), { ok: true, verified: 2 });
  });
});
