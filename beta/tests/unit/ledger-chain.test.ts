// Gobierna: plan v2 H1-02. Vectores dorados del verificador TS portado.
// Reutiliza los vectores de TEST-CNS-912 (tests/unit/common/ledger-chain.test.ts@9345b78): canonicalJson, hashes fijos, mutaciones de la cadena.
// La paridad TS<->SQL (TEST-CNS-1456/TEST-CNS-912 en el repo anterior) corre contra Postgres en tests/integration/ledger.test.ts.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson, computeEventHash, computePayloadHash, LEDGER_GENESIS_HASH, verifyChainRows, type ChainRow } from "../../src/ledger/ledger-chain.ts";
import { isLedgerEventType, LEDGER_EVENT_TYPES } from "../../src/ledger/ledger-event-types.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const T = "00000000-0000-4000-8000-000000000001";

function buildChain(n: number): ChainRow[] {
  const rows: ChainRow[] = [];
  let previous = LEDGER_GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const payload = { step: i, kind: "SYNTHETIC" };
    const base = {
      tenantId: T,
      chainSeq: i,
      aggregateType: "Invitation",
      aggregateId: `agg-${i % 2}`,
      sequence: Math.ceil(i / 2),
      eventType: "INVITATION_CREATED",
      actorType: "HUMAN",
      actorRole: null,
      recordedByRef: null,
      cosignedByRef: null,
      idempotencyKeyHash: null,
      occurredAt: `2026-10-01T12:00:${String(i).padStart(2, "0")}.000000Z`,
      environment: "LOCAL",
      payloadHash: computePayloadHash(payload),
      previousEventHash: previous,
    };
    const eventHash = computeEventHash(base);
    rows.push({ ...base, payload, eventHash });
    previous = eventHash;
  }
  return rows;
}

test("TEST-CNS-912 canonicalJson: claves ordenadas, sin espacios, undefined descartado y no enteros rechazados", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: null }, u: undefined }), '{"a":{"c":null,"d":[3,{"x":2,"y":1}]},"b":1}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
  assert.throws(() => canonicalJson({ x: 1.5 }), TypeError);
  assert.throws(() => canonicalJson({ x: 2 ** 60 }), TypeError);
});

test("TEST-CNS-912 vector fijo: el hash no cambia sin un cambio de versión de la canonicalización", () => {
  assert.equal(computePayloadHash({ a: 1 }), "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862");
  assert.equal(computePayloadHash({}), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
});

test("TEST-CNS-912 verifyChainRows: cadena íntegra y primer eslabón roto por cada tipo de mutación", () => {
  assert.deepEqual(verifyChainRows(buildChain(5)), { ok: true, verified: 5 });
  assert.deepEqual(verifyChainRows([]), { ok: true, verified: 0 });
  const cases: Array<[string, (rows: ChainRow[]) => ChainRow[], number, string, number]> = [
    ["payload mutado", (r) => r.map((x, i) => (i === 2 ? { ...x, payload: { step: 99, kind: "SYNTHETIC" } } : x)), 3, "PAYLOAD_HASH_MISMATCH", 2],
    ["occurredAt mutado", (r) => r.map((x, i) => (i === 2 ? { ...x, occurredAt: "2026-10-01T12:59:59.000000Z" } : x)), 3, "EVENT_HASH_MISMATCH", 2],
    ["environment mutado", (r) => r.map((x, i) => (i === 1 ? { ...x, environment: "REAL" } : x)), 2, "EVENT_HASH_MISMATCH", 1],
    ["campo del sobre mutado", (r) => r.map((x, i) => (i === 1 ? { ...x, aggregateId: "otro" } : x)), 2, "EVENT_HASH_MISMATCH", 1],
    ["fila borrada (hueco)", (r) => r.filter((_, i) => i !== 2), 4, "CHAIN_SEQ_GAP", 2],
    ["filas reordenadas", (r) => [r[1] as ChainRow, r[0] as ChainRow, ...r.slice(2)], 2, "CHAIN_SEQ_GAP", 0],
    ["previous roto", (r) => r.map((x, i) => (i === 4 ? { ...x, previousEventHash: "b".repeat(64) } : x)), 5, "PREVIOUS_HASH_MISMATCH", 4],
    ["hash mal formado", (r) => r.map((x, i) => (i === 0 ? { ...x, eventHash: "xyz" } : x)), 1, "MALFORMED_HASH", 0],
    ["primer eslabón sin génesis", (r) => r.map((x, i) => (i === 0 ? { ...x, previousEventHash: "c".repeat(64) } : x)), 1, "PREVIOUS_HASH_MISMATCH", 0],
  ];
  for (const [label, mutate, chainSeq, reason, verified] of cases) {
    const report = verifyChainRows(mutate(buildChain(5)));
    assert.equal(report.ok, false, label);
    if (!report.ok) {
      assert.equal(report.brokenAt.chainSeq, chainSeq, label);
      assert.equal(report.brokenAt.reason, reason, label);
      assert.equal(report.verified, verified, label);
    }
  }
  const rows = buildChain(2);
  const bad = { ...(rows[1] as ChainRow), eventType: "NOT_IN_VOCABULARY" };
  const report = verifyChainRows([rows[0] as ChainRow, { ...bad, eventHash: computeEventHash(bad) }]);
  assert.equal(report.ok === false && report.brokenAt.reason, "EVENT_TYPE_NOT_ALLOWED");
});

test("la lista blanca TS es idéntica al CHECK audit_event_event_type_allowlist vigente (0001, ampliado por 0004)", () => {
  assert.equal(new Set(LEDGER_EVENT_TYPES).size, LEDGER_EVENT_TYPES.length);
  // La definición vigente es la ÚLTIMA ADD CONSTRAINT en orden de migración (0001, luego 0004 que la reemplaza).
  const dir = join(HERE, "..", "..", "db", "migrations");
  const sql = ["0001_catalog_school_ledger.sql", "0004_manage_link.sql"].map((n) => readFileSync(join(dir, n), "utf8")).join("\n");
  const blocks = [...sql.matchAll(/audit_event_event_type_allowlist CHECK \(event_type IN \(([\s\S]*?)\)\s*\)/g)];
  const block = blocks[blocks.length - 1]?.[1] ?? "";
  const inSql = [...block.matchAll(/'([A-Z_]+)'/g)].map((m) => m[1] as string);
  assert.ok(inSql.length > 0);
  assert.deepEqual([...inSql].sort(), [...LEDGER_EVENT_TYPES].sort());
  assert.equal(isLedgerEventType("OTP_ISSUED"), false);
});
