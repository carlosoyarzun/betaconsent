// Gobierna: ADR-010 rev. 6 §2 (oraculo unico TS `ledger-chain.ts`: verificador incremental con las mismas `ChainBreakReason`), §3 fila PR-6f, F-PR6E-06, SEC-06-4 (C8: MALFORMED_PAYLOAD por tenant). SYNTHETIC ONLY. Sin BD.
// TEST-CNS-1735: createChainVerifier ≡ verifyChainRows en cadenas integras y rotas, con cortes de lote en todos los offsets, y cada ChainBreakReason; el payload no canonicalizable es MALFORMED_PAYLOAD (no lanza).

import assert from "node:assert/strict";
import test from "node:test";

import { computeEventHash, createChainVerifier, verifyChainRows } from "../../../src/server/modules/common/ledger-chain.ts";
import type { ChainBreakReason, ChainRow } from "../../../src/server/modules/common/ledger-chain.ts";
import { auditTenantChain } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import { buildChain, inBatches, TENANT_A } from "./ledger-chain-fixture.ts";

type Mutation = [label: string, mutate: (rows: ChainRow[]) => ChainRow[], reason: ChainBreakReason];

const MUTATIONS: Mutation[] = [
  ["payload mutado", (r) => r.map((x, i) => (i === 2 ? { ...x, payload: { step: 99, kind: "SYNTHETIC" } } : x)), "PAYLOAD_HASH_MISMATCH"],
  ["campo del sobre mutado", (r) => r.map((x, i) => (i === 3 ? { ...x, aggregateId: "otro" } : x)), "EVENT_HASH_MISMATCH"],
  ["fila borrada (hueco)", (r) => r.filter((_, i) => i !== 4), "CHAIN_SEQ_GAP"],
  ["previous roto", (r) => r.map((x, i) => (i === 5 ? { ...x, previousEventHash: "b".repeat(64) } : x)), "PREVIOUS_HASH_MISMATCH"],
  ["hash mal formado", (r) => r.map((x, i) => (i === 1 ? { ...x, eventHash: "xyz" } : x)), "MALFORMED_HASH"],
];

test("TEST-CNS-1735 createChainVerifier ≡ verifyChainRows: misma salida fila a fila en la cadena integra y en cada mutacion (cada ChainBreakReason)", () => {
  const ok = buildChain(8);
  const inc = createChainVerifier();
  for (const row of ok) assert.equal(inc.push(row), null);
  assert.deepEqual(inc.report(), verifyChainRows(ok));
  assert.deepEqual(inc.report(), { ok: true, verified: 8 });
  assert.deepEqual(createChainVerifier().report(), { ok: true, verified: 0 });

  for (const [label, mutate, reason] of MUTATIONS) {
    const rows = mutate(buildChain(8));
    const batch = verifyChainRows(rows);
    const v = createChainVerifier();
    let first: ReturnType<typeof v.push> = null;
    for (const row of rows) {
      const b = v.push(row);
      if (first === null && b !== null) first = b;
    }
    assert.deepEqual(v.report(), batch, label);
    assert.equal(first?.reason, reason, label);
    assert.deepEqual(v.broken, first, `${label}: la rotura es la primera y queda fija`);
  }
  // Tipo fuera de lista con hashes consistentes.
  const rows = buildChain(3);
  const bad = { ...(rows[2] as ChainRow), eventType: "NOT_IN_VOCABULARY" };
  const rehashed = [rows[0] as ChainRow, rows[1] as ChainRow, { ...bad, eventHash: computeEventHash(bad) }];
  assert.equal(verifyChainRows(rehashed).ok === false && (verifyChainRows(rehashed) as { brokenAt: { reason: string } }).brokenAt.reason, "EVENT_TYPE_NOT_ALLOWED");
});

test("TEST-CNS-1735 cortes de lote en todos los offsets: el resultado por lotes (auditTenantChain) no depende del tamano del lote", async () => {
  const n = 9;
  for (const [label, mutate] of [["integra", (r: ChainRow[]) => r] as const, ...MUTATIONS.map(([l, m]) => [l, m] as const)]) {
    const rows = mutate(buildChain(n));
    const expected = verifyChainRows(rows);
    for (let size = 1; size <= n + 1; size++) {
      const result = await auditTenantChain(TENANT_A, inBatches(rows, size), 0);
      assert.equal(result.verified, expected.verified, `${label} lote ${size}`);
      assert.deepEqual(result.broken === null ? { ok: true, verified: result.verified } : { ok: false, verified: result.verified, brokenAt: result.broken }, expected, `${label} lote ${size}`);
      assert.equal(result.events, rows.length, `${label} lote ${size}: cuenta todos los eslabones leidos`);
      assert.equal(result.head, rows.length === 0 ? 0 : rows[rows.length - 1]!.chainSeq, `${label} lote ${size}: cabeza`);
    }
  }
});

test("TEST-CNS-1735 payload no canonicalizable (float / entero no seguro) = rotura MALFORMED_PAYLOAD del tenant, sin lanzar; un payload valido posterior no la tapa", () => {
  for (const poison of [{ x: 1.5 }, { x: 2 ** 60 }, { nested: [{ y: 0.1 }] }]) {
    const rows = buildChain(4);
    // El hash almacenado corresponde a otro payload (la fila fue escrita fuera del camino normal): el recomputo debe reportar la rotura, no abortar.
    const poisoned = rows.map((x, i) => (i === 1 ? { ...x, payload: poison } : x));
    const v = createChainVerifier();
    assert.doesNotThrow(() => {
      for (const row of poisoned) v.push(row);
    });
    assert.deepEqual(v.report(), { ok: false, verified: 1, brokenAt: { chainSeq: 2, aggregateId: "agg-0", sequence: 1, reason: "MALFORMED_PAYLOAD" } });
  }
  // Un error que NO es de canonicalizacion no se traga: se relanza (fail-closed).
  const v = createChainVerifier();
  const row = buildChain(1)[0] as ChainRow;
  assert.throws(() => v.push({ ...row, payload: { get boom(): never { throw new RangeError("fallo ajeno"); } } }), RangeError);
});
