// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 (subconjunto IT0 de ADR-011 / S4-16),
// common.spec.yaml ledgerEnvelope, src/server/modules/common/ledger-chain.ts y ledger-event-types.ts.
// TEST-CNS-912. Funciones puras, sin red ni BD.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  computeEventHash,
  computePayloadHash,
  LEDGER_GENESIS_HASH,
  verifyChainRows,
  type ChainRow,
} from "../../../src/server/modules/common/ledger-chain.ts";
import { contractLedgerEventTypes, contractSecurityEventTypes } from "../../../src/server/modules/common/json-schema-lite.ts";
import {
  isLedgerEventType,
  LEDGER_EVENT_TYPES,
  LEDGER_LOCAL_SEED_EVENT_TYPES,
  LEDGER_TRANSITIONAL_SECURITY_EVENT_TYPES,
} from "../../../src/server/modules/common/ledger-event-types.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const T = "11111111-1111-4111-8111-111111111111";

function buildChain(n: number): ChainRow[] {
  const rows: ChainRow[] = [];
  let previous = LEDGER_GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const payload = { step: i, kind: "SYNTHETIC" };
    const base = {
      tenantId: T,
      chainSeq: i,
      aggregateType: "Revocation",
      aggregateId: `agg-${i % 2}`,
      sequence: Math.ceil(i / 2),
      eventType: "REVOCATION_REQUESTED",
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

test("TEST-CNS-912 vector fijo: el hash no cambia sin un cambio de version de la canonicalizacion", () => {
  assert.equal(computePayloadHash({ a: 1 }), "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"); // sha256 de {"a":1}
  assert.equal(computePayloadHash({}), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"); // sha256 de {}
});

test("TEST-CNS-912 verifyChainRows: cadena integra y primer eslabon roto por cada tipo de mutacion", () => {
  const ok = buildChain(5);
  assert.deepEqual(verifyChainRows(ok), { ok: true, verified: 5 });
  assert.deepEqual(verifyChainRows([]), { ok: true, verified: 0 });

  const cases: Array<[string, (rows: ChainRow[]) => ChainRow[], number, string, number]> = [
    ["payload mutado", (r) => r.map((x, i) => (i === 2 ? { ...x, payload: { step: 99, kind: "SYNTHETIC" } } : x)), 3, "PAYLOAD_HASH_MISMATCH", 2],
    ["occurredAt mutado (P2-1)", (r) => r.map((x, i) => (i === 2 ? { ...x, occurredAt: "2026-10-01T12:59:59.000000Z" } : x)), 3, "EVENT_HASH_MISMATCH", 2],
    ["environment mutado (P2-1)", (r) => r.map((x, i) => (i === 1 ? { ...x, environment: "STAGING" } : x)), 2, "EVENT_HASH_MISMATCH", 1],
    ["campo del sobre mutado", (r) => r.map((x, i) => (i === 1 ? { ...x, aggregateId: "otro" } : x)), 2, "EVENT_HASH_MISMATCH", 1],
    ["actor mutado", (r) => r.map((x, i) => (i === 3 ? { ...x, actorType: "FIXTURE" } : x)), 4, "EVENT_HASH_MISMATCH", 3],
    ["fila borrada (hueco)", (r) => r.filter((_, i) => i !== 2), 4, "CHAIN_SEQ_GAP", 2],
    ["filas reordenadas", (r) => [r[1] as ChainRow, r[0] as ChainRow, ...r.slice(2)], 2, "CHAIN_SEQ_GAP", 0],
    ["previous roto", (r) => r.map((x, i) => (i === 4 ? { ...x, previousEventHash: "b".repeat(64) } : x)), 5, "PREVIOUS_HASH_MISMATCH", 4],
    ["hash mal formado", (r) => r.map((x, i) => (i === 0 ? { ...x, eventHash: "xyz" } : x)), 1, "MALFORMED_HASH", 0],
    ["primer eslabon sin genesis", (r) => r.map((x, i) => (i === 0 ? { ...x, previousEventHash: "c".repeat(64) } : x)), 1, "PREVIOUS_HASH_MISMATCH", 0],
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

  // Tipo fuera de lista con hashes consistentes: lo atrapa la lista blanca del verificador.
  const rows = buildChain(2);
  const bad = { ...(rows[1] as ChainRow), eventType: "NOT_IN_VOCABULARY" };
  const rehashed = { ...bad, eventHash: computeEventHash(bad) };
  const report = verifyChainRows([rows[0] as ChainRow, rehashed]);
  assert.deepEqual(report.ok === false && report.brokenAt.reason, "EVENT_TYPE_NOT_ALLOWED");
});

test("TEST-CNS-912 lista blanca derivada del contrato (ledger-event-payloads.schema.json sin x-disabled-in-it0 + transitorios SECURITY + seed LOCAL) = TS = CHECK vigente (0017)", () => {
  assert.equal(new Set(LEDGER_EVENT_TYPES).size, LEDGER_EVENT_TYPES.length);
  for (const t of LEDGER_EVENT_TYPES) assert.match(t, /^[A-Z][A-Z_]+$/);
  assert.equal(isLedgerEventType("OTP_ISSUED"), true);
  assert.equal(isLedgerEventType("otp_issued"), false);

  const sql = readFileSync(join(HERE, "..", "..", "..", "db", "migrations", "0017_revocation_proposal_withdrawn_event.sql"), "utf8");
  const block = /audit_event_event_type_allowlist CHECK \(event_type IN \(([\s\S]*?)\)\)[,;]/.exec(sql)?.[1] ?? "";
  const inSql = [...block.matchAll(/'([A-Z_]+)'/g)].map((m) => m[1] as string);
  assert.deepEqual([...inSql].sort(), [...LEDGER_EVENT_TYPES].sort());

  // P1-B: la lista se DERIVA del contrato: $defs de ledger-event-payloads.schema.json menos x-disabled-in-it0,
  // mas los transitorios del stream SECURITY (security-event-payloads.schema.json) y el seed LOCAL declarado.
  const derived = [...contractLedgerEventTypes(), ...contractSecurityEventTypes(), ...LEDGER_LOCAL_SEED_EVENT_TYPES];
  assert.deepEqual([...LEDGER_EVENT_TYPES].sort(), [...derived].sort(), "LEDGER_EVENT_TYPES diverge del contrato");
  assert.deepEqual([...LEDGER_TRANSITIONAL_SECURITY_EVENT_TYPES].sort(), contractSecurityEventTypes().sort());
  for (const removed of ["CONSENT_EXPIRED", "CONSENT_SUPERSEDED", "DECISION_CONTESTED", "CONSENT_CONTEXT_STATUS_CHANGED"]) {
    assert.equal(isLedgerEventType(removed), false, `${removed} no debe estar en la lista`);
  }
  assert.ok(sql.includes("TRANSITORIOS") && sql.includes("common.spec.yaml:141"), "la migracion documenta los transitorios");
});
