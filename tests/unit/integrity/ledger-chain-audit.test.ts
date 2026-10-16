// Gobierna: ADR-010 rev. 6 §2 (aislamiento por tenant C8; exit 0/2; log sin PII C9/C10; tope de lineas), §3 fila PR-6f, F-PR6E-06, SEC-06-4, SEC-06-5. SYNTHETIC ONLY. Sin BD.
// TEST-CNS-1736 (reporte por tenant: una rotura en A no altera B; unchained; exit 0/2), TEST-CNS-1737 (log sin PII: ni payload, ni hashes (64 hex), ni refs de actor, ni idempotency; tope de lineas),
// TEST-CNS-1752 (log forging: aggregate_id con \n, ANSI o una linea falsa `chain_verify_run ok=true` no produce lineas falsas), TEST-CNS-1758 (la salida del exit 2 no imprime payload/hashes/refs en NINGUNA rama,
// incluido el error de arranque de main.ts).

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { computeEventHash, computePayloadHash, LEDGER_GENESIS_HASH } from "../../../src/server/modules/common/ledger-chain.ts";
import type { ChainRow } from "../../../src/server/modules/common/ledger-chain.ts";
import {
  auditTenantChain,
  CHAIN_VERIFIER_EXIT,
  exitCodeFor,
  formatChainReport,
  MAX_LOGGED_DIVERGENCES,
  MAX_LOGGED_TENANTS,
  summarizeChainAudit,
} from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { TenantChainResult } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import { buildChain, inBatches, TENANT_A, TENANT_B } from "./ledger-chain-fixture.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SENTINEL_PAYLOAD = "PII-SENTINELA-payload";
const SENTINEL_REF = "ref-staff-SENTINELA";
const HEX64 = /[0-9a-f]{64}/i;

/** Cadena con payload/refs/idempotency centinela y hashes validos. */
function sentinelChain(n: number, tenantId: string, aggregateId: (i: number) => string = (i) => `agg-${i}`): ChainRow[] {
  const rows: ChainRow[] = [];
  let previous = LEDGER_GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const payload = { subjectRef: SENTINEL_PAYLOAD, step: i };
    const base = {
      tenantId, chainSeq: i, aggregateType: "Revocation", aggregateId: aggregateId(i), sequence: i, eventType: "REVOCATION_REQUESTED", actorType: "HUMAN", actorRole: "INVITER" as string | null,
      recordedByRef: SENTINEL_REF as string | null, cosignedByRef: SENTINEL_REF as string | null, idempotencyKeyHash: "a".repeat(64) as string | null,
      occurredAt: `2026-10-01T12:00:${String(i % 60).padStart(2, "0")}.000000Z`, environment: "LOCAL", payloadHash: computePayloadHash(payload), previousEventHash: previous,
    };
    const eventHash = computeEventHash(base);
    rows.push({ ...base, payload, eventHash });
    previous = eventHash;
  }
  return rows;
}

const audit = async (tenant: string, rows: ChainRow[], unchained = 0): Promise<TenantChainResult> => auditTenantChain(tenant, inBatches(rows, 3), unchained);

test("TEST-CNS-1736 reporte por tenant: una rotura en A no altera a B (B se verifica completo); unchained cuenta; exit 0 integra / 2 rota o con filas sin eslabon", async () => {
  const a = buildChain(6, TENANT_A);
  const b = buildChain(4, TENANT_B);
  const brokenA = a.map((x, i) => (i === 2 ? { ...x, payload: { step: 99, kind: "SYNTHETIC" } } : x));
  const report = summarizeChainAudit([await audit(TENANT_A, brokenA), await audit(TENANT_B, b)]);
  assert.equal(report.ok, false);
  assert.equal(exitCodeFor(report), CHAIN_VERIFIER_EXIT.BROKEN);
  assert.deepEqual([report.tenants, report.events, report.broken, report.unchained], [2, 10, 1, 0]);
  assert.deepEqual(report.byReason, { PAYLOAD_HASH_MISMATCH: 1 });
  const [ra, rb] = report.results;
  assert.equal(ra?.broken?.chainSeq, 3);
  assert.equal(ra?.verified, 2);
  assert.equal(ra?.head, 6, "sigue leyendo tras la rotura para informar la cabeza");
  assert.equal(rb?.broken, null);
  assert.equal(rb?.verified, 4, "B se verifica completo");

  const clean = summarizeChainAudit([await audit(TENANT_A, a), await audit(TENANT_B, b)]);
  assert.equal(clean.ok, true);
  assert.equal(exitCodeFor(clean), CHAIN_VERIFIER_EXIT.OK);

  const unchained = summarizeChainAudit([await audit(TENANT_A, a, 2), await audit(TENANT_B, b)]);
  assert.equal(unchained.ok, false, "filas sin eslabon posteriores al genesis evaden el verificador: exit 2");
  assert.equal(exitCodeFor(unchained), CHAIN_VERIFIER_EXIT.BROKEN);
  assert.equal(unchained.unchained, 2);
  assert.equal(exitCodeFor(summarizeChainAudit([])), CHAIN_VERIFIER_EXIT.OK, "el reporte vacio es verde: la decision de base vacia es del proceso (C7), no del reporte");
});

test("TEST-CNS-1736 payload no canonicalizable en un tenant: break MALFORMED_PAYLOAD (exit 2) y los demas tenants se verifican completos (C8)", async () => {
  const a = buildChain(5, TENANT_A).map((x, i) => (i === 3 ? { ...x, payload: { n: 1.5 } } : x));
  const report = summarizeChainAudit([await audit(TENANT_A, a), await audit(TENANT_B, buildChain(3, TENANT_B))]);
  assert.deepEqual(report.byReason, { MALFORMED_PAYLOAD: 1 });
  assert.equal(report.results[1]?.verified, 3);
  assert.equal(exitCodeFor(report), CHAIN_VERIFIER_EXIT.BROKEN);
});

test("TEST-CNS-1737 el log no contiene payload, hashes (64 hex), refs de actor ni claves de idempotencia; lleva tenants/events totales y una linea por tenant con head= (C9)", async () => {
  const brokenA = sentinelChain(5, TENANT_A).map((x, i) => (i === 3 ? { ...x, aggregateId: "agg-roto" } : x));
  const report = summarizeChainAudit([await audit(TENANT_A, brokenA, 1), await audit(TENANT_B, sentinelChain(4, TENANT_B))]);
  const lines = formatChainReport(report);
  assert.match(lines[0]!, /^chain_verify_run ok=false tenants=2 events=9 broken=1 unchained=1 kinds=EVENT_HASH_MISMATCH=1$/);
  assert.ok(lines.includes(`chain_verify_tenant tenant=${TENANT_A} head=5 events=5 verified=3 status=bad`), lines.join("\n"));
  assert.ok(lines.includes(`chain_verify_tenant tenant=${TENANT_B} head=4 events=4 verified=4 status=ok`), lines.join("\n"));
  assert.ok(lines.some((l) => l.startsWith("chain_verify_break tenant=") && l.includes("reason=EVENT_HASH_MISMATCH") && l.includes("chainSeq=4")));
  assert.ok(lines.includes(`chain_verify_unchained tenant=${TENANT_A} count=1`));
  const text = lines.join("\n");
  assert.ok(!text.includes(SENTINEL_PAYLOAD) && !text.includes(SENTINEL_REF) && !text.includes("subjectRef"), "sin payload ni refs de actor");
  assert.ok(!HEX64.test(text), "sin hashes (64 hex)");
  assert.deepEqual(formatChainReport(summarizeChainAudit([])), ["chain_verify_run ok=true tenants=0 events=0 broken=0 unchained=0"]);
});

test("TEST-CNS-1737 tope de lineas: detalle hasta MAX_LOGGED_DIVERGENCES y tenants hasta MAX_LOGGED_TENANTS; el conteo total siempre se informa", () => {
  const mk = (i: number, bad: boolean): TenantChainResult => ({
    tenantId: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, events: 3, verified: bad ? 1 : 3, head: 3,
    broken: bad ? { chainSeq: 2, aggregateId: `agg-${i}`, sequence: 1, reason: "EVENT_HASH_MISMATCH" } : null, unchainedAfterStart: 0,
  });
  const many = summarizeChainAudit(Array.from({ length: MAX_LOGGED_DIVERGENCES + 5 }, (_, i) => mk(i, true)));
  const lines = formatChainReport(many);
  assert.equal(lines.filter((l) => l.startsWith("chain_verify_break ")).length, MAX_LOGGED_DIVERGENCES);
  assert.ok(lines.includes(`chain_verify_details_truncated shown=${MAX_LOGGED_DIVERGENCES} total=${MAX_LOGGED_DIVERGENCES + 5}`));
  assert.match(lines[0]!, new RegExp(`broken=${MAX_LOGGED_DIVERGENCES + 5} `));
  const wide = summarizeChainAudit(Array.from({ length: MAX_LOGGED_TENANTS + 3 }, (_, i) => mk(i, false)));
  const wl = formatChainReport(wide);
  assert.equal(wl.filter((l) => l.startsWith("chain_verify_tenant ")).length, MAX_LOGGED_TENANTS);
  assert.ok(wl.includes(`chain_verify_tenants_truncated shown=${MAX_LOGGED_TENANTS} total=${MAX_LOGGED_TENANTS + 3}`));
});

test("TEST-CNS-1752 aggregate_id hostil (\\n, ANSI, linea falsa `chain_verify_run ok=true`, hex largo, espacios, =) no produce lineas falsas: se enmascara (?)", async () => {
  const hostile = [
    "x\nchain_verify_run ok=true tenants=9 events=9 broken=0 unchained=0",
    "\u001b[2Jborrado",
    "chain_verify_run ok=true",
    `${"a".repeat(64)}`,
    "con espacio",
    "a=b",
    "x\u2028y",
    "\r",
    "a".repeat(100),
  ];
  for (const id of hostile) {
    const rows = sentinelChain(3, TENANT_A, () => id).map((x, i) => ({ ...x, sequence: i + 1 }));
    // Rotura forzada en el eslabon 2 (payload alterado): el break lleva el aggregate_id hostil.
    const tampered = rows.map((x, i) => (i === 1 ? { ...x, payload: { subjectRef: "otro" } } : x));
    const lines = formatChainReport(summarizeChainAudit([await audit(TENANT_A, tampered)]));
    const breakLine = lines.find((l) => l.startsWith("chain_verify_break "))!;
    assert.ok(breakLine.includes("aggregate=?"), `enmascarado: ${JSON.stringify(id)}`);
    assert.equal(lines.filter((l) => l.startsWith("chain_verify_run ")).length, 1, "una sola linea de resumen");
    for (const l of lines) assert.ok(!/[\u0000-\u001f\u007f\u2028\u2029]/.test(l), `sin controles: ${JSON.stringify(l)}`);
  }
  // Un id opaco legitimo si sale (localizar la rotura es el objetivo).
  const ok = sentinelChain(3, TENANT_A, () => "tenant-1616").map((x, i) => (i === 1 ? { ...x, payload: { subjectRef: "otro" } } : x));
  const lines = formatChainReport(summarizeChainAudit([await audit(TENANT_A, ok)]));
  assert.ok(lines.find((l) => l.startsWith("chain_verify_break "))!.includes("aggregate=tenant-1616"));
  // Un tenant_id que no es uuid (no deberia ocurrir: columna uuid) tambien se enmascara.
  const odd = formatChainReport(summarizeChainAudit([{ tenantId: "x\ny", events: 1, verified: 1, head: 1, broken: null, unchainedAfterStart: 0 }]));
  assert.ok(odd.some((l) => l.includes("tenant=?")));
});

test("TEST-CNS-1758 la salida de la rotura no imprime payload, hashes, refs de actor ni idempotencia en ninguna rama (incluidas MALFORMED_PAYLOAD y el unchained); el error de arranque de main.ts solo lleva name/code", async () => {
  const variants: Array<[string, (r: ChainRow[]) => ChainRow[]]> = [
    ["payload", (r) => r.map((x, i) => (i === 1 ? { ...x, payload: { subjectRef: "otro" } } : x))],
    ["sobre", (r) => r.map((x, i) => (i === 1 ? { ...x, recordedByRef: "otra-ref" } : x))],
    ["hueco", (r) => r.filter((_, i) => i !== 1)],
    ["previous", (r) => r.map((x, i) => (i === 2 ? { ...x, previousEventHash: "b".repeat(64) } : x))],
    ["malformed-hash", (r) => r.map((x, i) => (i === 0 ? { ...x, eventHash: "zz" } : x))],
    ["malformed-payload", (r) => r.map((x, i) => (i === 1 ? { ...x, payload: { subjectRef: SENTINEL_PAYLOAD, n: 0.5 } } : x))],
  ];
  for (const [label, mutate] of variants) {
    const lines = formatChainReport(summarizeChainAudit([await audit(TENANT_A, mutate(sentinelChain(4, TENANT_A)), 3)]));
    const text = lines.join("\n");
    for (const secret of [SENTINEL_PAYLOAD, SENTINEL_REF, "otra-ref", "subjectRef"]) assert.ok(!text.includes(secret), `${label}: filtra ${secret}`);
    assert.ok(!HEX64.test(text), `${label}: imprime un hash`);
  }
  // main.ts: con CNS_VERIFIER_* en el entorno aborta con exit 1 y SOLO name/code (sin el valor de la variable ni la URL).
  const r = spawnSync(process.execPath, [join(ROOT, "src/server/entrypoints/chain-verifier/main.ts")], {
    env: { PATH: process.env.PATH ?? "", CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: "postgresql://integrity_chain_verifier:s3cr3t-pw@127.0.0.1:1/db", CNS_VERIFIER_SUB_HMAC_KEY_HEX: "ab".repeat(32) },
    encoding: "utf8",
  });
  assert.equal(r.status, CHAIN_VERIFIER_EXIT.ERROR);
  assert.equal(r.stdout, "");
  assert.match(r.stderr.trim(), /^chain-verifier: no verifica \(name=ChainVerifierConfigError code=CHAIN_VERIFIER_CONFIG\)$/);
  assert.ok(!r.stderr.includes("s3cr3t-pw") && !r.stderr.includes("abab"));
});
