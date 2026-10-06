// Gobierna: CA-139. Registra la suite de contrato de CaseSessionStorePort contra el adaptador in-memory (TEST-CNS-1161, 1162, 1163).
// El registro contra Postgres vive en tests/integration/postgres/case-session.test.ts.

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { fixtureUuid } from "../uuid-fixture.ts";
import { runCaseSessionStoreContract } from "./case-session-store.contract.ts";

runCaseSessionStoreContract((name, body) => {
  test(name, () => body(createInMemoryCaseSessionStore()));
});

test("TEST-CNS-1163 CaseSessionStore in-memory: solo avanza la ultima actividad pasada la granularidad (60 s) y la inactividad sigue correcta", async () => {
  const store = createInMemoryCaseSessionStore();
  const T = "00000000-0000-4000-8000-000000001163";
  const t0 = Date.now();
  const base = { tenantId: T, sidHash: "a".repeat(64), caseRef: fixtureUuid("case-1163"), principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" as const };
  await store.create({ ...base, issuedAtMs: t0, expiresAtMs: t0 + 8 * 3_600_000 });
  const v = (nowMs: number) => store.validateAndTouch({ ...base, nowMs, idleTimeoutMs: 30 * 60_000 });
  assert.equal(await v(t0 + 10_000), true);
  assert.equal(store.rows()[0]!.lastSeenAtMs, t0);
  assert.equal(await v(t0 + 61_000), true);
  assert.equal(store.rows()[0]!.lastSeenAtMs, t0 + 61_000);
  assert.equal(await v(t0 + 61_000 + 30 * 60_000 + 1), false);
});

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-1162 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
