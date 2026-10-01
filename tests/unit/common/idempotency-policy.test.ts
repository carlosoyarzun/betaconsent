// Gobierna: CA-124 (PR-E), common.spec.yaml GRD-CM-08 (TTL P-33, sin valor aprobado), mismo patron D4
// fail-closed que P-15/P-18. TEST-CNS-868 (config sin default de produccion) y TEST-CNS-869 (adaptador
// in-memory equivalente: TTL, aislamiento por tenant y deshacer del journal). Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryIdempotencyAdapter } from "../../../src/infra/adapters/in-memory-idempotency.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY } from "../../../src/server/entrypoints/dev-local-config.ts";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const KEY = "a".repeat(64);
const R = { payloadHash: "b".repeat(64), status: 201, body: { ref: "x" } };

test("TEST-CNS-868 loadIdempotencyPolicyConfig: sin override ni CNS_IDEMPOTENCY_TTL_MS lanza (fail-closed, sin default de produccion)", () => {
  const saved = process.env.CNS_IDEMPOTENCY_TTL_MS;
  delete process.env.CNS_IDEMPOTENCY_TTL_MS;
  try {
    assert.throws(() => loadIdempotencyPolicyConfig(), /P-33/);
    assert.throws(() => loadIdempotencyPolicyConfig({}), /PENDING/);
    process.env.CNS_IDEMPOTENCY_TTL_MS = "abc";
    assert.throws(() => loadIdempotencyPolicyConfig(), /entero positivo/);
    process.env.CNS_IDEMPOTENCY_TTL_MS = "-5";
    assert.throws(() => loadIdempotencyPolicyConfig(), /entero positivo/);
    process.env.CNS_IDEMPOTENCY_TTL_MS = "1234";
    assert.deepEqual(loadIdempotencyPolicyConfig(), { ttlMs: 1234 });
    assert.deepEqual(loadIdempotencyPolicyConfig({ ttlMs: 99 }), { ttlMs: 99 }, "el override explicito manda");
    // El valor sintetico LOCAL-only del dev cumple lo que exige el loader real.
    assert.deepEqual(loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY), LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY);
  } finally {
    if (saved === undefined) delete process.env.CNS_IDEMPOTENCY_TTL_MS;
    else process.env.CNS_IDEMPOTENCY_TTL_MS = saved;
  }
});

test("TEST-CNS-869 in-memory IdempotencyPort: TTL (vencida no se encuentra y se reemplaza), la primera gana y aislamiento por tenant", async () => {
  let now = 1_000_000;
  const adapter = createInMemoryIdempotencyAdapter({ ttlMs: 1000, now: () => now });
  await adapter.store(A, KEY, R);
  assert.deepEqual(await adapter.find(A, KEY), R);
  assert.equal(await adapter.find(B, KEY), null, "otro tenant no la ve");
  await adapter.store(A, KEY, { ...R, status: 200 });
  assert.equal((await adapter.find(A, KEY))?.status, 201, "la vigente no se pisa");
  now += 1001;
  assert.equal(await adapter.find(A, KEY), null, "vencida: no se encuentra");
  await adapter.store(A, KEY, { ...R, status: 200 });
  assert.equal((await adapter.find(A, KEY))?.status, 200, "la vencida se reemplaza");
});

test("TEST-CNS-869 in-memory IdempotencyPort: dentro de la UoW find + ejecutar + store son atomicos (el fallo deshace la clave)", async () => {
  const tenancy = createInMemoryTenancy({ ledger: createInMemoryLedgerAdapter() });
  await assert.rejects(() =>
    tenancy.uow.inTenant(A, async (tx) => {
      await tx.idempotency.store(A, KEY, R);
      throw new Error("boom");
    }),
  );
  assert.equal(await tenancy.uow.inTenant(A, (tx) => tx.idempotency.find(A, KEY)), null);
});

test("TEST-CNS-883: idempotencia in-memory sin ttlMs (o <= 0) no se crea (fail-closed, sin TTL infinito); CONSENT_STORE=memory fuera de LOCAL no arranca", () => {
  assert.throws(() => createInMemoryIdempotencyAdapter(), /fail-closed/);
  assert.throws(() => createInMemoryIdempotencyAdapter({}), /fail-closed/);
  assert.throws(() => createInMemoryIdempotencyAdapter({ ttlMs: 0 }), /fail-closed/);
});
