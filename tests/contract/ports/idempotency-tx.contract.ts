// Gobierna: CA-124 (PR-E); src/server/ports/idempotency.port.ts, src/server/ports/unit-of-work.port.ts
// (TenantTxPorts.idempotency), common.spec.yaml GRD-CM-08 (idempotency_key), INV-CM-01 (atomicidad)
// e INV-CM-02/INV-3 (aislamiento, X5: TEST-CNS-102, conexion reusada A->B). Suite de contrato
// compartida memoria/Postgres: find + store de una Idempotency-Key DENTRO de la unidad de trabajo del
// tenant. TEST-CNS-862..864. Solo datos sinteticos.

import assert from "node:assert/strict";

import type { StoredIdempotentResponse } from "../../../src/server/ports/idempotency.port.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface IdempotencyTxHarness {
  readonly uow: UnitOfWorkPort;
}

export type RegisterIdempotencyTest = (name: string, body: (h: IdempotencyTxHarness) => Promise<void>) => void;

const TENANT_A = fixtureUuid("tenant-a-862");
const TENANT_B = fixtureUuid("tenant-b-862");
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);

function response(label: string, status = 201): StoredIdempotentResponse {
  return { payloadHash: hex(`payload:${label}`), status, body: { ref: fixtureUuid(`ref:${label}`), state: "DRAFT", sequence: 1 } };
}

export function runIdempotencyTxContract(register: RegisterIdempotencyTest): void {
  register("TEST-CNS-862 IdempotencyPort: find sin entrada = null; store + find en la misma tx; persiste tras COMMIT; la primera gana", async ({ uow }) => {
    const key = hex("key-862");
    assert.equal(await uow.inTenant(TENANT_A, (tx) => tx.idempotency.find(TENANT_A, key)), null);

    const first = response("first-862");
    await uow.inTenant(TENANT_A, async (tx) => {
      await tx.idempotency.store(TENANT_A, key, first);
      assert.deepEqual(await tx.idempotency.find(TENANT_A, key), first, "visible dentro de la propia tx");
    });
    assert.deepEqual(await uow.inTenant(TENANT_A, (tx) => tx.idempotency.find(TENANT_A, key)), first, "persistida tras el COMMIT");

    await uow.inTenant(TENANT_A, (tx) => tx.idempotency.store(TENANT_A, key, response("second-862", 200)));
    assert.deepEqual(await uow.inTenant(TENANT_A, (tx) => tx.idempotency.find(TENANT_A, key)), first, "la primera respuesta gana: una entrada vigente no se pisa");
  });

  register("TEST-CNS-863 IdempotencyPort: find + ejecutar + store son atomicos (si la unidad falla no queda la clave) y un store con tenantId ajeno a la tx se rechaza", async ({ uow }) => {
    const key = hex("key-863");
    await assert.rejects(
      () =>
        uow.inTenant(TENANT_A, async (tx) => {
          await tx.idempotency.store(TENANT_A, key, response("rolled-863"));
          throw new Error("falla despues del store");
        }),
      /falla despues del store/,
    );
    assert.equal(await uow.inTenant(TENANT_A, (tx) => tx.idempotency.find(TENANT_A, key)), null, "ROLLBACK: la clave no queda");

    // WITH CHECK de la policy / TenantScopeViolationError en memoria: nunca se escribe con otro tenant.
    await assert.rejects(() => uow.inTenant(TENANT_A, (tx) => tx.idempotency.store(TENANT_B, key, response("cross-863"))));
    assert.equal(await uow.inTenant(TENANT_B, (tx) => tx.idempotency.find(TENANT_B, key)), null);
  });

  register("TEST-CNS-864 IdempotencyPort X5/TEST-CNS-102: el tenant B no ve la clave del tenant A (misma scopeKeyHash), tampoco con la misma conexion A->B", async ({ uow }) => {
    const key = hex("key-864");
    const mine = response("a-864");
    await uow.inTenant(TENANT_A, (tx) => tx.idempotency.store(TENANT_A, key, mine));

    // Mismo hash de clave, otro tenant: 0 filas (RLS). Se consulta con el tenantId propio y con el ajeno.
    assert.equal(await uow.inTenant(TENANT_B, (tx) => tx.idempotency.find(TENANT_B, key)), null);
    assert.equal(await uow.inTenant(TENANT_B, (tx) => tx.idempotency.find(TENANT_A, key)), null, "ni pidiendo explicitamente el tenantId de A");
    // B puede usar la misma clave para SU respuesta sin pisar la de A.
    const theirs = response("b-864");
    await uow.inTenant(TENANT_B, (tx) => tx.idempotency.store(TENANT_B, key, theirs));
    assert.deepEqual(await uow.inTenant(TENANT_B, (tx) => tx.idempotency.find(TENANT_B, key)), theirs);
    assert.deepEqual(await uow.inTenant(TENANT_A, (tx) => tx.idempotency.find(TENANT_A, key)), mine);
    // A -> B -> A en secuencia (en Postgres, con pool de 1 conexion: la misma conexion fisica).
    assert.equal(await uow.inTenant(TENANT_B, (tx) => tx.idempotency.find(TENANT_A, hex("otra-864"))), null);
  });
}
