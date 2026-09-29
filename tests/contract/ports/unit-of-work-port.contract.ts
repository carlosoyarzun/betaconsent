// Gobierna: src/server/ports/unit-of-work.port.ts, CA-124 (postgres-design.md rev. 2 §5-§6),
// INV-CM-01 (append + proyección + outbox en una tx), INV-CM-02/INV-3 (aislamiento por tenant).
// Suite de contrato de UnitOfWorkPort: se registra contra cada adaptador. TEST-CNS-770, 771, 772.

import test from "node:test";
import assert from "node:assert/strict";

import type { LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import type { OutboxPort } from "../../../src/server/ports/outbox.port.ts";
import type { RevocationRepositoryPort } from "../../../src/server/ports/revocation-repository.port.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

/** Vista "fuera de la unidad de trabajo" sobre el mismo almacenamiento que usa `uow`. */
export interface UnitOfWorkHarness {
  readonly uow: UnitOfWorkPort;
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
  readonly outbox: OutboxPort;
}

export function runUnitOfWorkPortContract(adapterName: string, makeAdapter: () => Promise<UnitOfWorkHarness>): void {
  const TA = fixtureUuid("tenant-770-a");
  const TB = fixtureUuid("tenant-770-b");
  const REV = fixtureUuid("rev-770");

  const revocation = (tenantId: string, revocationRef = REV) => ({
    revocationRef,
    tenantId,
    chainRef: "chain-770",
    status: "REQUESTED" as const,
  });
  const event = (tenantId: string, aggregateId = REV) => ({
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId,
    actorType: "HUMAN" as const,
    payload: {},
  });
  const outboxInput = (tenantId: string) => ({
    tenantId,
    eventType: "consent.revoked" as const,
    contextRef: "BETA_2026_01",
    subjectRef: fixtureUuid("subject-770"),
    occurredAt: "2026-09-29T12:00:00.000Z",
    payload: { revocationRef: REV, scope: "ALL" as const, effectiveAt: "2026-09-29T12:00:00.000Z" },
    dedupeKey: `${REV}:consent.revoked`,
  });

  test(`TEST-CNS-770 UnitOfWorkPort contract (${adapterName}): si work lanza no queda ninguna escritura (repo, ledger, outbox) y el error se propaga; si resuelve, todo confirma`, async () => {
    const h = await makeAdapter();
    const boom = new Error("fallo inyectado");
    await assert.rejects(
      () =>
        h.uow.inTenant(TA, async (tx) => {
          await tx.revocationRepo.save(revocation(TA));
          await tx.ledger.append(event(TA));
          await tx.outbox.enqueue(outboxInput(TA));
          throw boom;
        }),
      (err: unknown) => err === boom,
    );
    assert.equal(await h.revocationRepo.findByRef(TA, REV), null);
    assert.equal((await h.ledger.listByAggregate(TA, "Revocation", REV)).length, 0);
    // Tras revertir, repetir la misma operación funciona y numera desde 1 (sin huecos).
    const ok = await h.uow.inTenant(TA, async (tx) => {
      await tx.revocationRepo.save(revocation(TA));
      const rec = await tx.ledger.append(event(TA));
      const enq = await tx.outbox.enqueue(outboxInput(TA));
      return { sequence: rec.sequence, status: enq.status };
    });
    assert.deepEqual(ok, { sequence: 1, status: "PENDING" });
    assert.equal((await h.revocationRepo.findByRef(TA, REV))?.status, "REQUESTED");
    assert.equal((await h.ledger.listByAggregate(TA, "Revocation", REV)).length, 1);
  });

  test(`TEST-CNS-771 UnitOfWorkPort contract (${adapterName}): aislamiento por tenant (INV-3): B no ve lo de A, tampoco tras A→B; escribir con tenantId ajeno se rechaza`, async () => {
    const h = await makeAdapter();
    await h.uow.inTenant(TA, async (tx) => {
      await tx.revocationRepo.save(revocation(TA));
      await tx.ledger.append(event(TA));
    });
    // B (después de A, mismo adaptador) no ve nada de A.
    await h.uow.inTenant(TB, async (tx) => {
      assert.equal(await tx.revocationRepo.findByRef(TB, REV), null);
      assert.equal(await tx.revocationRepo.findByRef(TA, REV), null, "ni siquiera pidiendo el tenant de A");
      assert.equal((await tx.ledger.listByAggregate(TA, "Revocation", REV)).length, 0);
      await assert.rejects(() => tx.revocationRepo.save(revocation(TA)), "WITH CHECK: tenantId falso");
      await assert.rejects(() => tx.ledger.append(event(TA)));
      await assert.rejects(() => tx.outbox.enqueue(outboxInput(TA)));
    });
    // Lo rechazado no dejó rastro y lo de A sigue intacto.
    assert.equal(await h.revocationRepo.findByRef(TB, REV), null);
    assert.equal((await h.revocationRepo.findByRef(TA, REV))?.status, "REQUESTED");
    assert.equal((await h.ledger.listByAggregate(TA, "Revocation", REV)).length, 1);
  });

  test(`TEST-CNS-772 UnitOfWorkPort contract (${adapterName}): sin tenantId no hay unidad de trabajo y las unidades concurrentes se serializan sin pisarse`, async () => {
    const h = await makeAdapter();
    await assert.rejects(() => h.uow.inTenant("", async () => undefined));
    const order: string[] = [];
    const run = (label: string, ref: string, fail: boolean) =>
      h.uow
        .inTenant(TA, async (tx) => {
          order.push(`${label}:start`);
          await tx.revocationRepo.save(revocation(TA, ref));
          await Promise.resolve();
          if (fail) throw new Error(label);
          order.push(`${label}:end`);
        })
        .catch(() => undefined);
    await Promise.all([run("a", fixtureUuid("r-a"), true), run("b", fixtureUuid("r-b"), false)]);
    assert.deepEqual(order, ["a:start", "b:start", "b:end"]);
    assert.equal(await h.revocationRepo.findByRef(TA, fixtureUuid("r-a")), null, "la unidad fallida se revirtió");
    assert.ok(await h.revocationRepo.findByRef(TA, fixtureUuid("r-b")), "la unidad exitosa de otro flujo no se perdió");
  });
}
