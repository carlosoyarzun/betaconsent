// Gobierna: src/server/ports/ledger.port.ts, src/server/ports/outbox.port.ts, CA-124 (PR-B),
// common.spec.yaml ledgerEnvelope (UNIQUE tenant_id, aggregate_id, sequence; expectedSequence),
// INV-CM-01, INV-CM-02/INV-3. Suite de contrato compartida memoria/Postgres para Ledger y Outbox
// dentro de una unidad de trabajo de tenant. TEST-CNS-780..786. Solo datos sinteticos.

import assert from "node:assert/strict";

import { LedgerSequenceConflictError } from "../../../src/server/ports/ledger.port.ts";
import type { LedgerEventInput, LedgerPort } from "../../../src/server/ports/ledger.port.ts";
import type { OutboxEnqueueInput, OutboxPort } from "../../../src/server/ports/outbox.port.ts";
import { validateOutboxEvent } from "../schema-lite.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface LedgerOutboxPorts {
  readonly ledger: LedgerPort;
  readonly outbox: OutboxPort;
}

/** Unidad de trabajo del adaptador bajo prueba (memoria: UnitOfWorkPort; Postgres: PgUnitOfWork). */
export interface LedgerOutboxHarness {
  inTenant<T>(tenantId: string, work: (ports: LedgerOutboxPorts) => Promise<T>): Promise<T>;
}

/** El registrador envuelve `test`/`pgTest` y construye el harness de cada adaptador. */
export type RegisterContractTest = (name: string, body: (h: LedgerOutboxHarness) => Promise<void>) => void;

function event(tenantId: string, aggregateId: string, extra: Partial<LedgerEventInput> = {}): LedgerEventInput {
  return {
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId,
    actorType: "HUMAN",
    payload: { reasonCode: "SYNTHETIC" },
    ...extra,
  };
}

function outboxInput(tenantId: string, revocationRef: string, dedupeKey = `${revocationRef}:consent.revoked`): OutboxEnqueueInput {
  return {
    tenantId,
    eventType: "consent.revoked",
    contextRef: "BETA_2026_01",
    subjectRef: fixtureUuid(`subject-${revocationRef}`),
    occurredAt: "2026-09-30T12:00:00.000Z",
    payload: { revocationRef, scope: "ALL", effectiveAt: "2026-09-30T12:00:00.000Z" },
    dedupeKey,
  };
}

export function runLedgerOutboxContract(adapterName: string, register: RegisterContractTest): void {
  const name = (id: string, text: string): string => `${id} Ledger/Outbox contract (${adapterName}): ${text}`;

  register(name("TEST-CNS-780", "append numera 1..n, devuelve el registro SYNTHETIC/no evidenciario y listByAggregate lo devuelve en orden"), async (h) => {
    const t = fixtureUuid("t780");
    const agg = fixtureUuid("agg780");
    const records = await h.inTenant(t, async ({ ledger }) => {
      const a = await ledger.append(
        event(t, agg, { actorRole: "UNVERIFIED_BEARER", recordedByRef: fixtureUuid("rec780"), payload: { n: 1, nested: { ok: true } } }),
      );
      const b = await ledger.append(event(t, agg, { eventType: "REVOCATION_CONFIRMED" }));
      return [a, b];
    });
    assert.deepEqual(records.map((r) => r.sequence), [1, 2]);
    const [first] = records;
    assert.equal(first?.dataClass, "SYNTHETIC");
    assert.equal(first?.evidentiary, false);
    assert.equal(first?.environment, "LOCAL");
    assert.ok(first?.occurredAt instanceof Date);

    const listed = await h.inTenant(t, ({ ledger }) => ledger.listByAggregate(t, "Revocation", agg));
    assert.deepEqual(listed.map((r) => [r.sequence, r.eventType]), [[1, "REVOCATION_REQUESTED"], [2, "REVOCATION_CONFIRMED"]]);
    assert.equal(listed[0]?.actorRole, "UNVERIFIED_BEARER");
    assert.equal(listed[0]?.recordedByRef, fixtureUuid("rec780"));
    assert.deepEqual(listed[0]?.payload, { n: 1, nested: { ok: true } });
    assert.equal("cosignedByRef" in (listed[1] ?? {}), false, "los opcionales ausentes no aparecen");
  });

  register(name("TEST-CNS-781", "la numeracion es por (tenant, aggregate): agregados y tenants distintos arrancan en 1 e incluso el mismo aggregateId en otro tenant"), async (h) => {
    const ta = fixtureUuid("t781-a");
    const tb = fixtureUuid("t781-b");
    const agg1 = fixtureUuid("agg781-1");
    const agg2 = fixtureUuid("agg781-2");
    await h.inTenant(ta, async ({ ledger }) => {
      assert.equal((await ledger.append(event(ta, agg1))).sequence, 1);
      assert.equal((await ledger.append(event(ta, agg1))).sequence, 2);
      assert.equal((await ledger.append(event(ta, agg2))).sequence, 1);
      // Mismo aggregateId con otro aggregateType comparte numeracion (UNIQUE tenant_id, aggregate_id, sequence).
      assert.equal((await ledger.append(event(ta, agg1, { aggregateType: "Other" }))).sequence, 3);
    });
    await h.inTenant(tb, async ({ ledger }) => {
      assert.equal((await ledger.append(event(tb, agg1))).sequence, 1);
    });
  });

  register(name("TEST-CNS-782", "expectedSequence: conflicto no escribe y reporta expected/actual; el correcto avanza; idempotencyKey deduplica antes del control"), async (h) => {
    const t = fixtureUuid("t782");
    const agg = fixtureUuid("agg782");
    await h.inTenant(t, async ({ ledger }) => {
      assert.equal((await ledger.append(event(t, agg, { expectedSequence: 0 }))).sequence, 1);
      await assert.rejects(
        () => ledger.append(event(t, agg, { expectedSequence: 0 })),
        (e: unknown) => e instanceof LedgerSequenceConflictError && e.expectedSequence === 0 && e.actualSequence === 1,
      );
      assert.equal((await ledger.append(event(t, agg, { expectedSequence: 1, idempotencyKey: "k-782" }))).sequence, 2);
      // Reintento con la misma clave: devuelve el existente aunque expectedSequence ya no coincida.
      const again = await ledger.append(event(t, agg, { expectedSequence: 1, idempotencyKey: "k-782" }));
      assert.equal(again.sequence, 2);
      assert.equal((await ledger.listByAggregate(t, "Revocation", agg)).length, 2, "ni el conflicto ni el replay escribieron");
    });
  });

  register(name("TEST-CNS-783", "dos unidades concurrentes con el mismo expectedSequence: una confirma y la otra recibe LedgerSequenceConflictError sin escribir"), async (h) => {
    const t = fixtureUuid("t783");
    const agg = fixtureUuid("agg783");
    const run = (label: string) =>
      h.inTenant(t, async ({ ledger }) => ledger.append(event(t, agg, { expectedSequence: 0, payload: { label } }))).then(
        (r) => ({ ok: true as const, sequence: r.sequence }),
        (e: unknown) => ({ ok: false as const, error: e }),
      );
    const results = await Promise.all([run("a"), run("b")]);
    assert.equal(results.filter((r) => r.ok).length, 1);
    const loser = results.find((r) => !r.ok);
    assert.ok(loser && !loser.ok && loser.error instanceof LedgerSequenceConflictError);
    const listed = await h.inTenant(t, ({ ledger }) => ledger.listByAggregate(t, "Revocation", agg));
    assert.deepEqual(listed.map((r) => r.sequence), [1]);
  });

  register(name("TEST-CNS-784", "outbox: sobre valido PENDING con eventId asignado; dedupe por (tenant, key) devuelve el mismo eventId; otra key o tenant crea otro"), async (h) => {
    const ta = fixtureUuid("t784-a");
    const tb = fixtureUuid("t784-b");
    const r = fixtureUuid("rev784");
    const first = await h.inTenant(ta, ({ outbox }) => outbox.enqueue(outboxInput(ta, r)));
    assert.equal(first.status, "PENDING");
    assert.equal(first.tenantId, ta);
    assert.ok(validateOutboxEvent(first.envelope).ok);
    assert.equal(first.envelope.environment, "LOCAL");
    assert.equal(first.envelope.dataClass, "SYNTHETIC");
    assert.equal(first.envelope.occurredAt, "2026-09-30T12:00:00.000Z");

    // Dedupe tambien entre unidades de trabajo distintas.
    const again = await h.inTenant(ta, ({ outbox }) => outbox.enqueue(outboxInput(ta, r)));
    assert.equal(again.envelope.eventId, first.envelope.eventId);
    const other = await h.inTenant(ta, ({ outbox }) => outbox.enqueue(outboxInput(ta, r, `${r}:otra`)));
    assert.notEqual(other.envelope.eventId, first.envelope.eventId);
    const sameKeyOtherTenant = await h.inTenant(tb, ({ outbox }) => outbox.enqueue(outboxInput(tb, r)));
    assert.notEqual(sameKeyOtherTenant.envelope.eventId, first.envelope.eventId);
    assert.equal(sameKeyOtherTenant.envelope.tenantRef, tb);
  });

  register(name("TEST-CNS-785", "aislamiento (INV-3): B no ve el ledger de A, escribir con tenantId ajeno se rechaza (ledger y outbox) y no deja rastro"), async (h) => {
    const ta = fixtureUuid("t785-a");
    const tb = fixtureUuid("t785-b");
    const agg = fixtureUuid("agg785");
    const r = fixtureUuid("rev785");
    await h.inTenant(ta, async ({ ledger, outbox }) => {
      await ledger.append(event(ta, agg));
      await outbox.enqueue(outboxInput(ta, r));
    });
    await h.inTenant(tb, async ({ ledger }) => {
      assert.equal((await ledger.listByAggregate(ta, "Revocation", agg)).length, 0, "ni pidiendo el tenant de A");
      assert.equal((await ledger.listByAggregate(tb, "Revocation", agg)).length, 0);
    });
    // Cada rechazo en su propia unidad (en Postgres el error aborta la transaccion).
    await assert.rejects(() => h.inTenant(tb, ({ ledger }) => ledger.append(event(ta, agg))));
    await assert.rejects(() => h.inTenant(tb, ({ outbox }) => outbox.enqueue(outboxInput(ta, fixtureUuid("rev785-x")))));
    assert.equal((await h.inTenant(ta, ({ ledger }) => ledger.listByAggregate(ta, "Revocation", agg))).length, 1);
    // El rechazo de B no dejo un evento 'rev785-x' en A: encolar esa key en A crea un registro nuevo (no dedupe).
    const fresh = await h.inTenant(ta, ({ outbox }) => outbox.enqueue(outboxInput(ta, fixtureUuid("rev785-x"))));
    assert.equal(fresh.status, "PENDING");
  });

  register(name("TEST-CNS-786", "atomicidad: si work lanza no queda ledger ni outbox y el error se propaga; el reintento numera desde 1"), async (h) => {
    const t = fixtureUuid("t786");
    const agg = fixtureUuid("agg786");
    const r = fixtureUuid("rev786");
    const boom = new Error("fallo inyectado");
    await assert.rejects(
      () =>
        h.inTenant(t, async ({ ledger, outbox }) => {
          await ledger.append(event(t, agg));
          await outbox.enqueue(outboxInput(t, r));
          throw boom;
        }),
      (e: unknown) => e === boom,
    );
    assert.equal((await h.inTenant(t, ({ ledger }) => ledger.listByAggregate(t, "Revocation", agg))).length, 0);
    const ok = await h.inTenant(t, async ({ ledger, outbox }) => {
      const rec = await ledger.append(event(t, agg));
      const enq = await outbox.enqueue(outboxInput(t, r));
      return { sequence: rec.sequence, status: enq.status };
    });
    assert.deepEqual(ok, { sequence: 1, status: "PENDING" });
  });
}
