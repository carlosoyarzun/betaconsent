// Gobierna: src/server/ports/outbox.port.ts (CA-127), ADR-001 §11 regla (4), outbox-events.schema.json.
// Suite de contrato de OutboxPort: se registra contra cada adaptador. TEST-CNS-694.

import test from "node:test";
import assert from "node:assert/strict";

import type { OutboxEnqueueInput, OutboxPort, OutboxRecord } from "../../../src/server/ports/outbox.port.ts";
import { validateOutboxEvent } from "../schema-lite.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

function input(tenantId: string, revocationRef: string, dedupeKey = `${revocationRef}:consent.revoked`): OutboxEnqueueInput {
  return {
    tenantId,
    eventType: "consent.revoked",
    contextRef: "BETA_2026_01",
    subjectRef: fixtureUuid(`subject-${revocationRef}`),
    occurredAt: "2026-09-28T12:00:00.000Z",
    payload: { revocationRef, scope: "ALL", effectiveAt: "2026-09-28T12:00:00.000Z" },
    dedupeKey,
  };
}

export function runOutboxPortContract(adapterName: string, makeAdapter: () => OutboxPort): void {
  const TA = fixtureUuid("tenant-694-a");
  const TB = fixtureUuid("tenant-694-b");
  const R = fixtureUuid("rev-694");

  test(`TEST-CNS-694 OutboxPort contract (${adapterName}): enqueue devuelve un sobre válido, PENDING, con eventId UUIDv4 asignado por el adaptador`, () => {
    const record: OutboxRecord = makeAdapter().enqueue(input(TA, R));
    assert.equal(record.status, "PENDING");
    assert.equal(record.tenantId, TA);
    assert.ok(validateOutboxEvent(record.envelope).ok);
    assert.equal(record.envelope.environment, "LOCAL");
    assert.equal(record.envelope.dataClass, "SYNTHETIC");
  });

  test(`TEST-CNS-694 OutboxPort contract (${adapterName}): dedupe por (tenant, key): repetir devuelve el mismo registro (mismo eventId)`, () => {
    const outbox = makeAdapter();
    const first = outbox.enqueue(input(TA, R));
    const second = outbox.enqueue(input(TA, R));
    assert.equal(second.envelope.eventId, first.envelope.eventId);
    // Otra key en el mismo tenant sí crea un registro nuevo.
    const other = outbox.enqueue(input(TA, R, `${R}:otra`));
    assert.notEqual(other.envelope.eventId, first.envelope.eventId);
  });

  test(`TEST-CNS-694 OutboxPort contract (${adapterName}): la misma key en otro tenant da 2 registros distintos (tenant_id es la clave de aislamiento)`, () => {
    const outbox = makeAdapter();
    const a = outbox.enqueue(input(TA, R));
    const b = outbox.enqueue(input(TB, R));
    assert.notEqual(a.envelope.eventId, b.envelope.eventId);
    assert.equal(a.envelope.tenantRef, TA);
    assert.equal(b.envelope.tenantRef, TB);
  });
}
