// Gobierna: CA-128 (X6, P1-A), contracts/schemas/ledger-event-payloads.schema.json y security-event-payloads.schema.json,
// common.spec.yaml INV-CM-05 / GRD-RV-19 (ERR-RV-13). TEST-CNS-922. assertLedgerPayload valida contra el contrato real.
// Cableado en los adaptadores de ledger (memoria y Postgres) desde X6 P1-A: TEST-CNS-972 (memoria) y TEST-CNS-973 (PG).

import assert from "node:assert/strict";
import test from "node:test";

import { assertLedgerPayload, LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";
import { LedgerVocabularyViolationError } from "../../../src/server/modules/common/ledger-event-types.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

test("TEST-CNS-922 assertLedgerPayload: payload conforme pasa; campo extra, ref no UUID o falta de requerido -> ERR-RV-13 sin valores en el mensaje", () => {
  const ok = {
    invitationRef: fixtureUuid("i"),
    participationRef: fixtureUuid("p"),
    enrollmentRef: fixtureUuid("e"),
    subjectRef: fixtureUuid("s"),
    reissueOfRef: null,
  };
  assert.doesNotThrow(() => assertLedgerPayload("INVITATION_CREATED", ok));
  for (const bad of [{ ...ok, email: "padre@example.invalid" }, { ...ok, invitationRef: "inv-1" }, { invitationRef: ok.invitationRef }]) {
    assert.throws(
      () => assertLedgerPayload("INVITATION_CREATED", bad),
      (e: unknown) => {
        assert.ok(e instanceof LedgerPayloadViolationError && e instanceof LedgerVocabularyViolationError);
        assert.ok(!/padre@|inv-1/.test(e.message), "el mensaje no filtra valores");
        return true;
      },
    );
  }
  // Stream SECURITY (transitorio) y seed LOCAL (sin $def: solo payload plano).
  assert.throws(() => assertLedgerPayload("OTP_ISSUED", { verificationRef: fixtureUuid("ver-1") }), LedgerPayloadViolationError);
  assert.doesNotThrow(() => assertLedgerPayload("TENANT_SEEDED", {}));
  assert.throws(() => assertLedgerPayload("TENANT_SEEDED", { nested: { a: 1 } }), LedgerPayloadViolationError);
});

test("TEST-CNS-972: el append del ledger en memoria rechaza (ERR-RV-13) un campo extra con PII sintética y NO persiste nada", async () => {
  const ledger = createInMemoryLedgerAdapter();
  const T = fixtureUuid("t972");
  const agg = fixtureUuid("inv972");
  const base = {
    eventType: "INVITATION_CREATED",
    tenantId: T,
    aggregateType: "Invitation",
    aggregateId: agg,
    actorType: "HUMAN" as const,
    expectedSequence: 0,
  };
  const valid = { invitationRef: agg, participationRef: fixtureUuid("p972"), enrollmentRef: fixtureUuid("e972"), subjectRef: fixtureUuid("s972"), reissueOfRef: null };
  await assert.rejects(
    () => ledger.append({ ...base, payload: { ...valid, guardianEmail: "padre.sintetico@example.invalid" }, idempotencyKey: "pii-1" }),
    (e: unknown) => e instanceof LedgerPayloadViolationError && !/padre|example/.test(e.message),
  );
  assert.equal(await ledger.currentSequence(T, agg), 0, "sin escritura");
  assert.deepEqual(await ledger.listByAggregate(T, "Invitation", agg), []);
  // La clave de idempotencia de un intento rechazado no queda reservada: el payload válido con la misma clave procede.
  assert.equal((await ledger.append({ ...base, payload: valid, idempotencyKey: "pii-1" })).sequence, 1);
});
