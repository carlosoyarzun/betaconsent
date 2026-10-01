// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128, "revocación hasta COMPLETED con el stub interno (R5-1)"),
// revocation.spec.yaml R5/R6/R7, GRD-RV-12/13/14, ERR-RV-10, INV-RV-03 (DELIVERED != COMPLETED),
// INV-RV-02, "CARLOS r3 R5-1". TEST-CNS-962 (ciclo completo en las tres vías), TEST-CNS-963
// (evidencia falsa/saltos/sin stub). SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { requestRevocation } from "../../../src/server/modules/revocation/revocation.ts";
import { attestDownstreamErasure, emitRevocationDownstream, recordDownstreamAck } from "../../../src/server/modules/revocation/downstream.ts";
import { INTERNAL_STUB_SUBSCRIPTION_REF } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { makeX6Env, REVOCATION_PATHS, revokeVia, signedEvidence, type X6Env } from "../../contract/x6-revocation-scenarios.ts";

const T = "tenant-x6-962";

const types = async (env: X6Env, ref: string): Promise<string[]> => (await env.ports.ledger.listByAggregate(T, "Revocation", ref)).map((e) => e.eventType);

for (const path of REVOCATION_PATHS) {
  test(`TEST-CNS-962 (${path}): la revocación llega hasta COMPLETED contra el stub interno (R5-1); DELIVERED no es COMPLETED; eventos con payload válido y secuencia sin huecos`, async () => {
    const env = makeX6Env();
    const { revocationRef, decisionRef } = await revokeVia(env, T, `962-${path}`, path);
    const refs = await env.stub.currentSubscriptionRefs(T);
    assert.deepEqual(refs, [INTERNAL_STUB_SUBSCRIPTION_REF]);

    assert.equal((await emitRevocationDownstream(env.ports, T, revocationRef)).status, "DOWNSTREAM_PENDING");
    const ack = signedEvidence(env, T, "ACK", revocationRef, refs, `962-${path}`);
    assert.equal((await recordDownstreamAck(env.ports, T, revocationRef, ack)).status, "DELIVERED");
    // INV-RV-03: DELIVERED = recibido, no suprimido; sin atestación no hay COMPLETED ni recibo final.
    assert.notEqual((await env.ports.revocationRepo.findByRef(T, revocationRef))?.status, "COMPLETED");
    assert.equal((await types(env, revocationRef)).includes("DOWNSTREAM_ERASURE_ATTESTED"), false);

    const attest = signedEvidence(env, T, "ERASURE_CONFIRMED", revocationRef, refs, `962-${path}`);
    assert.equal((await attestDownstreamErasure(env.ports, T, revocationRef, attest)).status, "COMPLETED");

    // Idempotencia (revocationRef, ackRef|attestationRef): reintentos devuelven COMPLETED sin eventos nuevos.
    const before = await types(env, revocationRef);
    assert.equal((await emitRevocationDownstream(env.ports, T, revocationRef)).status, "COMPLETED");
    assert.equal((await recordDownstreamAck(env.ports, T, revocationRef, ack)).status, "COMPLETED");
    assert.equal((await attestDownstreamErasure(env.ports, T, revocationRef, attest)).status, "COMPLETED");
    assert.deepEqual(await types(env, revocationRef), before);

    const events = await env.ports.ledger.listByAggregate(T, "Revocation", revocationRef);
    assert.deepEqual(events.map((e) => e.sequence), events.map((_, i) => i + 1));
    const tail = events.filter((e) => ["REVOCATION_DOWNSTREAM_EMITTED", "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED"].includes(e.eventType));
    assert.deepEqual(tail.map((e) => e.eventType), ["REVOCATION_DOWNSTREAM_EMITTED", "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED"]);
    for (const e of events.slice(3)) assert.ok(validateLedgerEventPayload(e.eventType, e.payload).ok, `${e.eventType}: ${validateLedgerEventPayload(e.eventType, e.payload).errors.join(";")}`);
    assert.deepEqual((events.find((e) => e.eventType === "REVOCATION_DOWNSTREAM_EMITTED")!.payload as { subscriptionRefs: string[] }).subscriptionRefs, refs, "destinos congelados en R5");
    assert.equal(events.filter((e) => e.eventType === "RECEIPT_CREATED").length, 2, "recibo de R4 + recibo final de R7");
    assert.equal(events.filter((e) => e.eventType === "CONSENT_REVOKED").length, 1);
    assert.equal((events.find((e) => e.eventType === "REVOCATION_DOWNSTREAM_EMITTED"))!.actorType, "SYSTEM_GUARD");

    // COMPLETED es terminal (INV-RV-02): la decisión sigue REVOKED y no hay nueva revocación sobre ella (GRD-RV-02).
    assert.equal((await env.ports.consentDecisionRepo.findByConsentId(T, decisionRef))?.state, "REVOKED");
    await assert.rejects(
      () => requestRevocation(env.ports, T, { revocationRef: fixtureUuid(`again-${path}`), chainRef: `chain-962-${path}`, revokedDecisionRef: decisionRef }),
      (e: unknown) => e instanceof DomainError && e.code === "ERR-RV-02",
    );
    // Un solo consent.revoked en el outbox pese a R5..R7 (R5 congela destinos, no re-encola).
    const outbox = env.ports.outbox as unknown as { enqueued: readonly unknown[] };
    assert.equal(outbox.enqueued.length, 1);
  });
}

test("TEST-CNS-963: evidencia falsa, incompleta o fuera de orden no avanza el estado (ERR-RV-10 / ERR-CM-06); sin stub falla cerrado (ERR-CM-12); la reconciliación no fija COMPLETED", async () => {
  const env = makeX6Env({ stubRefs: [fixtureUuid("sub-a"), fixtureUuid("sub-b")] });
  const { revocationRef } = await revokeVia(env, T, "963", "OTP");
  const refs = await env.stub.currentSubscriptionRefs(T);
  const state = async () => (await env.ports.revocationRepo.findByRef(T, revocationRef))?.status;
  const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

  // Fuera de orden: R6/R7 antes de R5 y R7 antes de R6.
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, signedEvidence(env, T, "ACK", revocationRef, refs, "963")), code("ERR-CM-06"));
  await assert.rejects(() => attestDownstreamErasure(env.ports, T, revocationRef, signedEvidence(env, T, "ERASURE_CONFIRMED", revocationRef, refs, "963")), code("ERR-CM-06"));
  await emitRevocationDownstream(env.ports, T, revocationRef);
  await assert.rejects(() => attestDownstreamErasure(env.ports, T, revocationRef, signedEvidence(env, T, "ERASURE_CONFIRMED", revocationRef, refs, "963")), code("ERR-CM-06"));
  assert.equal(await state(), "DOWNSTREAM_PENDING", "no se salta DELIVERED");

  const good = signedEvidence(env, T, "ACK", revocationRef, refs, "963");
  const before = await env.ports.ledger.listByAggregate(T, "Revocation", revocationRef);
  // ACK de un solo destino (conjunto congelado de 2), con firma falsa, ajena a otra revocación, o de un destino no congelado.
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, [good[0]!]), code("ERR-RV-10"));
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, [good[0]!, { ...good[1]!, signature: "00".repeat(32) }]), code("ERR-RV-10"));
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, [good[0]!, { ...good[1]!, signature: "zz" }]), code("ERR-RV-10"));
  const foreign = signedEvidence(env, T, "ACK", fixtureUuid("otra-revocacion"), refs, "963");
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, foreign), code("ERR-RV-10"));
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, [good[0]!, { ...good[0]! }]), code("ERR-RV-10"));
  const wrongKind = signedEvidence(env, T, "ERASURE_CONFIRMED", revocationRef, refs, "963");
  await assert.rejects(() => recordDownstreamAck(env.ports, T, revocationRef, wrongKind), code("ERR-RV-10"));
  assert.equal(await state(), "DOWNSTREAM_PENDING");
  assert.equal((await env.ports.ledger.listByAggregate(T, "Revocation", revocationRef)).length, before.length, "evidencia falsa: sin eventos");

  // Una atestación firmada como ACK (otro `kind`) no sirve para R7.
  await recordDownstreamAck(env.ports, T, revocationRef, good);
  await assert.rejects(() => attestDownstreamErasure(env.ports, T, revocationRef, good), code("ERR-RV-10"));
  assert.equal(await state(), "DELIVERED");
});

test("TEST-CNS-964: sin DownstreamStubPort R5 falla cerrado (ERR-CM-12) y la Revocation sigue APPLIED", async () => {
  const env = makeX6Env({ withStub: false });
  const { revocationRef } = await revokeVia(env, T, "963b", "OTP");
  await assert.rejects(() => emitRevocationDownstream(env.ports, T, revocationRef), (e: unknown) => e instanceof DomainError && e.code === "ERR-CM-12");
  assert.equal((await env.ports.revocationRepo.findByRef(T, revocationRef))?.status, "APPLIED");
});
