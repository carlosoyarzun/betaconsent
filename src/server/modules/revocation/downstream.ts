// Gobierna: specs/state-machines/revocation.spec.yaml R5 (APPLIED -> DOWNSTREAM_PENDING), R6
// (DOWNSTREAM_PENDING -> DELIVERED), R7 (DELIVERED -> COMPLETED), GRD-RV-12/13/14, ERR-RV-10,
// INV-RV-03 (DELIVERED != COMPLETED), INV-10 (ningún timer cierra una Revocation), "CARLOS r3 R5-1"
// (revocación hasta COMPLETED contra el stub interno), DEC-BR-014 rev. 8 §3 X6 (CA-128).
//
// Alcance IT0: el stub interno (DownstreamStubPort) es el único consumidor. Las transiciones las
// dispara un worker (SYSTEM_GUARD) o un test; ninguna se dispara por tiempo. COMPLETED solo con
// erasure.confirmed verificado de CADA subscriptionRef congelado en R5: la reconciliación nunca
// fija COMPLETED y DELIVERED (recibido) no lo implica. NO implementa: FLAG-deliveryFailed /
// FLAG-overdue (GRD-RV-12 reintentos, GRD-CM-12 plazo: LEGAL DECISION DEC-BR-006 sin valor), ni la
// firma/transporte reales (OPEN-CT-02). Con N>1 suscripciones, el `ackRef` del evento
// REVOCATION_DELIVERED es el del primer ACK por orden de subscriptionRef (la spec lo declara singular).

import { DomainError } from "../common/errors.ts";
import { sequencedAppender } from "../common/ledger-append.ts";
import type { RevocationRecord } from "../../ports/revocation-repository.port.ts";
import type { DownstreamEvidence, DownstreamStubPort } from "../../ports/downstream-stub.port.ts";
import { inTx, requireRevocation, revocationSequence, type RevocationPorts } from "./revocation.ts";

function stubOf(ports: RevocationPorts): DownstreamStubPort {
  // Sin stub configurado no hay destino que congelar ni evidencia que verificar: falla cerrado.
  if (!ports.downstreamStub) throw new DomainError("ERR-CM-12");
  return ports.downstreamStub;
}

const SYSTEM = { actorType: "SYSTEM_GUARD" } as const;

/** Destinos congelados en R5 (payload de REVOCATION_DOWNSTREAM_EMITTED); nunca se recalculan. */
async function frozenSubscriptionRefs(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<readonly string[]> {
  const events = await ports.ledger.listByAggregate(tenantId, "Revocation", revocationRef);
  const emitted = events.find((e) => e.eventType === "REVOCATION_DOWNSTREAM_EMITTED");
  const refs = (emitted?.payload as { subscriptionRefs?: unknown } | undefined)?.subscriptionRefs;
  if (!Array.isArray(refs) || refs.length === 0) throw new DomainError("ERR-CM-06");
  return refs as string[];
}

/** Cobertura exacta del conjunto congelado (sin faltantes, extras ni repetidos) y firma válida de
 * cada evidencia; si no, ERR-RV-10 sin escrituras (GRD-RV-13/14: una evidencia falsa no avanza). */
async function assertEvidenceCoversFrozen(
  ports: RevocationPorts,
  tenantId: string,
  kind: "ACK" | "ERASURE_CONFIRMED",
  revocationRef: string,
  frozen: readonly string[],
  evidences: readonly DownstreamEvidence[],
): Promise<readonly DownstreamEvidence[]> {
  const given = evidences.map((e) => e.subscriptionRef).sort();
  const expected = [...frozen].sort();
  if (given.length !== expected.length || given.some((ref, i) => ref !== expected[i])) throw new DomainError("ERR-RV-10");
  const stub = stubOf(ports);
  for (const evidence of evidences) {
    if (!(await stub.verifyEvidence(tenantId, kind, revocationRef, evidence))) throw new DomainError("ERR-RV-10");
  }
  return [...evidences].sort((a, b) => a.subscriptionRef.localeCompare(b.subscriptionRef));
}

/** R5: APPLIED -> DOWNSTREAM_PENDING. Congela el conjunto de destinos en el ledger. Idempotente. */
export function emitRevocationDownstream(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  return inTx(ports, tenantId, async (p) => {
    const base = await revocationSequence(p, tenantId, revocationRef);
    const found = await requireRevocation(p, tenantId, revocationRef);
    if (found.status === "DOWNSTREAM_PENDING" || found.status === "DELIVERED" || found.status === "COMPLETED") return found;
    if (found.status !== "APPLIED") throw new DomainError("ERR-CM-06");
    const subscriptionRefs = [...(await stubOf(p).currentSubscriptionRefs(tenantId))].sort();
    if (subscriptionRefs.length === 0) throw new DomainError("ERR-CM-12");
    await sequencedAppender(p.ledger, base).append({
      eventType: "REVOCATION_DOWNSTREAM_EMITTED",
      tenantId,
      aggregateType: "Revocation",
      aggregateId: revocationRef,
      ...SYSTEM,
      payload: { revocationRef, subscriptionRefs },
      idempotencyKey: `${revocationRef}:r5`,
    });
    const next: RevocationRecord = { ...found, status: "DOWNSTREAM_PENDING" };
    await p.revocationRepo.save(next);
    return next;
  });
}

/** R6: DOWNSTREAM_PENDING -> DELIVERED con ACK firmado de CADA subscriptionRef congelado
 * (GRD-RV-13). DELIVERED = recibido, no suprimido (RULE-CNS-026). Idempotente por (revocationRef, ackRef). */
export function recordDownstreamAck(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  acks: readonly DownstreamEvidence[],
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, async (p) => {
    const base = await revocationSequence(p, tenantId, revocationRef);
    const found = await requireRevocation(p, tenantId, revocationRef);
    if (found.status === "DELIVERED" || found.status === "COMPLETED") return found;
    if (found.status !== "DOWNSTREAM_PENDING") throw new DomainError("ERR-CM-06");
    const frozen = await frozenSubscriptionRefs(p, tenantId, revocationRef);
    const verified = await assertEvidenceCoversFrozen(p, tenantId, "ACK", revocationRef, frozen, acks);
    const ackRef = verified[0]!.evidenceRef;
    await sequencedAppender(p.ledger, base).append({
      eventType: "REVOCATION_DELIVERED",
      tenantId,
      aggregateType: "Revocation",
      aggregateId: revocationRef,
      ...SYSTEM,
      payload: { revocationRef, ackRef },
      idempotencyKey: `${revocationRef}:r6:${ackRef}`,
    });
    const next: RevocationRecord = { ...found, status: "DELIVERED" };
    await p.revocationRepo.save(next);
    return next;
  });
}

/** R7: DELIVERED -> COMPLETED con erasure.confirmed verificado de CADA subscriptionRef congelado
 * (GRD-RV-14). Emite DOWNSTREAM_ERASURE_ATTESTED + el recibo final (RECEIPT_CREATED, REQ-CNS-033).
 * Idempotente por (revocationRef, attestationRef). Desde DOWNSTREAM_PENDING no se salta DELIVERED. */
export function attestDownstreamErasure(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  attestations: readonly DownstreamEvidence[],
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, async (p) => {
    const base = await revocationSequence(p, tenantId, revocationRef);
    const found = await requireRevocation(p, tenantId, revocationRef);
    if (found.status === "COMPLETED") return found;
    if (found.status !== "DELIVERED") throw new DomainError("ERR-CM-06");
    const frozen = await frozenSubscriptionRefs(p, tenantId, revocationRef);
    const verified = await assertEvidenceCoversFrozen(p, tenantId, "ERASURE_CONFIRMED", revocationRef, frozen, attestations);
    const attestationRef = verified[0]!.evidenceRef;
    const appender = sequencedAppender(p.ledger, base);
    await appender.append({
      eventType: "DOWNSTREAM_ERASURE_ATTESTED",
      tenantId,
      aggregateType: "Revocation",
      aggregateId: revocationRef,
      ...SYSTEM,
      payload: { revocationRef },
      idempotencyKey: `${revocationRef}:r7:${attestationRef}`,
    });
    await appender.append({
      eventType: "RECEIPT_CREATED",
      tenantId,
      aggregateType: "Revocation",
      aggregateId: revocationRef,
      ...SYSTEM,
      payload: { receiptRef: revocationRef, managementLinkIssued: false },
      idempotencyKey: `${revocationRef}:receipt-final`,
    });
    const next: RevocationRecord = { ...found, status: "COMPLETED" };
    await p.revocationRepo.save(next);
    return next;
  });
}
