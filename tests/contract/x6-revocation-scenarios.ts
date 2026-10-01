// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128), revocation.spec.yaml (R1..R7, R1r..R3r, RH2/RH3),
// "CARLOS r3 R5-1". Escenarios compartidos entre los tests en memoria (unit) y Postgres real
// (integration): las tres vías de revocación (OTP -> enlace -> caso humano) hasta APPLIED y el
// tramo downstream (R5/R6/R7) contra el stub interno. SYNTHETIC ONLY.

import assert from "node:assert/strict";

import {
  attestHumanAssistedVerification,
  confirmRevocation,
  cosignCaseConfirmation,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  recordCaseConfirmationPendingCosign,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  verifyRevocationOtp,
  type RevocationPorts,
} from "../../src/server/modules/revocation/revocation.ts";
import {
  attestDownstreamErasure,
  emitRevocationDownstream,
  recordDownstreamAck,
} from "../../src/server/modules/revocation/downstream.ts";
import { createInMemoryDownstreamStub, type InMemoryDownstreamStub } from "../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink, type InMemoryRecoveryLinkChannelSink } from "../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRevocationRepository } from "../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../src/infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../src/infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "../../src/infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { withInMemoryTenancy } from "../../src/infra/adapters/in-memory-tenancy.ts";
import { createInMemoryStaffIdentityAdapter } from "../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { DownstreamEvidence } from "../../src/server/ports/downstream-stub.port.ts";
import { syntheticDecision } from "./synthetic-decision.ts";
import { fixtureUuid } from "./uuid-fixture.ts";

export const X6_STAFF = createInMemoryStaffIdentityAdapter([
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-03", role: "APPROVER" },
  { principalRef: "staff-synthetic-04", role: "APPROVER" },
]);

export type RevocationPath = "OTP" | "LINK" | "CASE";
export const REVOCATION_PATHS: readonly RevocationPath[] = ["OTP", "LINK", "CASE"];

export interface X6Env {
  readonly ports: RevocationPorts;
  readonly stub: InMemoryDownstreamStub;
  readonly sink: InMemoryRecoveryLinkChannelSink;
}

/** Siembra la GRANTED vigente (cadena `chain`) y lleva la revocación por `path` hasta APPLIED. */
export async function revokeVia(env: X6Env, T: string, label: string, path: RevocationPath): Promise<{ revocationRef: string; decisionRef: string; chainRef: string }> {
  const { ports, sink } = env;
  const D = fixtureUuid(`d-${label}`);
  const chain = `chain-${label}`;
  await ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: chain });
  let revocationRef = fixtureUuid(`r-${label}`);
  if (path === "OTP") {
    await requestRevocation(ports, T, { revocationRef, chainRef: chain, revokedDecisionRef: D });
    await verifyRevocationOtp(ports, T, revocationRef, fixtureUuid(`v-${label}`));
    assert.equal((await confirmRevocation(ports, T, revocationRef)).status, "APPLIED");
  } else if (path === "LINK") {
    await issueRecoveryLinkBearer(ports, T, chain, D, "REQUESTER_ASKED");
    const token = sink.sent[sink.sent.length - 1]!.recoveryPath.replace("/r/", "");
    const outcome = await revokeWithRecoveryLinkByHash(ports, hashRecoveryToken(token));
    assert.equal(outcome.kind, "CONFIRMED");
    revocationRef = (outcome as { revocationRef: string }).revocationRef;
    assert.equal((await ports.revocationRepo.findByRef(T, revocationRef))?.status, "APPLIED");
  } else {
    const caseRef = `case-${label}`;
    await ports.revocationRepo.save({ revocationRef, tenantId: T, chainRef: chain, caseRef, revokedDecisionRef: D, status: "REQUESTED" });
    await attestHumanAssistedVerification(ports, T, revocationRef, caseRef);
    await recordCaseConfirmationPendingCosign(ports, X6_STAFF, T, revocationRef, caseRef, { recordedByPrincipalRef: "staff-synthetic-01" });
    const done = await cosignCaseConfirmation(ports, X6_STAFF, T, revocationRef, caseRef, { cosignedByPrincipalRef: "staff-synthetic-02" });
    assert.equal(done.status, "APPLIED");
  }
  return { revocationRef, decisionRef: D, chainRef: chain };
}

export function signedEvidence(
  env: X6Env,
  kind: "ACK" | "ERASURE_CONFIRMED",
  revocationRef: string,
  subscriptionRefs: readonly string[],
  label: string,
): DownstreamEvidence[] {
  return subscriptionRefs.map((subscriptionRef) => {
    const evidenceRef = fixtureUuid(`${kind}-${label}-${subscriptionRef}`);
    return { subscriptionRef, evidenceRef, signature: env.stub.sign(kind, revocationRef, subscriptionRef, evidenceRef) };
  });
}

/** APPLIED -> DOWNSTREAM_PENDING -> DELIVERED -> COMPLETED contra el stub interno (R5-1). */
export async function completeDownstream(env: X6Env, T: string, revocationRef: string, label: string): Promise<void> {
  const { ports, stub } = env;
  const refs = await stub.currentSubscriptionRefs(T);
  assert.equal((await emitRevocationDownstream(ports, T, revocationRef)).status, "DOWNSTREAM_PENDING");
  assert.equal((await recordDownstreamAck(ports, T, revocationRef, signedEvidence(env, "ACK", revocationRef, refs, label))).status, "DELIVERED");
  assert.equal((await attestDownstreamErasure(ports, T, revocationRef, signedEvidence(env, "ERASURE_CONFIRMED", revocationRef, refs, label))).status, "COMPLETED");
}

/** Puertos in-memory completos (IT0 LOCAL/CI) con el stub interno de R5-1. */
export function makeX6Env(opts: { withStub?: boolean; stubRefs?: readonly string[] } = {}): X6Env {
  const stub = createInMemoryDownstreamStub(opts.stubRefs);
  const sink = createInMemoryRecoveryLinkChannelSink();
  const ports: RevocationPorts = withInMemoryTenancy({
    revocationRepo: createInMemoryRevocationRepository(),
    ledger: createInMemoryLedgerAdapter(),
    outbox: createInMemoryOutboxAdapter(),
    recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
    recoveryLinkChannel: sink,
    recoveryTokenPolicy: { ttlMs: 60_000 },
    consentDecisionRepo: createInMemoryConsentDecisionRepository(),
    ...(opts.withStub === false ? {} : { downstreamStub: stub }),
  });
  return { ports, stub, sink };
}

