// Gobierna: CA-128 (X6, re-verificación de seguridad, P2-1/3/4/5/6), revocation.spec RH2, GRD-RV-09, GRD-CM-13,
// downstream-stub.port.ts (R5-1), SEC-CNS-006 (OTP). TEST-CNS-1004..1009. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryDownstreamStub } from "../../../src/infra/adapters/in-memory-downstream-stub.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { loadRightsCaseHttpConfig } from "../../../src/server/entrypoints/http/config.ts";
import { deriveOtpChannelRefKey, opaqueChannelRef } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { opaqueUuidV4 } from "../../../src/server/modules/common/opaque-ref.ts";
import { proposeCaseVerification } from "../../../src/server/modules/revocation/revocation.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";
import { RH2_APPROVER, RH2_OPERATOR, RH2_ROSTER } from "../../contract/rh2-helper.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { makeX6Env } from "../../contract/x6-revocation-scenarios.ts";

const T = "tenant-x6-1004";
const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

// TEST-CNS-1004 (aprobacion RH2 por el handler HTTP de web) se retiro: RH2 vive en el proceso platform (ADR-010 rev. 5, 6d parte 2; TEST-CNS-1700+).

test("TEST-CNS-1005 P2-3: una propuesta RH2 pendiente con otro proposalRef no se reemplaza en silencio (ERR-CM-06); la misma es idempotente", async () => {
  const env = makeX6Env();
  const revocationRef = fixtureUuid("r-1005");
  const caseRef = fixtureUuid("c-1005");
  await env.ports.revocationRepo.save({ revocationRef, tenantId: T, chainRef: "chain-1005", caseRef, revokedDecisionRef: fixtureUuid("d-1005"), status: "REQUESTED" });
  const first = fixtureUuid("p1-1005");
  const input = { proposalRef: first, verificationScriptVersion: "guion-1" };
  await proposeCaseVerification(env.ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, input);
  await assert.rejects(
    () => proposeCaseVerification(env.ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: fixtureUuid("rh2-operator-2") }, { proposalRef: fixtureUuid("p2-1005"), verificationScriptVersion: "guion-2" }),
    code("ERR-CM-06"),
  );
  const kept = (await env.ports.revocationRepo.findByRef(T, revocationRef))!.proposal!;
  assert.deepEqual([kept.proposalRef, kept.proposedByRef, kept.verificationScriptVersion], [first, RH2_OPERATOR, "guion-1"]);
  assert.equal((await proposeCaseVerification(env.ports, RH2_ROSTER, T, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, input)).proposal?.proposalRef, first);
});

test("TEST-CNS-1006 P2-4: el MAC del stub cubre el tenant y la firma debe ser exactamente 64 hex", async () => {
  const stub = createInMemoryDownstreamStub();
  const [sub] = await stub.currentSubscriptionRefs("tenant-a");
  const rv = fixtureUuid("rv-1006");
  const ev = fixtureUuid("ev-1006");
  const signature = stub.sign("tenant-a", "ACK", rv, sub!, ev);
  const evidence = { subscriptionRef: sub!, evidenceRef: ev, signature };
  assert.equal(await stub.verifyEvidence("tenant-a", "ACK", rv, evidence), true);
  assert.equal(await stub.verifyEvidence("tenant-b", "ACK", rv, evidence), false, "firma de otro tenant no vale");
  for (const bad of [signature.slice(0, 62), `${signature}00`, signature.toUpperCase(), `${signature.slice(0, 63)}g`, "", "zz", ` ${signature}`, signature.slice(0, 63)]) {
    assert.equal(await stub.verifyEvidence("tenant-a", "ACK", rv, { ...evidence, signature: bad }), false, bad);
  }
});

test("TEST-CNS-1007 P2-5: channelRef del OTP usa una subclave HKDF distinta del secreto con que se hashea el código", () => {
  const secret = randomBytes(32);
  const sub = deriveOtpChannelRefKey(secret);
  assert.equal(sub.length, 32);
  assert.ok(!sub.equals(secret), "la subclave no es el secreto");
  assert.ok(deriveOtpChannelRefKey(secret).equals(sub), "determinista");
  assert.ok(!deriveOtpChannelRefKey(randomBytes(32)).equals(sub));
  const ref = opaqueChannelRef(secret, T, "canal-sintetico");
  assert.equal(ref, opaqueChannelRef(secret, T, "canal-sintetico"));
  assert.notEqual(ref, opaqueUuidV4("otp-channel", `${T}\u0000canal-sintetico`, secret), "no es el HMAC con el secreto crudo (el del hash del código)");
  assert.equal(ref, opaqueUuidV4("otp-channel", `${T}\u0000canal-sintetico`, sub));
  assert.notEqual(ref, opaqueChannelRef(secret, "otro-tenant", "canal-sintetico"));
});

test("TEST-CNS-1008 P2-6: el roster rechaza al construirse un principalRef duplicado (también entre roles)", () => {
  const dup = fixtureUuid("dup-1008");
  assert.throws(() => createInMemoryStaffIdentityAdapter([{ principalRef: dup, role: "RIGHTS_OPERATOR" }, { principalRef: dup, role: "APPROVER" }]), /duplicado/);
  assert.throws(() => createInMemoryStaffIdentityAdapter([{ principalRef: dup, role: "APPROVER" }, { principalRef: dup, role: "APPROVER" }]), /duplicado/);
  assert.doesNotThrow(() => createInMemoryStaffIdentityAdapter([{ principalRef: dup, role: "APPROVER" }, { principalRef: fixtureUuid("otro-1008"), role: "RIGHTS_OPERATOR" }]));
});
