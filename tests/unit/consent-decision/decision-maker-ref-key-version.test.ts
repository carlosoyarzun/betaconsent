// Gobierna: OPEN-CM-09 (Carlos, 2026-10-06), INV-CM-09, LEGAL DECISION decisionMakerRef (Carlos 2026-10-01, (a)).
// TEST-CNS-1210..TEST-CNS-1212 y TEST-CNS-1214 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  DECISION_MAKER_REF_KEY_VERSION,
  LEGACY_DECISION_MAKER_REF_KEY_VERSION,
  deriveDecisionMakerRef,
  deriveDecisionMakerRefKey,
  recomputeDecisionMakerRef,
  resolveDecisionMakerRefKeyVersion,
} from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { requestRightsOtp, submitRightsOtp } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const SECRET = Buffer.alloc(32, 7);
const TENANT = "11111111-1111-4111-8111-111111111111";
const EMAIL = "persona.sintetica@example.invalid";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test("TEST-CNS-1210 OPEN-CM-09: simulando rotacion a v3, un ref historico v2 se recomputa con la version registrada y no con la nueva; el formato sigue UUIDv4", () => {
  assert.equal(DECISION_MAKER_REF_KEY_VERSION, 2, "la constante vigente sigue en v2 (rotacion no ejecutada)");
  const refV2 = deriveDecisionMakerRef(deriveDecisionMakerRefKey(SECRET, 2), TENANT, EMAIL);
  const refV3 = deriveDecisionMakerRef(deriveDecisionMakerRefKey(SECRET, 3), TENANT, EMAIL);
  assert.match(refV2, UUID_V4);
  assert.match(refV3, UUID_V4);
  assert.notEqual(refV2, refV3, "versiones distintas -> refs distintos (info HKDF propio)");
  // Payloads de ledger: uno historico con v2 registrada, otro posterior a la rotacion con v3.
  const histPayload = { decisionMakerRef: refV2, decisionMakerRefKeyVersion: 2 };
  const newPayload = { decisionMakerRef: refV3, decisionMakerRefKeyVersion: 3 };
  // Simula la rotacion: la version conocida por el verificador sube a 3.
  assert.equal(recomputeDecisionMakerRef(SECRET, histPayload, TENANT, EMAIL, 3), histPayload.decisionMakerRef);
  assert.equal(recomputeDecisionMakerRef(SECRET, newPayload, TENANT, EMAIL, 3), newPayload.decisionMakerRef);
  // Recomputar el historico con la version nueva NO coincide (nunca se re-deriva con la clave nueva).
  assert.notEqual(recomputeDecisionMakerRef(SECRET, { decisionMakerRefKeyVersion: 3 }, TENANT, EMAIL, 3), histPayload.decisionMakerRef);
});

test("TEST-CNS-1214 OPEN-CM-09 P2-2: recompute falla cerrado si la version registrada es mayor que la conocida (DECISION_MAKER_REF_KEY_VERSION)", () => {
  const refV3 = deriveDecisionMakerRef(deriveDecisionMakerRefKey(SECRET, 3), TENANT, EMAIL);
  assert.throws(() => recomputeDecisionMakerRef(SECRET, { decisionMakerRef: refV3, decisionMakerRefKeyVersion: 3 }, TENANT, EMAIL), /mayor que la conocida/);
  assert.throws(() => recomputeDecisionMakerRef(SECRET, { decisionMakerRefKeyVersion: 99 }, TENANT, EMAIL, 3), /mayor que la conocida/);
});

test("TEST-CNS-1211 OPEN-CM-09: evento previo sin el campo se interpreta como v2; version invalida falla cerrado", () => {
  assert.equal(LEGACY_DECISION_MAKER_REF_KEY_VERSION, 2);
  assert.equal(resolveDecisionMakerRefKeyVersion({ decisionMakerRef: "x" }), 2);
  const ref = deriveDecisionMakerRef(deriveDecisionMakerRefKey(SECRET), TENANT, EMAIL);
  assert.equal(deriveDecisionMakerRefKey(SECRET).keyVersion, DECISION_MAKER_REF_KEY_VERSION, "la clave viaja como {key, keyVersion}");
  assert.equal(recomputeDecisionMakerRef(SECRET, {}, TENANT, EMAIL), ref, "sin campo -> v2 -> mismo ref que el vigente");
  for (const bad of [1, 0, -1, 2.5, "2", null, 1001, Number.NaN]) {
    assert.throws(() => resolveDecisionMakerRefKeyVersion({ decisionMakerRefKeyVersion: bad }), /keyVersion invalida/);
  }
  assert.throws(() => deriveDecisionMakerRefKey(SECRET, 1), /keyVersion invalida/);
  assert.throws(() => deriveDecisionMakerRefKey(SECRET, 2.5), /keyVersion invalida/);
});

test("TEST-CNS-1212 OPEN-CM-09: DECISION_MAKER_CHANNEL_VERIFIED nuevo registra la decisionMakerRefKeyVersion de la clave recibida (submitRightsOtp) (payload valida contra el contrato en el append)", async () => {
  const otpRepo = createInMemoryOtpVerificationRepository();
  const ledger = createInMemoryLedgerAdapter();
  const ports = {
    otpRepo,
    channel: createInMemoryOtpChannelSink(),
    ledger,
    uow: createInMemoryTenancy({ ledger, otpRepo }).uow,
    policy: { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 },
    secret: randomBytes(32),
  };
  const ver = fixtureUuid("ver-keyversion-1");
  await requestRightsOtp(ports, "tenant-1", ver, "REVOCATION", fixtureUuid("chain-kv"), "mgmt:chain-kv");
  const code = ports.channel.sent[0]?.code ?? "";
  await submitRightsOtp(ports, "tenant-1", ver, "REVOCATION", code, fixtureUuid("dm-kv"), 3);
  const events = await ports.ledger.listByAggregate("tenant-1", "DecisionMakerVerification", ver);
  const verified = events.find((e) => e.eventType === "DECISION_MAKER_CHANNEL_VERIFIED");
  assert.ok(verified);
  assert.equal(verified.payload.decisionMakerRefKeyVersion, 3, "la version viene de la clave que llega al emisor, no de la constante");
});
