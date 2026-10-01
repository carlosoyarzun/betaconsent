// Gobierna: CA-128 (X6 P2, Carlos 2026-10-01), contracts/schemas/invitation.schema.json (API-CNS-186),
// consent-decision.schema.json (API-CNS-188), EXT-B (i) (recipientChannelRef = email sintetico de dominio
// reservado), INV-CM-09 (refs UUIDv4). TEST-CNS-1011..1012. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { validateConsentDecisionProjection, validateInvitationProjection } from "../../../src/server/modules/common/json-schema-lite.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

const invitation = {
  invitationRef: fixtureUuid("inv"),
  tenantRef: "00000000-0000-0000-0000-000000000001",
  participationRef: fixtureUuid("sp"),
  enrollmentRef: fixtureUuid("en"),
  productRef: "LECTORPRO_BETA",
  contextRef: "ESTUDIO_BETA",
  subjectRef: fixtureUuid("subj"),
  state: "READY",
  sequence: 2,
  recipientBinding: "RECIPIENT_CHANNEL",
  recipientChannelRef: "padre.sintetico@example.invalid",
  boundDecisionMakerRef: fixtureUuid("dm"),
};

test("TEST-CNS-1011 invitation.schema: recipientChannelRef = email sintetico de dominio reservado (EXT-B (i)); UUID, email real, telefono o RUT rechazados", () => {
  assert.deepEqual(validateInvitationProjection(invitation).errors, []);
  for (const ok of ["a@x.test", "a@sub.colegio.invalid", "a@example.com", "a@example.org"]) {
    assert.ok(validateInvitationProjection({ ...invitation, recipientChannelRef: ok }).ok, ok);
  }
  for (const bad of [fixtureUuid("canal"), "persona@gmail.com", "+56912345678", "12345678-5", "a@example.cl", "sin-arroba", `${"a".repeat(250)}@x.test`]) {
    assert.equal(validateInvitationProjection({ ...invitation, recipientChannelRef: bad }).ok, false, "debe rechazar un canal no sintetico");
  }
  assert.equal(validateInvitationProjection({ ...invitation, extra: 1 }).ok, false, "additionalProperties=false");
  assert.equal(validateInvitationProjection({ ...invitation, subjectRef: "alumno-1" }).ok, false, "refs UUIDv4");
});

const decision = {
  consentId: fixtureUuid("c"),
  tenantRef: "00000000-0000-0000-0000-000000000001",
  productRef: "LECTORPRO_BETA",
  contextRef: "ESTUDIO_BETA",
  subjectRef: fixtureUuid("subj"),
  decisionMakerRef: fixtureUuid("dm"),
  chainRef: fixtureUuid("chain"),
  invitationRef: fixtureUuid("inv"),
  verificationRef: fixtureUuid("ver"),
  state: "GRANTED",
  sequence: 3,
  purposes: [{ purpose: "READING_ANALYTICS", choice: "GRANT" }],
  priorStepsComplete: true,
  stepsRecorded: ["CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
  receiptRef: fixtureUuid("rcpt"),
};

test("TEST-CNS-1012 consent-decision.schema: acepta los campos que el dominio persiste (invitationRef, verificationRef, receiptRef, pasos); refs UUIDv4, estado y pasos fuera de catalogo rechazados", () => {
  assert.deepEqual(validateConsentDecisionProjection(decision).errors, []);
  const { receiptRef: _r, ...pending } = decision;
  assert.ok(validateConsentDecisionProjection({ ...pending, state: "PENDING", priorStepsComplete: false, stepsRecorded: [] }).ok, "PENDING sin recibo");
  assert.equal(validateConsentDecisionProjection({ ...decision, receiptRef: "recibo-1" }).ok, false);
  assert.equal(validateConsentDecisionProjection({ ...decision, chainRef: "chain:abc" }).ok, false);
  assert.equal(validateConsentDecisionProjection({ ...decision, state: "UNKNOWN" }).ok, false);
  assert.equal(validateConsentDecisionProjection({ ...decision, stepsRecorded: ["OTRO_PASO"] }).ok, false);
  assert.equal(validateConsentDecisionProjection({ ...decision, stepsRecorded: ["SUBJECT_CONFIRMED", "SUBJECT_CONFIRMED"] }).ok, false, "sin duplicados");
  assert.equal(validateConsentDecisionProjection({ ...decision, email: "x@y.test" }).ok, false, "additionalProperties=false");
  const { sequence: _s, ...noSeq } = decision;
  assert.equal(validateConsentDecisionProjection(noSeq).ok, false, "sequence requerido");
});
