// Gobierna: OPEN-CM-09 (Carlos, 2026-10-06, obligatorio), contracts/schemas/ledger-event-payloads.schema.json
// (lista blanca por eventType, INV-CM-05). TEST-CNS-1213.

import test from "node:test";
import assert from "node:assert/strict";

import { fixtureUuid } from "../uuid-fixture.ts";
import { validateLedgerEventPayload } from "../schema-lite.ts";

const inv = { invitationRef: fixtureUuid("i"), verificationRef: fixtureUuid("v"), decisionMakerRef: fixtureUuid("d"), bindingResult: "OPEN_CT_PENDING" };
const chan = { verificationRef: fixtureUuid("v"), parentRef: fixtureUuid("p"), decisionMakerRef: fixtureUuid("d"), scope: "DECISION", method: "EMAIL_OTP", bindingResult: "OPEN_CT_PENDING" };

test("TEST-CNS-1213 contrato ledger: decisionMakerRefKeyVersion OBLIGATORIO en eventos nuevos (sin campo = rechazo), entero 2..1000; en otros eventos sigue prohibido", () => {
  for (const [type, base] of [["INVITATION_VERIFIED", inv], ["DECISION_MAKER_CHANNEL_VERIFIED", chan]] as const) {
    assert.equal(validateLedgerEventPayload(type, base)?.ok, false, `${type} sin campo se rechaza (obligatorio, Carlos 2026-10-06)`);
    assert.equal(validateLedgerEventPayload(type, { ...base, decisionMakerRefKeyVersion: 2 })?.ok, true);
    assert.equal(validateLedgerEventPayload(type, { ...base, decisionMakerRefKeyVersion: 3 })?.ok, true);
    for (const bad of [1, 0, 2.5, "2", null, 1001]) {
      assert.equal(validateLedgerEventPayload(type, { ...base, decisionMakerRefKeyVersion: bad })?.ok, false, `${type} rechaza ${String(bad)}`);
    }
  }
  assert.equal(validateLedgerEventPayload("INVITATION_SENT", { decisionMakerRefKeyVersion: 2 } as never)?.ok, false);
});
