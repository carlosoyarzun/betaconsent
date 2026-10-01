// Gobierna: CA-128 (X6, P1-A), contracts/schemas/ledger-event-payloads.schema.json y security-event-payloads.schema.json,
// common.spec.yaml INV-CM-05 / GRD-RV-19 (ERR-RV-13). TEST-CNS-922. assertLedgerPayload valida contra el contrato real.
// NOTA: NO esta cableado en los adaptadores (FINDING P1-A): los payloads que hoy emite el dominio no cumplen el contrato.

import assert from "node:assert/strict";
import test from "node:test";

import { assertLedgerPayload, LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";
import { LedgerVocabularyViolationError } from "../../../src/server/modules/common/ledger-event-types.ts";
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
  assert.throws(() => assertLedgerPayload("OTP_ISSUED", { verificationRef: "ver-1" }), LedgerPayloadViolationError);
  assert.doesNotThrow(() => assertLedgerPayload("TENANT_SEEDED", {}));
  assert.throws(() => assertLedgerPayload("TENANT_SEEDED", { nested: { a: 1 } }), LedgerPayloadViolationError);
});
