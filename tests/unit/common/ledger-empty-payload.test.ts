// Gobierna: CA-128 (X6 P2, aprobado por Carlos 2026-10-01), common.spec.yaml INV-CM-05, revocation.spec GRD-RV-19 /
// ERR-RV-13. TEST-CNS-1010. El payload `{}` solo es valido para los seed LOCAL; SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { LEDGER_EVENT_TYPES, LEDGER_LOCAL_SEED_EVENT_TYPES } from "../../../src/server/modules/common/ledger-event-types.ts";
import { assertLedgerPayload, LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";

test("TEST-CNS-1010 payload vacio: valido solo para TENANT_SEEDED y SCHOOL_PARTICIPATION_SEEDED; en cualquier otro tipo (con o sin $def, o desconocido) falla con ERR-RV-13", () => {
  for (const seed of LEDGER_LOCAL_SEED_EVENT_TYPES) assert.doesNotThrow(() => assertLedgerPayload(seed, {}));
  for (const seed of LEDGER_LOCAL_SEED_EVENT_TYPES) {
    assert.throws(() => assertLedgerPayload(seed, { extra: "x" }), LedgerPayloadViolationError, "el seed no admite campos");
  }
  const seeds = new Set<string>(LEDGER_LOCAL_SEED_EVENT_TYPES);
  for (const t of LEDGER_EVENT_TYPES.filter((e) => !seeds.has(e))) {
    assert.throws(() => assertLedgerPayload(t, {}), LedgerPayloadViolationError, `${t} con {} debe fallar`);
  }
  assert.throws(() => assertLedgerPayload("NOT_IN_VOCABULARY", {}), LedgerPayloadViolationError);
  assert.throws(() => assertLedgerPayload("CONSENT_EXPIRED", {}), LedgerPayloadViolationError, "tipo x-disabled-in-it0");
});
