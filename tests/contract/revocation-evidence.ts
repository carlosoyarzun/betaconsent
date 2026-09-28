// Gobierna: contracts/schemas/ledger-event-payloads.schema.json (CONSENT_REVOKED,
// RECEIPT_CREATED) y specs/state-machines/revocation.spec.yaml R4 (CA-127, FINDING P1).
// Helper compartido por los tests de R4: valida la evidencia de aplicación de una revocación
// contra el schema, no solo el conteo de eventos.

import assert from "node:assert/strict";

import type { LedgerRecord } from "../../src/server/ports/ledger.port.ts";
import { validateLedgerEventPayload } from "./schema-lite.ts";

export interface ExpectedRevocationEvidence {
  readonly revocationRef: string;
  readonly authPath: "OTP" | "RECOVERY";
  readonly recoveryMethod?: "CHANNEL_LINK" | "HUMAN_ASSISTED";
  readonly revokedDecisionRef?: string;
}

/** Exige exactamente un CONSENT_REVOKED y un RECEIPT_CREATED del agregado, ambos válidos contra
 * el schema, con authPath/recoveryMethod esperados y receiptRef == revocationRef (el
 * "Comprobante" mostrado al usuario). */
export function assertRevocationEvidence(events: readonly LedgerRecord[], expected: ExpectedRevocationEvidence): void {
  const revoked = events.filter((e) => e.eventType === "CONSENT_REVOKED");
  const receipts = events.filter((e) => e.eventType === "RECEIPT_CREATED");
  assert.equal(revoked.length, 1, "un solo CONSENT_REVOKED");
  assert.equal(receipts.length, 1, "un solo RECEIPT_CREATED");

  const revokedResult = validateLedgerEventPayload("CONSENT_REVOKED", revoked[0]!.payload);
  assert.ok(revokedResult.ok, `CONSENT_REVOKED inválido:\n${revokedResult.errors.join("\n")}`);
  const payload = revoked[0]!.payload as Record<string, unknown>;
  assert.equal(payload.revocationRef, expected.revocationRef);
  assert.equal(payload.authPath, expected.authPath);
  assert.equal(payload.recoveryMethod, expected.recoveryMethod);
  assert.equal(payload.scope, "ALL");
  if (expected.revokedDecisionRef !== undefined) assert.equal(payload.revokedDecisionRef, expected.revokedDecisionRef);

  const receiptResult = validateLedgerEventPayload("RECEIPT_CREATED", receipts[0]!.payload);
  assert.ok(receiptResult.ok, `RECEIPT_CREATED inválido:\n${receiptResult.errors.join("\n")}`);
  assert.equal((receipts[0]!.payload as Record<string, unknown>).receiptRef, expected.revocationRef);
}
