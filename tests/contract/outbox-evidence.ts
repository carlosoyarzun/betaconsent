// Gobierna: contracts/schemas/outbox-events.schema.json (API-CNS-185, DRAFT),
// revocation.spec.yaml R4 (emits consent.revoked). CA-127. Helper compartido por los tests de
// R4: valida el sobre del outbox contra el schema, no solo el conteo.

import assert from "node:assert/strict";

import type { LedgerRecord } from "../../src/server/ports/ledger.port.ts";
import type { OutboxRecord } from "../../src/server/ports/outbox.port.ts";
import type { ConsentDecisionRecord } from "../../src/server/ports/consent-decision-repository.port.ts";
import { validateOutboxEvent } from "./schema-lite.ts";

/** Claves prohibidas en el sobre y en el payload (INV-CM-05, INV-CM-09; outbox-events.schema.json
 * "Sin datos del apoderado"). */
export const OUTBOX_FORBIDDEN_KEYS = [
  "decisionMakerRef",
  "chainRef",
  "revokedDecisionRef",
  "consentId",
  "authPath",
  "recoveryMethod",
  "subscriptionRefs",
  "originPurposeRef",
  "reasonCode",
  "email",
  "name",
  "rut",
] as const;

/** Exige exactamente un consent.revoked de la revocación, válido contra el schema, con
 * effectiveAt == CONSENT_REVOKED.effectiveAt == occurredAt y tenant/context/subject de la
 * decisión revocada. Devuelve el registro. */
export function assertConsentRevokedOutbox(
  enqueued: readonly OutboxRecord[],
  ledgerEvents: readonly LedgerRecord[],
  expected: { readonly tenantId: string; readonly revocationRef: string; readonly decision: ConsentDecisionRecord },
): OutboxRecord {
  const mine = enqueued.filter((r) => r.envelope.payload.revocationRef === expected.revocationRef);
  assert.equal(mine.length, 1, "exactamente un consent.revoked por revocationRef");
  const record = mine[0]!;
  const result = validateOutboxEvent(record.envelope);
  assert.ok(result.ok, `sobre inválido:\n${result.errors.join("\n")}`);
  assert.ok(!Number.isNaN(Date.parse(record.envelope.occurredAt)), "occurredAt es un timestamp");

  const revoked = ledgerEvents.filter((e) => e.eventType === "CONSENT_REVOKED");
  assert.equal(revoked.length, 1);
  const effectiveAt = (revoked[0]!.payload as { effectiveAt: string }).effectiveAt;
  assert.equal(record.envelope.payload.effectiveAt, effectiveAt);
  assert.equal(record.envelope.occurredAt, effectiveAt);

  assert.equal(record.envelope.tenantRef, expected.tenantId);
  assert.equal(record.envelope.contextRef, expected.decision.contextRef);
  assert.equal(record.envelope.subjectRef, expected.decision.subjectRef);
  assert.equal(record.tenantId, expected.tenantId);
  assert.equal(record.dedupeKey, `${expected.revocationRef}:consent.revoked`);
  assert.equal(record.status, "PENDING");
  return record;
}
