// Gobierna: contracts/schemas/ledger-event-payloads.schema.json (X6 P1-A). Payloads mínimos VÁLIDOS para tests que
// escriben directo en el ledger (el append valida el payload contra el contrato, ERR-RV-13). SYNTHETIC ONLY.

import { fixtureUuid } from "./uuid-fixture.ts";

export const revocationRequestedPayload = (label: string): Record<string, unknown> => ({
  revocationRef: fixtureUuid(`rev:${label}`),
  revokedDecisionRef: fixtureUuid(`dec:${label}`),
  scope: "ALL",
  authPath: "OTP",
  originPurposeRef: "ALL",
  initiatedVia: "DECISION_MAKER",
});

export const revocationVerifiedPayload = (label: string): Record<string, unknown> => ({
  revocationRef: fixtureUuid(`rev:${label}`),
  authPath: "OTP",
  verificationRef: fixtureUuid(`ver:${label}`),
  assuranceLevel: "LD-02-PLACEHOLDER-V1",
});

export const rightsCaseOpenedPayload = (label: string): Record<string, unknown> => ({
  caseRef: fixtureUuid(`case:${label}`),
  reasonCode: "CHANNEL_UNREACHABLE",
  initiatedVia: "DECISION_MAKER",
});

/** Payload válido para el eventType de revocación dado (tests de mecánica del ledger: cadena, secuencia, dedupe). */
export function payloadFor(eventType: string, label = "default"): Record<string, unknown> {
  switch (eventType) {
    case "REVOCATION_REQUESTED":
      return revocationRequestedPayload(label);
    case "REVOCATION_VERIFIED":
      return revocationVerifiedPayload(label);
    case "REVOCATION_CONFIRMED":
      return { revocationRef: fixtureUuid(`rev:${label}`) };
    default:
      return {}; // tipo sin fixture (p. ej. fuera de la lista blanca: el append falla por vocabulario antes de validar payload)
  }
}
