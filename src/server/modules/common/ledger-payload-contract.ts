// Gobierna: CA-128 (X6, P1-A), common.spec.yaml ledgerEnvelope.payloadPolicy y INV-CM-05, revocation.spec
// GRD-RV-19 / ERR-RV-13 (LEDGER_VOCABULARY_VIOLATION), contracts/schemas/ledger-event-payloads.schema.json
// ("fuente unica de la lista blanca por eventType; additionalProperties=false: un campo fuera de lista o un
// valor fuera de enum hace fallar el append") y contracts/schemas/security-event-payloads.schema.json
// (eventos del stream SECURITY que hoy se emiten transitoriamente al ledger).
//
// Valida el payload contra `$defs[eventType]` del contrato real (no una copia) ANTES de cualquier efecto.
// Fail-closed: un payload fuera del contrato lanza LedgerPayloadViolationError (ERR-RV-13), sin escribir.

import { validateLedgerOrSecurityPayload } from "./json-schema-lite.ts";
import { LedgerVocabularyViolationError } from "./ledger-event-types.ts";

export class LedgerPayloadViolationError extends LedgerVocabularyViolationError {
  readonly violations: number;
  constructor(eventType: string, violations: number) {
    // Nunca incluye valores del payload (podrian ser PII): solo tipo de evento y cantidad.
    super(eventType);
    this.message = `LEDGER_VOCABULARY_VIOLATION: payload de ${eventType.slice(0, 60)} fuera del contrato (${violations} violaciones)`;
    this.name = "LedgerPayloadViolationError";
    this.violations = violations;
  }
}

/**
 * Tipos sin $def en ningun contrato: seed sintetico LOCAL (actor FIXTURE, seed.ts). X6 P1: su forma minima
 * es el objeto VACIO (seed.ts emite `{}`); cualquier campo, de cualquier valor, se rechaza (antes se
 * aceptaba cualquier string). FINDING: el contrato no declara su $def.
 */
export function assertLedgerPayload(eventType: string, payload: Readonly<Record<string, unknown>>): void {
  const result = validateLedgerOrSecurityPayload(eventType, payload);
  if (result === null) {
    if (Object.keys(payload).length !== 0) throw new LedgerPayloadViolationError(eventType, 1);
    return;
  }
  if (!result.ok) throw new LedgerPayloadViolationError(eventType, result.errors.length);
}
