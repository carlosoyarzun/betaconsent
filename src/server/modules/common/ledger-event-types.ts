// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128), common.spec.yaml ledgerEnvelope.payloadPolicy
// ("lista blanca por eventType"), revocation.spec GRD-RV-19 / ERR-RV-13 (LEDGER_VOCABULARY_VIOLATION),
// DEC-BR-017 §6 (vocabulario de payload; los nombres de evento salen de `events:` de cada
// specs/state-machines/*.spec.yaml). Subconjunto IT0 de ADR-011 (S4-16).
//
// Lista blanca de `event_type` del ledger integrity.audit_event. DEBE coincidir EXACTO con el
// CHECK `audit_event_event_type_allowlist` vigente (0013, redefinido por 0017 y por
// 0030_ledger_drop_transitional_security_events.sql, que quita los tipos del stream SECURITY: SEC-CNS-021 PR-2, ahora en ops.security_event) (test
// TEST-CNS-912 lo compara contra pg_get_constraintdef). Agregar un tipo = migracion nueva
// (nunca editar una mergeada) + esta lista + la spec que lo declara.

/** Tipos con $def en contracts/schemas/ledger-event-payloads.schema.json (menos `x-disabled-in-it0`:
 * CONSENT_EXPIRED, CONSENT_SUPERSEDED, DECISION_CONTESTED). TEST-CNS-912 lo deriva del contrato y falla si diverge. */
export const LEDGER_CONTRACT_EVENT_TYPES = [
  "INVITATION_CREATED", "INVITATION_READY", "INVITATION_SENT", "INVITATION_TOKEN_ROTATED", "INVITATION_OPENED",
  "INVITATION_VERIFIED", "INVITATION_COMPLETED", "INVITATION_DECLINED", "INVITATION_EXPIRED", "INVITATION_CANCELLED",
  "DECISION_MAKER_CHANNEL_VERIFIED",
  "CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED",
  "PURPOSE_DECISION_RECORDED", "CONSENT_GRANTED", "CONSENT_DECLINED", "RECEIPT_CREATED", "CONSENT_REVOKED",
  "REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "REVOCATION_DOWNSTREAM_EMITTED",
  "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED", "REVOCATION_FAILED", "REVOCATION_ESCALATED",
  "REVOCATION_PROPOSAL_WITHDRAWN",
  "RIGHTS_CASE_OPENED", "RIGHTS_CASE_CONTACTING", "RIGHTS_CASE_CLOSED",
  "TENANT_STATUS_CHANGED", "SCHOOL_PARTICIPATION_STATUS_CHANGED", "ENROLLMENT_STATUS_CHANGED",
] as const;

/**
 * Seed sintetico LOCAL (seed.ts, actor FIXTURE). El contrato no los declara: se aceptan solo con
 * actor_type = FIXTURE (CHECK en 0013) y por tanto solo en LOCAL (CHECK de 0002). FINDING: declarar su $def.
 */
export const LEDGER_LOCAL_SEED_EVENT_TYPES = ["TENANT_SEEDED", "SCHOOL_PARTICIPATION_SEEDED"] as const;

export const LEDGER_EVENT_TYPES = [
  ...LEDGER_CONTRACT_EVENT_TYPES,
  ...LEDGER_LOCAL_SEED_EVENT_TYPES,
] as const;

export type LedgerEventType = (typeof LEDGER_EVENT_TYPES)[number];

const ALLOWED: ReadonlySet<string> = new Set(LEDGER_EVENT_TYPES);

export function isLedgerEventType(value: string): value is LedgerEventType {
  return ALLOWED.has(value);
}

/** ERR-RV-13 LEDGER_VOCABULARY_VIOLATION: el append falla sin escribir (fail-closed). */
export class LedgerVocabularyViolationError extends Error {
  readonly eventType: string;
  constructor(eventType: string) {
    // El valor rechazado es un identificador de codigo, nunca PII, pero se acota por higiene de logs.
    super(`LEDGER_VOCABULARY_VIOLATION: eventType fuera de la lista blanca (${eventType.slice(0, 60)})`);
    this.name = "LedgerVocabularyViolationError";
    this.eventType = eventType;
  }
}

export function assertLedgerEventType(value: string): void {
  if (!isLedgerEventType(value)) throw new LedgerVocabularyViolationError(value);
}
