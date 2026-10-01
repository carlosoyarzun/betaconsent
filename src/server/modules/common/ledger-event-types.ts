// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128), common.spec.yaml ledgerEnvelope.payloadPolicy
// ("lista blanca por eventType"), revocation.spec GRD-RV-19 / ERR-RV-13 (LEDGER_VOCABULARY_VIOLATION),
// DEC-BR-017 §6 (vocabulario de payload; los nombres de evento salen de `events:` de cada
// specs/state-machines/*.spec.yaml). Subconjunto IT0 de ADR-011 (S4-16).
//
// Lista blanca de `event_type` del ledger integrity.audit_event. DEBE coincidir EXACTO con el
// CHECK `audit_event_event_type_allowlist` de db/migrations/0013_ledger_chain.sql (test
// TEST-CNS-912 lo compara contra pg_get_constraintdef). Agregar un tipo = migracion nueva
// (nunca editar una mergeada) + esta lista + la spec que lo declara.

export const LEDGER_EVENT_TYPES = [
  // consent-decision.spec
  "CONTEXT_INFORMATION_VIEWED",
  "CONSENT_VERSION_VIEWED",
  "DECISION_MAKER_AUTHORITY_DECLARED",
  "SUBJECT_CONFIRMED",
  "PURPOSE_DECISION_RECORDED",
  "CONSENT_GRANTED",
  "CONSENT_DECLINED",
  "RECEIPT_CREATED",
  "CONSENT_REVOKED",
  "CONSENT_EXPIRED",
  "CONSENT_SUPERSEDED",
  "DECISION_CONTESTED",
  // invitation.spec
  "INVITATION_CREATED",
  "INVITATION_READY",
  "INVITATION_SENT",
  "INVITATION_TOKEN_ROTATED",
  "INVITATION_OPENED",
  "INVITATION_VERIFIED",
  "INVITATION_COMPLETED",
  "INVITATION_DECLINED",
  "INVITATION_EXPIRED",
  "INVITATION_CANCELLED",
  // otp-challenge.spec
  "OTP_ISSUED",
  "OTP_FAILED",
  "OTP_LOCKED",
  "OTP_EXPIRED",
  "OTP_BUDGET_EXHAUSTED",
  "MANAGEMENT_TOKEN_ROTATED",
  "DECISION_MAKER_CHANNEL_VERIFIED",
  // revocation.spec
  "REVOCATION_REQUESTED",
  "REVOCATION_VERIFIED",
  "REVOCATION_CONFIRMED",
  "REVOCATION_DOWNSTREAM_EMITTED",
  "REVOCATION_DELIVERED",
  "DOWNSTREAM_ERASURE_ATTESTED",
  "REVOCATION_FAILED",
  "REVOCATION_ESCALATED",
  "RECOVERY_TOKEN_ISSUED",
  // rights-case.spec
  "RIGHTS_CASE_OPENED",
  "RIGHTS_CASE_CONTACTING",
  "RIGHTS_CASE_CLOSED",
  // tenant-context.spec
  "TENANT_STATUS_CHANGED",
  "SCHOOL_PARTICIPATION_STATUS_CHANGED",
  "ENROLLMENT_STATUS_CHANGED",
  "CONSENT_CONTEXT_STATUS_CHANGED",
  // Seed sintetico LOCAL (actor FIXTURE; src/server/modules/tenant-context/seed.ts)
  "TENANT_SEEDED",
  "SCHOOL_PARTICIPATION_SEEDED",
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
