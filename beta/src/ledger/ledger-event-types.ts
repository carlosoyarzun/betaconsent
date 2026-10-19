// Gobierna: plan v2 H1-02. Espejo EXACTO del CHECK audit_event_event_type_allowlist de db/migrations/0001_catalog_school_ledger.sql
// (lo verifica tests/unit/ledger-chain.test.ts). Subconjunto del repo anterior (origen: src/server/modules/common/ledger-event-types.ts@9345b78).
// Ampliar = migración nueva + esta lista.

export const LEDGER_EVENT_TYPES = [
  "INVITATION_CREATED",
  "INVITATION_SENT",
  "INVITATION_TOKEN_ROTATED",
  "INVITATION_OPENED",
  "INVITATION_VERIFIED",
  "INVITATION_COMPLETED",
  "INVITATION_DECLINED",
  "INVITATION_CANCELLED",
  "DECISION_MAKER_CHANNEL_VERIFIED",
  "OTP_LOCKED",
  "CONSENT_GRANTED",
  "CONSENT_DECLINED",
  "RECEIPT_CREATED",
  "CONSENT_REVOKED",
  "REVOCATION_REQUESTED",
  "REVOCATION_VERIFIED",
  "REVOCATION_CONFIRMED",
  "REVOCATION_APPLIED",
  "REVOCATION_HELD",
] as const;

export type LedgerEventType = (typeof LEDGER_EVENT_TYPES)[number];

const SET: ReadonlySet<string> = new Set(LEDGER_EVENT_TYPES);

export function isLedgerEventType(value: string): value is LedgerEventType {
  return SET.has(value);
}
