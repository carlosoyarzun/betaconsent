// Gobierna: DEC-BR-014 rev. 8 §4 (controles synthetic-only), X3 (D8 (a), Carlos 2026-10-01):
// allowlist de destinatarios de los sinks de canal de IT0. Misma regla que la función SQL
// app.is_reserved_email (db/migrations/0005_tenant_catalog.sql): dominios reservados
// `.test` / `.invalid` (cualquier profundidad) o example.com/.org/.net. Si cambia una, cambia la otra:
// tests/integration/postgres/synthetic-recipient-parity.test.ts (TEST-CNS-955) compara ambas.
// Los refs opacos (UUID, "mgmt:<chainRef>") no son direcciones y se admiten; todo lo que parezca una
// dirección real (arroba fuera de dominio reservado, teléfono) se rechaza. El error NO incluye el valor.

const RESERVED_TLD_RE = /^[^@\s]+@([a-z0-9-]+\.)*[a-z0-9-]+\.(test|invalid)$/i;
const RESERVED_EXAMPLE_RE = /^[^@\s]+@example\.(com|org|net)$/i;
const OPAQUE_REF_RE = /^[A-Za-z0-9:_-]{1,200}$/;
const PHONE_LIKE_RE = /^\d{7,}$/;

export function isReservedEmail(value: string): boolean {
  return RESERVED_TLD_RE.test(value) || RESERVED_EXAMPLE_RE.test(value);
}

export function isSyntheticRecipient(value: string): boolean {
  if (isReservedEmail(value)) return true;
  return OPAQUE_REF_RE.test(value) && !PHONE_LIKE_RE.test(value);
}

export class NonSyntheticRecipientError extends Error {
  readonly code = "NON_SYNTHETIC_RECIPIENT";
  constructor() {
    super("Destinatario no sintético rechazado por el sink (DEC-BR-014 §4: solo dominios reservados u opaco).");
    this.name = "NonSyntheticRecipientError";
  }
}

export function assertSyntheticRecipient(value: string): void {
  if (!isSyntheticRecipient(value)) throw new NonSyntheticRecipientError();
}
