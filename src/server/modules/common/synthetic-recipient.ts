// Gobierna: CA-128, decision EXT-B (i) (Carlos, 2026-10-01); db/migrations/0005_tenant_catalog.sql
// (app.is_reserved_email). Regla unica TS de "destinatario sintetico": email de dominio reservado
// (RFC 2606/6761: .test, .invalid, example.com|org|net). Misma regla que la funcion SQL; la paridad
// la verifica tests/integration/postgres (TEST-CNS-970). IT0: SYNTHETIC DATA ONLY; LD-21 (binding M2
// por el participante) queda pendiente para entrega real.

const RESERVED_TLD = /^[^@\s]+@([a-z0-9-]+\.)*[a-z0-9-]+\.(test|invalid)$/i;
const RESERVED_EXAMPLE = /^[^@\s]+@example\.(com|org|net)$/i;

/** true si `value` es un email de dominio reservado (equivalente a app.is_reserved_email). */
export function isSyntheticRecipient(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && (RESERVED_TLD.test(value) || RESERVED_EXAMPLE.test(value));
}
