// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-08 (idempotency_key) y ERR-CM-07:
// "Idempotency-Key ligada a (tenantRef, principal, operación), almacenada como hash con TTL
// P-33; replay solo al mismo principal; misma key + mismo payloadHash -> misma respuesta; misma
// key + otro hash -> conflicto". Puerto (ADR-001 §11). La clave llega ya hasheada
// (scopeKeyHash): este puerto nunca ve la Idempotency-Key en claro. El TTL P-33 no tiene valor
// aprobado en el repo (SEC-CNS-006 vive en Notion): el adaptador in-memory IT0 no expira
// entradas dentro de la vida del proceso.

export interface StoredIdempotentResponse {
  readonly payloadHash: string;
  readonly status: number;
  readonly body: Readonly<Record<string, unknown>>;
}

export interface IdempotencyPort {
  find(scopeKeyHash: string): StoredIdempotentResponse | null;
  store(scopeKeyHash: string, response: StoredIdempotentResponse): void;
}
