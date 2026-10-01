// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-08 (idempotency_key) y ERR-CM-07:
// "Idempotency-Key ligada a (tenantRef, principal, operación), almacenada como hash con TTL
// P-33; replay solo al mismo principal; misma key + mismo payloadHash -> misma respuesta; misma
// key + otro hash -> conflicto". Puerto (ADR-001 §11). CA-124 PR-E: forma parte de
// `TenantTxPorts` (unit-of-work.port.ts): find + ejecutar + store corren en la MISMA unidad de
// trabajo del tenant (atómico), y toda operación recibe el `tenantId` (RLS por tenant en
// Postgres; scope por tenant en memoria). La clave llega ya hasheada (scopeKeyHash): este puerto
// nunca ve la Idempotency-Key en claro. El TTL P-33 NO tiene valor aprobado: lo fija la
// configuración del adaptador (idempotency-policy.config.ts, fail-closed, sin default de
// producción); `find` ignora las entradas vencidas.

import type { TenantId } from "../modules/common/types.ts";

export interface StoredIdempotentResponse {
  readonly payloadHash: string;
  readonly status: number;
  readonly body: Readonly<Record<string, unknown>>;
}

export interface IdempotencyPort {
  /** Respuesta vigente (no vencida) del tenant para esa clave, o null. En Postgres bloquea la clave
   * hasta el fin de la transacción: dos requests con la misma clave se serializan. */
  find(tenantId: TenantId, scopeKeyHash: string): Promise<StoredIdempotentResponse | null>;
  /** Guarda la respuesta; la primera gana (una entrada vigente nunca se pisa). */
  store(tenantId: TenantId, scopeKeyHash: string, response: StoredIdempotentResponse): Promise<void>;
}
