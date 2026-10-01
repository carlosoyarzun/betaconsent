// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-08 ("almacenada como hash con TTL P-33") y
// SEC-CNS-006 P-33 (TTL de la Idempotency-Key). P-33 NO tiene valor aprobado en specs/contracts
// (grep de "P-33" en el repo, 2026-10-01: solo se cita por nombre).
//
// ACTUALIZADO (Carlos, 2026-10-01, CA-128): P-33 = 24 h APROBADO (approved-parameters.ts); es el valor
// por defecto en cualquier entorno. Override explícito o CNS_IDEMPOTENCY_TTL_MS siguen mandando.
//
// (Histórico) Mismo patrón D4 que otp-policy.config.ts y recovery-token-policy.config.ts (P-15/P-18): esta
// config NO fija un default de producción. Quien construye el adaptador exige el valor explícito
// (env CNS_IDEMPOTENCY_TTL_MS o override); si falta, lanza (fail-closed). El único valor
// sintético permitido vive en dev-local-config.ts (LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY) y en tests.

import { APPROVED_P33_IDEMPOTENCY_TTL_MS } from "./approved-parameters.ts";

export interface IdempotencyPolicy {
  readonly ttlMs: number;
}

export interface IdempotencyPolicyOverrides {
  readonly ttlMs?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0 || String(value) !== raw.trim()) {
    throw new Error(`${name} debe ser un entero positivo (P-33, SEC-CNS-006).`);
  }
  return value;
}

/**
 * Construye la política de idempotencia (P-33 TTL). Precedencia: override explícito > variable de
 * entorno > valor aprobado P-33 = 24 h (Carlos, 2026-10-01). Un valor inválido sigue lanzando.
 */
export function loadIdempotencyPolicyConfig(overrides: IdempotencyPolicyOverrides = {}): IdempotencyPolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_IDEMPOTENCY_TTL_MS") ?? APPROVED_P33_IDEMPOTENCY_TTL_MS;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error("P-33 (ttlMs) debe ser un entero positivo.");
  return { ttlMs };
}
