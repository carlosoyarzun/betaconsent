// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-08 ("almacenada como hash con TTL P-33") y
// SEC-CNS-006 P-33 (TTL de la Idempotency-Key). P-33 NO tiene valor aprobado en specs/contracts
// (grep de "P-33" en el repo, 2026-10-01: solo se cita por nombre).
//
// Mismo patrón D4 que otp-policy.config.ts y recovery-token-policy.config.ts (P-15/P-18): esta
// config NO fija un default de producción. Quien construye el adaptador exige el valor explícito
// (env CNS_IDEMPOTENCY_TTL_MS o override); si falta, lanza (fail-closed). El único valor
// sintético permitido vive en dev-local-config.ts (LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY) y en tests.

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
 * Construye la política de idempotencia (P-33 TTL). Sin default de producción: si ninguna fuente
 * (override explícito o variable de entorno) provee un valor, lanza (fail-closed).
 */
export function loadIdempotencyPolicyConfig(overrides: IdempotencyPolicyOverrides = {}): IdempotencyPolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_IDEMPOTENCY_TTL_MS");
  if (ttlMs === undefined) {
    throw new Error(
      "Política de idempotencia incompleta: P-33 (CNS_IDEMPOTENCY_TTL_MS) no tiene un valor aprobado " +
        "en specs/contracts (ver cabecera de este archivo). No hay default de producción: PENDING — " +
        "Carlos debe fijar P-33 en SEC-CNS-006 antes de un entrypoint real. dev.ts y los tests pueden " +
        "pasar un override explícito marcado LOCAL-only.",
    );
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error("P-33 (ttlMs) debe ser un entero positivo.");
  return { ttlMs };
}
