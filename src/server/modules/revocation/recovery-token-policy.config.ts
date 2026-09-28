// Gobierna: specs/state-machines/revocation.spec.yaml RV0 effects ("token P-31, TTL P-15") y
// SEC-CNS-006 P-15 (TTL del token de recuperación de /r/{token}). P-15 no tiene un valor
// numérico fijado en el repo: grep de "P-15" en specs/ y contracts/ el 2026-09-28 solo lo cita
// por nombre (revocation.spec.yaml:584,635,637), sin un número aprobado por Carlos ni una
// entrada resuelta en SEC-CNS-006.
//
// Mismo patrón D4 que otp-policy.config.ts (Carlos, 2026-09-27): esta config NO fija un
// default de producción. El entrypoint HTTP exige el valor explícito (env o override); si
// falta, no arranca (fail-closed). Los únicos valores sintéticos permitidos viven en
// dev-local-config.ts y en tests, marcados LOCAL_ONLY_* y nunca reutilizados como default de
// esta función.

export interface RecoveryTokenPolicy {
  readonly ttlMs: number;
}

export interface RecoveryTokenPolicyOverrides {
  readonly ttlMs?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} debe ser un entero positivo (P-15, SEC-CNS-006).`);
  }
  return value;
}

/**
 * Construye la política del token de recuperación (P-15 TTL). Sin default de producción: si
 * ninguna fuente (override explícito o variable de entorno) provee un valor, lanza
 * (fail-closed). `overrides` es la única vía LOCAL-only para tests/dev.ts.
 */
export function loadRecoveryTokenPolicyConfig(overrides: RecoveryTokenPolicyOverrides = {}): RecoveryTokenPolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_RECOVERY_TOKEN_TTL_MS");
  if (ttlMs === undefined) {
    throw new Error(
      "Política del token de recuperación incompleta: P-15 (CNS_RECOVERY_TOKEN_TTL_MS) no " +
        "tiene un valor aprobado en specs/contracts (ver cabecera de este archivo). No hay " +
        "default de producción: PENDING — Carlos debe fijar P-15 en SEC-CNS-006 antes de un " +
        "entrypoint real. dev.ts y los tests pueden pasar un override explícito marcado LOCAL-only.",
    );
  }
  return { ttlMs };
}
