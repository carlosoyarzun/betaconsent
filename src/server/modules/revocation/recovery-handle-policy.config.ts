// Gobierna: SEC-CNS-014 (APROBADO CON CAMBIOS), ADR-006 §6.2 ("crea handle RECOVERY, TTL 10
// min"), contracts/openapi/consent-it0.openapi.yaml securitySchemes.recoveryHandle (P-18).
// Mismo patrón D4 que otp-policy.config.ts / recovery-token-policy.config.ts (Carlos,
// 2026-09-27/28): esta config NO fija un default de producción; el entrypoint HTTP exige el
// valor explícito (override u override/env), si falta no arranca (fail-closed). Distinto de
// P-15 (recovery-token-policy.config.ts, TTL del `tenant_resolve.recovery_token` persistido en
// BD): P-18 es el TTL de la cookie firmada `__Host-cns-recovery` que fija GET /r/{token} sin
// leer la BD (SEC-CNS-014 FINDING P1: el GET solo hashea el token y firma el handle).

export interface RecoveryHandlePolicy {
  readonly ttlMs: number;
}

export interface RecoveryHandlePolicyOverrides {
  readonly ttlMs?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} debe ser un entero positivo (P-18, ADR-006 §6.2).`);
  }
  return value;
}

/**
 * Construye la política del handle RECOVERY (P-18 TTL, ADR-006 §6.2: 10 minutos). Sin default
 * de producción: si ninguna fuente (override explícito o variable de entorno) provee un valor,
 * lanza (fail-closed). `overrides` es la única vía LOCAL-only para tests/dev.ts.
 */
export function loadRecoveryHandlePolicyConfig(overrides: RecoveryHandlePolicyOverrides = {}): RecoveryHandlePolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_RECOVERY_HANDLE_TTL_MS");
  if (ttlMs === undefined) {
    throw new Error(
      "Política del handle de recuperación incompleta: P-18 (CNS_RECOVERY_HANDLE_TTL_MS) no " +
        "tiene un valor fijado en este entorno (ADR-006 §6.2: 10 minutos). No hay default de " +
        "producción; dev.ts y los tests pueden pasar un override explícito marcado LOCAL-only.",
    );
  }
  return { ttlMs };
}
