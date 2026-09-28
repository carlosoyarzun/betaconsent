// Gobierna: SEC-CNS-014 patrón (Carlos, 2026-09-28), contracts/openapi/consent-it0.openapi.yaml
// API-CNS-101 (GET /i/{token}). Mismo patrón D4 que recovery-handle-policy.config.ts: esta
// config NO fija un default de producción; el entrypoint HTTP exige el valor explícito (override
// u override/env), si falta no arranca (fail-closed). TTL de la cookie firmada
// `__Host-cns-i-handle` que fija GET /i/{token} sin leer la BD (link-handle.ts); solo necesita
// sobrevivir el 303 inmediato a GET /welcome, no la vigencia real de la invitación (esa la exige
// GRD-IV-07 contra la BD, en GET /welcome mismo).

export interface InvitationHandlePolicy {
  readonly ttlMs: number;
}

export interface InvitationHandlePolicyOverrides {
  readonly ttlMs?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} debe ser un entero positivo (SEC-CNS-014 patrón, API-CNS-101).`);
  }
  return value;
}

/**
 * Construye la política del handle INVITATION_LANDING. Sin default de producción: si ninguna
 * fuente (override explícito o variable de entorno) provee un valor, lanza (fail-closed).
 * `overrides` es la única vía LOCAL-only para tests/dev.ts.
 */
export function loadInvitationHandlePolicyConfig(overrides: InvitationHandlePolicyOverrides = {}): InvitationHandlePolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_INVITATION_HANDLE_TTL_MS");
  if (ttlMs === undefined) {
    throw new Error(
      "Política del handle de invitación incompleta: CNS_INVITATION_HANDLE_TTL_MS no tiene un " +
        "valor fijado en este entorno. No hay default de producción; dev.ts y los tests pueden " +
        "pasar un override explícito marcado LOCAL-only.",
    );
  }
  return { ttlMs };
}
