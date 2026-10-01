// Gobierna: SEC-CNS-014 patrón (Carlos, 2026-09-28), contracts/openapi/consent-it0.openapi.yaml
// API-CNS-102 (GET /m/{token}). Mismo patrón D4 que recovery-handle-policy.config.ts: esta
// config NO fija un default de producción; el entrypoint HTTP exige el valor explícito (override
// u override/env), si falta no arranca (fail-closed). TTL de la cookie firmada
// `__Host-cns-m-handle` que fija GET /m/{token} sin leer la BD (link-handle.ts); solo necesita
// sobrevivir el 303 inmediato a GET /manage, no la vigencia real del handle MANAGE_ENTRY (esa la
// resuelve TenantHandlePort.resolveByHash, en GET /manage mismo).

import { APPROVED_LINK_HANDLE_TTL_MS } from "../common/approved-parameters.ts";

/** TTL de los handles /i y /m = 10 min (Carlos, 2026-10-01): valor aprobado de approved-parameters.ts. */
export const DEFAULT_MANAGE_HANDLE_TTL_MS = APPROVED_LINK_HANDLE_TTL_MS;

export interface ManageHandlePolicy {
  readonly ttlMs: number;
}

export interface ManageHandlePolicyOverrides {
  readonly ttlMs?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} debe ser un entero positivo (SEC-CNS-014 patrón, API-CNS-102).`);
  }
  return value;
}

/**
 * Construye la política del handle MANAGE_ENTRY (la de link-handle.ts, no la del TenantHandlePort
 * en sí). Si ninguna fuente (override explícito o variable de
 * entorno) provee un valor se usa el aprobado (10 min, Carlos 2026-10-01). `overrides` es la vía LOCAL para
 * tests/dev.ts.
 */
export function loadManageHandlePolicyConfig(overrides: ManageHandlePolicyOverrides = {}): ManageHandlePolicy {
  // Precedencia: override explícito > variable de entorno > valor aprobado por Carlos (2026-10-01).
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_MANAGE_HANDLE_TTL_MS") ?? DEFAULT_MANAGE_HANDLE_TTL_MS;
  return { ttlMs };
}
