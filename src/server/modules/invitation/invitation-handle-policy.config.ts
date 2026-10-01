// Gobierna: SEC-CNS-014 patrón (Carlos, 2026-09-28), contracts/openapi/consent-it0.openapi.yaml
// API-CNS-101 (GET /i/{token}). Mismo patrón D4 que recovery-handle-policy.config.ts: esta
// config NO fija un default de producción; el entrypoint HTTP exige el valor explícito (override
// u override/env), si falta no arranca (fail-closed). TTL de la cookie firmada
// `__Host-cns-i-handle` que fija GET /i/{token} sin leer la BD (link-handle.ts); solo necesita
// sobrevivir el 303 inmediato a GET /welcome, no la vigencia real de la invitación (esa la exige
// GRD-IV-07 contra la BD, en GET /welcome mismo).

import { APPROVED_LINK_HANDLE_TTL_MS } from "../common/approved-parameters.ts";

// ACTUALIZADO (Carlos, 2026-10-01, CA-128): TTL del handle /i = 10 min APROBADO; default en cualquier
// entorno (override o CNS_INVITATION_HANDLE_TTL_MS siguen mandando).

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
 * Construye la política del handle INVITATION_LANDING. Precedencia: override > env > valor aprobado
 * (10 min, Carlos 2026-10-01).
 */
export function loadInvitationHandlePolicyConfig(overrides: InvitationHandlePolicyOverrides = {}): InvitationHandlePolicy {
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_INVITATION_HANDLE_TTL_MS") ?? APPROVED_LINK_HANDLE_TTL_MS;
  return { ttlMs };
}
