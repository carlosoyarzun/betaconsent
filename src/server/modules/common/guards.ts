// Gobierna: specs/state-machines/common.spec.yaml (sección `guards`). Guards deterministas
// transversales, reutilizados por las máquinas de estado de dominio. Ningún guard decide
// consentimiento, OTP, autoridad del apoderado ni revocación (Límites de IA, CLAUDE.md).

import { DomainError } from "./errors.ts";
import type { ActorType, Environment, ExecutionContext, ExecutionSource } from "./types.ts";
import type { ResolvedHandle, TenantHandlePort } from "../../ports/tenant-handle.port.ts";

/**
 * GRD-CM-01 (tenant_resolved_server_side): resuelve el handle del lado servidor; vacío,
 * expirado o rotado -> 404 uniforme (ERR-CM-01), sin evento.
 */
export function resolveHandleOrReject(port: TenantHandlePort, handle: string): ResolvedHandle {
  const resolved = port.resolve(handle);
  if (!resolved) {
    throw new DomainError("ERR-CM-01");
  }
  return resolved;
}

/**
 * GRD-CM-13 (fixture_actor_environment): actorType FIXTURE solo con environment LOCAL
 * (incluye CI, que corre como LOCAL: OPEN-CM-07). En DEV, STAGING y PRODUCTION se rechaza.
 */
export function assertFixtureEnvironment(actorType: ActorType, environment: Environment): void {
  if (actorType === "FIXTURE" && environment !== "LOCAL") {
    throw new DomainError("ERR-CM-10");
  }
}

/**
 * GRD-CM-14 (fixture_seed_channel): el origen FIXTURE solo existe por el rol/credencial de
 * seed del bootstrap LOCAL; cualquier otra fuente de ejecución (BEARER, STAFF, PLATFORM,
 * SYSTEM) que intente ejecutar una transición de la allowlist FIXTURE se rechaza, sin
 * importar qué declare el payload de la request (GRD-CM-15: la fuente nunca sale de un
 * campo del cliente).
 */
export function assertExecutionSourceIsSeed(ctx: ExecutionContext): void {
  if (ctx.source !== "FIXTURE") {
    throw new DomainError("ERR-CM-10");
  }
}

/**
 * GRD-CM-15 (source_from_execution_identity): exige que la fuente de ejecución sea una de
 * las declaradas como válidas para la transición. La fuente siempre viene de `ctx.source`
 * (construido por el entrypoint desde la identidad de ejecución), nunca de un parámetro de
 * la request; esta función no acepta ni consulta ningún campo de "fuente declarada" del
 * cuerpo de la solicitud.
 */
export function assertExecutionSourceIn(ctx: ExecutionContext, allowed: readonly ExecutionSource[]): void {
  if (!allowed.includes(ctx.source)) {
    throw new DomainError("ERR-CM-10");
  }
}
