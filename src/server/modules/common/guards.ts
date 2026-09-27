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

/** Entrada que el entrypoint HTTP construye del lado servidor a partir de la request cruda
 * (cabeceras Origin/X-CSRF-Token y la cookie CSRF), nunca de un campo del cuerpo. */
export interface CsrfAndOriginInput {
  /** Cabecera Origin de la request, o undefined si el cliente no la envió. */
  readonly originHeader: string | undefined;
  /**
   * Origen permitido, inyectado por configuración del entrypoint (nunca hardcodeado a un
   * dominio real; distinto por entorno/consola). La comparación es por igualdad EXACTA de
   * cadena: un origen de otra consola o con un sufijo parecido (p.ej. un dominio que solo
   * contiene el permitido como substring) nunca compara igual.
   */
  readonly allowedOrigin: string;
  /** Cabecera X-CSRF-Token de la request. */
  readonly csrfHeaderToken: string | undefined;
  /** Token CSRF de la cookie de sesión del portador (double-submit), fijado por el servidor. */
  readonly csrfCookieToken: string | undefined;
}

/**
 * GRD-CM-10 (csrf_and_origin): "Todo POST (httpPost: true) exige token CSRF y Origin/Host por
 * igualdad exacta". Aquí: (1) Origin debe ser IDÉNTICO al configurado (nunca prefijo/sufijo ni
 * substring, lo que cubre 'Origin de otra consola o con sufijo parecido', ERR-CM-09 según su
 * propia definición en common.spec.yaml); (2) el token CSRF de la cabecera debe coincidir
 * exactamente con el de la cookie (double-submit). onFail: ERR-CM-09 (CSRF_REJECTED), sin
 * efecto ni evento (common.spec.yaml ERR-CM-09).
 */
export function assertCsrfAndOrigin(input: CsrfAndOriginInput): void {
  const { originHeader, allowedOrigin, csrfHeaderToken, csrfCookieToken } = input;
  if (originHeader === undefined || originHeader !== allowedOrigin) {
    throw new DomainError("ERR-CM-09");
  }
  if (
    csrfHeaderToken === undefined ||
    csrfCookieToken === undefined ||
    csrfHeaderToken.length === 0 ||
    csrfHeaderToken !== csrfCookieToken
  ) {
    throw new DomainError("ERR-CM-09");
  }
}
