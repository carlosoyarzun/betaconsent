// Gobierna: DEC-BR-014 rev. 8 §3 X6 ("Las lecturas del operador van a un log de acceso en `ops`, no
// al ledger"), rights-case.spec INV-RC-04, GRD-RC-05, ADR-002 §10, ADR-006 §6.3 (CA-128).
// Puerto (ADR-001 §11): el dominio solo conoce esta interfaz; la tabla ops.access_log vive detras
// de un adaptador en src/infra/adapters/**. Append-only y sin PII: solo refs opacas, rol, accion.
// No es el ledger de consentimiento (no entra a la cadena SHA-256).

import type { TenantId } from "../modules/common/types.ts";

export type AccessLogActorRole = "RIGHTS_OPERATOR" | "APPROVER" | "TENANT_ADMIN" | "PLATFORM_ADMIN";
export type AccessLogAction = "RIGHTS_CASE_READ";
export type AccessLogResourceType = "RIGHTS_CASE";

export const ACCESS_LOG_ACTOR_ROLES: readonly AccessLogActorRole[] = ["RIGHTS_OPERATOR", "APPROVER", "TENANT_ADMIN", "PLATFORM_ADMIN"];
export const ACCESS_LOG_ACTIONS: readonly AccessLogAction[] = ["RIGHTS_CASE_READ"];
export const ACCESS_LOG_RESOURCE_TYPES: readonly AccessLogResourceType[] = ["RIGHTS_CASE"];
/** Ref opaca: sin '@', espacios ni texto libre (espejo del CHECK de 0014_ops_access_log.sql). */
export const ACCESS_LOG_REF_PATTERN = /^[A-Za-z0-9._:-]{1,100}$/;

export interface AccessLogEntry {
  readonly tenantId: TenantId;
  /** principalRef opaco del staff (p. ej. "staff-synthetic-01"); nunca email ni nombre. */
  readonly actorRef: string;
  readonly actorRole: AccessLogActorRole;
  readonly action: AccessLogAction;
  readonly resourceType: AccessLogResourceType;
  /** Ref opaca del recurso leido (p. ej. caseRef UUID). */
  readonly resourceRef: string;
}

export interface AccessLogRecord extends AccessLogEntry {
  readonly accessedAt: Date;
  readonly environment: "LOCAL" | "DEV" | "STAGING" | "PRODUCTION";
  readonly dataClass: "SYNTHETIC";
}

/** La entrada viola el vocabulario/forma sin PII: no se escribe nada (fail-closed). */
export class AccessLogValidationError extends Error {
  readonly field: string;
  constructor(field: string) {
    // Nunca incluye el valor rechazado (podria ser PII).
    super(`access log: campo invalido (${field})`);
    this.name = "AccessLogValidationError";
    this.field = field;
  }
}

export function validateAccessLogEntry(entry: AccessLogEntry): void {
  if (typeof entry.tenantId !== "string" || entry.tenantId.length === 0) throw new AccessLogValidationError("tenantId");
  if (!ACCESS_LOG_REF_PATTERN.test(entry.actorRef)) throw new AccessLogValidationError("actorRef");
  if (!ACCESS_LOG_ACTOR_ROLES.includes(entry.actorRole)) throw new AccessLogValidationError("actorRole");
  if (!ACCESS_LOG_ACTIONS.includes(entry.action)) throw new AccessLogValidationError("action");
  if (!ACCESS_LOG_RESOURCE_TYPES.includes(entry.resourceType)) throw new AccessLogValidationError("resourceType");
  if (!ACCESS_LOG_REF_PATTERN.test(entry.resourceRef)) throw new AccessLogValidationError("resourceRef");
}

export interface AccessLogPort {
  /** Append-only. Escribe en la MISMA transaccion que la lectura del operador (si la lectura confirma, el registro tambien). */
  record(entry: AccessLogEntry): Promise<void>;
  /** Registros del tenant en orden de insercion (para verificacion y auditoria interna; nunca borra). */
  listByTenant(tenantId: TenantId): Promise<readonly AccessLogRecord[]>;
}
