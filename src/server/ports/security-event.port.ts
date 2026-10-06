// Gobierna: CA-141 (decision de Carlos, 2026-10-06, opcion (a); D-5 solo escritura para el runtime), specs/session.spec.yaml
// (GRD-SE-14, INV-SE-05/06), common.spec.yaml streams.SECURITY, contracts/schemas/security-event-payloads.schema.json (API-CNS-184),
// db/migrations/0025_ops_security_event.sql, ADR-001 §11.
// Puerto (ADR-001 §11): el dominio solo conoce esta interfaz; la tabla ops.security_event vive detras de un adaptador en
// src/infra/adapters/**. Append-only y sin PII: solo refs opacas, rol y tipo. NO es el ledger de consentimiento ni ops.access_log.
// El runtime (app_rw) solo INSERTA (D-5): el puerto no expone lectura; los tests de Postgres leen con la conexion del dueno y el
// adaptador in-memory expone `list()` solo para verificacion.

import type { TenantId } from "../modules/common/types.ts";

export type SecurityEventType = "STAFF_LOGIN" | "STAFF_LOGOUT" | "CASE_LOGIN" | "CASE_LOGOUT" | "SESSION_REVOKED_BY_ROTATION";
export type SecurityEventActorRole = "TENANT_ADMIN" | "RIGHTS_OPERATOR" | "APPROVER";
export type SecurityEventSessionKind = "STAFF" | "CASE";

export const SECURITY_EVENT_TYPES: readonly SecurityEventType[] = ["STAFF_LOGIN", "STAFF_LOGOUT", "CASE_LOGIN", "CASE_LOGOUT", "SESSION_REVOKED_BY_ROTATION"];
export const SECURITY_EVENT_ACTOR_ROLES: readonly SecurityEventActorRole[] = ["TENANT_ADMIN", "RIGHTS_OPERATOR", "APPROVER"];
/** Roles de la sesion CASE (los unicos de app.case_session); espejo de CASE_* en security_event_session_shape (0025). */
export const SECURITY_EVENT_CASE_ROLES: readonly SecurityEventActorRole[] = ["RIGHTS_OPERATOR", "APPROVER"];
/** principalRef canonico; espejo del CHECK de 0014/0021/0022/0025. */
export const SECURITY_EVENT_ACTOR_REF_PATTERN = /^(staff-synthetic-[0-9]{2,6}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
/** Ref UUIDv4 (common.schema.json#/$defs/Ref); espejo de los CHECK de session_ref y case_ref (0023/0024/0025). */
export const SECURITY_EVENT_REF_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Causa de una revocacion de sesion: logout del usuario (USER_LOGOUT) o login posterior del mismo navegador (ROTATION). */
export type SessionRevokeCause = "USER_LOGOUT" | "ROTATION";

export interface SecurityEventEntry {
  readonly tenantId: TenantId;
  readonly eventType: SecurityEventType;
  /** principalRef opaco del staff (tomado de la FILA de la sesion, nunca de la cookie ni del cuerpo). */
  readonly actorRef: string;
  readonly actorRole: SecurityEventActorRole;
  readonly sessionKind: SecurityEventSessionKind;
  /** session_ref opaco (UUIDv4 de la base); NO es el sid ni su hash. */
  readonly sessionRef: string;
  /** Solo sesiones CASE. */
  readonly caseRef?: string | null;
}

export interface SecurityEventRecord extends SecurityEventEntry {
  readonly eventId: string;
  readonly schemaVersion: "1.0.0";
  readonly occurredAt: Date;
  readonly environment: "LOCAL" | "DEV" | "STAGING" | "PRODUCTION";
  readonly dataClass: "SYNTHETIC";
}

/**
 * No se pudo escribir el evento de seguridad (entrada invalida, fallo de la base o del sink). El llamador debe revertir TODO el efecto
 * de sesion (login sin sesion; logout sin revocar) y responder 503 sin Set-Cookie (D-3, fail-closed). Nunca incluye valores en el mensaje.
 */
export class SecurityEventWriteError extends Error {
  /** SQLSTATE de la base, si lo hay (nunca el mensaje ni el detalle de la base: podrian traer valores de fila). */
  readonly code: string | undefined;
  constructor(code?: string) {
    super("security event: no se pudo escribir");
    this.name = "SecurityEventWriteError";
    this.code = code;
  }
}

/** La entrada viola el vocabulario/forma sin PII: no se escribe nada (fail-closed). Es un fallo de escritura (503 en los bordes). */
export class SecurityEventValidationError extends SecurityEventWriteError {
  readonly field: string;
  constructor(field: string) {
    super();
    // Nunca incluye el valor rechazado (podria ser PII).
    this.message = `security event: campo invalido (${field})`;
    this.name = "SecurityEventValidationError";
    this.field = field;
  }
}

/** Espejo de los CHECK de ops.security_event (0025): falla ANTES de tocar la base o de mutar la sesion. */
export function validateSecurityEventEntry(entry: SecurityEventEntry): void {
  const fail = (field: string): never => {
    throw new SecurityEventValidationError(field);
  };
  if (typeof entry.tenantId !== "string" || entry.tenantId.length === 0) fail("tenantId");
  if (!SECURITY_EVENT_TYPES.includes(entry.eventType)) fail("eventType");
  if (typeof entry.actorRef !== "string" || !SECURITY_EVENT_ACTOR_REF_PATTERN.test(entry.actorRef)) fail("actorRef");
  if (!SECURITY_EVENT_ACTOR_ROLES.includes(entry.actorRole)) fail("actorRole");
  if (entry.sessionKind !== "STAFF" && entry.sessionKind !== "CASE") fail("sessionKind");
  if (typeof entry.sessionRef !== "string" || !SECURITY_EVENT_REF_PATTERN.test(entry.sessionRef)) fail("sessionRef");
  const caseRef = entry.caseRef ?? null;
  if (caseRef !== null && (typeof caseRef !== "string" || !SECURITY_EVENT_REF_PATTERN.test(caseRef))) fail("caseRef");
  if (entry.eventType === "STAFF_LOGIN" || entry.eventType === "STAFF_LOGOUT") {
    if (entry.sessionKind !== "STAFF" || caseRef !== null) fail("sessionKind");
  } else if (entry.eventType === "CASE_LOGIN" || entry.eventType === "CASE_LOGOUT") {
    if (entry.sessionKind !== "CASE" || caseRef === null) fail("sessionKind");
    if (!SECURITY_EVENT_CASE_ROLES.includes(entry.actorRole)) fail("actorRole");
  } else {
    if ((entry.sessionKind === "CASE") !== (caseRef !== null)) fail("caseRef");
    if (entry.sessionKind === "CASE" && !SECURITY_EVENT_CASE_ROLES.includes(entry.actorRole)) fail("actorRole");
  }
}

export interface SecurityEventPort {
  /**
   * Append-only. Escribe en la MISMA transaccion que crea o revoca la sesion (si la sesion confirma, el evento tambien; si falla, nada).
   * Lanza SecurityEventWriteError ante cualquier fallo.
   */
  record(entry: SecurityEventEntry): Promise<void>;
}
