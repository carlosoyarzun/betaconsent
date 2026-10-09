// Gobierna: CA-141 (decision de Carlos, 2026-10-06, opcion (a); D-5 solo escritura para el runtime), specs/session.spec.yaml
// (GRD-SE-14, INV-SE-05/06), common.spec.yaml streams.SECURITY, contracts/schemas/security-event-payloads.schema.json (API-CNS-184),
// db/migrations/0025_ops_security_event.sql, ADR-001 §11.
// SEC-CNS-021 PR-1 (aceptada por Carlos 2026-10-08; CA-146 / P-34; INV-21-04, INV-21-05): el puerto admite ademas la familia OTP / RECOVERY /
// MANAGEMENT (db/migrations/0029_security_event_otp_family.sql). En este PR NINGUN emisor la usa todavia: OTP_* y RECOVERY_TOKEN_ISSUED siguen
// en el ledger hasta SEC-CNS-021 PR-2 (F-1). Mismas reglas: solo refs UUIDv4 opacas y enums; cero correo, nombre, RUT, IP ni texto libre.
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

// ---- Familia OTP / RECOVERY / MANAGEMENT (SEC-CNS-021 PR-1; espejo de security_event_otp_shape en 0029) ----

/** Tipos de la familia OTP/RECOVERY/MANAGEMENT. `SecurityEventType`/`SECURITY_EVENT_TYPES` siguen siendo SOLO los de sesion (x-ops-only). */
export type OtpFamilySecurityEventType =
  | "OTP_ISSUED" | "OTP_FAILED" | "OTP_LOCKED" | "OTP_EXPIRED" | "OTP_BUDGET_EXHAUSTED" | "RECOVERY_TOKEN_ISSUED" | "MANAGEMENT_TOKEN_ROTATED";
export const OTP_FAMILY_SECURITY_EVENT_TYPES: readonly OtpFamilySecurityEventType[] = [
  "OTP_ISSUED", "OTP_FAILED", "OTP_LOCKED", "OTP_EXPIRED", "OTP_BUDGET_EXHAUSTED", "RECOVERY_TOKEN_ISSUED", "MANAGEMENT_TOKEN_ROTATED",
];
export type AnySecurityEventType = SecurityEventType | OtpFamilySecurityEventType;
export const ALL_SECURITY_EVENT_TYPES: readonly AnySecurityEventType[] = [...SECURITY_EVENT_TYPES, ...OTP_FAMILY_SECURITY_EVENT_TYPES];

export type SecurityEventOtpScope = "DECISION" | "REVOCATION" | "MANAGE";
export type SecurityEventScopeClass = "DECISION" | "RIGHTS";
export type SecurityEventKeyKind = "CHANNEL" | "INVITATION" | "CHAIN";
export type SecurityEventWindowKind = "DAY_1" | "DAYS_30";
export type RecoveryTokenTrigger = "REQUESTER_ASKED" | "LIMIT_REACHED" | "CASE_CONTACT" | "SCHOOL_REPORTED";
export type ManagementTokenTrigger = "RECEIPT_REISSUED" | "FAILURE_CAP";
export const SECURITY_EVENT_OTP_SCOPES: readonly SecurityEventOtpScope[] = ["DECISION", "REVOCATION", "MANAGE"];
export const SECURITY_EVENT_SCOPE_CLASSES: readonly SecurityEventScopeClass[] = ["DECISION", "RIGHTS"];
export const SECURITY_EVENT_KEY_KINDS: readonly SecurityEventKeyKind[] = ["CHANNEL", "INVITATION", "CHAIN"];
export const SECURITY_EVENT_WINDOW_KINDS: readonly SecurityEventWindowKind[] = ["DAY_1", "DAYS_30"];
export const RECOVERY_TOKEN_TRIGGERS: readonly RecoveryTokenTrigger[] = ["REQUESTER_ASKED", "LIMIT_REACHED", "CASE_CONTACT", "SCHOOL_REPORTED"];
export const MANAGEMENT_TOKEN_TRIGGERS: readonly ManagementTokenTrigger[] = ["RECEIPT_REISSUED", "FAILURE_CAP"];

export interface OtpIssuedEntry {
  readonly tenantId: TenantId;
  readonly eventType: "OTP_ISSUED";
  readonly verificationRef: string;
  readonly otpScope: SecurityEventOtpScope;
  /** channelRef opaco (seudonimo del canal); NUNCA el correo. */
  readonly channelRef: string;
}
export interface OtpOutcomeEntry {
  readonly tenantId: TenantId;
  readonly eventType: "OTP_FAILED" | "OTP_LOCKED" | "OTP_EXPIRED";
  readonly verificationRef: string;
  readonly otpScope: SecurityEventOtpScope;
}
export interface OtpBudgetExhaustedEntry {
  readonly tenantId: TenantId;
  readonly eventType: "OTP_BUDGET_EXHAUSTED";
  readonly verificationRef: string;
  readonly scopeClass: SecurityEventScopeClass;
  readonly keyKind: SecurityEventKeyKind;
  readonly windowKind: SecurityEventWindowKind;
}
export interface RecoveryTokenIssuedEntry {
  readonly tenantId: TenantId;
  readonly eventType: "RECOVERY_TOKEN_ISSUED";
  readonly recoveryRef: string;
  readonly trigger: RecoveryTokenTrigger;
}
export interface ManagementTokenRotatedEntry {
  readonly tenantId: TenantId;
  readonly eventType: "MANAGEMENT_TOKEN_ROTATED";
  readonly chainRef: string;
  readonly trigger: ManagementTokenTrigger;
}
export type OtpFamilySecurityEventEntry =
  | OtpIssuedEntry | OtpOutcomeEntry | OtpBudgetExhaustedEntry | RecoveryTokenIssuedEntry | ManagementTokenRotatedEntry;

/** Cualquier entrada que el puerto acepta: sesion (`SecurityEventEntry`, sin cambios) o familia OTP/RECOVERY/MANAGEMENT. */
export type AnySecurityEventEntry = SecurityEventEntry | OtpFamilySecurityEventEntry;

export interface OtpFamilySecurityEventMeta {
  readonly eventId: string;
  readonly schemaVersion: "1.0.0";
  readonly occurredAt: Date;
  readonly environment: "LOCAL" | "DEV" | "STAGING" | "PRODUCTION";
  readonly dataClass: "SYNTHETIC";
}
export type OtpFamilySecurityEventRecord = OtpFamilySecurityEventEntry & OtpFamilySecurityEventMeta;
export type AnySecurityEventRecord = SecurityEventRecord | OtpFamilySecurityEventRecord;

/** Narrowing: la entrada es de la familia OTP/RECOVERY/MANAGEMENT (por tipo; la forma la valida `validateSecurityEventEntry`). */
export function isOtpFamilyEntry(entry: AnySecurityEventEntry): entry is OtpFamilySecurityEventEntry {
  return (OTP_FAMILY_SECURITY_EVENT_TYPES as readonly string[]).includes(entry.eventType);
}

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
export function validateSecurityEventEntry(input: AnySecurityEventEntry): void {
  const fail = (field: string): never => {
    throw new SecurityEventValidationError(field);
  };
  if (isOtpFamilyEntry(input)) {
    validateOtpFamilyEntry(input);
    return;
  }
  const entry: SecurityEventEntry = input;
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

const OTP_FAMILY_ALLOWED_KEYS: Readonly<Record<OtpFamilySecurityEventType, readonly string[]>> = {
  OTP_ISSUED: ["tenantId", "eventType", "verificationRef", "otpScope", "channelRef"],
  OTP_FAILED: ["tenantId", "eventType", "verificationRef", "otpScope"],
  OTP_LOCKED: ["tenantId", "eventType", "verificationRef", "otpScope"],
  OTP_EXPIRED: ["tenantId", "eventType", "verificationRef", "otpScope"],
  OTP_BUDGET_EXHAUSTED: ["tenantId", "eventType", "verificationRef", "scopeClass", "keyKind", "windowKind"],
  RECOVERY_TOKEN_ISSUED: ["tenantId", "eventType", "recoveryRef", "trigger"],
  MANAGEMENT_TOKEN_ROTATED: ["tenantId", "eventType", "chainRef", "trigger"],
};

/**
 * Espejo de security_event_otp_shape y los CHECK de columna (0029; INV-21-04): falla ANTES de tocar la base. Es exacto: un campo desconocido
 * (p.ej. un correo) se rechaza por NOMBRE, nunca se descarta en silencio. Los mensajes no incluyen valores.
 */
function validateOtpFamilyEntry(entry: OtpFamilySecurityEventEntry): void {
  const fail = (field: string): never => {
    throw new SecurityEventValidationError(field);
  };
  const raw = entry as unknown as Record<string, unknown>;
  const allowed = OTP_FAMILY_ALLOWED_KEYS[entry.eventType];
  if (Object.keys(raw).some((k) => !allowed.includes(k))) fail("unknownField");
  const ref = (field: string): void => {
    const v = raw[field];
    if (typeof v !== "string" || !SECURITY_EVENT_REF_PATTERN.test(v)) fail(field);
  };
  const oneOf = (field: string, values: readonly string[]): void => {
    const v = raw[field];
    if (typeof v !== "string" || !values.includes(v)) fail(field);
  };
  if (typeof entry.tenantId !== "string" || entry.tenantId.length === 0) fail("tenantId");
  switch (entry.eventType) {
    case "OTP_ISSUED":
      ref("verificationRef"); oneOf("otpScope", SECURITY_EVENT_OTP_SCOPES); ref("channelRef");
      return;
    case "OTP_FAILED":
    case "OTP_LOCKED":
    case "OTP_EXPIRED":
      ref("verificationRef"); oneOf("otpScope", SECURITY_EVENT_OTP_SCOPES);
      return;
    case "OTP_BUDGET_EXHAUSTED":
      ref("verificationRef"); oneOf("scopeClass", SECURITY_EVENT_SCOPE_CLASSES); oneOf("keyKind", SECURITY_EVENT_KEY_KINDS); oneOf("windowKind", SECURITY_EVENT_WINDOW_KINDS);
      // CFG-OT-BUDGET: INVITATION solo DECISION, CHAIN solo RIGHTS, DAYS_30 solo (RIGHTS, CHAIN).
      if (entry.keyKind === "INVITATION" && entry.scopeClass !== "DECISION") fail("keyKind");
      if (entry.keyKind === "CHAIN" && entry.scopeClass !== "RIGHTS") fail("keyKind");
      if (entry.windowKind === "DAYS_30" && !(entry.scopeClass === "RIGHTS" && entry.keyKind === "CHAIN")) fail("windowKind");
      return;
    case "RECOVERY_TOKEN_ISSUED":
      ref("recoveryRef"); oneOf("trigger", RECOVERY_TOKEN_TRIGGERS);
      return;
    case "MANAGEMENT_TOKEN_ROTATED":
      ref("chainRef"); oneOf("trigger", MANAGEMENT_TOKEN_TRIGGERS);
      return;
    default:
      return fail("eventType");
  }
}

export interface SecurityEventPort {
  /**
   * Append-only. Escribe en la MISMA transaccion que crea o revoca la sesion (si la sesion confirma, el evento tambien; si falla, nada).
   * Lanza SecurityEventWriteError ante cualquier fallo.
   */
  record(entry: AnySecurityEventEntry): Promise<void>;
}
