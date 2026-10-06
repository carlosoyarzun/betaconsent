// Gobierna: CA-138 (aprobado por Carlos, 2026-10-05), SEC-CNS-018 rev. 2 (D-3), SEC-CNS-020 (P2-3), common.spec.yaml
// GRD-CM-01 (sesion + membership, 404 uniforme), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-001 §11.
//
// Registro SERVIDOR de sesiones STAFF. La cookie firmada (staff-session.ts) lleva sid/iat/exp; este puerto es lo que permite
// REVOCAR (logout) y expirar por inactividad. Cero PII: solo el HASH del sid (sha256 hex; el sid en claro nunca se
// persiste), refs opacas del principal y el rol. Cada operacion recibe el tenantId resuelto en servidor (RLS por tenant en
// Postgres; scope por tenant en memoria): un sid de otro tenant no existe para este.

import type { TenantId } from "../modules/common/types.ts";
import type { SessionRevokeCause } from "./security-event.port.ts";
import type { StaffRole } from "./staff-identity.port.ts";

/**
 * CA-138 (P2-4): granularidad con que se avanza la ultima actividad. `validateAndTouch` solo ESCRIBE `last_seen_at` si el valor guardado es
 * anterior a `nowMs - 60 s`; dentro de esa ventana valida sin escribir (un GET no genera un UPDATE por request). La inactividad sigue siendo
 * correcta (nunca se extiende de mas: el valor guardado esta atrasado a lo sumo 60 s, asi que la sesion puede expirar hasta 60 s ANTES, nunca despues).
 */
export const STAFF_SESSION_TOUCH_GRANULARITY_MS = 60_000;

export interface StaffSessionRecord {
  readonly tenantId: TenantId;
  /** sha256 hex (64) del sid. */
  readonly sidHash: string;
  readonly principalRef: string;
  readonly role: StaffRole;
  readonly issuedAtMs: number;
  /** Expiracion ABSOLUTA (ms epoch); igual al `exp` de la cookie. */
  readonly expiresAtMs: number;
}

export interface StaffSessionValidation {
  readonly tenantId: TenantId;
  readonly sidHash: string;
  readonly principalRef: string;
  readonly role: StaffRole;
  readonly nowMs: number;
  /** Inactividad maxima: la sesion cuya ultima actividad es anterior a `nowMs - idleTimeoutMs` ya no sirve. */
  readonly idleTimeoutMs: number;
}

export interface StaffSessionStorePort {
  /**
   * Registra una sesion nueva (sid nuevo; un sid repetido es un error, nunca se reutiliza) y devuelve su `sessionRef` (UUIDv4 opaco que genera
   * la base; no es el sid). CA-141: en la MISMA transaccion escribe STAFF_LOGIN en ops.security_event; si el evento falla
   * (SecurityEventWriteError) no queda sesion.
   */
  create(record: StaffSessionRecord): Promise<{ readonly sessionRef: string }>;
  /**
   * ATOMICO: true (y avanza la ultima actividad a `nowMs`) solo si la sesion existe en ESE tenant, el principal y el rol
   * coinciden, no esta revocada, no paso su expiracion absoluta (`expiresAtMs > nowMs`) y no supero la inactividad.
   * Cualquier otro caso devuelve false sin distinguir la causa.
   */
  validateAndTouch(input: StaffSessionValidation): Promise<boolean>;
  /**
   * Revoca el sid en servidor (idempotente; solo marca, nunca reactiva). Un sid desconocido, de otro tenant o ya revocado no hace nada y devuelve
   * false SIN escribir evento. CA-141: si el UPDATE revoco una fila (true), en la MISMA transaccion escribe STAFF_LOGOUT (cause USER_LOGOUT) o
   * SESSION_REVOKED_BY_ROTATION (cause ROTATION), con actor tomados de la FILA (no de la cookie). Si el evento falla
   * (SecurityEventWriteError) la revocacion se revierte: la sesion sigue activa.
   */
  revoke(tenantId: TenantId, sidHash: string, nowMs: number, cause: SessionRevokeCause): Promise<boolean>;
  /** Limpieza: borra las sesiones del tenant cuya expiracion absoluta es anterior a `nowMs - retentionMs`. Devuelve cuantas. */
  purgeExpired(tenantId: TenantId, nowMs: number, retentionMs: number): Promise<number>;
}
