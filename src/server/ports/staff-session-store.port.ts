// Gobierna: CA-138 (aprobado por Carlos, 2026-10-05), SEC-CNS-018 rev. 2 (D-3), SEC-CNS-020 (P2-3), common.spec.yaml
// GRD-CM-01 (sesion + membership, 404 uniforme), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-001 §11.
//
// Registro SERVIDOR de sesiones STAFF. La cookie firmada (staff-session.ts) lleva sid/iat/exp; este puerto es lo que permite
// REVOCAR (logout) y expirar por inactividad. Cero PII: solo el HASH del sid (sha256 hex; el sid en claro nunca se
// persiste), refs opacas del principal y el rol. Cada operacion recibe el tenantId resuelto en servidor (RLS por tenant en
// Postgres; scope por tenant en memoria): un sid de otro tenant no existe para este.

import type { TenantId } from "../modules/common/types.ts";
import type { StaffRole } from "./staff-identity.port.ts";

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
  /** Registra una sesion nueva (sid nuevo; un sid repetido es un error, nunca se reutiliza). */
  create(record: StaffSessionRecord): Promise<void>;
  /**
   * ATOMICO: true (y avanza la ultima actividad a `nowMs`) solo si la sesion existe en ESE tenant, el principal y el rol
   * coinciden, no esta revocada, no paso su expiracion absoluta (`expiresAtMs > nowMs`) y no supero la inactividad.
   * Cualquier otro caso devuelve false sin distinguir la causa.
   */
  validateAndTouch(input: StaffSessionValidation): Promise<boolean>;
  /** Revoca el sid en servidor (idempotente; solo marca, nunca la reactiva). Un sid desconocido o de otro tenant no hace nada. */
  revoke(tenantId: TenantId, sidHash: string, nowMs: number): Promise<void>;
  /** Limpieza: borra las sesiones del tenant cuya expiracion absoluta es anterior a `nowMs - retentionMs`. Devuelve cuantas. */
  purgeExpired(tenantId: TenantId, nowMs: number, retentionMs: number): Promise<number>;
}
