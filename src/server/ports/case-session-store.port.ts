// Gobierna: CA-139 (aprobado por Carlos, 2026-10-06; P1-1 de la revision de CA-138), SEC-CNS-018 rev. 2 (D-3), common.spec.yaml
// GRD-CM-01 (sesion + ligadura al caso, 404 uniforme), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-001 §11.
//
// Registro SERVIDOR de sesiones CASE (RIGHTS_OPERATOR/APPROVER). Misma semantica que StaffSessionStorePort (CA-138) mas la
// ligadura al caseRef. La cookie firmada (case-session.ts) lleva sid/iat/exp; este puerto permite REVOCAR (logout) y expirar por
// inactividad. Cero PII: solo el HASH del sid, refs opacas (principal, caso) y el rol. Cada operacion recibe el tenantId
// resuelto en servidor (RLS por tenant en Postgres; scope por tenant en memoria).

import type { TenantId } from "../modules/common/types.ts";
import type { CaseStaffRole } from "./staff-identity.port.ts";

/** Misma granularidad que la sesion STAFF (CA-138 P2-4): `last_seen_at` solo se escribe si esta atrasado mas de 60 s. */
export const CASE_SESSION_TOUCH_GRANULARITY_MS = 60_000;

export interface CaseSessionRecord {
  readonly tenantId: TenantId;
  /** sha256 hex (64) del sid. */
  readonly sidHash: string;
  readonly caseRef: string;
  readonly principalRef: string;
  readonly role: CaseStaffRole;
  readonly issuedAtMs: number;
  /** Expiracion ABSOLUTA (ms epoch); igual al `exp` de la cookie. */
  readonly expiresAtMs: number;
}

export interface CaseSessionValidation {
  readonly tenantId: TenantId;
  readonly sidHash: string;
  readonly caseRef: string;
  readonly principalRef: string;
  readonly role: CaseStaffRole;
  readonly nowMs: number;
  readonly idleTimeoutMs: number;
}

export interface CaseSessionStorePort {
  /** Registra una sesion nueva (un sid repetido es un error, nunca se reutiliza). */
  create(record: CaseSessionRecord): Promise<void>;
  /**
   * ATOMICO: true (y avanza la ultima actividad) solo si la sesion existe en ESE tenant, caso, principal y rol coinciden, no esta
   * revocada, no paso su expiracion absoluta y no supero la inactividad. Cualquier otro caso devuelve false sin distinguir la causa.
   */
  validateAndTouch(input: CaseSessionValidation): Promise<boolean>;
  /** Revoca el sid en servidor (idempotente; nunca reactiva). Un sid desconocido o de otro tenant no hace nada. */
  revoke(tenantId: TenantId, sidHash: string, nowMs: number): Promise<void>;
  /** Borra las sesiones del tenant cuya expiracion absoluta es anterior a `nowMs - retentionMs`. Devuelve cuantas. */
  purgeExpired(tenantId: TenantId, nowMs: number, retentionMs: number): Promise<number>;
}
