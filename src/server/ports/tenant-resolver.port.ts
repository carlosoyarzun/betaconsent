// Gobierna: CA-124, diseño postgres-design.md rev. 2 §3 (`tenant_resolve.*`, excepción ADR-006 §4)
// y §5 ("Lookups sin tenant. Salen de los repos"), common.spec.yaml GRD-CM-01 (el tenant se
// resuelve en servidor). Puerto de tx corta y SIN tenant: recibe solo el hash de un secreto de
// portador (token o handle, nunca en claro) y devuelve la identidad mínima (tenant + ref
// opaca); el llamador entra luego a `UnitOfWorkPort.inTenant(tenantId, ...)` y relee el
// agregado bajo el tenant. Cero PII; la respuesta a "desconocido" es siempre `null`.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export interface ResolvedInvitationToken {
  readonly tenantId: TenantId;
  readonly invitationRef: string;
}

export interface ResolvedRecoveryToken {
  readonly tenantId: TenantId;
  /** Ref opaca del token (RecoveryTokenRecord.recoveryRef), distinta del token en claro. */
  readonly recoveryRef: string;
}

export interface ResolvedTenantHandle {
  readonly tenantId: TenantId;
  readonly chainRef: ChainRef;
  readonly revokedDecisionRef: string;
}

export interface TenantResolverPort {
  /** GRD-IV-07: por sha256 del token de invitación; no evalúa expiración ni estado. */
  byInvitationTokenHash(tokenHash: string): Promise<ResolvedInvitationToken | null>;
  /** GRD-RV-06: por sha256 del token de recuperación; no evalúa consumo ni expiración. */
  byRecoveryTokenHash(tokenHash: string): Promise<ResolvedRecoveryToken | null>;
  /** SEC-CNS-014 patrón: por `hashTenantHandle(handle)`; null si desconocido, rotado o expirado. */
  byHandleHash(handleHash: string): Promise<ResolvedTenantHandle | null>;
}
