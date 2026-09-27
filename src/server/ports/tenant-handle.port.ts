// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-01 (tenant_resolved_server_side),
// specs/state-machines/rights-case.spec.yaml GRD-RC-14 (case_bound_to_handle_chain).
// Puerto (ADR-001 §11): resuelve un handle de portador (/m/, /r/) a (tenantId, chainRef) del
// lado servidor. Nunca a partir de un campo enviado por el cliente.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export interface ResolvedHandle {
  readonly tenantId: TenantId;
  readonly chainRef: ChainRef;
  readonly revokedDecisionRef: string;
}

export interface TenantHandlePort {
  /**
   * Devuelve la resolución vigente del handle, o `null` si el handle es desconocido, rotado
   * o expirado (GRD-CM-01 onFail: ERR-CM-01, 404 uniforme, sin evento).
   */
  resolve(handle: string): ResolvedHandle | null;
}
