// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-01 (tenant_resolved_server_side),
// specs/state-machines/rights-case.spec.yaml GRD-RC-14 (case_bound_to_handle_chain).
// Puerto (ADR-001 §11): resuelve un handle de portador (/m/, /r/) a (tenantId, chainRef) del
// lado servidor. Nunca a partir de un campo enviado por el cliente.

import { createHash } from "node:crypto";

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
  /**
   * SEC-CNS-014 patrón (Carlos, 2026-09-28): resuelve por `hashTenantHandle(handle)`, para que
   * GET /manage (consent-flow-server.ts) pueda validar el handle MANAGE_ENTRY que fijó GET
   * /m/{token} sin que ese GET haya leído la BD (revocation-flow.handler.ts
   * handleRedeemManagementLink). Nunca confundir con `resolve(handle)`: esa sigue resolviendo
   * por el handle EN CLARO (uso existente, RC2u vía `manageHandleCookieName`,
   * rights-case-resume.handler.ts), sin relación con este método.
   */
  resolveByHash(handleHash: string): ResolvedHandle | null;
}

/** SEC-CNS-014 patrón (Carlos, 2026-09-28): sha256 hex del handle en claro. GET /m/{token}
 * hashea con esta función SIN leer ningún port, para que el 303 sea idéntico sea o no válido el
 * handle; GET /manage resuelve luego por este mismo hash vía `resolveByHash`, nunca por el
 * handle en claro. Exportada para que ambos lados (handler HTTP y adaptador in-memory)
 * compartan el mismo algoritmo. */
export function hashTenantHandle(handle: string): string {
  return createHash("sha256").update(handle).digest("hex");
}
