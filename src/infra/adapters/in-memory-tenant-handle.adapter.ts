// Gobierna: src/server/ports/tenant-handle.port.ts, GRD-CM-01, GRD-RC-14.
// Adaptador in-memory para IT0 LOCAL/CI: simula la resolución de un handle de portador
// (/m/, /r/) contra un registro de handles emitidos, incluida la rotación (token viejo
// deja de resolver tras emitir uno nuevo para la misma cadena).

import type { ResolvedHandle, TenantHandlePort } from "../../server/ports/tenant-handle.port.ts";

interface SeedHandle {
  readonly handle: string;
  readonly tenantId: string;
  readonly chainRef: string;
  readonly revokedDecisionRef: string;
}

export interface InMemoryTenantHandleAdapter extends TenantHandlePort {
  /** Emite (o reemplaza) el handle vigente de una cadena; el handle anterior deja de resolver. */
  issue(seed: SeedHandle): void;
  /** Marca un handle existente como rotado (deja de resolver) sin emitir uno nuevo. */
  rotate(handle: string): void;
}

export function createInMemoryTenantHandleAdapter(seeds: readonly SeedHandle[] = []): InMemoryTenantHandleAdapter {
  const byHandle = new Map<string, ResolvedHandle>();

  for (const seed of seeds) {
    byHandle.set(seed.handle, {
      tenantId: seed.tenantId,
      chainRef: seed.chainRef,
      revokedDecisionRef: seed.revokedDecisionRef,
    });
  }

  return {
    resolve(handle: string): ResolvedHandle | null {
      return byHandle.get(handle) ?? null;
    },
    issue(seed: SeedHandle): void {
      byHandle.set(seed.handle, {
        tenantId: seed.tenantId,
        chainRef: seed.chainRef,
        revokedDecisionRef: seed.revokedDecisionRef,
      });
    },
    rotate(handle: string): void {
      byHandle.delete(handle);
    },
  };
}
