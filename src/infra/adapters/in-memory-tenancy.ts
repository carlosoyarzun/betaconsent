// Gobierna: CA-124 (diseño postgres-design.md rev. 2 §5). Cableado in-memory del par
// UnitOfWorkPort + TenantResolverPort sobre los MISMOS adaptadores que ya componen los puertos
// de un módulo (tests y entrypoints IT0): comparten estado, así el journal del UoW deshace
// exactamente lo que el resto del proceso ve.

import type { TenantResolverPort } from "../../server/ports/tenant-resolver.port.ts";
import type { TenantTxPorts, UnitOfWorkPort } from "../../server/ports/unit-of-work.port.ts";
import type { TenantHandlePort } from "../../server/ports/tenant-handle.port.ts";
import { createInMemoryTenantResolver } from "./in-memory-tenant-resolver.adapter.ts";
import { createInMemoryUnitOfWork } from "./in-memory-unit-of-work.adapter.ts";

export interface InMemoryTenancyPorts {
  readonly uow: UnitOfWorkPort;
  readonly tenantResolver: TenantResolverPort;
}

export function createInMemoryTenancy(
  ports: TenantTxPorts & { readonly invitationRepo?: unknown; readonly tenantHandle?: Pick<TenantHandlePort, "resolveByHash"> },
): InMemoryTenancyPorts {
  return {
    uow: createInMemoryUnitOfWork(ports),
    tenantResolver: createInMemoryTenantResolver({
      recoveryTokenRepo: ports.recoveryTokenRepo,
      invitationRepo: ports.invitationRepo,
      tenantHandle: ports.tenantHandle,
    }),
  };
}

/** `bag` + `uow` + `tenantResolver` (atajo para armar los puertos de un módulo). */
export function withInMemoryTenancy<B extends TenantTxPorts>(
  bag: B & { readonly invitationRepo?: unknown; readonly tenantHandle?: Pick<TenantHandlePort, "resolveByHash"> },
): B & InMemoryTenancyPorts {
  return { ...bag, ...createInMemoryTenancy(bag) };
}
