// Gobierna: src/server/ports/tenant-resolver.port.ts, CA-124 (diseño postgres-design.md rev. 2
// §3 tenant_resolve.*, §5). Adaptador in-memory IT0: resuelve por hash contra los mismos
// repos/registro que ya usa el proceso (lookup sin tenant fuera del puerto de repo:
// UNSCOPED_LOOKUP). Solo devuelve identidad mínima (tenant + ref opaca); no evalúa consumo,
// expiración ni estado (eso lo relee el dominio bajo `inTenant`).

import type { InvitationRecord } from "../../server/ports/invitation-repository.port.ts";
import type { RecoveryTokenRecord } from "../../server/ports/recovery-token.port.ts";
import type { TenantHandlePort } from "../../server/ports/tenant-handle.port.ts";
import type { TenantResolverPort } from "../../server/ports/tenant-resolver.port.ts";
import { hasUnscopedLookup, UNSCOPED_LOOKUP } from "./in-memory-tx.ts";

export interface InMemoryTenantResolverSources {
  /** Repo de invitaciones in-memory (con UNSCOPED_LOOKUP); sin él, el hash no resuelve. */
  readonly invitationRepo?: unknown;
  /** Repo de tokens de recuperación in-memory (con UNSCOPED_LOOKUP); sin él, no resuelve. */
  readonly recoveryTokenRepo?: unknown;
  /** Registro de handles de portador (/m/, /r/): se delega en `resolveByHash`. */
  readonly tenantHandle?: Pick<TenantHandlePort, "resolveByHash">;
}

export function createInMemoryTenantResolver(sources: InMemoryTenantResolverSources): TenantResolverPort {
  return {
    async byInvitationTokenHash(tokenHash) {
      const repo = sources.invitationRepo;
      if (!hasUnscopedLookup<InvitationRecord>(repo)) return null;
      const found = repo[UNSCOPED_LOOKUP](tokenHash);
      return found ? { tenantId: found.tenantId, invitationRef: found.invitationRef } : null;
    },
    async byRecoveryTokenHash(tokenHash) {
      const repo = sources.recoveryTokenRepo;
      if (!hasUnscopedLookup<RecoveryTokenRecord>(repo)) return null;
      const found = repo[UNSCOPED_LOOKUP](tokenHash);
      return found ? { tenantId: found.tenantId, recoveryRef: found.recoveryRef } : null;
    },
    async byHandleHash(handleHash) {
      const registry = sources.tenantHandle;
      if (!registry) return null;
      return registry.resolveByHash(handleHash);
    },
  };
}
