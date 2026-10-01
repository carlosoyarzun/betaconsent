// Gobierna: CA-124 (H09), PR-C; src/server/ports/tenant-resolver.port.ts,
// db/migrations/0007_tenant_resolve.sql, ADR-006 §4 (excepcion de lookup sin tenant),
// common.spec.yaml GRD-CM-01, revocation.spec.yaml GRD-RV-06, diseno postgres-design.md §3, §5 y
// P1-2. ADR-001 §11: solo este adaptador conoce el SQL de tenant_resolve.*.
//
// Tx corta y SIN tenant: una conexion limpia (sin app.tenant_id, P1-1) del rol app_rw ejecuta la
// funcion SECURITY DEFINER tenant_resolve.by_*_hash. Devuelve solo (tenantId, ref opaca);
// desconocido => null (respuesta uniforme). No evalua consumo ni expiracion.
//
// CA-124 PR-D: byInvitationTokenHash (tenant_resolve.by_invitation_token_hash) y byHandleHash
// (tenant_resolve.by_handle_hash, 0011) completan el puerto; el handle rotado ya no resuelve.

import type {
  ResolvedInvitationToken,
  ResolvedRecoveryToken,
  ResolvedTenantHandle,
  TenantResolverPort,
} from "../../../server/ports/tenant-resolver.port.ts";
import type { ChainRef } from "../../../server/modules/common/types.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";

const SHA256_HEX = /^[0-9a-f]{64}$/;

async function resolveOne<R, T>(
  pool: PoolLike,
  hash: string,
  sql: string,
  map: (row: R) => T,
): Promise<T | null> {
  // Un hash que no es SHA-256 hex no puede existir: sin viaje a la base.
  if (!SHA256_HEX.test(hash)) return null;
  const client = await acquireCleanClient(pool);
  try {
    const r = await client.query<R>(sql, [hash]);
    const row = r.rows[0];
    client.release();
    return row ? map(row) : null;
  } catch (error) {
    client.release(true);
    throw error;
  }
}

export function createPgTenantResolver(pool: PoolLike): TenantResolverPort {
  return {
    byInvitationTokenHash(tokenHash: string): Promise<ResolvedInvitationToken | null> {
      return resolveOne<{ tenant_id: string; invitation_ref: string }, ResolvedInvitationToken>(
        pool,
        tokenHash,
        "SELECT tenant_id, invitation_ref FROM tenant_resolve.by_invitation_token_hash($1)",
        (row) => ({ tenantId: row.tenant_id, invitationRef: row.invitation_ref }),
      );
    },
    byRecoveryTokenHash(tokenHash: string): Promise<ResolvedRecoveryToken | null> {
      return resolveOne<{ tenant_id: string; recovery_ref: string }, ResolvedRecoveryToken>(
        pool,
        tokenHash,
        "SELECT tenant_id, recovery_ref FROM tenant_resolve.by_recovery_token_hash($1)",
        (row) => ({ tenantId: row.tenant_id, recoveryRef: row.recovery_ref }),
      );
    },
    byHandleHash(handleHash: string): Promise<ResolvedTenantHandle | null> {
      return resolveOne<{ tenant_id: string; chain_ref: string; revoked_decision_ref: string }, ResolvedTenantHandle>(
        pool,
        handleHash,
        "SELECT tenant_id, chain_ref, revoked_decision_ref FROM tenant_resolve.by_handle_hash($1)",
        (row) => ({ tenantId: row.tenant_id, chainRef: row.chain_ref as ChainRef, revokedDecisionRef: row.revoked_decision_ref }),
      );
    },
  };
}
