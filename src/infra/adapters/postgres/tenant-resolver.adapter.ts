// Gobierna: CA-124 (H09), PR-C; src/server/ports/tenant-resolver.port.ts,
// db/migrations/0007_tenant_resolve.sql, ADR-006 §4 (excepcion de lookup sin tenant),
// common.spec.yaml GRD-CM-01, revocation.spec.yaml GRD-RV-06, diseno postgres-design.md §3, §5 y
// P1-2. ADR-001 §11: solo este adaptador conoce el SQL de tenant_resolve.*.
//
// Tx corta y SIN tenant: una conexion limpia (sin app.tenant_id, P1-1) del rol app_rw ejecuta la
// funcion SECURITY DEFINER tenant_resolve.by_*_hash. Devuelve solo (tenantId, ref opaca);
// desconocido => null (respuesta uniforme). No evalua consumo ni expiracion.
//
// byInvitationTokenHash y byHandleHash quedan fuera de PR-C (sus tablas llegan en PR-D): lanzan
// en vez de devolver null, para que un cableado prematuro no confunda "no implementado" con
// "desconocido".

import type {
  ResolvedInvitationToken,
  ResolvedRecoveryToken,
  ResolvedTenantHandle,
  TenantResolverPort,
} from "../../../server/ports/tenant-resolver.port.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";

const SHA256_HEX = /^[0-9a-f]{64}$/;

export class TenantResolverNotImplementedError extends Error {
  constructor(method: string) {
    super(`PgTenantResolver.${method} no está implementado todavía (CA-124 PR-D).`);
    this.name = "TenantResolverNotImplementedError";
  }
}

export function createPgTenantResolver(pool: PoolLike): TenantResolverPort {
  return {
    async byInvitationTokenHash(): Promise<ResolvedInvitationToken | null> {
      throw new TenantResolverNotImplementedError("byInvitationTokenHash");
    },
    async byRecoveryTokenHash(tokenHash: string): Promise<ResolvedRecoveryToken | null> {
      // Un hash que no es SHA-256 hex no puede existir: sin viaje a la base.
      if (!SHA256_HEX.test(tokenHash)) return null;
      const client = await acquireCleanClient(pool);
      try {
        const r = await client.query<{ tenant_id: string; recovery_ref: string }>(
          "SELECT tenant_id, recovery_ref FROM tenant_resolve.by_recovery_token_hash($1)",
          [tokenHash],
        );
        const row = r.rows[0];
        client.release();
        return row ? { tenantId: row.tenant_id, recoveryRef: row.recovery_ref } : null;
      } catch (error) {
        client.release(true);
        throw error;
      }
    },
    async byHandleHash(): Promise<ResolvedTenantHandle | null> {
      throw new TenantResolverNotImplementedError("byHandleHash");
    },
  };
}
