// Gobierna: CA-124 (H09), PR-D; src/server/ports/tenant-handle.port.ts, db/migrations/
// 0011_tenant_resolve_invitation_handle.sql (tenant_resolve.handle), common.spec.yaml GRD-CM-01,
// rights-case.spec.yaml GRD-RC-14, ADR-006 §4, SEC-CNS-014 patron (resolver por hash).
// ADR-001 §11: solo este adaptador conoce el SQL de tenant_resolve.*_handle.
//
// TenantHandlePort es de SOLO LECTURA (resolve / resolveByHash): ambos resuelven por el HASH del handle
// (sha256 hex), nunca guardan el handle en claro, y delegan en TenantResolverPort.byHandleHash
// (tx corta y sin tenant, funcion SECURITY DEFINER). La emision y la rotacion no estan en el puerto
// (hoy solo las hace la siembra de dev/tests con el adaptador in-memory); aqui se ofrecen como
// funciones de infraestructura que corren DENTRO de una tx de tenant (el tenant sale de
// app.current_tenant_id() en la base, nunca de un parametro): `registerTenantHandle` y
// `rotateTenantHandle`. El puerto de emision llega con el flujo que emite handles (PR-E).

import { hashTenantHandle, type ResolvedHandle, type TenantHandlePort } from "../../../server/ports/tenant-handle.port.ts";
import type { PoolLike } from "./pool.ts";
import { createPgTenantResolver } from "./tenant-resolver.adapter.ts";
import type { TenantTx } from "./unit-of-work.ts";

export function createPgTenantHandleAdapter(pool: PoolLike): TenantHandlePort {
  const resolver = createPgTenantResolver(pool);
  const byHash = (handleHash: string): Promise<ResolvedHandle | null> => resolver.byHandleHash(handleHash);
  return {
    resolve: (handle) => byHash(hashTenantHandle(handle)),
    resolveByHash: byHash,
  };
}

export interface TenantHandleSeed {
  /** Handle en claro (solo para hashearlo aqui; nunca persiste). */
  readonly handle: string;
  readonly chainRef: string;
  readonly revokedDecisionRef: string;
}

/** Registra el handle del tenant de la tx (idempotente para la misma tupla; otra tupla = 23505). */
export async function registerTenantHandle(tx: TenantTx, seed: TenantHandleSeed): Promise<void> {
  await tx.query("SELECT tenant_resolve.register_handle($1, $2, $3)", [
    hashTenantHandle(seed.handle),
    seed.chainRef,
    seed.revokedDecisionRef,
  ]);
}

/** Rota (invalida) el handle del tenant de la tx; un handle de otro tenant o inexistente no cambia. */
export async function rotateTenantHandle(tx: TenantTx, handle: string): Promise<void> {
  await tx.query("SELECT tenant_resolve.rotate_handle($1)", [hashTenantHandle(handle)]);
}
