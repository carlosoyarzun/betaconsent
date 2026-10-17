// Gobierna: ADR-010 rev. 4 §4.6 (authorization_check), §7 fila PR-4; db/migrations/0035 y 0036 (contrato con el adapter, P2-7); findings F-A10-13.
//
// Disciplina de llamada a las funciones SECURITY DEFINER del esquema `platform` (F-A10-13):
//  1. El principal se fija SOLO con set_config('app.principal_ref', $1, true) (local a la transaccion; nunca sesion, nunca ALTER ROLE ... SET).
//  2. Las funciones NO lanzan excepcion ante un DENY (devuelven NULL/false/0 filas) para que la fila de authorization_check se confirme: el adaptador hace
//     COMMIT siempre que la llamada no falle por un error de base, y SOLO DESPUES traduce el DENY a un error generico uniforme (PlatformDeniedError, sin motivo).
//  3. Un error de base (SQLSTATE) hace ROLLBACK y se relanza como PlatformDeniedError uniforme tambien (no filtra nombres de constraint ni de objeto); salvo la indisponibilidad (PR-7a, T-10): PlatformUnavailableError.
//  4. ADR-010 PR-6c (F-PR6-36): LOGIN_CASE no declara principal: el adapter fija solo el sid de la sesion PLATFORM con set_config('app.session_sid', $1, true) (local a la transaccion) y la BASE lo
//     resuelve contra platform.platform_session. El sid es un secreto de sesion (256 bits): nunca se registra.
// Este es el unico archivo que escribe app.principal_ref y app.session_sid desde src/**. Cero PII: el principal es un UUIDv4 opaco.

import { PlatformDeniedError, PlatformUnavailableError } from "../../../server/ports/oidc-exchange.port.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";
import { isRolledBackRetryable, isServiceUnavailableError, retryRolledBack } from "./transient-error.ts";

const SID_RE = /^[0-9a-f]{64}$/;
const PRINCIPAL_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface PlatformQuery {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<{ rows: R[]; rowCount: number | null }>;
}

/**
 * Ejecuta `work` en UNA transaccion con el principal fijado (o sin principal, para el verifier, que no actua en nombre de nadie). Siempre COMMIT si `work`
 * termina; ROLLBACK + PlatformDeniedError si falla. `work` devuelve el resultado crudo y el llamador decide el DENY DESPUES del COMMIT.
 */
export async function withPlatformTransaction<T>(
  pool: PoolLike,
  principalRef: string | null,
  work: (tx: PlatformQuery) => Promise<T>,
  options: { readonly sessionSid?: string | null } = {},
): Promise<T> {
  if (principalRef !== null && !PRINCIPAL_RE.test(principalRef)) throw new PlatformDeniedError();
  const sessionSid = options.sessionSid ?? null;
  if (sessionSid !== null && !SID_RE.test(sessionSid)) throw new PlatformDeniedError();
  // PR-7a: un error de tx revertida (clase 40, 55P03) se reintenta con tope ANTES de decidir DENY/503 (no correlaciona con la existencia del recurso); `work` corre solo dentro de la tx.
  return retryRolledBack(() => platformTransactionOnce(pool, principalRef, sessionSid, work));
}

async function platformTransactionOnce<T>(pool: PoolLike, principalRef: string | null, sessionSid: string | null, work: (tx: PlatformQuery) => Promise<T>): Promise<T> {
  const client = await acquireCleanClient(pool);
  let broken = false;
  try {
    await client.query("BEGIN");
    try {
      if (principalRef !== null) await client.query("SELECT set_config('app.principal_ref', $1, true)", [principalRef]);
      if (sessionSid !== null) await client.query("SELECT set_config('app.session_sid', $1, true)", [sessionSid]);
      const result = await work(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
        broken = true;
      }
      // PR-7a (T-10): indisponibilidad de la base (SQLSTATE 08/40/53/57/55P03, conexion perdida) NO es un DENY: 503 uniforme en el borde. Cualquier otro error de base sigue siendo el DENY uniforme.
      if (isRolledBackRetryable(error)) throw error; // lo reintenta retryRolledBack; agotado el tope, el borde lo traduce en 503 uniforme (isUnavailable)
      throw isServiceUnavailableError(error) ? new PlatformUnavailableError() : new PlatformDeniedError();
    }
  } finally {
    client.release(broken);
  }
}
