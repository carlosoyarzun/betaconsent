// Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4), §7 fila PR-4; specs/db-roles.spec.yaml (platform_rw: enqueue_oidc_exchange; integrity_verifier: claim_oidc_exchange y
// record_assertion); db/migrations/0036_adr010_verifier_assertions.sql; F-A10-13 (COMMIT ante un DENY + error generico); ADR-001 §11.
//
// Dos adaptadores sobre las funciones SECURITY DEFINER de platform; ninguno toca tablas (los roles no tienen privilegios de tabla):
//  - createPgOidcExchangeQueue(pool de platform_rw): encola code + PKCE. Envia solo el sha256 del nonce de step-up (binding).
//  - createPgOidcExchangeStore(pool de integrity_verifier): claim (lease) y recordAssertion. Los secretos (code, PKCE) devueltos por claim viven solo en memoria.
// Un DENY de la base ya esta confirmado (authorization_check) cuando aqui se traduce a PlatformDeniedError uniforme (F-A10-13).

import { createHash } from "node:crypto";
import type { AssertionRecord, ClaimedExchange, EnqueueExchangeInput, OidcExchangeQueuePort, OidcExchangeStorePort } from "../../../server/ports/oidc-exchange.port.ts";
import { PlatformDeniedError } from "../../../server/ports/oidc-exchange.port.ts";
import type { PoolLike } from "./pool.ts";
import { withPlatformTransaction } from "./platform-call.ts";

export function nonceBinding(actionNonce: string): string {
  return createHash("sha256").update(actionNonce, "utf8").digest("hex");
}

export function createPgOidcExchangeQueue(pool: PoolLike): OidcExchangeQueuePort {
  return {
    async enqueue(input: EnqueueExchangeInput): Promise<string> {
      const rows = await withPlatformTransaction(pool, input.principalRef, async (tx) =>
        (await tx.query<{ exchange_ref: string | null }>("SELECT platform.enqueue_oidc_exchange($1, $2, $3, $4) AS exchange_ref", [
          nonceBinding(input.actionNonce),
          input.code,
          input.pkceVerifier,
          input.ttlSeconds,
        ])).rows,
      );
      const ref = rows[0]?.exchange_ref;
      if (typeof ref !== "string") throw new PlatformDeniedError(); // DENY: la evidencia ya se confirmo
      return ref;
    },
  };
}

export function createPgOidcExchangeStore(pool: PoolLike): OidcExchangeStorePort {
  return {
    async claim(leaseSeconds: number): Promise<ClaimedExchange | null> {
      const rows = await withPlatformTransaction(pool, null, async (tx) =>
        (await tx.query<{ o_exchange_ref: string; o_binding: string; o_principal_ref: string; o_code: string; o_pkce_verifier: string }>(
          "SELECT o_exchange_ref, o_binding, o_principal_ref, o_code, o_pkce_verifier FROM platform.claim_oidc_exchange($1)",
          [leaseSeconds],
        )).rows,
      );
      const row = rows[0];
      if (row === undefined) return null;
      return { exchangeRef: row.o_exchange_ref, nonceHash: row.o_binding, principalRef: row.o_principal_ref, code: row.o_code, pkceVerifier: row.o_pkce_verifier };
    },

    async recordAssertion(record: AssertionRecord): Promise<boolean> {
      const attested = record.decision === "ATTESTED";
      const rows = await withPlatformTransaction(pool, null, async (tx) =>
        (await tx.query<{ attested: boolean }>("SELECT platform.record_assertion($1, $2, $3, $4, $5, $6, $7, $8) AS attested", [
          record.exchangeRef,
          record.decision,
          attested ? null : record.reason,
          attested ? record.subHmac : null,
          attested ? record.assertionHash : null,
          attested ? record.authTime.toISOString() : null,
          attested ? record.acr : null,
          attested ? (record.amr === null ? null : [...record.amr]) : null,
        ])).rows,
      );
      return rows[0]?.attested === true;
    },
  };
}
