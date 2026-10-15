// Gobierna: ADR-010 rev. 5 §4.3 (puntos 2-4), §5.1/§5.2 (login sin principal previo; state; aserciones LOGIN), §5.4 (P-48, P-51, P-52, P-53), §10 fila PR-6b; specs/db-roles.spec.yaml
// (platform_rw: begin_oidc_authorization, complete_oidc_callback, exchange_status, record_limit_event; integrity_verifier: claim_oidc_exchange, record_assertion, record_login_assertion);
// db/migrations/0036 + 0050 + 0051; findings F-A10-12 y F-A10-13; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Adaptadores sobre las funciones SECURITY DEFINER de platform; ninguno toca tablas (los roles no tienen privilegios de tabla):
//  - createPgOidcAuthorization(pool de platform_rw): begin (AWAITING_CALLBACK con state_hash + PKCE), complete (state -> PENDING con el code), status y eventos de limite.
//  - createPgOidcExchangeQueue(pool de platform_rw, stepUpLimit): composicion begin + complete(STEP_UP) con un state propio, para tests y LOCAL (un navegador honesto haria lo mismo). La ruta
//    HTTP de produccion usa begin y complete por separado, con el state en una cookie.
//  - createPgOidcExchangeStore(pool de integrity_verifier): claim (lease), recordAssertion (STEP_UP) y recordLoginAssertion (LOGIN_*). Los secretos (code, PKCE) devueltos por claim viven solo
//    en memoria. La base resuelve el principal del login; esta capa nunca lo recibe.
// Un DENY de la base ya esta confirmado (authorization_check / session_event) cuando aqui se traduce a PlatformDeniedError uniforme (F-A10-13).

import { createHash, randomBytes } from "node:crypto";
import type {
  AssertionRecord,
  BeginAuthorizationInput,
  ClaimedExchange,
  EnqueueExchangeInput,
  ExchangeKind,
  ExchangeStatus,
  LoginAssertionRecord,
  OidcAuthorizationPort,
  OidcExchangeQueuePort,
  OidcExchangeStorePort,
} from "../../../server/ports/oidc-exchange.port.ts";
import { PlatformDeniedError } from "../../../server/ports/oidc-exchange.port.ts";
import type { PoolLike } from "./pool.ts";
import { withPlatformTransaction } from "./platform-call.ts";

export function nonceBinding(actionNonce: string): string {
  return createHash("sha256").update(actionNonce, "utf8").digest("hex");
}

export function stateHashOf(state: string): string {
  return createHash("sha256").update(state, "utf8").digest("hex");
}

const STATUSES: ReadonlySet<string> = new Set(["AWAITING_CALLBACK", "PENDING", "ATTESTED", "REJECTED"]);
const KINDS: ReadonlySet<string> = new Set(["LOGIN_PLATFORM", "LOGIN_CASE", "STEP_UP"]);

export function createPgOidcAuthorization(pool: PoolLike): OidcAuthorizationPort {
  return {
    async begin(input: BeginAuthorizationInput): Promise<string> {
      if (input.kind === "LOGIN_PLATFORM" && (input.principalRef ?? null) !== null) throw new PlatformDeniedError();
      if (input.kind !== "LOGIN_PLATFORM" && (input.principalRef ?? null) === null) throw new PlatformDeniedError();
      if (input.kind === "STEP_UP" && input.stepUpLimit === undefined) throw new PlatformDeniedError();
      const principal = input.kind === "LOGIN_PLATFORM" ? null : (input.principalRef ?? null);
      const rows = await withPlatformTransaction(pool, principal, async (tx) =>
        (await tx.query<{ exchange_ref: string | null }>("SELECT platform.begin_oidc_authorization($1, $2, $3, $4, $5, $6, $7, $8, $9) AS exchange_ref", [
          input.kind,
          stateHashOf(input.state),
          input.bindingHex,
          input.pkceVerifier,
          input.targetRefHash ?? null,
          input.ttlSeconds,
          input.maxAwaiting,
          input.stepUpLimit?.max ?? null,
          input.stepUpLimit?.windowSeconds ?? null,
        ])).rows,
      );
      const ref = rows[0]?.exchange_ref;
      if (typeof ref !== "string") throw new PlatformDeniedError(); // DENY: la evidencia ya se confirmo
      return ref;
    },

    async complete(input: { state: string; code: string }): Promise<string | null> {
      try {
        const rows = await withPlatformTransaction(pool, null, async (tx) =>
          (await tx.query<{ exchange_ref: string | null }>("SELECT platform.complete_oidc_callback($1, $2) AS exchange_ref", [input.state, input.code])).rows,
        );
        const ref = rows[0]?.exchange_ref;
        return typeof ref === "string" ? ref : null;
      } catch (error) {
        if (error instanceof PlatformDeniedError) return null; // un error de base no se distingue de "state invalido" hacia afuera
        throw error;
      }
    },

    async status(input: { exchangeRef: string; state: string }): Promise<ExchangeStatus | null> {
      try {
        const rows = await withPlatformTransaction(pool, null, async (tx) =>
          (await tx.query<{ status: string | null }>("SELECT platform.exchange_status($1::uuid, $2) AS status", [input.exchangeRef, input.state])).rows,
        );
        const status = rows[0]?.status;
        return typeof status === "string" && STATUSES.has(status) ? (status as ExchangeStatus) : null;
      } catch (error) {
        if (error instanceof PlatformDeniedError) return null;
        throw error;
      }
    },

    async recordLimitEvent(input: { limitKind: "P-49" | "P-50"; windowSeconds: number; principalRef?: string | null }): Promise<void> {
      await withPlatformTransaction(pool, input.principalRef ?? null, async (tx) => {
        await tx.query("SELECT platform.record_limit_event($1, $2)", [input.limitKind, input.windowSeconds]);
        return null;
      });
    },
  };
}

export interface StepUpLimitConfig {
  readonly max: number;
  readonly windowSeconds: number;
}

/** Composicion begin + complete para STEP_UP (tests/LOCAL). Genera su propio state (>= 128 bits). */
export function createPgOidcExchangeQueue(pool: PoolLike, stepUpLimit: StepUpLimitConfig): OidcExchangeQueuePort {
  const authorization = createPgOidcAuthorization(pool);
  return {
    async enqueue(input: EnqueueExchangeInput): Promise<string> {
      const state = randomBytes(24).toString("base64url");
      await authorization.begin({
        kind: "STEP_UP",
        state,
        bindingHex: nonceBinding(input.actionNonce),
        pkceVerifier: input.pkceVerifier,
        principalRef: input.principalRef,
        ttlSeconds: input.ttlSeconds,
        maxAwaiting: null,
        stepUpLimit: { max: stepUpLimit.max, windowSeconds: stepUpLimit.windowSeconds },
      });
      const ref = await authorization.complete({ state, code: input.code });
      if (ref === null) throw new PlatformDeniedError();
      return ref;
    },
  };
}

export function createPgOidcExchangeStore(pool: PoolLike): OidcExchangeStorePort {
  return {
    async claim(leaseSeconds: number): Promise<ClaimedExchange | null> {
      const rows = await withPlatformTransaction(pool, null, async (tx) =>
        (await tx.query<{ o_exchange_ref: string; o_binding: string; o_principal_ref: string | null; o_kind: string; o_code: string; o_pkce_verifier: string }>(
          "SELECT o_exchange_ref, o_binding, o_principal_ref, o_kind, o_code, o_pkce_verifier FROM platform.claim_oidc_exchange($1)",
          [leaseSeconds],
        )).rows,
      );
      const row = rows[0];
      if (row === undefined) return null;
      if (!KINDS.has(row.o_kind)) throw new PlatformDeniedError();
      return {
        exchangeRef: row.o_exchange_ref,
        kind: row.o_kind as ExchangeKind,
        nonceHash: row.o_binding,
        principalRef: row.o_principal_ref,
        code: row.o_code,
        pkceVerifier: row.o_pkce_verifier,
      };
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

    async recordLoginAssertion(record: LoginAssertionRecord): Promise<boolean> {
      const attested = record.decision === "ATTESTED";
      const rows = await withPlatformTransaction(pool, null, async (tx) =>
        (await tx.query<{ attested: boolean }>("SELECT platform.record_login_assertion($1, $2, $3, $4, $5::smallint, $6, $7, $8, $9, $10, $11, $12) AS attested", [
          record.exchangeRef,
          record.decision,
          attested ? null : record.reason,
          attested ? record.subHmac : null,
          attested ? record.keyVersion : null,
          attested ? record.assertionHash : null,
          attested ? record.authTime.toISOString() : null,
          attested ? record.acr : null,
          attested ? (record.amr === null ? null : [...record.amr]) : null,
          attested ? record.limits.p48MaxFailures : null,
          attested ? record.limits.p48WindowSeconds : null,
          attested ? record.limits.p52AssertionSeconds : null,
        ])).rows,
      );
      return rows[0]?.attested === true;
    },
  };
}
