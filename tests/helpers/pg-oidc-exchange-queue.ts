// Gobierna: ADR-010 rev. 5 §4.3(2) / §10 PR-6b (seguridad PR-6b P2: no es codigo de produccion). Composicion begin_oidc_authorization + complete_oidc_callback para STEP_UP con un state propio,
// como lo haria un navegador honesto. Solo tests (verifier-e2e). La ruta HTTP de produccion usa begin y complete por separado, con el state en una cookie.

import { randomBytes } from "node:crypto";
import { createPgOidcAuthorization, nonceBinding } from "../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import type { PoolLike } from "../../src/infra/adapters/postgres/pool.ts";
import { PlatformDeniedError } from "../../src/server/ports/oidc-exchange.port.ts";
import type { EnqueueExchangeInput, OidcExchangeQueuePort } from "../../src/server/ports/oidc-exchange.port.ts";

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

