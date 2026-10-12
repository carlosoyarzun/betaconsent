// Gobierna: ADR-010 rev. 4 §4.3 (nonce, canje OIDC en el verifier, aserciones), §7 fila PR-4; specs/db-roles.spec.yaml (platform_rw, integrity_verifier);
// db/migrations/0036_adr010_verifier_assertions.sql; findings F-A10-12 y F-A10-13; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Dos lados de la cola platform.oidc_exchange, con roles de base distintos y SIN privilegios de tabla (solo funciones SECURITY DEFINER):
//  - OidcExchangeQueuePort (proceso platform, platform_rw): encola code + PKCE. platform NO tiene egress ni lee la cola.
//  - OidcExchangeStorePort (proceso verifier, integrity_verifier): toma una solicitud (lease), canjea fuera de la base y registra la asercion. Es la UNICA
//    forma de atestar un nonce de step-up. Solo claims minimos: nunca el ID token crudo, el email ni el sub en claro (el sub viaja como HMAC).
// Cero PII: refs opacas (UUIDv4) y hashes hex.

/** Un DENY de la base. Mensaje UNIFORME y sin motivo (F-A10-13): el motivo queda en platform.authorization_check, no en la respuesta. */
export class PlatformDeniedError extends Error {
  readonly code = "PLATFORM_DENIED";
  constructor() {
    super("platform: operacion no autorizada");
    this.name = "PlatformDeniedError";
  }
}

export interface EnqueueExchangeInput {
  /** Principal que inicia el step-up (sale de la sesion PLATFORM; nunca de la request). UUIDv4. */
  principalRef: string;
  /** Nonce de step-up EN CLARO devuelto una vez por platform.issue_action_nonce; viaja como `nonce` al IdP. El adaptador solo envia su sha256. */
  actionNonce: string;
  /** Authorization code del IdP (secreto operativo N4, se anula al consumirse). */
  code: string;
  /** code_verifier PKCE (secreto operativo N4). */
  pkceVerifier: string;
  /** Vida de la solicitud en segundos (1..600). */
  ttlSeconds: number;
}

export interface OidcExchangeQueuePort {
  /** Devuelve exchangeRef. Un DENY de la base lanza PlatformDeniedError (tras confirmar la evidencia). */
  enqueue(input: EnqueueExchangeInput): Promise<string>;
}

export interface ClaimedExchange {
  exchangeRef: string;
  /** sha256 hex del nonce de step-up; el ID token debe traerlo como `nonce` (hasheado). */
  nonceHash: string;
  principalRef: string;
  code: string;
  pkceVerifier: string;
}

export type RejectionReason = "SUB_MISMATCH" | "INVALID_CLAIMS" | "EXCHANGE_FAILED";
export const REJECTION_REASONS: readonly RejectionReason[] = ["SUB_MISMATCH", "INVALID_CLAIMS", "EXCHANGE_FAILED"];

export type AssertionRecord =
  | {
      decision: "ATTESTED";
      exchangeRef: string;
      /** HMAC-SHA256(K_sub, iss || sub) en hex. Nunca el sub. */
      subHmac: string;
      /** sha256 hex del ID token crudo (el token se descarta). */
      assertionHash: string;
      authTime: Date;
      acr: string | null;
      amr: readonly string[] | null;
    }
  | { decision: "REJECTED"; exchangeRef: string; reason: RejectionReason };

export interface OidcExchangeStorePort {
  /** Toma una solicitud PENDING vigente (lease en la base) o null. */
  claim(leaseSeconds: number): Promise<ClaimedExchange | null>;
  /** true solo si quedo ATTESTED. false = REJECTED o la base degrado/denego (el motivo queda en la evidencia, no aqui). */
  recordAssertion(record: AssertionRecord): Promise<boolean>;
}
