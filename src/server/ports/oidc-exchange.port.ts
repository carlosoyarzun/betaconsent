// Gobierna: ADR-010 rev. 4 §4.3 (nonce, canje OIDC en el verifier, aserciones), §7 fila PR-4; specs/db-roles.spec.yaml (platform_rw, integrity_verifier);
// db/migrations/0036_adr010_verifier_assertions.sql; findings F-A10-12 y F-A10-13; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Dos lados de la cola platform.oidc_exchange, con roles de base distintos y SIN privilegios de tabla (solo funciones SECURITY DEFINER):
//  - OidcExchangeQueuePort (proceso platform, platform_rw): encola code + PKCE. platform NO tiene egress ni lee la cola.
//  - OidcExchangeStorePort (proceso verifier, integrity_verifier): toma una solicitud (lease), canjea fuera de la base y registra la asercion. Es la UNICA
//    forma de atestar un nonce de step-up. Solo claims minimos: nunca el ID token crudo, el email ni el sub en claro (el sub viaja como HMAC).
// Cero PII: refs opacas (UUIDv4) y hashes hex.
// ADR-010 rev. 5 PR-6b (§4.3(2), §5.2): la solicitud nace AWAITING_CALLBACK con state + PKCE (OidcAuthorizationPort.begin), el callback la pasa a PENDING solo si `state` coincide
// (complete) y el verifier registra la asercion: STEP_UP por recordAssertion, LOGIN_* por recordLoginAssertion (la BASE resuelve el principal; el verifier solo entrega el sub_hmac y
// nunca recibe el principal). exchangeRef va solo en una cookie `__Host-` Strict (G-8), nunca en la URL.

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

/** Tipo de solicitud (oidc_exchange.kind, 0050). */
export type ExchangeKind = "LOGIN_PLATFORM" | "LOGIN_CASE" | "STEP_UP";
export type LoginKind = "LOGIN_PLATFORM" | "LOGIN_CASE";
export const LOGIN_KINDS: readonly LoginKind[] = ["LOGIN_PLATFORM", "LOGIN_CASE"];

export interface ClaimedExchange {
  exchangeRef: string;
  kind: ExchangeKind;
  /** sha256 hex del nonce (step-up: del action nonce; login: del nonce aleatorio del navegador); el ID token debe traerlo como `nonce` (hasheado). */
  nonceHash: string;
  /** NULL en LOGIN_PLATFORM (el principal lo resuelve la base por sub_hmac, P6-1). */
  principalRef: string | null;
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

/** Parametros de login por configuracion (P-48, P-52; G-6/G-7). La base no tiene defaults: NULL o fuera de rango => REJECTED NOT_CONFIGURED (fail-closed). */
export interface LoginLimits {
  /** P-48: fallos de autenticacion por identidad (principal resuelto) en la ventana (aprobado: 5). */
  p48MaxFailures: number;
  /** P-48: ventana en segundos (aprobado: 900 = 15 min). */
  p48WindowSeconds: number;
  /** P-52: vida de la asercion LOGIN desde auth_time, en segundos (aprobado: 300 = 5 min; la base no admite mas). */
  p52AssertionSeconds: number;
}

export type LoginRejectionReason = "INVALID_CLAIMS" | "EXCHANGE_FAILED";

export type LoginAssertionRecord =
  | {
      decision: "ATTESTED";
      exchangeRef: string;
      /** HMAC-SHA256(K_sub, iss || sub) en hex; la base lo usa para resolver el principal y NO lo persiste. */
      subHmac: string;
      /** Version de K_sub con que se calculo el HMAC (F-PR6-16). */
      keyVersion: number;
      assertionHash: string;
      authTime: Date;
      acr: string | null;
      amr: readonly string[] | null;
      limits: LoginLimits;
    }
  | { decision: "REJECTED"; exchangeRef: string; reason: LoginRejectionReason };

export interface OidcExchangeStorePort {
  /** Toma una solicitud PENDING vigente (lease en la base) o null. */
  claim(leaseSeconds: number): Promise<ClaimedExchange | null>;
  /** STEP_UP. true solo si quedo ATTESTED. false = REJECTED o la base degrado/denego (el motivo queda en la evidencia, no aqui). */
  recordAssertion(record: AssertionRecord): Promise<boolean>;
  /** LOGIN_*. true solo si quedo ATTESTED; la base NO devuelve el principal (N6'). Un rechazo no persiste el sub_hmac. */
  recordLoginAssertion(record: LoginAssertionRecord): Promise<boolean>;
}

/** Estado de la solicitud visible para el navegador (sin code ni claims). */
export type ExchangeStatus = "AWAITING_CALLBACK" | "PENDING" | "ATTESTED" | "REJECTED";

export interface BeginAuthorizationInput {
  kind: ExchangeKind;
  /** `state` en claro (>= 128 bits, base64url); solo viaja su sha256 a la base. */
  state: string;
  /** sha256 hex del `nonce` enviado al IdP (login: aleatorio; step-up: del action nonce). */
  bindingHex: string;
  pkceVerifier: string;
  /** Solo LOGIN_CASE: sha256 hex del case_ref destino (G-7, F-PR6-27). */
  targetRefHash?: string | null;
  /** LOGIN_CASE y STEP_UP: principal de la sesion validada (nunca de la request). LOGIN_PLATFORM: no se envia. */
  principalRef?: string | null;
  ttlSeconds: number;
  /** P-53 (sin valor aprobado): tope global de filas AWAITING_CALLBACK; null = sin tope (solo LOCAL, lo exige el startup-check de platform). */
  maxAwaiting: number | null;
  /** P-51 (STEP_UP): intentos por operador en la ventana. Obligatorio para STEP_UP. */
  stepUpLimit?: { max: number; windowSeconds: number };
}

/** Lado platform (platform_rw): inicio y cierre del flujo de autorizacion. Sin SELECT ni DML sobre oidc_exchange. */
export interface OidcAuthorizationPort {
  /** Devuelve exchangeRef. Un DENY de la base lanza PlatformDeniedError (tras confirmar la evidencia). */
  begin(input: BeginAuthorizationInput): Promise<string>;
  /** AWAITING_CALLBACK -> PENDING. null = state falta, ajeno, reusado o vencido (404 uniforme; no encola nada). */
  complete(input: { state: string; code: string }): Promise<string | null>;
  /** Estado solo si (exchangeRef, state) son coherentes; null en cualquier otro caso. */
  status(input: { exchangeRef: string; state: string }): Promise<ExchangeStatus | null>;
  /** Evento de limite excedido aplicado en memoria por platform (P-49/P-50). Sin IP. */
  recordLimitEvent(input: { limitKind: "P-49" | "P-50"; windowSeconds: number; principalRef?: string | null }): Promise<void>;
}
