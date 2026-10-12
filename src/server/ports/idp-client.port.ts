// Gobierna: ADR-010 rev. 4 §4.3.3 (canje en el verifier; JWKS por el proxy de egress en IT0b, JWKS sintetico fijo en LOCAL), §7 fila PR-4; ADR-001 §11.
// APR-IDP (parametros concretos del IdP) sigue PENDING: no hay IdP real, endpoints ni secretos reales en este PR.
//
// Puerto del IdP que usa SOLO el proceso verifier (platform no tiene egress). El adaptador real (IT0b) hablara con el token endpoint y el JWKS a traves del
// proxy de egress (P-45 sin aprobar). En LOCAL existe un adaptador sintetico en memoria (src/infra/adapters/synthetic-idp.adapter.ts).

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  [member: string]: unknown;
}

export interface Jwks {
  keys: readonly Jwk[];
}

export interface IdpClientPort {
  /** Canjea el code (+ PKCE) en el token endpoint. Devuelve el ID token crudo (vive solo en memoria del verifier). Cualquier fallo lanza. */
  exchangeCode(input: { code: string; pkceVerifier: string }): Promise<{ idToken: string }>;
  /** JWKS del issuer fijado (cache y rotacion son del adaptador). */
  getJwks(): Promise<Jwks>;
}
