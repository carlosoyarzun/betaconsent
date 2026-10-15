// Gobierna: ADR-010 rev. 5 §4.3(3) y §10 fila PR-6b ("adaptador de IdP real apagado"); F-A10-24 (issuer, token_endpoint y jwks_uri FIJADOS por configuracion: sin discovery, sin jku/x5u);
// ADR-001 §11 (este adaptador vive solo en src/infra/adapters/**). APR-IDP (parametros concretos), P-45 (egress proxy) y TP-02 (transferencia internacional) siguen PENDING: este adaptador esta APAGADO.
//
// Apagado significa: (a) NO abre sockets por si mismo: el cliente HTTP se INYECTA (`IdpHttpClient`; el proxy de egress de IT0b lo proveera) y en este repo nadie lo cablea; (b) el factory se niega en LOCAL
// (ahi se usa el IdP sintetico), se niega sin la bandera `egressApproved` (P-45) y se niega ante cualquier configuracion incompleta o insegura (fail-closed); (c) createVerifierIdp sigue lanzando fuera de LOCAL.
// Cero PII y cero secretos en errores: los mensajes nunca incluyen code, verifier PKCE, token ni cuerpo de respuesta.

import type { IdpClientPort, Jwks } from "../../server/ports/idp-client.port.ts";

export interface IdpHttpResponse {
  readonly status: number;
  readonly body: string;
}

/** Cliente HTTP inyectado (proxy de egress, P-45). Debe respetar `timeoutMs` (menor que el lease del claim) y no seguir redirecciones. */
export interface IdpHttpClient {
  postForm(url: string, form: Readonly<Record<string, string>>, options: { timeoutMs: number }): Promise<IdpHttpResponse>;
  get(url: string, options: { timeoutMs: number }): Promise<IdpHttpResponse>;
}

export interface OidcIdpConfig {
  readonly environment: string;
  /** Bandera de egress aprobado (P-45). Sin ella el factory se niega. */
  readonly egressApproved: boolean;
  readonly issuer: string;
  /** Endpoints fijados por configuracion (APR-IDP): https, sin credenciales en la URL. */
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** Timeout por llamada, entero 1000..25000 ms (el lease maximo del claim es 120 s; el verifier usa 30 s por defecto). */
  readonly timeoutMs: number;
  /** TTL del cache del JWKS (ms), entero 1000..3600000. La rotacion por kid se resuelve al expirar. */
  readonly jwksCacheTtlMs: number;
  readonly now?: () => number;
}

export class IdpConfigError extends Error {
  constructor(detail: string) {
    super(`configuracion del IdP invalida: ${detail}. Abortando (fail-closed).`);
    this.name = "IdpConfigError";
  }
}

function httpsUrl(name: string, value: string): URL {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new IdpConfigError(`${name} no es una URL`);
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.hash !== "") throw new IdpConfigError(`${name} debe ser https, sin credenciales ni fragmento`);
  return u;
}

const isInt = (v: unknown, min: number, max: number): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max;

/** Factory del adaptador real. APAGADO: lanza en LOCAL, sin egress aprobado, o con configuracion incompleta/insegura. */
export function createOidcIdpAdapter(config: OidcIdpConfig, http: IdpHttpClient): IdpClientPort {
  if (config.environment === "LOCAL") throw new IdpConfigError("en LOCAL se usa el IdP sintetico; el adaptador real no se activa");
  if (config.environment !== "DEV" && config.environment !== "STAGING") throw new IdpConfigError("environment fuera del enum cerrado");
  if (config.egressApproved !== true) throw new IdpConfigError("egress no aprobado (P-45 PENDING)");
  const issuer = httpsUrl("issuer", config.issuer);
  const token = httpsUrl("tokenEndpoint", config.tokenEndpoint);
  const jwks = httpsUrl("jwksUri", config.jwksUri);
  if (token.origin !== issuer.origin || jwks.origin !== issuer.origin) throw new IdpConfigError("tokenEndpoint y jwksUri deben pertenecer al origen del issuer");
  if (config.clientId === "" || config.redirectUri === "") throw new IdpConfigError("clientId y redirectUri son obligatorios");
  httpsUrl("redirectUri", config.redirectUri);
  if (!isInt(config.timeoutMs, 1000, 25_000)) throw new IdpConfigError("timeoutMs debe ser un entero entre 1000 y 25000");
  if (!isInt(config.jwksCacheTtlMs, 1000, 3_600_000)) throw new IdpConfigError("jwksCacheTtlMs debe ser un entero entre 1000 y 3600000");
  const now = config.now ?? Date.now;
  let cache: { jwks: Jwks; at: number } | null = null;

  return {
    async exchangeCode(input: { code: string; pkceVerifier: string }): Promise<{ idToken: string }> {
      const res = await http.postForm(
        token.toString(),
        { grant_type: "authorization_code", code: input.code, code_verifier: input.pkceVerifier, client_id: config.clientId, redirect_uri: config.redirectUri },
        { timeoutMs: config.timeoutMs },
      );
      if (res.status !== 200) throw new Error("canje rechazado por el IdP");
      let parsed: unknown;
      try {
        parsed = JSON.parse(res.body);
      } catch {
        throw new Error("respuesta del IdP no es JSON");
      }
      const idToken = typeof parsed === "object" && parsed !== null ? (parsed as { id_token?: unknown }).id_token : undefined;
      if (typeof idToken !== "string" || idToken.length === 0) throw new Error("respuesta del IdP sin id_token");
      return { idToken };
    },

    async getJwks(): Promise<Jwks> {
      if (cache !== null && now() - cache.at < config.jwksCacheTtlMs) return cache.jwks;
      const res = await http.get(jwks.toString(), { timeoutMs: config.timeoutMs });
      if (res.status !== 200) throw new Error("JWKS no disponible");
      let parsed: unknown;
      try {
        parsed = JSON.parse(res.body);
      } catch {
        throw new Error("JWKS no es JSON");
      }
      const keys = typeof parsed === "object" && parsed !== null ? (parsed as { keys?: unknown }).keys : undefined;
      if (!Array.isArray(keys) || keys.length === 0 || keys.length > 20 || !keys.every((k) => typeof k === "object" && k !== null && typeof (k as { kty?: unknown }).kty === "string")) {
        throw new Error("JWKS invalido");
      }
      const value: Jwks = { keys: keys as Jwks["keys"] };
      cache = { jwks: value, at: now() };
      return value;
    },
  };
}
