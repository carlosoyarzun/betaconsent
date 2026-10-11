// Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4), §4.1 (proceso verifier = integrity_verifier), §7 fila PR-4 (DF-4, F-X8-15).
// Modulo del proceso verifier (el entrypoint/unidad de servicio llega en PR-6): un ciclo = tomar UNA solicitud del canje, canjear el code en el IdP (el unico
// proceso con egress), verificar el ID token y registrar la asercion. platform NO canjea ni lee code/PKCE.
// Limites de IA (Master Plan §32): este codigo no decide si existe consentimiento ni la autoridad de nadie; solo atesta que la persona que inicio el step-up
// se autentico en el IdP. La decision de si el sub_hmac corresponde al principal_ref la toma la BASE (platform.record_assertion, N6), no este modulo.
// Cero PII y cero secretos en logs/errores: el resultado del ciclo es un enum; nunca se devuelve el token, el code ni los claims.

import { computeSubHmac, IdTokenRejected, validateIdTokenPolicy, VerifierConfigError, verifyIdToken } from "./id-token.ts";
import type { IdTokenPolicy } from "./id-token.ts";
import type { IdpClientPort } from "../../ports/idp-client.port.ts";
import type { OidcExchangeStorePort, RejectionReason } from "../../ports/oidc-exchange.port.ts";

export interface VerifierConfig {
  issuer: string;
  audience: string;
  allowedAlgs: IdTokenPolicy["allowedAlgs"];
  /** P-36 (PENDING): se pasa explicito; no hay default. */
  maxAuthAgeSeconds: number;
  /** APR-IDP (PENDING): vacio/ausente = no se exige. */
  requiredAcrAnyOf?: readonly string[];
  /** K_sub del SecretStore (F-X8-09 pendiente): >= 32 bytes. */
  subHmacKey: Buffer;
  /**
   * Lease del claim en segundos (entero 1..120, default 30). record_assertion exige un lease VIGENTE: el timeout HTTP del IdP (canje + JWKS) debe ser MENOR que el lease
   * (el adaptador real lo impone; el sintetico no tiene red) o la asercion se rechaza.
   */
  leaseSeconds?: number;
  clockSkewSeconds?: number;
}

export interface VerifierDeps {
  store: OidcExchangeStorePort;
  idp: IdpClientPort;
  config: VerifierConfig;
  /** Reloj inyectable (ms desde epoch). */
  now?: () => number;
}

/** Resultado de un ciclo: nunca incluye datos del token. */
export type VerifierCycleResult = "IDLE" | "ATTESTED" | "REJECTED";

/** Valida la configuracion COMPLETA antes de tomar nada de la cola. Lanza VerifierConfigError (el ciclo aborta; no se registra REJECTED). */
export function validateVerifierConfig(config: VerifierConfig, nowSeconds: number): void {
  validateIdTokenPolicy({
    issuer: config.issuer,
    audience: config.audience,
    allowedAlgs: config.allowedAlgs,
    maxAuthAgeSeconds: config.maxAuthAgeSeconds,
    ...(config.requiredAcrAnyOf === undefined ? {} : { requiredAcrAnyOf: config.requiredAcrAnyOf }),
    ...(config.clockSkewSeconds === undefined ? {} : { clockSkewSeconds: config.clockSkewSeconds }),
    nowSeconds,
  });
  const lease = config.leaseSeconds ?? 30;
  if (typeof lease !== "number" || !Number.isSafeInteger(lease) || lease < 1 || lease > 120) throw new VerifierConfigError("leaseSeconds debe ser un entero entre 1 y 120");
  if (!Buffer.isBuffer(config.subHmacKey) || config.subHmacKey.length < 32) throw new VerifierConfigError("K_sub debe tener al menos 32 bytes");
}

function rejectionFor(error: unknown): RejectionReason {
  return error instanceof IdTokenRejected ? "INVALID_CLAIMS" : "EXCHANGE_FAILED";
}

export async function runVerifierCycle(deps: VerifierDeps): Promise<VerifierCycleResult> {
  const { store, idp, config } = deps;
  const now = deps.now ?? Date.now;
  validateVerifierConfig(config, Math.floor(now() / 1000));
  const claimed = await store.claim(config.leaseSeconds ?? 30);
  if (claimed === null) return "IDLE";

  try {
    // El code y el verifier PKCE solo existen en este alcance; se anulan en la base al registrar la asercion.
    const { idToken } = (await idp.exchangeCode({ code: claimed.code, pkceVerifier: claimed.pkceVerifier }));
    const jwks = await idp.getJwks();
    const verified = verifyIdToken(idToken, jwks, claimed.nonceHash, {
      issuer: config.issuer,
      audience: config.audience,
      allowedAlgs: config.allowedAlgs,
      maxAuthAgeSeconds: config.maxAuthAgeSeconds,
      ...(config.requiredAcrAnyOf === undefined ? {} : { requiredAcrAnyOf: config.requiredAcrAnyOf }),
      ...(config.clockSkewSeconds === undefined ? {} : { clockSkewSeconds: config.clockSkewSeconds }),
      nowSeconds: Math.floor(now() / 1000),
    });
    const attested = await store.recordAssertion({
      decision: "ATTESTED",
      exchangeRef: claimed.exchangeRef,
      subHmac: computeSubHmac(config.subHmacKey, config.issuer, verified.sub),
      assertionHash: verified.assertionHash,
      authTime: verified.authTime,
      acr: verified.acr,
      amr: verified.amr,
    });
    // La base puede degradar a REJECTED (sub_hmac no mapeado al principal, nonce vencido): el resultado refleja lo que quedo registrado.
    return attested ? "ATTESTED" : "REJECTED";
  } catch (error) {
    if (error instanceof VerifierConfigError) throw error; // despliegue roto: se aborta, no se "rechaza" al titular
    // Cualquier fallo del canje o de la verificacion cierra la solicitud como REJECTED (sin detalle). Si ni eso se puede registrar, la solicitud vence por TTL.
    await store.recordAssertion({ decision: "REJECTED", exchangeRef: claimed.exchangeRef, reason: rejectionFor(error) });
    return "REJECTED";
  }
  // El ID token crudo solo existio dentro del try: no se asigna fuera ni se devuelve.
}
